#include "refreshservice.h"
#include "config.h"
#include "datamanager.h"
#include "tokenmanager.h"
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

bool RefreshService::handleRequest(const QString &input,
                                   const QString &output) {
  QFile inFile(input);
  if (!inFile.open(QIODevice::ReadOnly)) {
    qWarning() << "Cannot open input file:" << input;
    return false;
  }
  QByteArray data = inFile.readAll();
  QJsonDocument doc = QJsonDocument::fromJson(data);
  if (doc.isNull()) {
    qWarning() << "Invalid JSON in input";
    return false;
  }
  QJsonObject req = doc.object();

  QString grantType = req["grant_type"].toString();
  if (grantType != "refresh_token") {
    QJsonObject resp;
    resp["error"] = "unsupported_grant_type";
    resp["error_description"] = "Expected refresh_token grant";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  QString refreshToken = req["refresh_token"].toString();
  QString clientId = req["client_id"].toString();
  QString clientSecret = req["client_secret"].toString();

  Client *client = DataManager::instance().findClientById(clientId);
  if (!client) {
    QJsonObject resp;
    resp["error"] = "invalid_client";
    resp["error_description"] = "Client not found";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }
  if (!DataManager::instance().checkClientSecret(clientId, clientSecret)) {
    QJsonObject resp;
    resp["error"] = "invalid_client";
    resp["error_description"] = "Invalid client secret";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }
  if (!client->allowedGrants.contains("refresh_token")) {
    QJsonObject resp;
    resp["error"] = "unauthorized_client";
    resp["error_description"] = "Client not allowed to use refresh_token";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  // Find refresh record
  RefreshRecord rec;
  if (!DataManager::instance().findRefreshRecord(refreshToken, rec)) {
    QJsonObject resp;
    resp["error"] = "invalid_grant";
    resp["error_description"] = "Refresh token not found";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  // Check if rotated or revoked
  if (rec.rotated) {
    QJsonObject resp;
    resp["error"] = "invalid_grant";
    resp["error_description"] = "Refresh token already used (rotated)";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }
  if (DataManager::instance().isRefreshTokenRevoked(refreshToken)) {
    QJsonObject resp;
    resp["error"] = "invalid_grant";
    resp["error_description"] = "Refresh token revoked";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }
  if (rec.expires < QDateTime::currentDateTimeUtc()) {
    QJsonObject resp;
    resp["error"] = "invalid_grant";
    resp["error_description"] = "Refresh token expired";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  // Mark old as rotated
  DataManager::instance().markRefreshRotated(refreshToken);

  // Generate new access token (use same scopes and roles from user)
  // We need user roles to regenerate
  User *user = DataManager::instance().findUserByUsername(
      rec.userId);
  User *userObj = DataManager::instance().findUserByUserId(rec.userId);
  if (!userObj) {
    QJsonObject resp;
    resp["error"] = "server_error";
    resp["error_description"] = "User associated with refresh not found";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  QString accessToken = TokenManager::generateAccessToken(
      rec.clientId, rec.userId, rec.scopes, userObj->roles, client->aud);

  // Generate new refresh token
  QString newRefreshToken = QUuid::createUuid().toString(QUuid::WithoutBraces);
  RefreshRecord newRec;
  newRec.refreshToken = newRefreshToken;
  newRec.userId = rec.userId;
  newRec.clientId = rec.clientId;
  newRec.scopes = rec.scopes;
  newRec.expires = QDateTime::currentDateTimeUtc().addDays(
      Config::instance().refreshTtlDays());
  newRec.rotated = false;
  DataManager::instance().addRefreshRecord(newRec);

  QJsonObject resp;
  resp["access_token"] = accessToken;
  resp["refresh_token"] = newRefreshToken;
  resp["token_type"] = "Bearer";
  resp["expires_in"] = Config::instance().accessTtlSec();
  QFile outFile(output);
  if (outFile.open(QIODevice::WriteOnly)) {
    outFile.write(QJsonDocument(resp).toJson());
  }
  return true;
}