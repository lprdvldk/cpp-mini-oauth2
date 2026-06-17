#include "tokenservice.h"
#include "config.h"
#include "datamanager.h"
#include "tokenmanager.h"
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

bool TokenService::handleRequest(const QString &input, const QString &output) {
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

  if (grantType == "password") {
    if (!client->allowedGrants.contains("password")) {
      QJsonObject resp;
      resp["error"] = "unauthorized_client";
      resp["error_description"] = "Grant type not allowed for this client";
      QFile outFile(output);
      if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(QJsonDocument(resp).toJson());
      }
      return true;
    }

    QString username = req["username"].toString();
    QString password = req["password"].toString();
    if (!DataManager::instance().verifyPassword(username, password)) {
      QJsonObject resp;
      resp["error"] = "invalid_grant";
      resp["error_description"] = "Invalid username or password";
      QFile outFile(output);
      if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(QJsonDocument(resp).toJson());
      }
      return true;
    }

    User *user = DataManager::instance().findUserByUsername(username);
    if (!user || user->status != "active") {
      QJsonObject resp;
      resp["error"] = "invalid_grant";
      resp["error_description"] = "User not active";
      QFile outFile(output);
      if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(QJsonDocument(resp).toJson());
      }
      return true;
    }

    QStringList requestedScopes = req["scopes"].toVariant().toStringList();
    QStringList userScopes =
        DataManager::instance().getScopesForRoles(user->roles);
    QStringList allowedScopes = client->allowedScopes;
    QStringList finalScopes =
        DataManager::instance().intersectScopes(requestedScopes, allowedScopes);
    finalScopes =
        DataManager::instance().intersectScopes(finalScopes, userScopes);

    // Generate access token
    QString accessToken = TokenManager::generateAccessToken(
        clientId, user->userId, finalScopes, user->roles, client->aud);
    // Generate refresh token
    QString refreshToken = QUuid::createUuid().toString(QUuid::WithoutBraces);
    RefreshRecord rec;
    rec.refreshToken = refreshToken;
    rec.userId = user->userId;
    rec.clientId = clientId;
    rec.scopes = finalScopes;
    rec.expires = QDateTime::currentDateTimeUtc().addDays(
        Config::instance().refreshTtlDays());
    rec.rotated = false;
    DataManager::instance().addRefreshRecord(rec);

    QJsonObject resp;
    resp["access_token"] = accessToken;
    resp["refresh_token"] = refreshToken;
    resp["token_type"] = "Bearer";
    resp["expires_in"] = Config::instance().accessTtlSec();
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  } else if (grantType == "client_credentials") {
    if (!client->allowedGrants.contains("client_credentials")) {
      QJsonObject resp;
      resp["error"] = "unauthorized_client";
      resp["error_description"] = "Grant type not allowed for this client";
      QFile outFile(output);
      if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(QJsonDocument(resp).toJson());
      }
      return true;
    }

    QStringList requestedScopes = req["scopes"].toVariant().toStringList();
    QStringList finalScopes = DataManager::instance().intersectScopes(
        requestedScopes, client->allowedScopes);

    // No user, so sub = client_id, roles empty
    QString accessToken = TokenManager::generateAccessToken(
        clientId, clientId, finalScopes, QStringList(), client->aud);
    // No refresh token for client_credentials
    QJsonObject resp;
    resp["access_token"] = accessToken;
    resp["token_type"] = "Bearer";
    resp["expires_in"] = Config::instance().accessTtlSec();
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  } else {
    QJsonObject resp;
    resp["error"] = "unsupported_grant_type";
    resp["error_description"] = "Grant type not supported";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }
}