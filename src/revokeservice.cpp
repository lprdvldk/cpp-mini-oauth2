#include "datamanager.h"
#include "jwt-cpp/jwt.h"
#include "revokeservice.h"
#include "tokenmanager.h"
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

bool RevokeService::handleRequest(const QString &input, const QString &output) {
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

  QString token = req["token"].toString();
  QString tokenTypeHint =
      req["token_type_hint"].toString();

  if (token.isEmpty()) {
    QJsonObject resp;
    resp["error"] = "invalid_request";
    resp["error_description"] = "Missing token";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  // Determine token type
  if (tokenTypeHint.isEmpty()) {
    tokenTypeHint = "access_token";
  }

  if (tokenTypeHint == "access_token") {
    try {
      auto decoded = jwt::decode(token.toStdString());
      auto jtiClaim = decoded.get_payload_claim("jti");
      if (jtiClaim.get_type() != jwt::json::type::string) {
        throw std::exception();
      }
      QString jti = QString::fromStdString(jtiClaim.as_string());
      auto expClaim = decoded.get_payload_claim("exp");
      QDateTime exp = QDateTime::fromSecsSinceEpoch(expClaim.as_integer());
      DataManager::instance().revokeAccessToken(jti, exp);
      QJsonObject resp;
      resp["status"] = "success";
      QFile outFile(output);
      if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(QJsonDocument(resp).toJson());
      }
      return true;
    } catch (...) {
      QJsonObject resp;
      resp["error"] = "invalid_token";
      resp["error_description"] = "Could not parse access token";
      QFile outFile(output);
      if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(QJsonDocument(resp).toJson());
      }
      return true;
    }
  } else if (tokenTypeHint == "refresh_token") {
    RefreshRecord rec;
    if (!DataManager::instance().findRefreshRecord(token, rec)) {
      QJsonObject resp;
      resp["error"] = "invalid_token";
      resp["error_description"] = "Refresh token not found";
      QFile outFile(output);
      if (outFile.open(QIODevice::WriteOnly)) {
        outFile.write(QJsonDocument(resp).toJson());
      }
      return true;
    }
    DataManager::instance().revokeRefreshToken(token, rec.expires);
    DataManager::instance().removeRefreshRecord(token);
    QJsonObject resp;
    resp["status"] = "success";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  } else {
    QJsonObject resp;
    resp["error"] = "unsupported_token_type";
    resp["error_description"] =
        "token_type_hint must be access_token or refresh_token";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }
}