#include "introspectservice.h"
#include "config.h"
#include "datamanager.h"
#include "tokenmanager.h"
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <jwt-cpp/jwt.h>

bool IntrospectService::handleRequest(const QString &input,
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

  QString token = req["token"].toString();
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

  // Validate token for access
  QString clientId, userId;
  QStringList scopes, roles;
  QString expectedAudience = "payments-api"; // any expected audience
  bool valid = TokenManager::validateAccessToken(
      token, expectedAudience, clientId, userId, scopes, roles);

  QJsonObject resp;
  resp["active"] = valid;

  if (valid) {
    resp["client_id"] = clientId;
    resp["sub"] = userId;
    resp["scope"] = scopes.join(" ");
    resp["roles"] = QJsonArray::fromStringList(roles);
    try {
      auto decoded = jwt::decode(token.toStdString());
      resp["exp"] =
          static_cast<qint64>(decoded.get_payload_claim("exp").as_integer());
      resp["iat"] =
          static_cast<qint64>(decoded.get_payload_claim("iat").as_integer());
      resp["jti"] =
          QString::fromStdString(decoded.get_payload_claim("jti").as_string());
    } catch (...) {
    }
  } else {
    qWarning() << "Token revoked: " << input;
  }

  QFile outFile(output);
  if (outFile.open(QIODevice::WriteOnly)) {
    outFile.write(QJsonDocument(resp).toJson());
  }
  return true;
}