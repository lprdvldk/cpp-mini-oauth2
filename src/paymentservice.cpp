#include "paymentservice.h"
#include "config.h"
#include "datamanager.h"
#include "tokenmanager.h"
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

bool PaymentsService::handleRequest(const QString &input,
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

  QString accessToken = req["access_token"].toString();
  QString method = req["method"].toString().toUpper();
  if (accessToken.isEmpty()) {
    QJsonObject resp;
    resp["error"] = "invalid_request";
    resp["error_description"] = "Missing access_token";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  // Toekn Validation
  QString clientId, userId;
  QStringList scopes, roles;
  QString expectedAudience = "payments-api";
  if (!TokenManager::validateAccessToken(accessToken, expectedAudience,
                                         clientId, userId, scopes, roles)) {
    QJsonObject resp;
    resp["error"] = "invalid_token";
    resp["error_description"] = "Token validation failed";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  QString requiredScope;
  if (method == "GET") {
    requiredScope = "payments:read";
  } else if (method == "POST") {
    requiredScope = "payments:write";
  } else {
    QJsonObject resp;
    resp["error"] = "bad_request";
    resp["error_description"] = "Unsupported method";
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  if (!scopes.contains(requiredScope)) {
    QJsonObject resp;
    resp["error"] = "insufficient_scope";
    resp["error_description"] = "Required scope missing: " + requiredScope;
    QFile outFile(output);
    if (outFile.open(QIODevice::WriteOnly)) {
      outFile.write(QJsonDocument(resp).toJson());
    }
    return true;
  }

  QJsonObject resp;
  resp["status"] = "success";
  resp["message"] = "Access granted to payments resource";
  resp["user_id"] = userId;
  if (method == "GET") {
    resp["data"] = "List of payments (dummy)";
  } else if (method == "POST") {
    resp["data"] = "Payment created (dummy)";
  }
  QFile outFile(output);
  if (outFile.open(QIODevice::WriteOnly)) {
    outFile.write(QJsonDocument(resp).toJson());
  }
  return true;
}