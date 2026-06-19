#include "introspectservice.h"

#include <jwt-cpp/jwt.h>

#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "tokenmanager.h"
#include "utils.h"

using namespace utils;

bool IntrospectService::handleRequest(const QString &input,
                                      const QString &output) {
    QJsonObject request;
    if (!readRequest(input, request)) {
        writeError(output, 400, "Invalid JSON or cannot read input file");
        return true;
    }

    QString token = request["token"].toString();
    if (token.isEmpty()) {
        writeError(output, 400, "Missing token");
        return true;
    }

    QString clientId, userId;
    QStringList scopes, roles;
    QString expectedAudience = "payments-api";
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
            resp["exp"] = static_cast<qint64>(
                decoded.get_payload_claim("exp").as_integer());
            resp["iat"] = static_cast<qint64>(
                decoded.get_payload_claim("iat").as_integer());
            resp["jti"] = QString::fromStdString(
                decoded.get_payload_claim("jti").as_string());
        } catch (...) {
        }
    }

    return writeResponse(output, resp);
}