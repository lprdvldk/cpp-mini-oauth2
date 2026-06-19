#include "paymentservice.h"

#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>

#include "tokenmanager.h"
#include "utils.h"

using namespace utils;

namespace {

bool validateToken(const QString &accessToken, const QString &expectedAudience,
                   const QString &output, QString &clientId, QString &userId,
                   QStringList &scopes, QStringList &roles) {
    if (!TokenManager::validateAccessToken(accessToken, expectedAudience,
                                           clientId, userId, scopes, roles)) {
        return writeError(output, 401, "Unauthorized");
    }
    return true;
}

bool getRequiredScope(const QString &method, QString &requiredScope,
                      const QString &output) {
    const QString methodUpper = method.toUpper();
    if (methodUpper == "GET") {
        requiredScope = "payments:read";
        return true;
    } else if (methodUpper == "POST") {
        requiredScope = "payments:write";
        return true;
    } else {
        writeError(output, 400, "Bad Request");
        return true;
    }
}

bool checkScope(const QStringList &tokenScopes, const QString &requiredScope,
                const QString &output) {
    if (!tokenScopes.contains(requiredScope)) {
        writeError(output, 403,
                   "Forbidden. Required scope missing : " + requiredScope);
        return true;
    }
    return true;
}

bool buildPaymentResponse(const QString &output, const QString &userId,
                          const QString &method) {
    QJsonObject resp;
    resp["status"] = "success";
    resp["message"] = "Access granted to payments resource";
    resp["user_id"] = userId;

    const QString methodUpper = method.toUpper();
    if (methodUpper == "GET") {
        resp["data"] = "List of payments (dummy)";
    } else if (methodUpper == "POST") {
        resp["data"] = "Payment created (dummy)";
    }

    return writeResponse(output, resp);
}

}  // namespace

bool PaymentsService::handleRequest(const QString &input,
                                    const QString &output) {
    QJsonObject request;
    if (!readRequest(input, request)) {
        writeError(output, 400, "Bad Request");
        return true;
    }

    const auto accessToken = request["access_token"].toString();
    if (accessToken.isEmpty()) {
        return writeError(output, 400, "Bad Request");
    }

    QString clientId, userId;
    QStringList scopes, roles;
    const QString expectedAudience = "payments-api";
    if (!validateToken(accessToken, expectedAudience, output, clientId, userId,
                       scopes, roles)) {
        return true;
    }

    const auto method = request["method"].toString();
    QString requiredScope;
    if (!getRequiredScope(method, requiredScope, output)) {
        return true;
    }

    if (!checkScope(scopes, requiredScope, output)) {
        return true;
    }

    return buildPaymentResponse(output, userId, method);
}