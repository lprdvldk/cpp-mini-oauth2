#include "revokeservice.h"

#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

#include "datamanager.h"
#include "jwt-cpp/jwt.h"
#include "utils.h"

namespace {

using namespace utils;

bool handleAccessTokenRevocation(const QString &token, const QString &output) {
    try {
        if (!utils::isValidJwtFormat(token)) {
            writeError(output, 400, "Bad request");
            return true;
        }
        auto decoded = jwt::decode(token.toStdString());
        auto jtiClaim = decoded.get_payload_claim("jti");
        if (jtiClaim.get_type() != jwt::json::type::string) {
            throw std::exception();
        }
        auto jti = QString::fromStdString(jtiClaim.as_string());
        auto expClaim = decoded.get_payload_claim("exp");
        auto exp = QDateTime::fromSecsSinceEpoch(expClaim.as_integer());
        DataManager::instance().revokeAccessToken(jti, exp);
        return writeSuccessResponse(output);
    } catch (...) {
        writeError(output, 401, "Unauthorized");
        return true;
    }
}

bool handleRefreshTokenRevocation(const QString &token, const QString &output) {
    RefreshRecord rec;
    if (!DataManager::instance().findRefreshRecord(token, rec)) {
        return writeError(output, 401, "Unauthorized");
    }
    DataManager::instance().revokeRefreshToken(token, rec.expires);
    DataManager::instance().removeRefreshRecord(token);
    return writeSuccessResponse(output);
}

}  // namespace

bool RevokeService::handleRequest(const QString &input, const QString &output) {
    QJsonObject request;
    if (!readRequest(input, request)) {
        writeError(output, 400, "Bad Request");
        return true;
    }

    const QString token = request["token"].toString();
    if (token.isEmpty()) {
        writeError(output, 400, "Bad Request");
        return true;
    }

    QString tokenTypeHint = request["token_type_hint"].toString();
    if (tokenTypeHint.isEmpty()) {
        tokenTypeHint = "access_token";
    }

    if (tokenTypeHint == "access_token") {
        return handleAccessTokenRevocation(token, output);
    } else if (tokenTypeHint == "refresh_token") {
        return handleRefreshTokenRevocation(token, output);
    } else {
        writeError(output, 400, "Bad Request");
        return true;
    }
}