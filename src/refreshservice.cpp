#include "refreshservice.h"

#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

#include "config.h"
#include "datamanager.h"
#include "tokenmanager.h"
#include "utils.h"

namespace {

using namespace utils;

bool validateRefreshToken(const QString &refreshToken, const QString &output,
                          RefreshRecord &rec, const User *&user) {
    if (!DataManager::instance().findRefreshRecord(refreshToken, rec)) {
        writeError(output, 401, "Unauthorized");
        return true;
    }

    if (rec.rotated) {
        writeError(output, 409, "Conflict");
        return true;
    }

    if (DataManager::instance().isRefreshTokenRevoked(refreshToken)) {
        writeError(output, 401, "Unauthorized");
        return true;
    }

    if (rec.expires < QDateTime::currentDateTimeUtc()) {
        writeError(output, 401, "Unauthorized");
        return true;
    }

    user = DataManager::instance().findUserByUserId(rec.userId);
    if (!user) {
        writeError(output, 500, "Internal Error");
        return true;
    }

    return true;
}

bool generateNewTokens(const RefreshRecord &oldRec, const User *user,
                       const Client *client, const QString &output) {
    DataManager::instance().markRefreshRotated(oldRec.refreshToken);

    const auto accessToken = TokenManager::generateAccessToken(
        oldRec.clientId, oldRec.userId, oldRec.scopes, user->roles,
        client->aud);

    const auto newRefreshToken =
        QUuid::createUuid().toString(QUuid::WithoutBraces);
    RefreshRecord newRec;
    newRec.refreshToken = newRefreshToken;
    newRec.userId = oldRec.userId;
    newRec.clientId = oldRec.clientId;
    newRec.scopes = oldRec.scopes;
    newRec.expires = QDateTime::currentDateTimeUtc().addDays(
        Config::instance().refreshTtlDays());
    newRec.rotated = false;
    DataManager::instance().addRefreshRecord(newRec);

    return writeTokenResponse(output, accessToken, newRefreshToken);
}

}  // namespace

bool RefreshService::handleRequest(const QString &input,
                                   const QString &output) {
    QJsonObject request;
    if (!readRequest(input, request)) {
        writeError(output, 400, "Bad Request");
        return true;
    }

    const QString grantType = request["grant_type"].toString();
    if (grantType != "refresh_token") {
        writeError(output, 400, "Bad Request");
        return true;
    }

    const Client *client = nullptr;
    if (!validateClient(request, client, output)) {
        return true;
    }

    const QString refreshToken = request["refresh_token"].toString();
    RefreshRecord rec;
    const User *user = nullptr;
    if (!validateRefreshToken(refreshToken, output, rec, user)) {
        return true;
    }

    return generateNewTokens(rec, user, client, output);
}