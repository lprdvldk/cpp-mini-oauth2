#include "tokenservice.h"

#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

#include "config.h"
#include "datamanager.h"
#include "tokenmanager.h"
#include "utils.h"

namespace {

using namespace utils;

bool handlePasswordGrant(const QJsonObject &request, const Client *client,
                         const QString &output) {
    if (!client->allowedGrants.contains("password")) {
        return writeError(output, 403,
                          "Client not allowed for grant: password");
    }

    const QString username = request["username"].toString();
    const QString password = request["password"].toString();
    if (!DataManager::instance().verifyPassword(username, password)) {
        return writeError(output, 401, "Unauthorized");
    }

    auto user = DataManager::instance().findUserByUsername(username);
    if (!user || user->status != "active") {
        return writeError(output, 403, "Forbidden");
    }

    const auto requestedScopes = request["scopes"].toVariant().toStringList();
    const auto userScopes =
        DataManager::instance().getScopesForRoles(user->roles);
    auto finalScopes = DataManager::instance().intersectScopes(
        requestedScopes, client->allowedScopes);
    finalScopes =
        DataManager::instance().intersectScopes(finalScopes, userScopes);

    const QString accessToken = TokenManager::generateAccessToken(
        client->clientId, user->userId, finalScopes, user->roles, client->aud);

    const QString refreshToken =
        QUuid::createUuid().toString(QUuid::WithoutBraces);
    RefreshRecord rec;
    rec.refreshToken = refreshToken;
    rec.userId = user->userId;
    rec.clientId = client->clientId;
    rec.scopes = finalScopes;
    rec.expires = QDateTime::currentDateTimeUtc().addDays(
        Config::instance().refreshTtlDays());
    rec.rotated = false;
    DataManager::instance().addRefreshRecord(rec);

    QJsonObject response;
    response["access_token"] = accessToken;
    response["refresh_token"] = refreshToken;
    response["token_type"] = "Bearer";
    response["expires_in"] = Config::instance().accessTtlSec();

    return writeResponse(output, response);
}

bool handleClientCredentialsGrant(const QJsonObject &request,
                                  const Client *client, const QString &output) {
    if (!client->allowedGrants.contains("client_credentials")) {
        return writeError(output, 403,
                          "Client not allowed for grant: client_credentials");
    }

    const auto requestedScopes = request["scopes"].toVariant().toStringList();
    const auto finalScopes = DataManager::instance().intersectScopes(
        requestedScopes, client->allowedScopes);

    const QString accessToken = TokenManager::generateAccessToken(
        client->clientId, client->clientId, finalScopes, QStringList(),
        client->aud);

    QJsonObject response;
    response["access_token"] = accessToken;
    response["token_type"] = "Bearer";
    response["expires_in"] = Config::instance().accessTtlSec();

    return writeResponse(output, response);
}

}  // namespace

bool TokenService::handleRequest(const QString &input, const QString &output) {
    QJsonObject request;
    if (!readRequest(input, request)) {
        writeError(output, 400, "Bad Request");
        return true;
    }

    const Client *client = nullptr;
    if (!validateClient(request, client, output)) {
        return true;
    }

    const QString grantType = request["grant_type"].toString();
    if (grantType == "password") {
        return handlePasswordGrant(request, client, output);
    } else if (grantType == "client_credentials") {
        return handleClientCredentialsGrant(request, client, output);
    } else {
        return writeError(output, 400, "unsupported_grant_type");
    }
}