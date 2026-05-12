#include "tokenmanager.h"

#include <QUuid>
#include <QDebug>

#include <jwt-cpp/jwt.h>

const QString TokenManager::secret = "supersecret";
const QString TokenManager::issuer = "mini-auth";
const int TokenManager::access_ttl_sec = 900;
const int TokenManager::refresh_ttl_days = 14;

QString TokenManager::generateAccessToken(const QString &clientId, const QString &userId, const QStringList &scopes, const QStringList &roles, const QString &audience)
{
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::seconds(TokenManager::access_ttl_sec);

    std::vector<std::string> scopesStd;
    for (const auto &s : scopes) scopesStd.push_back(s.toStdString());

    std::vector<std::string> rolesStd;
    for (const auto &r : roles) rolesStd.push_back(r.toStdString());

    auto token = jwt::create()
                     .set_type("AT")
                     .set_algorithm("HS256")
                     .set_issuer(issuer .toStdString())
                     .set_audience(audience.toStdString())
                     .set_subject(userId.toStdString())
                     .set_payload_claim("client_id", jwt::claim(clientId.toStdString()))
                     .set_payload_claim("scopes", jwt::claim(scopesStd.begin(), scopesStd.end()))
                     .set_payload_claim("roles", jwt::claim(rolesStd.begin(), rolesStd.end()))
                     .set_issued_at(now)
                     .set_expires_at(exp)
                     .set_payload_claim("jti", jwt::claim(QUuid::createUuid().toString(QUuid::WithoutBraces).toStdString()))
                     .sign(jwt::algorithm::hs256{secret.toStdString()});

    return QString::fromStdString(token);
}

bool TokenManager::validateAccessToken(const QString &token, const QString &expectedAudience, QString &clientId, QString &userId, QStringList &scopes, QStringList &roles)
{
    try {
        auto decoded = jwt::decode(token.toStdString());
        auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{secret.toStdString()})
                            .with_issuer(issuer.toStdString())
                            .with_audience(expectedAudience.toStdString());
        verifier.verify(decoded);

        clientId = QString::fromStdString(decoded.get_payload_claim("client_id").as_string());
        userId = QString::fromStdString(decoded.get_subject());

        auto scopesVal = decoded.get_payload_claim("scopes");
        if (scopesVal.get_type() == jwt::json::type::array) {
            auto arr = scopesVal.as_array();
            for (const auto &item : arr)
                scopes << QString::fromStdString(item.get<std::string>());
        }

        auto rolesVal = decoded.get_payload_claim("roles");
        if (rolesVal.get_type() == jwt::json::type::array) {
            auto arr = rolesVal.as_array();
            for (const auto &item : arr)
                roles << QString::fromStdString(item.get<std::string>());
        }
        return true;
    } catch (const std::exception &e) {
        qWarning() << "JWT validation failed:" << e.what();
        return false;
    }
}
