#include "tokenmanager.h"

#include <jwt-cpp/jwt.h>

#include <QUuid>

#include "datamanager.h"
#include "utils.h"

static QString s_secret;
static QString s_issuer;
static int s_accessTtlSec = 900;

void TokenManager::initialize(const QString &secret, const QString &issuer,
                              int accessTtlSec) {
    s_secret = secret;
    s_issuer = issuer;
    s_accessTtlSec = accessTtlSec;
}

QString TokenManager::generateAccessToken(const QString &clientId,
                                          const QString &userId,
                                          const QStringList &scopes,
                                          const QStringList &roles,
                                          const QString &audience) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::seconds(s_accessTtlSec);

    std::vector<std::string> scopesStd;
    for (const auto &s : scopes)
        scopesStd.push_back(s.toStdString());

    std::vector<std::string> rolesStd;
    for (const auto &r : roles)
        rolesStd.push_back(r.toStdString());

    auto token =
        jwt::create()
            .set_type("AT")
            .set_algorithm("HS256")
            .set_issuer(s_issuer.toStdString())
            .set_audience(audience.toStdString())
            .set_subject(userId.toStdString())
            .set_payload_claim("client_id", jwt::claim(clientId.toStdString()))
            .set_payload_claim("scopes",
                               jwt::claim(scopesStd.begin(), scopesStd.end()))
            .set_payload_claim("roles",
                               jwt::claim(rolesStd.begin(), rolesStd.end()))
            .set_issued_at(now)
            .set_expires_at(exp)
            .set_payload_claim("jti",
                               jwt::claim(QUuid::createUuid()
                                              .toString(QUuid::WithoutBraces)
                                              .toStdString()))
            .sign(jwt::algorithm::hs256{s_secret.toStdString()});

    return QString::fromStdString(token);
}

bool TokenManager::validateAccessToken(const QString &token,
                                       const QString &expectedAudience,
                                       QString &clientId, QString &userId,
                                       QStringList &scopes,
                                       QStringList &roles) {
    try {
        if (!utils::isValidJwtFormat(token)) {
            return false;
        }
        auto decoded = jwt::decode(token.toStdString());
        auto verifier =
            jwt::verify()
                .allow_algorithm(jwt::algorithm::hs256{s_secret.toStdString()})
                .with_issuer(s_issuer.toStdString())
                .with_audience(expectedAudience.toStdString());
        verifier.verify(decoded);

        auto jtiClaim = decoded.get_payload_claim("jti");
        if (jtiClaim.get_type() != jwt::json::type::string) {
            return false;
        }
        QString jti = QString::fromStdString(jtiClaim.as_string());

        if (DataManager::instance().isAccessTokenRevoked(jti)) {
            return false;
        }

        clientId = QString::fromStdString(
            decoded.get_payload_claim("client_id").as_string());
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
        utils::logError("JWT validation failed: " + QString(e.what()));
        return false;
    }
}