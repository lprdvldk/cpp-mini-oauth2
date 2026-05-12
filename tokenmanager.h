#ifndef TOKENMANAGER_H
#define TOKENMANAGER_H

#include <QString>
#include <QStringList>

class TokenManager
{
public:
    static const QString secret;
    static const QString issuer;
    static const int access_ttl_sec;
    static const int refresh_ttl_days;

    static QString generateAccessToken(const QString &clientId, const QString &userId, const QStringList &scopes, const QStringList &roles, const QString &audience);

    static bool validateAccessToken(const QString &token, const QString &expectedAudience, QString &clientId, QString &userId, QStringList &scopes, QStringList &roles);
};

#endif // TOKENMANAGER_H
