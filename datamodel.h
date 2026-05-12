#ifndef DATAMODEL_H
#define DATAMODEL_H

#include <QDateTime>

struct Role {
    QStringList scopes;
};

struct User {
    QString userId;
    QString username;
    QString passwordHash;
    QStringList roles;
    QString status;
};

struct Client {
    QString clientId;
    QString clientSecret;
    QStringList allowedGrants;
    QStringList allowedScopes;
    QString aud;
};

struct RefreshRecord {
    QString refreshToken;
    QString clientId;
    QString userId;
    QStringList scopes;
    QDateTime expires;
    bool rotated = false;
};

#endif // DATAMODEL_H
