#ifndef DATAMANAGER_H
#define DATAMANAGER_H

#include <QDateTime>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QVector>

#include "datamodel.h"

class DataManager {
public:
    static DataManager &instance();

    static void setDataDirectory(const QString &path);

    bool loadAll();
    bool saveAll();

    // Users
    auto users() const {
        return m_users_;
    }
    const User *findUserByUsername(const QString &username);
    const User *findUserByUserId(const QString &userId);
    bool verifyPassword(const QString &username, const QString &password);

    // Clients
    auto clients() const {
        return m_clients_;
    }
    const Client *findClientById(const QString &clientId);
    bool checkClientSecret(const QString &clientId, const QString &secret);

    // Roles
    auto roles() const {
        return m_roles_;
    }
    QStringList getScopesForRoles(const QStringList &roleNames) const;

    // Refresh index
    auto refreshRecords() const {
        return m_refreshRecords_;
    }
    void addRefreshRecord(const RefreshRecord &record);
    bool findRefreshRecord(const QString &refreshToken, RefreshRecord &out);
    bool markRefreshRotated(const QString &refreshToken);
    bool removeRefreshRecord(const QString &refreshToken);

    // Revocations
    void revokeAccessToken(const QString &jti, const QDateTime &exp);
    void revokeRefreshToken(const QString &refreshToken, const QDateTime &exp);
    bool isAccessTokenRevoked(const QString &jti) const;
    bool isRefreshTokenRevoked(const QString &refreshToken) const;

    // Utility
    QStringList intersectScopes(const QStringList &requested,
                                const QStringList &allowed) const;

private:
    DataManager() = default;

    // Get file paths
    static QString usersFilePath();
    static QString clientsFilePath();
    static QString rolesFilePath();
    static QString refreshIndexFilePath();
    static QString revocationsFilePath();

    bool loadUsers();
    bool loadClients();
    bool loadRoles();
    bool loadRefreshIndex();
    bool loadRevocations();

    bool saveUsers() const;
    bool saveClients() const;
    bool saveRoles() const;
    bool saveRefreshIndex() const;
    bool saveRevocations() const;

    QHash<QString, User> m_users_;
    QHash<QString, Client> m_clients_;
    QHash<QString, Role> m_roles_;
    QVector<RefreshRecord> m_refreshRecords_;
    QVector<RevocationRecord> m_revocations_;

    static QString s_dataDir_;  // base dir for data
};

#endif  // DATAMANAGER_H