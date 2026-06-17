#ifndef DATAMANAGER_H
#define DATAMANAGER_H

#include "datamodel.h"
#include <QDateTime>
#include <QHash>
#include <QString>
#include <QStringList>
#include <QVector>

class DataManager {
public:
  static DataManager &instance();

  static void setDataDirectory(const QString &path);

  bool loadAll();
  bool saveAll();

  // Users
  QVector<User> users() const { return m_users; }
  User *findUserByUsername(const QString &username);
  User *findUserByUserId(const QString &userId);
  bool verifyPassword(const QString &username, const QString &password);

  // Clients
  QVector<Client> clients() const { return m_clients; }
  Client *findClientById(const QString &clientId);
  bool checkClientSecret(const QString &clientId, const QString &secret);

  // Roles
  QHash<QString, Role> roles() const { return m_roles; }
  QStringList getScopesForRoles(const QStringList &roleNames) const;

  // Refresh index
  QVector<RefreshRecord> refreshRecords() const { return m_refreshRecords; }
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

  QVector<User> m_users;
  QVector<Client> m_clients;
  QHash<QString, Role> m_roles;
  QVector<RefreshRecord> m_refreshRecords;
  QVector<RevocationRecord> m_revocations;

  static QString s_dataDir; // base dir for data
};

#endif // DATAMANAGER_H