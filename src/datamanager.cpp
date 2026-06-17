#include "datamanager.h"
#include <QCryptographicHash>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

// Static data files path
QString DataManager::s_dataDir = "data/";

// Static methods for data files paths
QString DataManager::usersFilePath() { return s_dataDir + "users.json"; }

QString DataManager::clientsFilePath() { return s_dataDir + "clients.json"; }

QString DataManager::rolesFilePath() { return s_dataDir + "roles.json"; }

QString DataManager::refreshIndexFilePath() {
  return s_dataDir + "refresh_index.ndjson";
}

QString DataManager::revocationsFilePath() {
  return s_dataDir + "revocations.ndjson";
}

DataManager &DataManager::instance() {
  static DataManager dm;
  return dm;
}

void DataManager::setDataDirectory(const QString &path) {
  s_dataDir = path;
  QDir().mkpath(s_dataDir);
}

bool DataManager::loadAll() {
  bool ok = true;
  if (!loadUsers())
    ok = false;
  if (!loadClients())
    ok = false;
  if (!loadRoles())
    ok = false;
  if (!loadRefreshIndex())
    ok = false;
  if (!loadRevocations())
    ok = false;
  return ok;
}

bool DataManager::saveAll() {
  bool ok = true;
  if (!saveUsers())
    ok = false;
  if (!saveClients())
    ok = false;
  if (!saveRoles())
    ok = false;
  if (!saveRefreshIndex())
    ok = false;
  if (!saveRevocations())
    ok = false;
  return ok;
}

bool DataManager::loadUsers() {
  QFile file(usersFilePath());
  if (!file.open(QIODevice::ReadOnly)) {
    qWarning() << "Could not open users file:" << usersFilePath();
    return false;
  }
  QByteArray data = file.readAll();
  QJsonDocument doc = QJsonDocument::fromJson(data);
  if (doc.isNull()) {
    qWarning() << "Invalid JSON in users file";
    return false;
  }
  QJsonArray arr = doc.array();
  m_users.clear();
  for (const auto &val : arr) {
    QJsonObject obj = val.toObject();
    User u;
    u.userId = obj["user_id"].toString();
    u.username = obj["username"].toString();
    u.passwordHash = obj["password_hash"].toString();
    u.roles = obj["roles"].toVariant().toStringList();
    u.status = obj["status"].toString();
    m_users.append(u);
  }
  return true;
}

bool DataManager::saveUsers() const {
  QJsonArray arr;
  for (const User &u : m_users) {
    QJsonObject obj;
    obj["user_id"] = u.userId;
    obj["username"] = u.username;
    obj["password_hash"] = u.passwordHash;
    obj["roles"] = QJsonArray::fromStringList(u.roles);
    obj["status"] = u.status;
    arr.append(obj);
  }
  QJsonDocument doc(arr);
  QFile file(usersFilePath());
  if (!file.open(QIODevice::WriteOnly)) {
    qWarning() << "Could not write users file";
    return false;
  }
  file.write(doc.toJson(QJsonDocument::Indented));
  return true;
}

User *DataManager::findUserByUsername(const QString &username) {
  for (User &u : m_users) {
    if (u.username == username)
      return &u;
  }
  return nullptr;
}

User *DataManager::findUserByUserId(const QString &userId) {
  for (User &u : m_users) {
    if (u.userId == userId)
      return &u;
  }
  return nullptr;
}

bool DataManager::verifyPassword(const QString &username,
                                 const QString &password) {
  User *user = findUserByUsername(username);
  if (!user)
    return false;
  QByteArray hash =
      QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256)
          .toHex();
  return user->passwordHash == QString::fromUtf8(hash);
}

bool DataManager::loadClients() {
  QFile file(clientsFilePath());
  if (!file.open(QIODevice::ReadOnly)) {
    qWarning() << "Could not open clients file:" << clientsFilePath();
    return false;
  }
  QByteArray data = file.readAll();
  QJsonDocument doc = QJsonDocument::fromJson(data);
  if (doc.isNull()) {
    qWarning() << "Invalid JSON in clients file";
    return false;
  }
  QJsonArray arr = doc.array();
  m_clients.clear();
  for (const auto &val : arr) {
    QJsonObject obj = val.toObject();
    Client c;
    c.clientId = obj["client_id"].toString();
    c.clientSecret = obj["client_secret"].toString();
    c.allowedGrants = obj["allowed_grants"].toVariant().toStringList();
    c.allowedScopes = obj["allowed_scopes"].toVariant().toStringList();
    c.aud = obj["aud"].toString();
    m_clients.append(c);
  }
  return true;
}

bool DataManager::saveClients() const {
  QJsonArray arr;
  for (const Client &c : m_clients) {
    QJsonObject obj;
    obj["client_id"] = c.clientId;
    obj["client_secret"] = c.clientSecret;
    obj["allowed_grants"] = QJsonArray::fromStringList(c.allowedGrants);
    obj["allowed_scopes"] = QJsonArray::fromStringList(c.allowedScopes);
    obj["aud"] = c.aud;
    arr.append(obj);
  }
  QJsonDocument doc(arr);
  QFile file(clientsFilePath());
  if (!file.open(QIODevice::WriteOnly)) {
    qWarning() << "Could not write clients file";
    return false;
  }
  file.write(doc.toJson(QJsonDocument::Indented));
  return true;
}

Client *DataManager::findClientById(const QString &clientId) {
  for (Client &c : m_clients) {
    if (c.clientId == clientId)
      return &c;
  }
  return nullptr;
}

bool DataManager::checkClientSecret(const QString &clientId,
                                    const QString &secret) {
  Client *c = findClientById(clientId);
  if (!c)
    return false;
  return c->clientSecret == secret;
}

// ----- Roles -----
bool DataManager::loadRoles() {
  QFile file(rolesFilePath());
  if (!file.open(QIODevice::ReadOnly)) {
    qWarning() << "Could not open roles file:" << rolesFilePath();
    return false;
  }
  QByteArray data = file.readAll();
  QJsonDocument doc = QJsonDocument::fromJson(data);
  if (doc.isNull()) {
    qWarning() << "Invalid JSON in roles file";
    return false;
  }
  QJsonObject obj = doc.object();
  m_roles.clear();
  for (auto it = obj.begin(); it != obj.end(); ++it) {
    Role r;
    r.scopes = it.value().toObject()["scopes"].toVariant().toStringList();
    m_roles[it.key()] = r;
  }
  return true;
}

bool DataManager::saveRoles() const {
  QJsonObject obj;
  for (auto it = m_roles.begin(); it != m_roles.end(); ++it) {
    QJsonObject roleObj;
    roleObj["scopes"] = QJsonArray::fromStringList(it.value().scopes);
    obj[it.key()] = roleObj;
  }
  QJsonDocument doc(obj);
  QFile file(rolesFilePath());
  if (!file.open(QIODevice::WriteOnly)) {
    qWarning() << "Could not write roles file";
    return false;
  }
  file.write(doc.toJson(QJsonDocument::Indented));
  return true;
}

QStringList DataManager::getScopesForRoles(const QStringList &roleNames) const {
  QStringList result;
  for (const QString &role : roleNames) {
    if (m_roles.contains(role)) {
      result.append(m_roles[role].scopes);
    }
  }
  result.removeDuplicates();
  return result;
}

bool DataManager::loadRefreshIndex() {
  QFile file(refreshIndexFilePath());
  if (!file.open(QIODevice::ReadOnly)) {
    qWarning() << "Could not open refresh index file:"
               << refreshIndexFilePath();
    return false;
  }
  m_refreshRecords.clear();
  while (!file.atEnd()) {
    QByteArray line = file.readLine();
    if (line.trimmed().isEmpty())
      continue;
    QJsonDocument doc = QJsonDocument::fromJson(line);
    if (doc.isNull())
      continue;
    QJsonObject obj = doc.object();
    RefreshRecord rec;
    rec.refreshToken = obj["refresh_token"].toString();
    rec.userId = obj["user_id"].toString();
    rec.clientId = obj["client_id"].toString();
    rec.scopes = obj["scopes"].toVariant().toStringList();
    rec.expires = QDateTime::fromSecsSinceEpoch(obj["exp"].toInteger());
    rec.rotated = obj["rotated"].toBool();
    m_refreshRecords.append(rec);
  }
  return true;
}

bool DataManager::saveRefreshIndex() const {
  QFile file(refreshIndexFilePath());
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    qWarning() << "Could not write refresh index file";
    return false;
  }
  for (const RefreshRecord &rec : m_refreshRecords) {
    QJsonObject obj;
    obj["refresh_token"] = rec.refreshToken;
    obj["user_id"] = rec.userId;
    obj["client_id"] = rec.clientId;
    obj["scopes"] = QJsonArray::fromStringList(rec.scopes);
    obj["exp"] = static_cast<qint64>(rec.expires.toSecsSinceEpoch());
    obj["rotated"] = rec.rotated;
    QJsonDocument doc(obj);
    file.write(doc.toJson(QJsonDocument::Compact) + "\n");
  }
  return true;
}

void DataManager::addRefreshRecord(const RefreshRecord &record) {
  m_refreshRecords.append(record);
  saveRefreshIndex();
}

bool DataManager::findRefreshRecord(const QString &refreshToken,
                                    RefreshRecord &out) {
  for (const RefreshRecord &rec : m_refreshRecords) {
    if (rec.refreshToken == refreshToken) {
      out = rec;
      return true;
    }
  }
  return false;
}

bool DataManager::markRefreshRotated(const QString &refreshToken) {
  for (RefreshRecord &rec : m_refreshRecords) {
    if (rec.refreshToken == refreshToken) {
      rec.rotated = true;
      saveRefreshIndex();
      return true;
    }
  }
  return false;
}

bool DataManager::removeRefreshRecord(const QString &refreshToken) {
  int idx = -1;
  for (int i = 0; i < m_refreshRecords.size(); ++i) {
    if (m_refreshRecords[i].refreshToken == refreshToken) {
      idx = i;
      break;
    }
  }
  if (idx >= 0) {
    m_refreshRecords.removeAt(idx);
    saveRefreshIndex();
    return true;
  }
  return false;
}

bool DataManager::loadRevocations() {
  QFile file(revocationsFilePath());
  if (!file.open(QIODevice::ReadOnly)) {
    qWarning() << "Could not open revocations file:" << revocationsFilePath();
    return false;
  }
  m_revocations.clear();
  while (!file.atEnd()) {
    QByteArray line = file.readLine();
    if (line.trimmed().isEmpty())
      continue;
    QJsonDocument doc = QJsonDocument::fromJson(line);
    if (doc.isNull())
      continue;
    QJsonObject obj = doc.object();
    RevocationRecord rec;
    rec.type = obj["type"].toString();
    rec.tokenId = obj["token_id"].toString();
    rec.expires = QDateTime::fromSecsSinceEpoch(obj["exp"].toInteger());
    m_revocations.append(rec);
  }
  return true;
}

bool DataManager::saveRevocations() const {
  QFile file(revocationsFilePath());
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    qWarning() << "Could not write revocations file";
    return false;
  }
  for (const RevocationRecord &rec : m_revocations) {
    QJsonObject obj;
    obj["type"] = rec.type;
    obj["token_id"] = rec.tokenId;
    obj["exp"] = static_cast<qint64>(rec.expires.toSecsSinceEpoch());
    QJsonDocument doc(obj);
    file.write(doc.toJson(QJsonDocument::Compact) + "\n");
  }
  return true;
}

void DataManager::revokeAccessToken(const QString &jti, const QDateTime &exp) {
  RevocationRecord rec;
  rec.type = "access";
  rec.tokenId = jti;
  rec.expires = exp;
  m_revocations.append(rec);
  saveRevocations();
}

void DataManager::revokeRefreshToken(const QString &refreshToken,
                                     const QDateTime &exp) {
  RevocationRecord rec;
  rec.type = "refresh";
  rec.tokenId = refreshToken;
  rec.expires = exp;
  m_revocations.append(rec);
  saveRevocations();
}

bool DataManager::isAccessTokenRevoked(const QString &jti) const {
  for (const RevocationRecord &rec : m_revocations) {
    if (rec.type == "access" && rec.tokenId == jti) {
      if (rec.expires > QDateTime::currentDateTimeUtc())
        return true;
    }
  }
  return false;
}

bool DataManager::isRefreshTokenRevoked(const QString &refreshToken) const {
  for (const RevocationRecord &rec : m_revocations) {
    if (rec.type == "refresh" && rec.tokenId == refreshToken) {
      if (rec.expires > QDateTime::currentDateTimeUtc())
        return true;
    }
  }
  return false;
}

QStringList DataManager::intersectScopes(const QStringList &requested,
                                         const QStringList &allowed) const {
  QStringList result;
  for (const QString &s : requested) {
    if (allowed.contains(s))
      result.append(s);
  }
  result.removeDuplicates();
  return result;
}