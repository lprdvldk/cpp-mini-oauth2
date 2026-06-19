#include "datamanager.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include "utils.h"

// Static data files path
QString DataManager::s_dataDir_ = "data/";

// Static methods for data files paths
QString DataManager::usersFilePath() {
    return s_dataDir_ + "users.json";
}

QString DataManager::clientsFilePath() {
    return s_dataDir_ + "clients.json";
}

QString DataManager::rolesFilePath() {
    return s_dataDir_ + "roles.json";
}

QString DataManager::refreshIndexFilePath() {
    return s_dataDir_ + "refresh_index.ndjson";
}

QString DataManager::revocationsFilePath() {
    return s_dataDir_ + "revocations.ndjson";
}

DataManager &DataManager::instance() {
    static DataManager dm;
    return dm;
}

void DataManager::setDataDirectory(const QString &path) {
    s_dataDir_ = path;
    QDir().mkpath(s_dataDir_);
}

bool DataManager::loadAll() {
    bool ok = true;
    if (!loadUsers()) {
        utils::logError("Failed to load users");
        ok = false;
    }
    if (!loadClients()) {
        utils::logError("Failed to load clients");
        ok = false;
    }
    if (!loadRoles()) {
        utils::logError("Failed to load roles");
        ok = false;
    }
    if (!loadRefreshIndex()) {
        utils::logError("Failed to load refresh index");
        ok = false;
    }
    if (!loadRevocations()) {
        utils::logError("Failed to load revocations");
        ok = false;
    }
    return ok;
}

bool DataManager::saveAll() {
    bool ok = true;
    if (!saveUsers()) {
        utils::logError("Failed to save users");
        ok = false;
    }
    if (!saveClients()) {
        utils::logError("Failed to save clients");
        ok = false;
    }
    if (!saveRoles()) {
        utils::logError("Failed to save roles");
        ok = false;
    }
    if (!saveRefreshIndex()) {
        utils::logError("Failed to save refresh index");
        ok = false;
    }
    if (!saveRevocations()) {
        utils::logError("Failed to save revocations");
        ok = false;
    }
    return ok;
}

bool DataManager::loadUsers() {
    QFile file(usersFilePath());
    if (!file.open(QIODevice::ReadOnly)) {
        utils::logError("Could not open users file: " + usersFilePath());
        return false;
    }
    QByteArray data = file.readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        utils::logError("Invalid JSON in users file: " + usersFilePath());
        return false;
    }
    QJsonArray arr = doc.array();
    m_users_.clear();
    for (const auto &val : arr) {
        QJsonObject obj = val.toObject();
        User u;
        u.userId = obj["user_id"].toString();
        u.username = obj["username"].toString();
        u.passwordHash = obj["password_hash"].toString();
        u.roles = obj["roles"].toVariant().toStringList();
        u.status = obj["status"].toString();
        m_users_.insert(u.userId, u);
    }
    return true;
}

bool DataManager::saveUsers() const {
    QJsonArray arr;
    for (const User &u : m_users_) {
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
        utils::logError("Could not write users file: " + usersFilePath());
        return false;
    }
    file.write(doc.toJson(QJsonDocument::Indented));
    return true;
}

const User *DataManager::findUserByUsername(const QString &username) {
    for (User &u : m_users_) {
        if (u.username == username) {
            return &u;
        }
    }
    return nullptr;
}

const User *DataManager::findUserByUserId(const QString &userId) {
    for (User &u : m_users_) {
        if (u.userId == userId) {
            return &u;
        }
    }
    return nullptr;
}

bool DataManager::verifyPassword(const QString &username,
                                 const QString &password) {
    auto *user = findUserByUsername(username);
    if (!user) {
        return false;
    }
    QByteArray hash =
        QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256)
            .toHex();
    return user->passwordHash == QString::fromUtf8(hash);
}

bool DataManager::loadClients() {
    QFile file(clientsFilePath());
    if (!file.open(QIODevice::ReadOnly)) {
        utils::logError("Could not open clients file: " + clientsFilePath());
        return false;
    }
    QByteArray data = file.readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        utils::logError("Invalid JSON in clients file: " + clientsFilePath());
        return false;
    }
    QJsonArray arr = doc.array();
    m_clients_.clear();
    for (const auto &val : arr) {
        QJsonObject obj = val.toObject();
        Client c;
        c.clientId = obj["client_id"].toString();
        c.clientSecret = obj["client_secret"].toString();
        c.allowedGrants = obj["allowed_grants"].toVariant().toStringList();
        c.allowedScopes = obj["allowed_scopes"].toVariant().toStringList();
        c.aud = obj["aud"].toString();
        m_clients_.insert(c.clientId, c);
    }
    return true;
}

bool DataManager::saveClients() const {
    QJsonArray arr;
    for (const Client &c : m_clients_) {
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
        utils::logError("Could not write clients file: " + clientsFilePath());
        return false;
    }
    file.write(doc.toJson(QJsonDocument::Indented));
    return true;
}

const Client *DataManager::findClientById(const QString &clientId) {
    for (Client &c : m_clients_) {
        if (c.clientId == clientId) {
            return &c;
        }
    }
    return nullptr;
}

bool DataManager::checkClientSecret(const QString &clientId,
                                    const QString &secret) {
    auto *c = findClientById(clientId);
    if (!c) {
        return false;
    }
    return c->clientSecret == secret;
}

// ----- Roles -----
bool DataManager::loadRoles() {
    QFile file(rolesFilePath());
    if (!file.open(QIODevice::ReadOnly)) {
        utils::logError("Could not open roles file: " + rolesFilePath());
        return false;
    }
    QByteArray data = file.readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        utils::logError("Invalid JSON in roles file: " + rolesFilePath());
        return false;
    }
    QJsonObject obj = doc.object();
    m_roles_.clear();
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        Role r;
        r.scopes = it.value().toObject()["scopes"].toVariant().toStringList();
        m_roles_[it.key()] = r;
    }
    return true;
}

bool DataManager::saveRoles() const {
    QJsonObject obj;
    for (auto it = m_roles_.begin(); it != m_roles_.end(); ++it) {
        QJsonObject roleObj;
        roleObj["scopes"] = QJsonArray::fromStringList(it.value().scopes);
        obj[it.key()] = roleObj;
    }
    QJsonDocument doc(obj);
    QFile file(rolesFilePath());
    if (!file.open(QIODevice::WriteOnly)) {
        utils::logError("Could not write roles file: " + rolesFilePath());
        return false;
    }
    file.write(doc.toJson(QJsonDocument::Indented));
    return true;
}

QStringList DataManager::getScopesForRoles(const QStringList &roleNames) const {
    QStringList result;
    for (const QString &role : roleNames) {
        if (m_roles_.contains(role)) {
            result.append(m_roles_[role].scopes);
        }
    }
    result.removeDuplicates();
    return result;
}

bool DataManager::loadRefreshIndex() {
    QFile file(refreshIndexFilePath());
    if (!file.open(QIODevice::ReadOnly)) {
        utils::logError("Could not open refresh index file: " +
                        refreshIndexFilePath());
        return false;
    }
    m_refreshRecords_.clear();
    while (!file.atEnd()) {
        QByteArray line = file.readLine();
        if (line.trimmed().isEmpty()) {
            continue;
        }
        QJsonDocument doc = QJsonDocument::fromJson(line);
        if (doc.isNull()) {
            utils::logError("Invalid line in refresh index file");
            continue;
        }
        QJsonObject obj = doc.object();
        RefreshRecord rec;
        rec.refreshToken = obj["refresh_token"].toString();
        rec.userId = obj["user_id"].toString();
        rec.clientId = obj["client_id"].toString();
        rec.scopes = obj["scopes"].toVariant().toStringList();
        rec.expires = QDateTime::fromSecsSinceEpoch(obj["exp"].toInteger());
        rec.rotated = obj["rotated"].toBool();
        m_refreshRecords_.append(rec);
    }
    return true;
}

bool DataManager::saveRefreshIndex() const {
    QFile file(refreshIndexFilePath());
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        utils::logError("Could not write refresh index file: " +
                        refreshIndexFilePath());
        return false;
    }
    for (const RefreshRecord &rec : m_refreshRecords_) {
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
    m_refreshRecords_.append(record);
    saveRefreshIndex();
}

bool DataManager::findRefreshRecord(const QString &refreshToken,
                                    RefreshRecord &out) {
    for (const RefreshRecord &rec : m_refreshRecords_) {
        if (rec.refreshToken == refreshToken) {
            out = rec;
            return true;
        }
    }
    return false;
}

bool DataManager::markRefreshRotated(const QString &refreshToken) {
    for (RefreshRecord &rec : m_refreshRecords_) {
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
    for (int i = 0; i < m_refreshRecords_.size(); ++i) {
        if (m_refreshRecords_[i].refreshToken == refreshToken) {
            idx = i;
            break;
        }
    }
    if (idx >= 0) {
        m_refreshRecords_.removeAt(idx);
        saveRefreshIndex();
        return true;
    }
    return false;
}

bool DataManager::loadRevocations() {
    QFile file(revocationsFilePath());
    if (!file.open(QIODevice::ReadOnly)) {
        utils::logError("Could not open revocations file: " +
                        revocationsFilePath());
        return false;
    }
    m_revocations_.clear();
    while (!file.atEnd()) {
        QByteArray line = file.readLine();
        if (line.trimmed().isEmpty()) {
            continue;
        }
        QJsonDocument doc = QJsonDocument::fromJson(line);
        if (doc.isNull()) {
            utils::logError("Invalid line in revocations file");
            continue;
        }
        QJsonObject obj = doc.object();
        RevocationRecord rec;
        rec.type = obj["type"].toString();
        rec.tokenId = obj["token_id"].toString();
        rec.expires = QDateTime::fromSecsSinceEpoch(obj["exp"].toInteger());
        m_revocations_.append(rec);
    }
    return true;
}

bool DataManager::saveRevocations() const {
    QFile file(revocationsFilePath());
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        utils::logError("Could not write revocations file: " +
                        revocationsFilePath());
        return false;
    }
    for (const RevocationRecord &rec : m_revocations_) {
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
    m_revocations_.append(rec);
    saveRevocations();
}

void DataManager::revokeRefreshToken(const QString &refreshToken,
                                     const QDateTime &exp) {
    RevocationRecord rec;
    rec.type = "refresh";
    rec.tokenId = refreshToken;
    rec.expires = exp;
    m_revocations_.append(rec);
    saveRevocations();
}

bool DataManager::isAccessTokenRevoked(const QString &jti) const {
    for (const RevocationRecord &rec : m_revocations_) {
        if (rec.type == "access" && rec.tokenId == jti) {
            if (rec.expires > QDateTime::currentDateTimeUtc()) {
                return true;
            }
        }
    }
    return false;
}

bool DataManager::isRefreshTokenRevoked(const QString &refreshToken) const {
    for (const RevocationRecord &rec : m_revocations_) {
        if (rec.type == "refresh" && rec.tokenId == refreshToken) {
            if (rec.expires > QDateTime::currentDateTimeUtc()) {
                return true;
            }
        }
    }
    return false;
}

QStringList DataManager::intersectScopes(const QStringList &requested,
                                         const QStringList &allowed) const {
    QStringList result;
    for (const QString &s : requested) {
        if (allowed.contains(s)) {
            result.append(s);
        }
    }
    result.removeDuplicates();
    return result;
}