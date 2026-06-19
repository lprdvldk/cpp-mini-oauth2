#include "config.h"

#include <QFile>
#include <QJsonDocument>

#include "utils.h"

Config &Config::instance() {
    static Config cfg;
    return cfg;
}

bool Config::load(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        utils::logError("Config file not found: " + path + ", using defaults.");
        return false;
    }
    QByteArray data = file.readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        utils::logError("Invalid JSON in config file: " + path +
                        ", using defaults.");
        return false;
    }
    QJsonObject obj = doc.object();
    if (obj.contains("issuer")) {
        m_issuer_ = obj["issuer"].toString();
    }
    if (obj.contains("auth_secret")) {
        m_secret_ = obj["auth_secret"].toString();
    }
    if (obj.contains("access_ttl_sec")) {
        m_accessTtlSec_ = obj["access_ttl_sec"].toInt();
    }
    if (obj.contains("refresh_ttl_days")) {
        m_refreshTtlDays_ = obj["refresh_ttl_days"].toInt();
    }
    if (obj.contains("clock_skew_sec")) {
        m_clockSkewSec_ = obj["clock_skew_sec"].toInt();
    }
    return true;
}