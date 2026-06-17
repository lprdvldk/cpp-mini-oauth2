#include "config.h"
#include <QDebug>
#include <QFile>
#include <QJsonDocument>

Config &Config::instance() {
  static Config cfg;
  return cfg;
}

bool Config::load(const QString &path) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly)) {
    qWarning() << "Config file not found, using defaults.";
    return false;
  }
  QByteArray data = file.readAll();
  QJsonDocument doc = QJsonDocument::fromJson(data);
  if (doc.isNull()) {
    qWarning() << "Invalid JSON in config file, using defaults.";
    return false;
  }
  QJsonObject obj = doc.object();
  if (obj.contains("issuer"))
    m_issuer = obj["issuer"].toString();
  if (obj.contains("auth_secret"))
    m_secret = obj["auth_secret"].toString();
  if (obj.contains("access_ttl_sec"))
    m_accessTtlSec = obj["access_ttl_sec"].toInt();
  if (obj.contains("refresh_ttl_days"))
    m_refreshTtlDays = obj["refresh_ttl_days"].toInt();
  if (obj.contains("clock_skew_sec"))
    m_clockSkewSec = obj["clock_skew_sec"].toInt();
  return true;
}