#ifndef CONFIG_H
#define CONFIG_H

#include <QJsonObject>
#include <QString>

class Config {
public:
  static Config &instance();

  bool load(const QString &path = "config/auth.json");

  QString issuer() const { return m_issuer; }
  QString secret() const { return m_secret; }
  int accessTtlSec() const { return m_accessTtlSec; }
  int refreshTtlDays() const { return m_refreshTtlDays; }
  int clockSkewSec() const { return m_clockSkewSec; }

private:
  Config() = default;

  QString m_issuer = "mini-auth";
  QString m_secret = "supersecret";
  int m_accessTtlSec = 900;
  int m_refreshTtlDays = 14;
  int m_clockSkewSec = 60;
};

#endif // CONFIG_H