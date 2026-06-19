#ifndef CONFIG_H
#define CONFIG_H

#include <QJsonObject>
#include <QString>

class Config {
public:
    static Config &instance();

    bool load(const QString &path = "config/auth.json");

    QString issuer() const {
        return m_issuer_;
    }
    QString secret() const {
        return m_secret_;
    }
    int accessTtlSec() const {
        return m_accessTtlSec_;
    }
    int refreshTtlDays() const {
        return m_refreshTtlDays_;
    }
    int clockSkewSec() const {
        return m_clockSkewSec_;
    }

private:
    Config() = default;

    QString m_issuer_ = "mini-auth";
    QString m_secret_ = "supersecret";
    int m_accessTtlSec_ = 900;
    int m_refreshTtlDays_ = 14;
    int m_clockSkewSec_ = 60;
};

#endif  // CONFIG_H