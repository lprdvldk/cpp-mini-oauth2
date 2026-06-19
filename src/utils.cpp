#include "utils.h"

#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QMap>
#include <QRegularExpression>
#include <stdexcept>

#include "config.h"
#include "datamanager.h"

namespace utils {

static QString statusStringForCode(int code) {
    static const QMap<int, QString> map = {{400, "Bad request"},
                                           {401, "Unauthorized"},
                                           {403, "Forbidden"},
                                           {409, "Conflict"},
                                           {500, "Internal server error"}};
    return map.value(code, "Error");
}

void logError(const QString &message) {
    QFile logFile("error.log");
    if (logFile.open(QIODevice::Append | QIODevice::Text)) {
        QString msg =
            QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + " " +
            message + "\n";
        logFile.write(msg.toUtf8());
        logFile.close();
        return;
    }
    throw std::runtime_error("cannot open log file");
}

bool isValidJwtFormat(const QString &token) {
    const auto parts = token.split('.');
    if (parts.size() != 3)
        return false;

    for (const auto &part : parts) {
        QByteArray decoded = QByteArray::fromBase64(
            part.toLatin1(),
            QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        if (decoded.isEmpty())
            return false;

        QJsonDocument doc = QJsonDocument::fromJson(decoded);
        if (doc.isNull() || !doc.isObject())
            return false;
    }
    return true;
}

bool readRequest(const QString &input, QJsonObject &request) {
    QFile inFile(input);
    if (!inFile.open(QIODevice::ReadOnly)) {
        logError("Cannot open input file: " + input);
        return false;
    }
    const auto data = inFile.readAll();
    const auto doc = QJsonDocument::fromJson(data);
    if (doc.isNull()) {
        logError("Invalid JSON in input file: " + input);
        return false;
    }
    request = doc.object();
    return true;
}

bool writeResponse(const QString &output, const QJsonObject &response) {
    QFile outFile(output);
    if (!outFile.open(QIODevice::WriteOnly)) {
        logError("Cannot open output file: " + output);
        return false;
    }
    outFile.write(QJsonDocument(response).toJson());
    return true;
}

bool writeError(const QString &output, int code, const QString &description) {
    QJsonObject response;
    response["status"] = statusStringForCode(code);
    response["code"] = code;
    response["description"] = description;

    if (code == 500) {
        logError("[500] " + description);
    }

    return writeResponse(output, response);
}

bool writeErrorResponse(const QString &output, const QString &error,
                        const QString &description) {
    return writeError(output, 400, description);
}

bool writeSuccessResponse(const QString &output) {
    QJsonObject response;
    response["status"] = "success";
    return writeResponse(output, response);
}

bool writeTokenResponse(const QString &output, const QString &accessToken,
                        const QString &refreshToken) {
    QJsonObject response;
    response["access_token"] = accessToken;
    if (!refreshToken.isEmpty()) {
        response["refresh_token"] = refreshToken;
    }
    response["token_type"] = "Bearer";
    response["expires_in"] = Config::instance().accessTtlSec();
    return writeResponse(output, response);
}

bool validateClient(const QJsonObject &request, const Client *&client,
                    const QString &output, const QStringList &requiredGrants) {
    const QString clientId = request["client_id"].toString();
    const QString clientSecret = request["client_secret"].toString();

    client = DataManager::instance().findClientById(clientId);
    if (!client) {
        writeError(output, 401, "Client not found");
        return false;
    }

    if (!DataManager::instance().checkClientSecret(clientId, clientSecret)) {
        writeError(output, 401, "Invalid client secret");
        return false;
    }

    for (const QString &grant : requiredGrants) {
        if (!client->allowedGrants.contains(grant)) {
            writeError(output, 403, "Client not allowed for grant: " + grant);
            return false;
        }
    }

    return true;
}

}  // namespace utils