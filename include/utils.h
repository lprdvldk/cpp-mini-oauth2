#ifndef UTILS_H
#define UTILS_H

#include <QJsonObject>
#include <QString>

#include "datamodel.h"

namespace utils {

bool readRequest(const QString &input, QJsonObject &request);

bool writeResponse(const QString &output, const QJsonObject &response);

bool writeError(const QString &output, int code, const QString &description);

bool writeErrorResponse(const QString &output, const QString &error,
                        const QString &description);

bool writeSuccessResponse(const QString &output);

bool writeTokenResponse(const QString &output, const QString &accessToken,
                        const QString &refreshToken);

bool validateClient(const QJsonObject &request, const Client *&client,
                    const QString &output,
                    const QStringList &requiredGrants = {});

void logError(const QString &message);

bool isValidJwtFormat(const QString &token);

}  // namespace utils

#endif  // UTILS_H