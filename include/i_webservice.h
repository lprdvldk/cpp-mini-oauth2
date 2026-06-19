#ifndef I_WEBSERVICE_H
#define I_WEBSERVICE_H

#include <QString>

class IWebService {
public:
    virtual ~IWebService() = default;

    virtual bool handleRequest(const QString& input, const QString& output) = 0;
};

#endif  // I_WEBSERVICE_H