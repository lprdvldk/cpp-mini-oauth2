#ifndef REFRESHSERVICE_H
#define REFRESHSERVICE_H

#include "i_webservice.h"

class RefreshService : public IWebService {
public:
    bool handleRequest(const QString &input, const QString &output) override;
};

#endif  // REFRESHSERVICE_H