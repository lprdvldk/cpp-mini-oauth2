#ifndef TOKENSERVICE_H
#define TOKENSERVICE_H

#include "i_webservice.h"

class TokenService : public IWebService {
public:
    bool handleRequest(const QString &input, const QString &output) override;
};

#endif  // TOKENSERVICE_H