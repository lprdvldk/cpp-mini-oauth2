#ifndef REVOKESERVICE_H
#define REVOKESERVICE_H

#include "i_webservice.h"

class RevokeService : public IWebService {
public:
  bool handleRequest(const QString &input, const QString &output) override;
};

#endif // REVOKESERVICE_H