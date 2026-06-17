#ifndef INTROSPECTSERVICE_H
#define INTROSPECTSERVICE_H

#include "i_webservice.h"

class IntrospectService : public IWebService {
public:
  bool handleRequest(const QString &input, const QString &output) override;
};

#endif // INTROSPECTSERVICE_H