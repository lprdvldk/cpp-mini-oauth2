#ifndef PAYMENTSERVICE_H
#define PAYMENTSERVICE_H

#include "i_webservice.h"

class PaymentsService : public IWebService {
public:
  bool handleRequest(const QString &input, const QString &output) override;
};

#endif // PAYMENTSERVICE_H