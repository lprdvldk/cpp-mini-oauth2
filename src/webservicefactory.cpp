#include "webservicefactory.h"

#include "i_webservice.h"

WebServiceFactory &WebServiceFactory::instance() {
    static WebServiceFactory factory;
    return factory;
}

std::unique_ptr<IWebService> WebServiceFactory::createWebService(
    std::string_view endpoint) const {
    auto it = m_creators.find(std::string(endpoint));
    if (it != m_creators.end()) {
        return it->second();
    }
    return nullptr;
}