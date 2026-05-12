#include "webservicefactory.h"

#include "i_webservice.h"

WebServiceFactory& WebServiceFactory::instance()
{
    static WebServiceFactory factory;
    return factory;
}

std::unique_ptr<IWebService> WebServiceFactory::createWebService(std::string_view endpoint) const
{
    //  реализовать создание нужного веб сервиса соответствующему полученному эндпоинту
    return std::unique_ptr<IWebService> ();
}
