#ifndef WEBSERVICEFACTORY_H
#define WEBSERVICEFACTORY_H

#include <memory>
#include <string_view>

class IWebService;

class WebServiceFactory
{
public:
    static WebServiceFactory& instance();

    std::unique_ptr<IWebService> createWebService(std::string_view endpoint) const;

    template<class WebService>
    void registerWebService(std::string_view endpoint)
    {
        // реализовать регистрацию класса реализации вебсервиса для соответствующего эндпоинта
    }
};


#endif // WEBSERVICEFACTORY_H
