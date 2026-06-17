#ifndef WEBSERVICEFACTORY_H
#define WEBSERVICEFACTORY_H

#include <functional>
#include <memory>
#include <string_view>
#include <unordered_map>

class IWebService;

class WebServiceFactory {
public:
  static WebServiceFactory &instance();

  std::unique_ptr<IWebService>
  createWebService(std::string_view endpoint) const;

  template <class WebService>
  void registerWebService(std::string_view endpoint) {
    m_creators[std::string(endpoint)] = []() -> std::unique_ptr<IWebService> {
      return std::make_unique<WebService>();
    };
  }

private:
  WebServiceFactory() = default;
  std::unordered_map<std::string, std::function<std::unique_ptr<IWebService>()>>
      m_creators;
};

#endif // WEBSERVICEFACTORY_H