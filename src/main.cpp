#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDebug>

#include "config.h"
#include "datamanager.h"
#include "i_webservice.h"
#include "tokenmanager.h"
#include "webservicefactory.h"

#include "introspectservice.h"
#include "paymentservice.h"
#include "refreshservice.h"
#include "revokeservice.h"
#include "tokenservice.h"

int main(int argc, char *argv[]) {
  QCoreApplication app(argc, argv);

  if (!Config::instance().load()) {
    qWarning() << "Could not load config, using defaults.";
  }

  TokenManager::initialize(Config::instance().secret(),
                           Config::instance().issuer(),
                           Config::instance().accessTtlSec());

  if (!DataManager::instance().loadAll()) {
    qWarning() << "Some data files could not be loaded.";
  }

  WebServiceFactory::instance().registerWebService<TokenService>("/token");
  WebServiceFactory::instance().registerWebService<RefreshService>(
      "/token/refresh");
  WebServiceFactory::instance().registerWebService<PaymentsService>(
      "/api/payments");
  WebServiceFactory::instance().registerWebService<RevokeService>("/revoke");
  WebServiceFactory::instance().registerWebService<IntrospectService>(
      "/introspect");

  QCommandLineParser parser;
  parser.setApplicationDescription("Mini OAuth2 server emulator");
  parser.addHelpOption();
  parser.addPositionalArgument("endpoint", "Endpoint name (e.g. /token)");
  parser.addPositionalArgument("input", "Input JSON file path");
  parser.addPositionalArgument("output", "Output JSON file path");
  parser.process(app);

  const QStringList args = parser.positionalArguments();
  if (args.size() != 3) {
    qCritical() << "Ошибка: требуется ровно три аргумента.";
    parser.showHelp(1);
  }

  QString endpoint = args[0];
  QString inputPath = args[1];
  QString outputPath = args[2];

  auto webService =
      WebServiceFactory::instance().createWebService(endpoint.toStdString());
  if (webService) {
    bool result = webService->handleRequest(inputPath, outputPath);
    if (!result) {
      qWarning() << "Service handler returned error.";
      return 1;
    }
  } else {
    qCritical() << "Ошибка: незарегистрированный эндпоинт.";
    parser.showHelp(1);
  }

  DataManager::instance().saveAll();

  return 0;
}