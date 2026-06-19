#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

#include "config.h"
#include "datamanager.h"
#include "i_webservice.h"
#include "introspectservice.h"
#include "paymentservice.h"
#include "refreshservice.h"
#include "revokeservice.h"
#include "tokenmanager.h"
#include "tokenservice.h"
#include "utils.h"
#include "webservicefactory.h"

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    QCommandLineParser parser;
    parser.setApplicationDescription("Mini OAuth2 server emulator");
    parser.addHelpOption();
    parser.addPositionalArgument("endpoint", "Endpoint name (e.g. /token)");
    parser.addPositionalArgument("input", "Input JSON file path");
    parser.addPositionalArgument("output", "Output JSON file path");
    parser.process(app);

    const QStringList args = parser.positionalArguments();
    if (args.size() != 3) {
        parser.showHelp(1);
        return 1;
    }

    QString endpoint = args[0];
    QString inputPath = args[1];
    QString outputPath = args[2];

    auto writeInitError = [&](const QString &description) {
        QJsonObject resp;
        resp["status"] = "Internal server error";
        resp["code"] = 500;
        resp["description"] = description;
        QFile outFile(outputPath);
        if (outFile.open(QIODevice::WriteOnly)) {
            outFile.write(QJsonDocument(resp).toJson());
        }
    };

    if (!Config::instance().load()) {
        utils::logError("Failed to load configuration");
        return 1;
    }

    TokenManager::initialize(Config::instance().secret(),
                             Config::instance().issuer(),
                             Config::instance().accessTtlSec());

    if (!DataManager::instance().loadAll()) {
        utils::logError("Failed to load data files");
        return 1;
    }

    WebServiceFactory::instance().registerWebService<TokenService>("/token");
    WebServiceFactory::instance().registerWebService<RefreshService>(
        "/token/refresh");
    WebServiceFactory::instance().registerWebService<PaymentsService>(
        "/api/payments");
    WebServiceFactory::instance().registerWebService<RevokeService>("/revoke");
    WebServiceFactory::instance().registerWebService<IntrospectService>(
        "/introspect");

    auto webService =
        WebServiceFactory::instance().createWebService(endpoint.toStdString());
    if (!webService) {
        utils::logError("Unregistered endpoint: " + endpoint);
        return 1;
    }

    bool result = webService->handleRequest(inputPath, outputPath);
    if (!result) {
        utils::logError("Service handler returned error");
        return 1;
    }

    DataManager::instance().saveAll();

    return 0;
}