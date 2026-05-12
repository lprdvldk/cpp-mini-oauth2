#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDebug>

#include "webservicefactory.h"
#include "i_webservice.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    QCommandLineParser parser;

    parser.process(app);

    const QStringList args = parser.positionalArguments();
    if (args.size() != 3) {
        qCritical() << "Ошибка: требуется ровно три аргумента.";
        parser.showHelp(1);
    }

    QString endpoint = args[0];

    QString inputPath = args[1];
    QString outputPath = args[2];

    auto webService = WebServiceFactory::instance().createWebService(endpoint.toStdString());
    if (webService) {
        webService->handleRequest(inputPath, outputPath);
    } else {
        qCritical() << "Ошибка: незарегистрированный эндпоинт.";
        parser.showHelp(1);
    }

    return 0;
}
