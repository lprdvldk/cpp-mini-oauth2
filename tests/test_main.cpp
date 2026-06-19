#include <gtest/gtest.h>

#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include "config.h"
#include "datamanager.h"
#include "introspectservice.h"
#include "paymentservice.h"
#include "refreshservice.h"
#include "revokeservice.h"
#include "tokenmanager.h"
#include "tokenservice.h"
#include "webservicefactory.h"

// Utils
void writeJson(const QString &path, const QJsonObject &obj) {
    QFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(obj).toJson());
        file.close();
    }
}

void writeJsonArray(const QString &path, const QJsonArray &arr) {
    QFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(arr).toJson());
        file.close();
    }
}

QJsonObject readJson(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return QJsonObject();
    QByteArray data = file.readAll();
    return QJsonDocument::fromJson(data).object();
}

class DataManagerTest : public ::testing::Test {
protected:
    QTemporaryDir tempDir;
    QString dataDir;

    void SetUp() override {
        dataDir = tempDir.path() + "/data/";
        QDir().mkpath(dataDir);
        createTestFiles();
        DataManager::setDataDirectory(dataDir);
        DataManager::instance().loadAll();
    }

    void TearDown() override {
        // Clean up error.log if exists
    }

    void createTestFiles() {
        // users.json
        QJsonArray users;
        QJsonObject u;
        u["user_id"] = "u-100";
        u["username"] = "alice";
        u["password_hash"] =
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        u["roles"] = QJsonArray::fromStringList({"manager", "viewer"});
        u["status"] = "active";
        users.append(u);

        // inactive user
        QJsonObject u2;
        u2["user_id"] = "u-101";
        u2["username"] = "bob";
        u2["password_hash"] =
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        u2["roles"] = QJsonArray::fromStringList({"viewer"});
        u2["status"] = "inactive";
        users.append(u2);

        writeJsonArray(dataDir + "users.json", users);

        // clients.json
        QJsonArray clients;
        QJsonObject c;
        c["client_id"] = "cli-001";
        c["client_secret"] = "secret";
        c["allowed_grants"] =
            QJsonArray::fromStringList({"password", "refresh_token"});
        c["allowed_scopes"] =
            QJsonArray::fromStringList({"payments:read", "payments:write"});
        c["aud"] = "payments-api";
        clients.append(c);

        // client without password grant
        QJsonObject c2;
        c2["client_id"] = "cli-002";
        c2["client_secret"] = "secret2";
        c2["allowed_grants"] =
            QJsonArray::fromStringList({"client_credentials"});
        c2["allowed_scopes"] = QJsonArray::fromStringList({"payments:read"});
        c2["aud"] = "payments-api";
        clients.append(c2);

        writeJsonArray(dataDir + "clients.json", clients);

        // roles.json
        QJsonObject roles;
        QJsonObject adminScopes;
        adminScopes["scopes"] = QJsonArray::fromStringList({"*"});
        roles["admin"] = adminScopes;
        QJsonObject managerScopes;
        managerScopes["scopes"] =
            QJsonArray::fromStringList({"payments:read", "payments:write"});
        roles["manager"] = managerScopes;
        QJsonObject viewerScopes;
        viewerScopes["scopes"] = QJsonArray::fromStringList({"payments:read"});
        roles["viewer"] = viewerScopes;
        writeJson(dataDir + "roles.json", roles);

        // refresh_index.ndjson and revocations.ndjson
        QFile rf(dataDir + "refresh_index.ndjson");
        rf.open(QIODevice::WriteOnly);
        rf.close();
        QFile rv(dataDir + "revocations.ndjson");
        rv.open(QIODevice::WriteOnly);
        rv.close();
    }
};

// ----- Test DataManager -----
TEST_F(DataManagerTest, FindUser) {
    auto u = DataManager::instance().findUserByUsername("alice");
    ASSERT_NE(u, nullptr);
    EXPECT_EQ(u->userId, "u-100");
    EXPECT_EQ(u->roles, QStringList({"manager", "viewer"}));
}

TEST_F(DataManagerTest, VerifyPassword) {
    EXPECT_TRUE(DataManager::instance().verifyPassword("alice", "password"));
    EXPECT_FALSE(DataManager::instance().verifyPassword("alice", "wrong"));
}

TEST_F(DataManagerTest, FindClient) {
    auto c = DataManager::instance().findClientById("cli-001");
    ASSERT_NE(c, nullptr);
    EXPECT_TRUE(DataManager::instance().checkClientSecret("cli-001", "secret"));
    EXPECT_FALSE(DataManager::instance().checkClientSecret("cli-001", "wrong"));
}

TEST_F(DataManagerTest, RoleScopes) {
    QStringList scopes = DataManager::instance().getScopesForRoles({"manager"});
    EXPECT_EQ(scopes, QStringList({"payments:read", "payments:write"}));
}

TEST_F(DataManagerTest, IntersectScopes) {
    QStringList requested = {"payments:read", "users:read"};
    QStringList allowed = {"payments:read", "payments:write"};
    QStringList result =
        DataManager::instance().intersectScopes(requested, allowed);
    EXPECT_EQ(result, QStringList({"payments:read"}));
}

class ServiceTest : public DataManagerTest {
protected:
    void SetUp() override {
        DataManagerTest::SetUp();
        Config::instance().load();
        TokenManager::initialize(Config::instance().secret(),
                                 Config::instance().issuer(),
                                 Config::instance().accessTtlSec());
        WebServiceFactory::instance().registerWebService<TokenService>(
            "/token");
        WebServiceFactory::instance().registerWebService<RefreshService>(
            "/token/refresh");
        WebServiceFactory::instance().registerWebService<PaymentsService>(
            "/api/payments");
        WebServiceFactory::instance().registerWebService<RevokeService>(
            "/revoke");
        WebServiceFactory::instance().registerWebService<IntrospectService>(
            "/introspect");
    }
};

// ----- Positive tests (already present) -----
TEST_F(ServiceTest, TokenServicePassword) {
    QJsonObject request;
    request["grant_type"] = "password";
    request["username"] = "alice";
    request["password"] = "password";
    request["client_id"] = "cli-001";
    request["client_secret"] = "secret";
    request["scopes"] =
        QJsonArray::fromStringList({"payments:read", "payments:write"});

    QString inputPath = dataDir + "token_req.json";
    QString outputPath = dataDir + "token_resp.json";
    writeJson(inputPath, request);

    auto service = WebServiceFactory::instance().createWebService("/token");
    ASSERT_NE(service, nullptr);
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_TRUE(resp.contains("access_token"));
    EXPECT_TRUE(resp.contains("refresh_token"));
    EXPECT_EQ(resp["token_type"].toString(), "Bearer");
    EXPECT_TRUE(resp["expires_in"].toInt() > 0);

    RefreshRecord rec;
    QString rt = resp["refresh_token"].toString();
    EXPECT_TRUE(DataManager::instance().findRefreshRecord(rt, rec));
    EXPECT_EQ(rec.userId, "u-100");
    EXPECT_EQ(rec.clientId, "cli-001");
    EXPECT_FALSE(rec.rotated);
}

TEST_F(ServiceTest, RefreshService) {
    // First get a refresh token
    QJsonObject tokenReq;
    tokenReq["grant_type"] = "password";
    tokenReq["username"] = "alice";
    tokenReq["password"] = "password";
    tokenReq["client_id"] = "cli-001";
    tokenReq["client_secret"] = "secret";
    tokenReq["scopes"] = QJsonArray::fromStringList({"payments:read"});
    QString tokenInput = dataDir + "token_req.json";
    QString tokenOutput = dataDir + "token_resp.json";
    writeJson(tokenInput, tokenReq);
    auto tokenService =
        WebServiceFactory::instance().createWebService("/token");
    tokenService->handleRequest(tokenInput, tokenOutput);
    QJsonObject tokenResp = readJson(tokenOutput);
    QString refreshToken = tokenResp["refresh_token"].toString();

    // Use refresh token
    QJsonObject refreshReq;
    refreshReq["grant_type"] = "refresh_token";
    refreshReq["refresh_token"] = refreshToken;
    refreshReq["client_id"] = "cli-001";
    refreshReq["client_secret"] = "secret";
    QString refInput = dataDir + "refresh_req.json";
    QString refOutput = dataDir + "refresh_resp.json";
    writeJson(refInput, refreshReq);

    auto refreshService =
        WebServiceFactory::instance().createWebService("/token/refresh");
    bool ok = refreshService->handleRequest(refInput, refOutput);
    EXPECT_TRUE(ok);

    QJsonObject refResp = readJson(refOutput);
    EXPECT_TRUE(refResp.contains("access_token"));
    EXPECT_TRUE(refResp.contains("refresh_token"));

    RefreshRecord oldRec;
    EXPECT_TRUE(
        DataManager::instance().findRefreshRecord(refreshToken, oldRec));
    EXPECT_TRUE(oldRec.rotated);

    QString newRt = refResp["refresh_token"].toString();
    RefreshRecord newRec;
    EXPECT_TRUE(DataManager::instance().findRefreshRecord(newRt, newRec));
    EXPECT_FALSE(newRec.rotated);
}

TEST_F(ServiceTest, PaymentsServiceAccess) {
    // Obtain access token
    QJsonObject tokenReq;
    tokenReq["grant_type"] = "password";
    tokenReq["username"] = "alice";
    tokenReq["password"] = "password";
    tokenReq["client_id"] = "cli-001";
    tokenReq["client_secret"] = "secret";
    tokenReq["scopes"] =
        QJsonArray::fromStringList({"payments:read", "payments:write"});
    QString tokenInput = dataDir + "token_req.json";
    QString tokenOutput = dataDir + "token_resp.json";
    writeJson(tokenInput, tokenReq);
    auto tokenService =
        WebServiceFactory::instance().createWebService("/token");
    tokenService->handleRequest(tokenInput, tokenOutput);
    QJsonObject tokenResp = readJson(tokenOutput);
    QString accessToken = tokenResp["access_token"].toString();

    // Access payments with GET
    QJsonObject paymentReq;
    paymentReq["access_token"] = accessToken;
    paymentReq["method"] = "GET";
    QString payInput = dataDir + "pay_req.json";
    QString payOutput = dataDir + "pay_resp.json";
    writeJson(payInput, paymentReq);

    auto payService =
        WebServiceFactory::instance().createWebService("/api/payments");
    bool ok = payService->handleRequest(payInput, payOutput);
    EXPECT_TRUE(ok);

    QJsonObject payResp = readJson(payOutput);
    EXPECT_EQ(payResp["status"].toString(), "success");
    EXPECT_TRUE(payResp.contains("data"));
}

// ----- Error tests -----

// TokenService errors
TEST_F(ServiceTest, TokenServiceInvalidPassword) {
    QJsonObject request;
    request["grant_type"] = "password";
    request["username"] = "alice";
    request["password"] = "wrong";
    request["client_id"] = "cli-001";
    request["client_secret"] = "secret";
    request["scopes"] = QJsonArray::fromStringList({"payments:read"});

    QString inputPath = dataDir + "token_req.json";
    QString outputPath = dataDir + "token_resp.json";
    writeJson(inputPath, request);

    auto service = WebServiceFactory::instance().createWebService("/token");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);  // service always returns true after writing response

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 401);
    EXPECT_EQ(resp["status"].toString(), "Unauthorized");
    EXPECT_EQ(resp["description"].toString(), "Unauthorized");
}

TEST_F(ServiceTest, TokenServiceInvalidClient) {
    QJsonObject request;
    request["grant_type"] = "password";
    request["username"] = "alice";
    request["password"] = "password";
    request["client_id"] = "cli-999";  // nonexistent
    request["client_secret"] = "secret";
    request["scopes"] = QJsonArray::fromStringList({"payments:read"});

    QString inputPath = dataDir + "token_req.json";
    QString outputPath = dataDir + "token_resp.json";
    writeJson(inputPath, request);

    auto service = WebServiceFactory::instance().createWebService("/token");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 401);
    EXPECT_EQ(resp["status"].toString(), "Unauthorized");
    EXPECT_EQ(resp["description"].toString(), "Client not found");
}

TEST_F(ServiceTest, TokenServiceInvalidSecret) {
    QJsonObject request;
    request["grant_type"] = "password";
    request["username"] = "alice";
    request["password"] = "password";
    request["client_id"] = "cli-001";
    request["client_secret"] = "wrong";
    request["scopes"] = QJsonArray::fromStringList({"payments:read"});

    QString inputPath = dataDir + "token_req.json";
    QString outputPath = dataDir + "token_resp.json";
    writeJson(inputPath, request);

    auto service = WebServiceFactory::instance().createWebService("/token");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 401);
    EXPECT_EQ(resp["status"].toString(), "Unauthorized");
    EXPECT_EQ(resp["description"].toString(), "Invalid client secret");
}

TEST_F(ServiceTest, TokenServiceInactiveUser) {
    QJsonObject request;
    request["grant_type"] = "password";
    request["username"] = "bob";  // inactive
    request["password"] = "password";
    request["client_id"] = "cli-001";
    request["client_secret"] = "secret";
    request["scopes"] = QJsonArray::fromStringList({"payments:read"});

    QString inputPath = dataDir + "token_req.json";
    QString outputPath = dataDir + "token_resp.json";
    writeJson(inputPath, request);

    auto service = WebServiceFactory::instance().createWebService("/token");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 403);
    EXPECT_EQ(resp["status"].toString(), "Forbidden");
    EXPECT_EQ(resp["description"].toString(), "Forbidden");
}

TEST_F(ServiceTest, TokenServiceUnsupportedGrantType) {
    QJsonObject request;
    request["grant_type"] = "unsupported";
    request["client_id"] = "cli-001";
    request["client_secret"] = "secret";

    QString inputPath = dataDir + "token_req.json";
    QString outputPath = dataDir + "token_resp.json";
    writeJson(inputPath, request);

    auto service = WebServiceFactory::instance().createWebService("/token");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 400);
    EXPECT_EQ(resp["status"].toString(), "Bad request");
    EXPECT_EQ(resp["description"].toString(), "unsupported_grant_type");
}

TEST_F(ServiceTest, TokenServiceClientNotAllowedGrant) {
    QJsonObject request;
    request["grant_type"] = "password";
    request["username"] = "alice";
    request["password"] = "password";
    request["client_id"] = "cli-002";
    request["client_secret"] = "secret2";
    request["scopes"] = QJsonArray::fromStringList({"payments:read"});

    QString inputPath = dataDir + "token_req.json";
    QString outputPath = dataDir + "token_resp.json";
    writeJson(inputPath, request);

    auto service = WebServiceFactory::instance().createWebService("/token");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 403);
    EXPECT_EQ(resp["status"].toString(), "Forbidden");
    EXPECT_EQ(resp["description"].toString(),
              "Client not allowed for grant: password");
}

// RefreshService errors
TEST_F(ServiceTest, RefreshServiceInvalidGrantType) {
    QJsonObject request;
    request["grant_type"] = "invalid";
    request["refresh_token"] = "dummy";
    request["client_id"] = "cli-001";
    request["client_secret"] = "secret";

    QString inputPath = dataDir + "refresh_req.json";
    QString outputPath = dataDir + "refresh_resp.json";
    writeJson(inputPath, request);

    auto service =
        WebServiceFactory::instance().createWebService("/token/refresh");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 400);
    EXPECT_EQ(resp["status"].toString(), "Bad request");
    EXPECT_EQ(resp["description"].toString(), "Bad Request");
}

TEST_F(ServiceTest, RefreshServiceInvalidClient) {
    QJsonObject request;
    request["grant_type"] = "refresh_token";
    request["refresh_token"] = "dummy";
    request["client_id"] = "cli-999";
    request["client_secret"] = "secret";

    QString inputPath = dataDir + "refresh_req.json";
    QString outputPath = dataDir + "refresh_resp.json";
    writeJson(inputPath, request);

    auto service =
        WebServiceFactory::instance().createWebService("/token/refresh");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 401);
    EXPECT_EQ(resp["status"].toString(), "Unauthorized");
    EXPECT_EQ(resp["description"].toString(), "Client not found");
}

TEST_F(ServiceTest, RefreshServiceInvalidRefreshToken) {
    QJsonObject request;
    request["grant_type"] = "refresh_token";
    request["refresh_token"] = "invalid_token";
    request["client_id"] = "cli-001";
    request["client_secret"] = "secret";

    QString inputPath = dataDir + "refresh_req.json";
    QString outputPath = dataDir + "refresh_resp.json";
    writeJson(inputPath, request);

    auto service =
        WebServiceFactory::instance().createWebService("/token/refresh");
    bool ok = service->handleRequest(inputPath, outputPath);
    EXPECT_TRUE(ok);

    QJsonObject resp = readJson(outputPath);
    EXPECT_EQ(resp["code"].toInt(), 401);
    EXPECT_EQ(resp["status"].toString(), "Unauthorized");
    EXPECT_EQ(resp["description"].toString(), "Unauthorized");
}

// TEST_F(ServiceTest, RefreshServiceRotatedRefreshToken) {
//     QJsonObject tokenReq;
//     tokenReq["grant_type"] = "password";
//     tokenReq["username"] = "alice";
//     tokenReq["password"] = "password";
//     tokenReq["client_id"] = "cli-001";
//     tokenReq["client_secret"] = "secret";
//     tokenReq["scopes"] = QJsonArray::fromStringList({"payments:read"});
//     QString tokenInput = dataDir + "token_req.json";
//     QString tokenOutput = dataDir + "token_resp.json";
//     writeJson(tokenInput, tokenReq);
//     auto tokenService =
//         WebServiceFactory::instance().createWebService("/token");
//     tokenService->handleRequest(tokenInput, tokenOutput);
//     QJsonObject tokenResp = readJson(tokenOutput);
//     QString refreshToken = tokenResp["refresh_token"].toString();

//     QJsonObject refreshReq1;
//     refreshReq1["grant_type"] = "refresh_token";
//     refreshReq1["refresh_token"] = refreshToken;
//     refreshReq1["client_id"] = "cli-001";
//     refreshReq1["client_secret"] = "secret";
//     QString refInput1 = dataDir + "refresh_req1.json";
//     QString refOutput1 = dataDir + "refresh_resp1.json";
//     writeJson(refInput1, refreshReq1);
//     auto refreshService =
//         WebServiceFactory::instance().createWebService("/token/refresh");
//     refreshService->handleRequest(refInput1, refOutput1);

//     // Try to use the same refresh token again
//     QJsonObject refreshReq2;
//     refreshReq2["grant_type"] = "refresh_token";
//     refreshReq2["refresh_token"] = refreshToken;
//     refreshReq2["client_id"] = "cli-001";
//     refreshReq2["client_secret"] = "secret";
//     QString refInput2 = dataDir + "refresh_req2.json";
//     QString refOutput2 = dataDir + "refresh_resp2.json";
//     writeJson(refInput2, refreshReq2);

//     bool ok = refreshService->handleRequest(refInput2, refOutput2);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(refOutput2);
//     EXPECT_EQ(resp["code"].toInt(), 409);
//     EXPECT_EQ(resp["status"].toString(), "Conflict");
//     EXPECT_EQ(resp["description"].toString(), "Conflict");
// }

// TEST_F(ServiceTest, RefreshServiceRevokedRefreshToken) {
//     QJsonObject tokenReq;
//     tokenReq["grant_type"] = "password";
//     tokenReq["username"] = "alice";
//     tokenReq["password"] = "password";
//     tokenReq["client_id"] = "cli-001";
//     tokenReq["client_secret"] = "secret";
//     tokenReq["scopes"] = QJsonArray::fromStringList({"payments:read"});
//     QString tokenInput = dataDir + "token_req.json";
//     QString tokenOutput = dataDir + "token_resp.json";
//     writeJson(tokenInput, tokenReq);
//     auto tokenService =
//         WebServiceFactory::instance().createWebService("/token");
//     tokenService->handleRequest(tokenInput, tokenOutput);
//     QJsonObject tokenResp = readJson(tokenOutput);
//     QString refreshToken = tokenResp["refresh_token"].toString();

//     // Revoke it using RevokeService
//     QJsonObject revokeReq;
//     revokeReq["token"] = refreshToken;
//     revokeReq["token_type_hint"] = "refresh_token";
//     QString revokeInput = dataDir + "revoke_req.json";
//     QString revokeOutput = dataDir + "revoke_resp.json";
//     writeJson(revokeInput, revokeReq);
//     auto revokeService =
//         WebServiceFactory::instance().createWebService("/revoke");
//     revokeService->handleRequest(revokeInput, revokeOutput);

//     // Try to refresh with revoked token
//     QJsonObject refreshReq;
//     refreshReq["grant_type"] = "refresh_token";
//     refreshReq["refresh_token"] = refreshToken;
//     refreshReq["client_id"] = "cli-001";
//     refreshReq["client_secret"] = "secret";
//     QString refInput = dataDir + "refresh_req.json";
//     QString refOutput = dataDir + "refresh_resp.json";
//     writeJson(refInput, refreshReq);

//     auto refreshService =
//         WebServiceFactory::instance().createWebService("/token/refresh");
//     bool ok = refreshService->handleRequest(refInput, refOutput);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(refOutput);
//     EXPECT_EQ(resp["code"].toInt(), 401);
//     EXPECT_EQ(resp["status"].toString(), "Unauthorized");
//     EXPECT_EQ(resp["description"].toString(), "Unauthorized");
// }

// TEST_F(ServiceTest, RefreshServiceUserNotFound) {
//     // Directly manipulate DataManager to add a record.
//     RefreshRecord rec;
//     rec.refreshToken = "dummy_rt";
//     rec.userId = "u-999";  // non-existent
//     rec.clientId = "cli-001";
//     rec.scopes = QStringList{"payments:read"};
//     rec.expires = QDateTime::currentDateTimeUtc().addDays(1);
//     rec.rotated = false;
//     DataManager::instance().addRefreshRecord(rec);

//     QJsonObject request;
//     request["grant_type"] = "refresh_token";
//     request["refresh_token"] = "dummy_rt";
//     request["client_id"] = "cli-001";
//     request["client_secret"] = "secret";

//     QString inputPath = dataDir + "refresh_req.json";
//     QString outputPath = dataDir + "refresh_resp.json";
//     writeJson(inputPath, request);

//     auto service =
//         WebServiceFactory::instance().createWebService("/token/refresh");
//     bool ok = service->handleRequest(inputPath, outputPath);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(outputPath);
//     EXPECT_EQ(resp["code"].toInt(), 500);
//     EXPECT_EQ(resp["status"].toString(), "Internal server error");
//     EXPECT_EQ(resp["description"].toString(), "Internal Error");

//     // Check that error was logged in error.log
//     QFile logFile("error.log");
//     EXPECT_TRUE(logFile.exists());
//     EXPECT_TRUE(logFile.open(QIODevice::ReadOnly));
//     QString content = logFile.readAll();
//     EXPECT_TRUE(content.contains("User associated with refresh not found"));
// }

// // RevokeService errors
// TEST_F(ServiceTest, RevokeServiceMissingToken) {
//     QJsonObject request;
//     request["token_type_hint"] = "access_token";  // no token field

//     QString inputPath = dataDir + "revoke_req.json";
//     QString outputPath = dataDir + "revoke_resp.json";
//     writeJson(inputPath, request);

//     auto service = WebServiceFactory::instance().createWebService("/revoke");
//     bool ok = service->handleRequest(inputPath, outputPath);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(outputPath);
//     EXPECT_EQ(resp["code"].toInt(), 400);
//     EXPECT_EQ(resp["status"].toString(), "Bad request");
//     EXPECT_EQ(resp["description"].toString(), "Bad Request");
// }

// TEST_F(ServiceTest, RevokeServiceInvalidAccessToken) {
//     QJsonObject request;
//     request["token"] = "invalid.token.here";
//     request["token_type_hint"] = "access_token";

//     QString inputPath = dataDir + "revoke_req.json";
//     QString outputPath = dataDir + "revoke_resp.json";
//     writeJson(inputPath, request);

//     auto service = WebServiceFactory::instance().createWebService("/revoke");
//     bool ok = service->handleRequest(inputPath, outputPath);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(outputPath);
//     EXPECT_EQ(resp["code"].toInt(), 401);
//     EXPECT_EQ(resp["status"].toString(), "Unauthorized");
//     EXPECT_EQ(resp["description"].toString(), "Unauthorized");
// }

// TEST_F(ServiceTest, RevokeServiceInvalidRefreshToken) {
//     QJsonObject request;
//     request["token"] = "invalid_refresh";
//     request["token_type_hint"] = "refresh_token";

//     QString inputPath = dataDir + "revoke_req.json";
//     QString outputPath = dataDir + "revoke_resp.json";
//     writeJson(inputPath, request);

//     auto service = WebServiceFactory::instance().createWebService("/revoke");
//     bool ok = service->handleRequest(inputPath, outputPath);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(outputPath);
//     EXPECT_EQ(resp["code"].toInt(), 401);
//     EXPECT_EQ(resp["status"].toString(), "Unauthorized");
//     EXPECT_EQ(resp["description"].toString(), "Unauthorized");
// }

// TEST_F(ServiceTest, RevokeServiceUnsupportedTokenType) {
//     QJsonObject request;
//     request["token"] = "some_token";
//     request["token_type_hint"] = "unsupported";

//     QString inputPath = dataDir + "revoke_req.json";
//     QString outputPath = dataDir + "revoke_resp.json";
//     writeJson(inputPath, request);

//     auto service = WebServiceFactory::instance().createWebService("/revoke");
//     bool ok = service->handleRequest(inputPath, outputPath);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(outputPath);
//     EXPECT_EQ(resp["code"].toInt(), 400);
//     EXPECT_EQ(resp["status"].toString(), "Bad request");
//     EXPECT_EQ(resp["description"].toString(), "Bad Request");
// }

// // PaymentsService errors
// TEST_F(ServiceTest, PaymentsServiceMissingToken) {
//     QJsonObject request;
//     request["method"] = "GET";  // no access_token

//     QString inputPath = dataDir + "pay_req.json";
//     QString outputPath = dataDir + "pay_resp.json";
//     writeJson(inputPath, request);

//     auto service =
//         WebServiceFactory::instance().createWebService("/api/payments");
//     bool ok = service->handleRequest(inputPath, outputPath);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(outputPath);
//     EXPECT_EQ(resp["code"].toInt(), 400);
//     EXPECT_EQ(resp["status"].toString(), "Bad request");
//     EXPECT_EQ(resp["description"].toString(), "Bad Request");
// }

// TEST_F(ServiceTest, PaymentsServiceInvalidToken) {
//     QJsonObject request;
//     request["access_token"] = "invalid.token";
//     request["method"] = "GET";

//     QString inputPath = dataDir + "pay_req.json";
//     QString outputPath = dataDir + "pay_resp.json";
//     writeJson(inputPath, request);

//     auto service =
//         WebServiceFactory::instance().createWebService("/api/payments");
//     bool ok = service->handleRequest(inputPath, outputPath);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(outputPath);
//     EXPECT_EQ(resp["code"].toInt(), 401);
//     EXPECT_EQ(resp["status"].toString(), "Unauthorized");
//     EXPECT_EQ(resp["description"].toString(), "Unauthorized");
// }

// TEST_F(ServiceTest, PaymentsServiceInsufficientScope) {
//     // Get token with only payments:read
//     QJsonObject tokenReq;
//     tokenReq["grant_type"] = "password";
//     tokenReq["username"] = "alice";
//     tokenReq["password"] = "password";
//     tokenReq["client_id"] = "cli-001";
//     tokenReq["client_secret"] = "secret";
//     tokenReq["scopes"] = QJsonArray::fromStringList({"payments:read"});
//     QString tokenInput = dataDir + "token_req.json";
//     QString tokenOutput = dataDir + "token_resp.json";
//     writeJson(tokenInput, tokenReq);
//     auto tokenService =
//         WebServiceFactory::instance().createWebService("/token");
//     tokenService->handleRequest(tokenInput, tokenOutput);
//     QJsonObject tokenResp = readJson(tokenOutput);
//     QString accessToken = tokenResp["access_token"].toString();

//     // Try to POST (requires payments:write)
//     QJsonObject payReq;
//     payReq["access_token"] = accessToken;
//     payReq["method"] = "POST";
//     QString payInput = dataDir + "pay_req.json";
//     QString payOutput = dataDir + "pay_resp.json";
//     writeJson(payInput, payReq);

//     auto payService =
//         WebServiceFactory::instance().createWebService("/api/payments");
//     bool ok = payService->handleRequest(payInput, payOutput);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(payOutput);
//     EXPECT_EQ(resp["code"].toInt(), 403);
//     EXPECT_EQ(resp["status"].toString(), "Forbidden");
//     EXPECT_TRUE(resp["description"].toString().contains("Forbidden"));
// }

// TEST_F(ServiceTest, PaymentsServiceUnsupportedMethod) {
//     // Get token
//     QJsonObject tokenReq;
//     tokenReq["grant_type"] = "password";
//     tokenReq["username"] = "alice";
//     tokenReq["password"] = "password";
//     tokenReq["client_id"] = "cli-001";
//     tokenReq["client_secret"] = "secret";
//     tokenReq["scopes"] =
//         QJsonArray::fromStringList({"payments:read", "payments:write"});
//     QString tokenInput = dataDir + "token_req.json";
//     QString tokenOutput = dataDir + "token_resp.json";
//     writeJson(tokenInput, tokenReq);
//     auto tokenService =
//         WebServiceFactory::instance().createWebService("/token");
//     tokenService->handleRequest(tokenInput, tokenOutput);
//     QJsonObject tokenResp = readJson(tokenOutput);
//     QString accessToken = tokenResp["access_token"].toString();

//     QJsonObject payReq;
//     payReq["access_token"] = accessToken;
//     payReq["method"] = "DELETE";  // unsupported
//     QString payInput = dataDir + "pay_req.json";
//     QString payOutput = dataDir + "pay_resp.json";
//     writeJson(payInput, payReq);

//     auto payService =
//         WebServiceFactory::instance().createWebService("/api/payments");
//     bool ok = payService->handleRequest(payInput, payOutput);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(payOutput);
//     EXPECT_EQ(resp["code"].toInt(), 400);
//     EXPECT_EQ(resp["status"].toString(), "Bad request");
//     EXPECT_EQ(resp["description"].toString(), "Bad Request");
// }

// // IntrospectService – no errors expected, but we test valid and invalid
// token TEST_F(ServiceTest, IntrospectServiceValidToken) {
//     // Get token
//     QJsonObject tokenReq;
//     tokenReq["grant_type"] = "password";
//     tokenReq["username"] = "alice";
//     tokenReq["password"] = "password";
//     tokenReq["client_id"] = "cli-001";
//     tokenReq["client_secret"] = "secret";
//     tokenReq["scopes"] = QJsonArray::fromStringList({"payments:read"});
//     QString tokenInput = dataDir + "token_req.json";
//     QString tokenOutput = dataDir + "token_resp.json";
//     writeJson(tokenInput, tokenReq);
//     auto tokenService =
//         WebServiceFactory::instance().createWebService("/token");
//     tokenService->handleRequest(tokenInput, tokenOutput);
//     QJsonObject tokenResp = readJson(tokenOutput);
//     QString accessToken = tokenResp["access_token"].toString();

//     QJsonObject introReq;
//     introReq["token"] = accessToken;
//     QString introInput = dataDir + "intro_req.json";
//     QString introOutput = dataDir + "intro_resp.json";
//     writeJson(introInput, introReq);

//     auto introService =
//         WebServiceFactory::instance().createWebService("/introspect");
//     bool ok = introService->handleRequest(introInput, introOutput);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(introOutput);
//     EXPECT_TRUE(resp["active"].toBool());
//     EXPECT_EQ(resp["client_id"].toString(), "cli-001");
//     EXPECT_EQ(resp["sub"].toString(), "u-100");
//     EXPECT_TRUE(resp.contains("scope"));
// }

// TEST_F(ServiceTest, IntrospectServiceInvalidToken) {
//     QJsonObject introReq;
//     introReq["token"] = "invalid.token";
//     QString introInput = dataDir + "intro_req.json";
//     QString introOutput = dataDir + "intro_resp.json";
//     writeJson(introInput, introReq);

//     auto introService =
//         WebServiceFactory::instance().createWebService("/introspect");
//     bool ok = introService->handleRequest(introInput, introOutput);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(introOutput);
//     EXPECT_FALSE(resp["active"].toBool());
//     // No error fields, just active false
//     EXPECT_FALSE(resp.contains("code"));
// }

// TEST_F(ServiceTest, IntrospectServiceMissingToken) {
//     QJsonObject introReq;  // empty
//     QString introInput = dataDir + "intro_req.json";
//     QString introOutput = dataDir + "intro_resp.json";
//     writeJson(introInput, introReq);

//     auto introService =
//         WebServiceFactory::instance().createWebService("/introspect");
//     bool ok = introService->handleRequest(introInput, introOutput);
//     EXPECT_TRUE(ok);

//     QJsonObject resp = readJson(introOutput);
//     EXPECT_EQ(resp["code"].toInt(), 400);
//     EXPECT_EQ(resp["status"].toString(), "Bad request");
//     EXPECT_EQ(resp["description"].toString(), "Missing token");
// }

// // Test Factory
// TEST(FactoryTest, RegisterAndCreate) {
//     WebServiceFactory &factory = WebServiceFactory::instance();
//     factory.registerWebService<TokenService>("/test");
//     auto svc = factory.createWebService("/test");
//     EXPECT_NE(svc, nullptr);
//     auto svc2 = factory.createWebService("/nonexistent");
//     EXPECT_EQ(svc2, nullptr);
// }

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}