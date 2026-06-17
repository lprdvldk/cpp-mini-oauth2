#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <gtest/gtest.h>

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
    // Delete everything
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
  User *u = DataManager::instance().findUserByUsername("alice");
  ASSERT_NE(u, nullptr);
  EXPECT_EQ(u->userId, "u-100");
  EXPECT_EQ(u->roles, QStringList({"manager", "viewer"}));
}

TEST_F(DataManagerTest, VerifyPassword) {
  EXPECT_TRUE(DataManager::instance().verifyPassword("alice", "password"));
  EXPECT_FALSE(DataManager::instance().verifyPassword("alice", "wrong"));
}

TEST_F(DataManagerTest, FindClient) {
  Client *c = DataManager::instance().findClientById("cli-001");
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
    WebServiceFactory::instance().registerWebService<TokenService>("/token");
    WebServiceFactory::instance().registerWebService<RefreshService>(
        "/token/refresh");
    WebServiceFactory::instance().registerWebService<PaymentsService>(
        "/api/payments");
    WebServiceFactory::instance().registerWebService<RevokeService>("/revoke");
    WebServiceFactory::instance().registerWebService<IntrospectService>(
        "/introspect");
  }
};

// ----- Test Services -----
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
  auto tokenService = WebServiceFactory::instance().createWebService("/token");
  tokenService->handleRequest(tokenInput, tokenOutput);
  QJsonObject tokenResp = readJson(tokenOutput);
  QString refreshToken = tokenResp["refresh_token"].toString();

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
  EXPECT_TRUE(DataManager::instance().findRefreshRecord(refreshToken, oldRec));
  EXPECT_TRUE(oldRec.rotated);

  QString newRt = refResp["refresh_token"].toString();
  RefreshRecord newRec;
  EXPECT_TRUE(DataManager::instance().findRefreshRecord(newRt, newRec));
  EXPECT_FALSE(newRec.rotated);
}

TEST_F(ServiceTest, PaymentsServiceAccess) {
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
  auto tokenService = WebServiceFactory::instance().createWebService("/token");
  tokenService->handleRequest(tokenInput, tokenOutput);
  QJsonObject tokenResp = readJson(tokenOutput);
  QString accessToken = tokenResp["access_token"].toString();

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

// Test Factory
TEST(FactoryTest, RegisterAndCreate) {
  WebServiceFactory &factory = WebServiceFactory::instance();
  factory.registerWebService<TokenService>("/test");
  auto svc = factory.createWebService("/test");
  EXPECT_NE(svc, nullptr);
  auto svc2 = factory.createWebService("/nonexistent");
  EXPECT_EQ(svc2, nullptr);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}