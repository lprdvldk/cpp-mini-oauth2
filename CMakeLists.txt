cmake_minimum_required(VERSION 3.16)

project(cli-server LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

include_directories(include)
include_directories(jwt-cpp)

add_executable(cli-server
    src/main.cpp
    src/config.cpp
    src/datamanager.cpp
    src/introspectservice.cpp
    src/paymentservice.cpp
    src/refreshservice.cpp
    src/revokeservice.cpp
    src/tokenmanager.cpp
    src/tokenservice.cpp
    src/webservicefactory.cpp
    include/config.h
    include/datamanager.h
    include/datamodel.h
    include/i_webservice.h
    include/introspectservice.h
    include/paymentservice.h
    include/refreshservice.h
    include/revokeservice.h
    include/tokenmanager.h
    include/tokenservice.h
    include/webservicefactory.h
)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

if(OPENSSL_FOUND)
    target_include_directories(cli-server PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(cli-server PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

target_link_libraries(cli-server PRIVATE Qt${QT_VERSION_MAJOR}::Core)

include(GNUInstallDirs)
install(TARGETS cli-server
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# ---- Тесты ----
enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
FetchContent_MakeAvailable(googletest)

add_executable(cli-server-tests
    tests/test_main.cpp
    src/config.cpp
    src/datamanager.cpp
    src/introspectservice.cpp
    src/paymentservice.cpp
    src/refreshservice.cpp
    src/revokeservice.cpp
    src/tokenmanager.cpp
    src/tokenservice.cpp
    src/webservicefactory.cpp
)

target_include_directories(cli-server-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/jwt-cpp
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(cli-server-tests PRIVATE
    gtest
    gtest_main
    Qt${QT_VERSION_MAJOR}::Core
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
)

add_test(NAME cli-server-tests COMMAND cli-server-tests)