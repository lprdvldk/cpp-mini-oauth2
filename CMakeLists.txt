cmake_minimum_required(VERSION 3.16)

project(cli-server LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)
find_package(OpenSSL REQUIRED)

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
    src/utils.cpp
)

# set_target_properties(cli-server PROPERTIES
#     CXX_CLANG_TIDY "clang-tidy;-checks=-*,bugprone-*,performance-*,modernize-*"
# )

target_include_directories(cli-server PRIVATE 
    include
    jwt-cpp
)

target_link_libraries(cli-server PRIVATE 
    Qt${QT_VERSION_MAJOR}::Core
    OpenSSL::Crypto
    OpenSSL::SSL
)

include(GNUInstallDirs)
install(TARGETS cli-server
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
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
    src/utils.cpp
)

target_include_directories(cli-server-tests PRIVATE
    include
    jwt-cpp
)

target_link_libraries(cli-server-tests PRIVATE
    gtest
    gtest_main
    Qt${QT_VERSION_MAJOR}::Core
    OpenSSL::Crypto
    OpenSSL::SSL
)

add_test(NAME cli-server-tests COMMAND cli-server-tests)
