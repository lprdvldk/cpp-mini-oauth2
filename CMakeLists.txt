cmake_minimum_required(VERSION 3.16)

project(cli-server LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_executable(cli-server
  main.cpp
  i_webservice.h
  webservicefactory.h webservicefactory.cpp



  tokenmanager.h tokenmanager.cpp




)

target_include_directories(cli-server PRIVATE jwt-cpp)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
target_link_libraries(cli-server PRIVATE OpenSSL::Crypto)

target_link_libraries(cli-server PRIVATE Qt${QT_VERSION_MAJOR}::Core)

include(GNUInstallDirs)
install(TARGETS cli-server
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
