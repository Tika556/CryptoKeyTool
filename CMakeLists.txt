cmake_minimum_required(VERSION 3.10)
project(CryptoKeyTool)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(CryptoKeyTool main.cpp)
target_link_libraries(CryptoKeyTool OpenSSL::SSL OpenSSL::Crypto)
