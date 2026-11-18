# Host-side tests for the shared Tang core. Not part of the ESP-IDF or ESPHome
# builds. Run with `make test` from the repository root (see tests/run.sh).
cmake_minimum_required(VERSION 3.16)
project(esp32_tang_host_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(MbedTLS 3 REQUIRED)
find_package(Threads REQUIRED)

set(TANG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../components/tang_server)

add_library(tang_core STATIC
  ${TANG_DIR}/tang_core.cpp
  ${TANG_DIR}/tang_crypto.cpp)
target_include_directories(tang_core PUBLIC ${TANG_DIR})
target_compile_options(tang_core PRIVATE -Wall -Wextra)
target_link_libraries(tang_core PUBLIC MbedTLS::mbedcrypto Threads::Threads)

add_executable(tang_tests
  test_main.cpp
  test_util.cpp
  test_crypto.cpp)
target_compile_options(tang_tests PRIVATE -Wall -Wextra)
target_link_libraries(tang_tests PRIVATE tang_core)

enable_testing()
add_test(NAME tang_tests COMMAND tang_tests)
