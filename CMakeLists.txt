cmake_minimum_required(VERSION 3.16)
project(ohboyscan VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(OHBOY_BUILD_TESTS "Build unit tests" ON)
option(OHBOY_STATIC_RUNTIME "Link libstdc++/libgcc statically (portable binaries)" OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)

add_library(ohboy_core STATIC
  src/util.cpp
  src/config.cpp
  src/json.cpp
  src/crypto.cpp
  src/routeros_api.cpp
  src/snapshot.cpp
  src/preset.cpp
  src/audit.cpp
  src/alert.cpp
  src/history.cpp
)
target_include_directories(ohboy_core PUBLIC src)
target_link_libraries(ohboy_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(ohboy_core PUBLIC OHBOY_VERSION="${PROJECT_VERSION}")
target_compile_options(ohboy_core PUBLIC -Wall -Wextra -Wpedantic -Wno-maybe-uninitialized)

add_executable(ohboyscan src/main.cpp)
target_link_libraries(ohboyscan PRIVATE ohboy_core)
target_compile_options(ohboyscan PRIVATE -Wall -Wextra -Wpedantic)
if(OHBOY_STATIC_RUNTIME)
  target_link_options(ohboyscan PRIVATE -static-libstdc++ -static-libgcc)
endif()

install(TARGETS ohboyscan RUNTIME DESTINATION bin)
install(FILES deploy/ohboyscan.conf.example DESTINATION share/ohboyscan)

if(OHBOY_BUILD_TESTS)
  enable_testing()
  add_executable(unit_tests tests/unit_tests.cpp)
  target_link_libraries(unit_tests PRIVATE ohboy_core)
  # When cross-compiling, CMAKE_CROSSCOMPILING_EMULATOR (qemu) is used automatically.
  add_test(NAME unit_tests COMMAND unit_tests)
endif()
