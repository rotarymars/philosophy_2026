cmake_minimum_required(VERSION 3.16)
project(philohash VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Hash function library
add_library(philohash
  src/sha256.cpp
)
target_include_directories(philohash PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_options(philohash PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra>
)

# CLI: hash every file in texts/
add_executable(hash_texts apps/hash_texts.cpp)
target_link_libraries(hash_texts PRIVATE philohash)
target_compile_definitions(hash_texts PRIVATE
  PHILOHASH_TEXTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/texts"
)

# Tests
include(CTest)
if(BUILD_TESTING)
  add_executable(test_sha256 tests/test_sha256.cpp)
  target_link_libraries(test_sha256 PRIVATE philohash)
  add_test(NAME sha256 COMMAND test_sha256)
endif()
