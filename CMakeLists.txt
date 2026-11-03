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
  src/sha256_variants.cpp
  src/chunk_methods.cpp
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

# Statistical tests shared by the experiments
find_package(Threads REQUIRED)
add_library(bench STATIC apps/bench.cpp)
target_include_directories(bench PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/apps)
target_link_libraries(bench PUBLIC Threads::Threads)
target_compile_options(bench PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra>
)

# Experiments
foreach(experiment sigma_experiment chunk_experiment)
  add_executable(${experiment} apps/${experiment}.cpp)
  target_link_libraries(${experiment} PRIVATE philohash bench)
  target_compile_definitions(${experiment} PRIVATE
    PHILOHASH_TEXTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/texts"
    PHILOHASH_RESULTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/results"
  )
  target_compile_options(${experiment} PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra>
  )
endforeach()

# Tests
include(CTest)
if(BUILD_TESTING)
  add_executable(test_sha256 tests/test_sha256.cpp)
  target_link_libraries(test_sha256 PRIVATE philohash)
  add_test(NAME sha256 COMMAND test_sha256)

  add_executable(test_sha256_variants tests/test_sha256_variants.cpp)
  target_link_libraries(test_sha256_variants PRIVATE philohash)
  add_test(NAME sha256_variants COMMAND test_sha256_variants)

  add_executable(test_chunk_methods tests/test_chunk_methods.cpp)
  target_link_libraries(test_chunk_methods PRIVATE philohash)
  add_test(NAME chunk_methods COMMAND test_chunk_methods)
endif()
