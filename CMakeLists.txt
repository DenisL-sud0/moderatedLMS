cmake_minimum_required(VERSION 3.16)
project(ModeratedOfflineLMS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_executable(offline_lms src/main.cpp)
target_link_libraries(offline_lms PRIVATE SQLite::SQLite3 OpenSSL::Crypto)
target_compile_options(offline_lms PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wconversion>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>)

install(TARGETS offline_lms RUNTIME DESTINATION bin)
