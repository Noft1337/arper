cmake_minimum_required(VERSION 3.24)
project(arper C)

set(CMAKE_C_STANDARD 23)

set(SRC "${CMAKE_SOURCE_DIR}/src")
file(GLOB SOURCES "${SRC}/*.c")
add_executable(arper ${SOURCES})

target_include_directories(arper PRIVATE ${SRC})

