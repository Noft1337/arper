cmake_minimum_required(VERSION 3.24)
project(arper C)

set(CMAKE_C_STANDARD 23)

add_executable(arper main.c packeter.h if_menu.h logger.c)
