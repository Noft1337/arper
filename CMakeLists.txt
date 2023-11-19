cmake_minimum_required(VERSION 3.24)
project(arper C)

set(CMAKE_C_STANDARD 23)

add_executable(arper main.c logger.c packeter.c if_menu.c
        utils.h)
