//
// Created by michael on 11/13/23.
//
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include "logger.h"


void set_type_msg(char msg[], int type){
    if (type == INFO) {
        strcpy(msg, "[INFO]");
    }
    else if (type == WARNING) {
        strcpy(msg, "[WARNING]");
    }
    else if (type == CRITICAL) {
        strcpy(msg, "[CRITICAL]");
    }
    else if (type == ERROR) {
        strcpy(msg, "[ERROR]");
    }
    else{
        printf("Bad logging type received: %d\n", type);
        kill(getpid(), SIGSEGV);
    }
}

void set_time_string(char *time_string){
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    sprintf(time_string, "[%d:%d:%d %d-%d-%d]", tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
}

void logger(char *msg, int type, ...){
    char type_msg[10];
    char decleration[] = "[*]";
    char current_time[50];

    // Logger fstring support
    va_list args;
    va_start(args, type);
    va_end(args);

    set_time_string(current_time);
    set_type_msg(type_msg, type);

    printf("%s - %s | %s | --> ", decleration, current_time, type_msg);
    vprintf(msg, args);
    printf("\n");
}