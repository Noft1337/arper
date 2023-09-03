#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>


#define INTERFACES_AMOUNT 255

char *generateInterfacesMenu(){
    return NULL;
}


struct ifaddrs *getInterfaces(){
    struct ifaddrs *addresses;
    if (getifaddrs(&addresses) == -1)
    {
        perror("getifaddrs call failed\n");
        return NULL;
    }
    return addresses;
}


int appendStringToInterfacesArray(char string[], char array[][16], size_t sizeOfArray){
    int set = 0;
    for (int i = 0; i < sizeOfArray; i++){
        if (array[i][0] == '\0'){
            set = 1;
            sprintf(array[i], string, strlen(string));
            break;
        }
    }
    return set;
}


int checkIfInterfaceInArray(char name[], char array[][16], size_t sizeOfArray){
    size_t length = strlen(name);
    for (int i = 0; i < sizeOfArray; i++){
        size_t currentLength = strlen(array[i]);
        if (currentLength == length && strncmp(array[i], name, length) == 0){
            return 1;
        }
    }
    return 0;
}


int setInterfaces(char interfacesNames[][16]){

    struct ifaddrs *addresses = getInterfaces();
    if (!addresses){
        perror("Error obtaining network interfaces");
        return -1;
    }
    const int interfacesAmount = INTERFACES_AMOUNT;
    struct ifaddrs *address = addresses;

    while(address)
    {
        int family = address->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6)
        {
            char *interfaceName = address->ifa_name;
            if (!checkIfInterfaceInArray(interfaceName, interfacesNames, interfacesAmount)){
                appendStringToInterfacesArray(interfaceName, interfacesNames, interfacesAmount);
            }
        }
        address = address->ifa_next;
    }
    freeifaddrs(addresses);
    return 0;
}


void printInterfaces(){
    size_t interfacesAmount = INTERFACES_AMOUNT;
    char interfacesNames[interfacesAmount][16];
    memset(interfacesNames, '\0', sizeof(interfacesNames));
    setInterfaces(interfacesNames);

    for (int i = 0; i < INTERFACES_AMOUNT; i++) {
        if (interfacesNames[i][0] == '\0'){
            break;
        }
        printf("\t%d: %s\n", i + 1, interfacesNames[i]);
    }
}
