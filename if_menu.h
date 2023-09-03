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


void printInterfaces(char interfacesNames[][16], size_t length){
    for (int i = 0; i < length; i++) {
        if (interfacesNames[i][0] == '\0'){
            break;
        }
        printf("  %d: %s\n", i + 1, interfacesNames[i]);
    }
}


int getMaxPick(char interfaces[][16]){
    int i = 0;
    while(interfaces[i][0] != '\0'){
        if (i > 255){
            return -1;
        }
        i++;
    }
    return i;
}

int isDigit(char *string, int maxIterations){
    int i = 0;
    while (i < maxIterations || string[i] != '\0' || string[i] != '\n'){
        if (string[i] == '\n'){
            string[i] = '\0';
            break;
        } else if (47 > string[i] || string[i] > 58){
            return 0;
        }
        i++;
    }
    if (i > 0){
        return 1;
    }
    return 0;
}

void setInterface(char *toString){
    size_t interfacesAmount = INTERFACES_AMOUNT;
    char interfacesNames[interfacesAmount][16];
    memset(interfacesNames, '\0', sizeof(interfacesNames));
    setInterfaces(interfacesNames);
    int valid = 0;
    int maxPick = getMaxPick(interfacesNames);
    char pick[100];
    int numPick;


    printf("Available interfaces to sniff on:\n");
    printInterfaces(interfacesNames, interfacesAmount);
    while(!valid){
        printf("Choose interface: ");
        fgets(pick, sizeof(pick), stdin);
        if (isDigit(pick, sizeof(pick))){
            numPick = atoi(pick);
            if (numPick <= maxPick) {
                valid = 1;
            }
        }
        if (!valid) {
            printf("Invalid pick.\n");
        }
    }

    sprintf(toString, interfacesNames[numPick - 1], sizeof(toString));

}
