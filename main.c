#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<netinet/if_ether.h>
#include<sys/socket.h>
#include"logger.h"
#include<arpa/inet.h>

char MAIN_VERSION[] = "0.0.1";

int init_socket(int *s){
    *s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(*s){
        logger("Socket initialized successfully", INFO);
    } else {
        logger("Couldn't create socket ", ERROR);
        return 0;  
    }
    return 1; 
}

int main(){
    int socket_r;
    if(!init_socket(&socket_r)){return -1;}
    return 0;
}