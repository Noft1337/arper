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
#include <net/if.h>


char MAIN_VERSION[] = "0.0.1";
int BUFFER = 65536;


int init_socket(int *s){
    *s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    uid_t uid = getuid();
    logger("Running program with uid: %d", INFO, uid);
    if (uid != 0){
        perror("Please run the program as \"root\"");
        exit(-1);
    } 
    if(*s > 0){
        logger("Socket initialized successfully", INFO);
    } else {
        logger("Couldn't create socket ", ERROR);
        return 0;  
    }
    return 1; 
}

int main(){
    int socket_r;
    size_t r_data;
    unsigned char mem[BUFFER];
    struct ifreq ifr;
    struct sockaddr src_addr;
    socklen_t = sizeof(src_addr);
    int sock_set;

    // Init process
    if(!init_socket(&socket_r)){return -1;}


    // Sniffing process
    while(1){
        r_data = recvfrom(socket_r, )
    }


    return 0;
}