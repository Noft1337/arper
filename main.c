#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include "logger.h"
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>



#define MAIN_VERSION "0.0.4"
#define BUFFER 65536
#define INTERFACE "m0"


void init_msg(){
    printf("Program v%s\nLogger v%s\nStarting program...\n", MAIN_VERSION, LOGGER_VERSION);
}


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

void set_if(struct ifreq *ifr){
    memset(ifr, 0, sizeof(* ifr));
    snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), INTERFACE);
}


void print_traffic(unsigned char *mem, int num, size_t size, time_t start, time_t current){
    double time_stamp = ((double)current - (double)start) / CLOCKS_PER_SEC;
    printf("[#%d] - [%f]", num, time_stamp);
    for (int i = 0; i < size; i++){
        printf("%02x", mem[i]);
    }
    printf("\n\n");
}


void bind_socket(int sock_fd, struct ifreq *ifr, struct sockaddr_ll *saddr, socklen_t addr_len){
    if (ioctl(sock_fd, SIOCGIFINDEX, ifr) == -1){
        perror("ioctl");
        close(sock_fd);
        exit(-1);
    } else {
        logger("ioctl started successfully", INFO);
    }
    saddr->sll_family = AF_PACKET;
    saddr->sll_ifindex = ifr->ifr_ifindex;
    saddr->sll_protocol = htons(ETH_P_ALL);
    if (bind(sock_fd, saddr, addr_len) == -1){
        perror("Bind error");
        close(sock_fd);
        exit(-1);
    } else {
        logger("Bound socket successfully on \"%s\"", INFO, INTERFACE);
    }
}


int main(){
    int socket_r;
    int packet_num = 0;
    unsigned char mem[BUFFER];
    struct ifreq ifr;
    struct sockaddr_ll src_addr;
    time_t start, current;
    size_t r_data;
    socklen_t addr_len = sizeof(src_addr);

    // Init process
    init_msg();
    if(!init_socket(&socket_r)){return -1;}
    set_if(&ifr);
    bind_socket(socket_r, &ifr, &src_addr,addr_len);
    start = clock();

    // Sniffing process
    while(1){
         r_data = recvfrom(socket_r, mem, BUFFER, 0, NULL, NULL);
         if (r_data > 0) {
             packet_num++;
             current = clock();
             print_traffic(mem, packet_num, r_data, start, current);
             if (packet_num == 10) {
                 break;
             }
         }
    }

    close(socket_r);
    return 0;
}