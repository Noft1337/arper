#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "logger.h"
#include "packeter.h"
#include "if_menu.h"
#include "utils.h"


uint8_t LOCAL_MAC[6];

void init_msg(){
    printf("Program v%s\nLogger v%s\nStarting program...\n", MAIN_VERSION, LOGGER_VERSION);
}


void set_mac(uint8_t *mac_var, Byte *mem){
    uint8_t ah, al;
    for (int i = 0; i <= 15; i += 3){
        ah = convert_raw_to_hex_char(mem[i]) << 4;
        al = convert_raw_to_hex_char(mem[i + 1]);
        mac_var[i - 2 * (i/3)] = ah + al;
    }
}


void init_mac(char interface[]){
    FILE* mac;
    char path[100];
    int file_len;
    char mac_string[40] = { 0x0 };

    if (strlen(interface) > 75){
        errno = ENAMETOOLONG;
        perror("Interface name is too long");
        exit(2);
    }
    sprintf(path, "/sys/class/net/%s/address", interface);
    mac = fopen(path, "r");
    if (!mac){
        char err_msg[150];
        sprintf(err_msg, "Couldn't open %s for reading", path);
        perror(err_msg);
        exit(2);
    }
    Byte *content = (Byte *)malloc(20);
    fseek(mac, 0 ,SEEK_END);
    file_len = (int)ftell(mac);
    fseek(mac, 0, SEEK_SET);
    fread(content, 1, file_len, mac);
    set_mac(LOCAL_MAC, content);
    print_hex_set(LOCAL_MAC, mac_string, 6);
    logger("Binding socket on \"%s\" (%s)", INFO, interface, mac_string);

    free(content);
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

void set_if(struct ifreq *ifr, char *interface){
    memset(ifr, 0, sizeof(* ifr));
    snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), interface);
}


void print_traffic(Byte *mem, int num, size_t size, double timestamp){
    printf("[*] - [%d][#%f] - ", num, timestamp);
    for (int i = 0; i < size; i++){
        printf("%02x", mem[i]);
    }
    printf("\n");
}


void bind_socket(int sock_fd, struct ifreq *ifr, struct sockaddr_ll *saddr, socklen_t addr_len, char interface[]){
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
        logger("Bound socket successfully on \"%s\"", INFO, interface);
    }
}


double get_timedelta(struct timespec *start, struct timespec *end){
    clock_gettime(CLOCK_MONOTONIC, end);
    time_t seconds = end->tv_sec - start->tv_sec;
    long  nanoseconds = end->tv_nsec - start->tv_nsec;
    if (nanoseconds < 0){
        seconds -= 1;
        nanoseconds += 100000000;
    }
    return (double)seconds + (double)nanoseconds / 1000000000;
}

void set_and_log_interface(char *interface_string){
    set_interface(interface_string);
    logger("Selected interface: %s", INFO, interface_string);
}


int send_malicious_arp(const struct inet_frame *request){
    // Build the ARP response
    struct inet_frame response;
    generate_arp_reply(request, &response, LOCAL_MAC);

    // Send the malicious response
    if(response.arp_segment.op_code[1] == 0x2){
        return 1;
    }
    return 0;
}


int main(){
    int socket_r;
    int packet_num = 0;
    double timestamp;
    Byte mem[BUFFER];
    struct ifreq ifr;
    struct sockaddr_ll src_addr;
    struct timespec start, current;
    struct inet_frame i_frame;
    size_t data_length;
    socklen_t addr_len = sizeof(src_addr);
    char interface[16];
    int request;


    // Init process
    init_msg();
    set_and_log_interface(interface);
    if(!init_socket(&socket_r)){return -1;}
    init_mac(interface);
    set_if(&ifr, interface);
    bind_socket(socket_r, &ifr, &src_addr,addr_len, interface);
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Sniffing process
    while(1){
        // TODO: Create a condition that if KeyboardInterrupt signal is sent, exit the program safely.
        data_length = recvfrom(socket_r, mem, BUFFER, 0, NULL, NULL);
        if (data_length > 0) {
            request = setup_inet_frame_from_raw_bytes(&i_frame, mem, data_length);
            if(is_protocol(i_frame, ARP) && request){
                send_malicious_arp(&i_frame);
                logger("Received an ARP Request", INFO);
                print_inet_frame(i_frame);
            }
        }
    }

    (socket_r);
    return 0;
}