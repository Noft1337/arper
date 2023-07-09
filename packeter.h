#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#define PACKETER_VERSION "0.0.1"

#define ARP_BYTES {0x08, 0x06}
#define IPV4_BYTES {0x08, 0x00}
#define IPV6_BYTES {0x86, 0xDD};

#define ARP 1
#define IPV4 2
#define IPV6 3


struct inet_frame{
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    unsigned char protocol[2];
};


bool compare_arrays(const unsigned char *arr1, const unsigned char *arr2, size_t len){
    for (int i = 0; i < len; i++){
        if (arr1[i] != arr2[i]){
            return false;
        }
    }
    return true;
}


int get_ether_type(struct inet_frame f){
    const unsigned char arp_bytes[] = ARP_BYTES;
    const unsigned char ipv4_bytes[] = IPV4_BYTES;
    const unsigned char ipv6_bytes[] = IPV6_BYTES;

    if (compare_arrays(f.protocol, arp_bytes, 2)){
        return ARP;
    } else if (compare_arrays(f.protocol, ipv4_bytes, 2)){
        return IPV4;
    } else if (compare_arrays(f.protocol, arp_bytes, 2)){
        return IPV6;
    } else {
        perror("Unknown Ether II type");
        return -1;
    }
}


bool is_protocol(struct inet_frame f, int protocol){
    if (protocol == get_ether_type(f)){
        return true;
    }
    return false;
}
