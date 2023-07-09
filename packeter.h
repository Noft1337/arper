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

#define MIN_FRAME_LEN 14

#define ARP_BYTES {0x08, 0x06}
#define IPV4_BYTES {0x08, 0x00}
#define IPV6_BYTES {0x86, 0xDD};

#define ARP 1
#define IPV4 2
#define IPV6 3
#define ETHER_TYPES {"ARP", "IPV4"}


struct inet_frame{
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint8_t ether_type[2];
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

    if (compare_arrays(f.ether_type, arp_bytes, 2)){
        return ARP;
    } else if (compare_arrays(f.ether_type, ipv4_bytes, 2)){
        return IPV4;
    } else if (compare_arrays(f.ether_type, ipv6_bytes, 2)){
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


void set_mac_addr(struct inet_frame *f, const unsigned char *bytes){
    for (int i = 0; i < 6; i++){
        f->dst_mac[i] = bytes[i];
        f->src_mac[i] = bytes[i + 6];
    }
}


void set_protocol(struct inet_frame *f, const unsigned char *bytes) {
    f->ether_type[0] = bytes[12];
    f->ether_type[1] = bytes[13];
}


void setup_inet_frame_from_raw_bytes(struct inet_frame *f, const unsigned char *bytes, const size_t len){
    if (len < MIN_FRAME_LEN){
        perror("Invalid packet length");
    } else {
        set_mac_addr(f, bytes);
        set_protocol(f, bytes);
    }
}


char convert_hex_to_raw_char(const uint8_t value){
    char converted;
    if(value < 10){
        // Means that it is a character
        converted = (char)(value + '0');
    } else if (value < 16) {
        // Means that it is a number
        converted = (char)(value + ('A' - 10));
    } else {
        perror("Invalid hex value");
    }
    return converted;
}


void print_hex_set(const uint8_t *set, char *target, const size_t length){
    uint8_t al, ah;
    int str_length;

    for (int i = 0; i < length; i++){
        ah = set[i] >> 4;
        al = set[i] & 0x0F;
        str_length = (int)strlen(target);
        target[str_length] = (char) convert_hex_to_raw_char(ah);
        target[str_length + 1] = (char) convert_hex_to_raw_char(al);
        if (i != length - 1) {
            target[str_length + 3] = ':';
        }
    }
}


void print_inet_frame(const struct inet_frame f){
    const char *ether_types[] = ETHER_TYPES;
    char src_mac[18] = {18 * '\0'};
    char dst_mac[18] = {18 * '\0'};
    char ether_type[6] = {6 * '\0'};

    print_hex_set(f.src_mac, src_mac, 6);
    print_hex_set(f.dst_mac, dst_mac, 6);
    print_hex_set(f.ether_type, ether_type, 2);
    // TODO: take care of when ether type isnt valid
    printf("Source MAC: %s\n"
           "Destination MAC: %s\n"
           "Ether II Type: %s (%s)\n\n",
           src_mac, dst_mac, ether_type, ether_types[get_ether_type(f) - 1]
       );
}
