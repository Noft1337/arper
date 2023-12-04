#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <errno.h>
#include "packeter.h"
#include "utils.h"

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
    } else if (compare_arrays(f.ether_type, ipv6_bytes, 2)) {
        return IPV6;
    }
    return 0;
}


bool is_protocol(struct inet_frame f, int protocol){
    if (protocol == get_ether_type(f)){
        return true;
    }
    return false;
}


int set_bytes_in_pos(const Byte *from, Byte *to, int pos_from, int pos_to, size_t len){
    int updated_pos = pos_to;

    for (int i = 0; i < len; i++){
        to[i+pos_to] = from[i+pos_from];
    }

    return updated_pos;
}


uint8_t convert_raw_to_hex_char(const unsigned char raw_char){
    uint8_t converted;
    if(47 < raw_char  && raw_char < 58){
        // Means that it is a character
        converted = (uint8_t)(raw_char - '0');
    } else if (96 < raw_char && raw_char < 123) {
        // Means that it is a number
        converted = (uint8_t) (raw_char - ('a' - 10));
    } else if (64 < raw_char && raw_char < 91) {
        converted = (uint8_t) (raw_char - ('A' - 10));
    } else {
        perror("Invalid hex raw_char");
        return 0x0;
    }
    return converted;
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
        return 0x0;
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
            target[str_length + 2] = ':';
            target[str_length + 3] = 0x0;
        } else {
            target[str_length + 2] = 0x0;
        }
    }
}


void print_inet_frame(const struct inet_frame f){
    const char *ether_types[] = ETHER_TYPES;
    char src_mac[18] = {};
    char dst_mac[18] = {};
    char ether_type[6] = {};
    int type = get_ether_type(f);

    print_hex_set(f.src_mac, src_mac, 6);
    print_hex_set(f.dst_mac, dst_mac, 6);
    print_hex_set(f.ether_type, ether_type, 2);
    printf("Source MAC: %s\n"
           "Destination MAC: %s\n"
           "Ether II Type: %s (%s)\n\n",
           src_mac, dst_mac, ether_type, ether_types[type]
    );
}


unsigned int set_field_from_bytes(uint8_t *field, const unsigned char *bytes, int len, int start_byte){
    unsigned int pos;
    for (int i = start_byte; i < len + start_byte; i++){
        field[i - start_byte] = bytes[i];
        pos = i;
    }
    return pos;
}


int setup_inet_frame_from_raw_bytes(struct inet_frame *f, const unsigned char *bytes, const size_t len){
    if (len < MIN_FRAME_LEN){
        errno = ELNRNG;
        perror("Invalid packet length");
        return 0;
    } else {
        uint8_t b_arp[2] = ARP_BYTES;
        set_field_from_bytes(f->dst_mac, bytes, MAC_SIZE, 0);
        set_field_from_bytes(f->src_mac, bytes, MAC_SIZE, 6);
        set_field_from_bytes(f->ether_type, bytes, sizeof(f->ether_type), 12);
    }
    return 1;
}


Byte *create_arp_reply_from_bytes(const Byte *b, const Byte *mac_addr){
    Byte arp_defaults[] = ARP_DEFAULT_BYTES;
    Byte *resp = (Byte *)s_malloc(ARP_RESP_SIZE);

    // Reverse destination and source
    // Set the source mac to be our own
    set_bytes_in_pos(mac_addr, resp, 0, 6, MAC_SIZE);
    // Set the destination to be the source of the request
    set_bytes_in_pos(b, resp, 6, 0, MAC_SIZE);
    // Set the default 10 Bytes
    set_bytes_in_pos(arp_defaults, resp, 0, 12, ARP_DEFAULTS_SIZE);
    // Exchange Sender's MAC, IP with TARGET's IP and our MAC
    set_bytes_in_pos(mac_addr, resp, 0, 22, MAC_SIZE);
    set_bytes_in_pos(b, resp, 38, 28, IPV4_SIZE);
    set_bytes_in_pos(b, resp, 22, 32, MAC_SIZE);
    set_bytes_in_pos(b, resp, 28, 38, IPV4_SIZE);

    return resp;
}
