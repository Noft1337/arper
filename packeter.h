#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>

#define PACKETER_VERSION "0.0.4"

/*
 ARP Frames are bulit like this:
    Ether II:
        - DST_MAC: 6 Bytes (On request it will be FF:FF:FF:FF:FF:FF)
        - SRC_MAC: 6 Bytes
        - TYPE: 2 Bytes (08:06)
    ARP:
        - HW_TYPE: 2 Bytes (00:01 on home PC)
        - PROTOCOL: 2 Bytes (Most likely IPv4 (08:00) and sometimes IPv6 (86:DD))
        - HW_SIZE: 1 Byte (The size of the MAC, which is 6)
        - PROTOCOL_SIZE: 1 Byte (Size of PROTOCOL, which is 4)
        - OP_CODE: 4 Bytes (The type of the packet, Request (00:01) or Reply (00:02) )
        - SENDER_MAC: 6 Bytes
        - SENDER_IP: 4 Bytes
        - TARGET_MAC: 6 Bytes (00:00:00:00:00:00)
        - TARGET_IP: 4 Bytes
 */

#define MIN_FRAME_LEN 14

#define ARP_BYTES {0x08, 0x06}
#define IPV4_BYTES {0x08, 0x00}
#define IPV6_BYTES {0x86, 0xDD}

#define ARP 1
#define IPV4 2
#define IPV6 3
#define ETHER_TYPES {"UNKNOWN", "ARP", "IPV4", "IPV6"}

#define BROD_MAC {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define ARP_IPV4_DEFAULT_9_BYTES {0x8, 0x6, 0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0}
#define ARP_PADDING {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
#define MAC_QUERY_LENGTH 60
#define MAC_RESP_LENGTH 42
#define OP_REQUEST_BYTES {0x0, 0x1}
#define OP_REPLY_BYTES {0x0, 0x2}

uint8_t LOCAL_MAC[6];


struct arp {
    uint8_t hw_type[2];
    uint8_t protocol_type[4];
    uint8_t hw_size;
    uint8_t protocol_size;
    uint8_t op_code[2];
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    bool is_request;
};


struct inet_frame{
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint8_t ether_type[2];
    struct arp arp_segment;

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
        errno = EOVERFLOW;
        perror("Unknown Ether II type");
        return 0;
    }
}


bool is_protocol(struct inet_frame f, int protocol){
    if (protocol == get_ether_type(f)){
        return true;
    }
    return false;
}


void set_field_from_raw_bytes(uint8_t *field, const unsigned char *bytes, int len, int start_byte){
    for (int i = start_byte; i < len + start_byte; i++){
        field[i - start_byte] = bytes[i];
    }
}


void set_arp_request(struct inet_frame *f, const unsigned char *b){
    uint8_t target_mac[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    uint8_t protocol_type[] = {0x8, 0x0};
    f->arp_segment.hw_size = 6;
    f->arp_segment.protocol_size = 4;

}


void set_iframe_to_arp(struct inet_frame *f, const unsigned char *b){
    uint8_t op_request[2] = OP_REQUEST_BYTES;
    uint8_t op_reply[2] = OP_REPLY_BYTES;
    set_field_from_raw_bytes(f->arp_segment.op_code, b, sizeof(f->arp_segment.op_code), 14);
    if (f->arp_segment.op_code[1] == op_request[1]){
        set_arp_request(f, b);
    } else if (f->arp_segment.op_code[1] == op_reply[1]){
        return;
    } else {
        errno = EPROTONOSUPPORT;
        perror("Invalid OP_CODE for ARP");
    }
}


void setup_inet_frame_from_raw_bytes(struct inet_frame *f, const unsigned char *bytes, const size_t len){
    if (len < MIN_FRAME_LEN){
        errno = ELNRNG;
        perror("Invalid packet length");
    } else {
        uint8_t b_arp[2] = ARP_BYTES;
        set_field_from_raw_bytes(f->dst_mac, bytes, sizeof(f->dst_mac), 0);
        set_field_from_raw_bytes(f->src_mac, bytes, sizeof(f->src_mac), 6);
        set_field_from_raw_bytes(f->ether_type, bytes, sizeof(f->ether_type), 12);
        if(f->ether_type == b_arp){
            set_iframe_to_arp(f, bytes);
        }
    }
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


void set_arp_packet_struct(struct inet_frame *f, const unsigned char *bytes){
    struct arp arpSegment;
    set_field_from_raw_bytes(arpSegment.hw_type, bytes, 2, 14);
    set_field_from_raw_bytes(arpSegment.protocol_type, bytes, 2, 16);
    arpSegment.hw_size = bytes[18];
    arpSegment.protocol_size = bytes[19];
    set_field_from_raw_bytes(arpSegment.op_code, bytes, 4, 20);
    set_field_from_raw_bytes(arpSegment.src_mac, bytes, 6, 28);
    set_field_from_raw_bytes(arpSegment.src_ip, bytes, 4, 34);
    set_field_from_raw_bytes(arpSegment.dst_mac, bytes, 4, 38);
    set_field_from_raw_bytes(arpSegment.src_mac, bytes, 6, 44);
    f->arp_segment = arpSegment;
    //src,dst ip
}



void print_inet_frame(const struct inet_frame f){
    const char *ether_types[] = ETHER_TYPES;
    char src_mac[18] = {};
    char dst_mac[18] = {};
    char ether_type[6] = {};
    int type = get_ether_type(f);
    if (type < 0){
        return;
    }

    print_hex_set(f.src_mac, src_mac, 6);
    print_hex_set(f.dst_mac, dst_mac, 6);
    print_hex_set(f.ether_type, ether_type, 2);
    printf("Source MAC: %s\n"
           "Destination MAC: %s\n"
           "Ether II Type: %s (%s)\n\n",
           src_mac, dst_mac, ether_type, ether_types[type]
    );
}


uint8_t get_mac(){
    return 0xf;
}