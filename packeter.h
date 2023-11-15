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
#include <stdbool.h>

#define PACKETER_VERSION "0.0.4"
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
    /*
     * Ethernet frame consists only Layer 2,
     * which includes the ARP segment in itself
     */
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint8_t ether_type[2];
    struct arp arp_segment;
    uint8_t padding[18];
};


extern bool is_protocol(
        struct inet_frame f, int protocol
        );
extern int setup_inet_frame_from_raw_bytes(
        struct inet_frame *f, const unsigned char *bytes, size_t len
        );
extern void print_hex_set(const uint8_t *set, char *target, size_t length);
extern uint8_t convert_raw_to_hex_char(unsigned char raw_char);
extern void print_inet_frame(struct inet_frame f);
