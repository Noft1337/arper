//
// Created by michael on 11/19/23.
//
#include <inttypes.h>

typedef uint8_t Byte;
typedef uint64_t Pointer;

#define MAIN_VERSION "0.0.8"
#define BUFFER 65536
#define MAX_ARP_SPOOFS 10

extern void *s_malloc(size_t size);
extern void s_free(Byte *mem, size_t size);