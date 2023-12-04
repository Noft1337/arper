#include <stdlib.h>
#include <string.h>
#include "utils.h"


void *s_malloc(size_t size){
    void *p = malloc(size);
    memset(p, 0, size);

    return p;
}

void s_free(Byte *mem, size_t size){
    memset(mem, 0, size);
    free(mem);
}