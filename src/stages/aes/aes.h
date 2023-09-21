#ifndef _INCLUDE_AES_H
#define _INCLUDE_AES_H

#include <stdint.h>
#include <rte_mbuf.h>

//#define ENCRYPT_LEN 1024

struct aes_state{
    uint8_t key[16];
    uint8_t iv[16];
}__attribute__((packed));

#endif /* _INCLUDE_AES_H */

