/*
 * Count-min Sketch implementation
 */
#include "count-min-sketch.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Note that we support atomic read/write on the count-min sketch
 * table (cm_sketch). This requires all the table cell to be 64-bits
 * aligned. Therefore, we start at an aligned address and each cell
 * address is also an aligned address.
 */


/*
 * Experienced method online. The result is nearly good as AES.
 */
static uint32_t
cm_hash1 (uint32_t x)
{
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

/*
 * Robert Jenkin's hashing method
 */
static uint32_t
cm_hash2 (uint32_t a)
{
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);
    return a;
}

/*
 * Thomas Wang's hashing method
 */
static uint32_t
cm_hash3(uint32_t a) 
{
    a = (a ^ 61) ^ (a >> 16);
    a = a + (a << 3);
    a = a ^ (a >> 4);
    a = a * 0x27d4eb2d;
    a = a ^ (a >> 15);
    return a;
}

/*
 * Knuth's multiplicative hashing method
 */
static uint32_t 
cm_hash4(uint32_t v)
{
    return v * UINT32_C(2654435761);
}

/* 
* Murmur hash
*/

// static uint32_t fmix32 ( uint32_t h )
// {
//   h ^= h >> 16;
//   h *= 0x85ebca6b;
//   h ^= h >> 13;
//   h *= 0xc2b2ae35;
//   h ^= h >> 16;

//   return h;
// }

// static uint32_t rotl32 ( uint32_t x, int8_t r )
// {
//   return (x << r) | (x >> (32 - r));
// }

// static uint32_t
// cm_hash5(uint32_t x)
// {
//     const uint8_t * data = (const uint8_t*)(&x);
//     int len = sizeof(x);
//     const int nblocks = len / 4;
//     int i;

//     uint32_t h1 = 0x12345678;

//     uint32_t c1 = 0xcc9e2d51;
//     uint32_t c2 = 0x1b873593;

//     //----------
//     // body

//     const uint32_t * blocks = (const uint32_t *)(data + nblocks*4);

//     for(i = -nblocks; i; i++)
//     {
//         uint32_t k1 = blocks[i];

//         k1 *= c1;
//         k1 = rotl32(k1,15);
//         k1 *= c2;
        
//         h1 ^= k1;
//         h1 = rotl32(h1,13); 
//         h1 = h1*5+0xe6546b64;
//     }

//     //----------
//     // tail

//     const uint8_t * tail = (const uint8_t*)(data + nblocks*4);

//     uint32_t k1 = 0;

//     switch(len & 3)
//     {
//     case 3: k1 ^= tail[2] << 16;
//     case 2: k1 ^= tail[1] << 8;
//     case 1: k1 ^= tail[0];
//             k1 *= c1; k1 = rotl32(k1,15); k1 *= c2; h1 ^= k1;
//     };

//     //----------
//     // finalization

//     h1 ^= len;

//     h1 = fmix32(h1);

//     return h1;
// }

/* 
* xxHash
*/

static const uint32_t PRIME32_1 = 2654435761U;
static const uint32_t PRIME32_2 = 2246822519U;
static const uint32_t PRIME32_3 = 3266489917U;
static const uint32_t PRIME32_4 =  668265263U;
static const uint32_t PRIME32_5 =  374761393U;

#define xxh_rotl32(x, r) ((x << r) | (x >> (32 - r)))

static uint32_t xxh32_round(uint32_t seed, const uint32_t input)
{
	seed += input * PRIME32_2;
	seed = xxh_rotl32(seed, 13);
	seed *= PRIME32_1;
	return seed;
}

uint32_t cm_hash6(uint32_t x)
{
    size_t len = sizeof(x);
	const uint8_t *p = (const uint8_t *)(&x);
    const uint32_t *p_32 = &x;
	const uint8_t *b_end = p + len;
    
	uint32_t h32;
    uint32_t seed = 0x12345678;

	if (len >= 16) {
		const uint8_t *const limit = b_end - 16;
		uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
		uint32_t v2 = seed + PRIME32_2;
		uint32_t v3 = seed + 0;
		uint32_t v4 = seed - PRIME32_1;

		do {
			v1 = xxh32_round(v1, *p_32);
			p += 4;
			v2 = xxh32_round(v2, *p_32);
			p += 4;
			v3 = xxh32_round(v3, *p_32);
			p += 4;
			v4 = xxh32_round(v4, *p_32);
			p += 4;
		} while (p <= limit);

		h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) +
			xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
	} else {
		h32 = seed + PRIME32_5;
	}

	h32 += (uint32_t)len;

	while (p + 4 <= b_end) {
		h32 += *p_32 * PRIME32_3;
		h32 = xxh_rotl32(h32, 17) * PRIME32_4;
		p += 4;
	}

	while (p < b_end) {
		h32 += (*p) * PRIME32_5;
		h32 = xxh_rotl32(h32, 11) * PRIME32_1;
		p++;
	}

	h32 ^= h32 >> 15;
	h32 *= PRIME32_2;
	h32 ^= h32 >> 13;
	h32 *= PRIME32_3;
	h32 ^= h32 >> 16;

	return h32;
}



static uint32_t
flow_to_hash(int row,
             uint32_t flow_id)
{
    uint32_t ret;

    switch (row) {
        case 0: ret = cm_hash1(flow_id); break;
        case 1: ret = cm_hash2(flow_id); break;
        case 2: ret = cm_hash3(flow_id); break;
        case 3: ret = cm_hash4(flow_id); break;
        // case 4: ret = cm_hash5(flow_id); break;
        // case 5: ret = cm_hash6(flow_id); break;
        default: ret = flow_id; break;
    }

    return ret;
}

uint64_t 
cm_sketch_read(uint64_t *cm_sketch,
               int row, 
               uint32_t flow_id)
{
    uint32_t bucket_id = flow_to_hash (row, flow_id) % CM_COL_NUM;
    //debug
    //printf("bucket_id = %d\n", bucket_id);

    uint64_t ret_val = cm_sketch[row * CM_ROW_NUM + bucket_id];

    //debug
    //printf("ret_val = %ld\n",ret_val);

    return ret_val;
}

#define MAX(a,b) (((a)>(b))?(a):(b))

void
cm_sketch_update(uint64_t *cm_sketch,
                 int row,
                 uint32_t flow_id)
                 //uint64_t new_val)
{
    uint32_t bucket_id = flow_to_hash (row, flow_id) % CM_COL_NUM;
    uint64_t *write_addr = cm_sketch + row * CM_ROW_NUM + bucket_id;
    uint64_t old_val = *write_addr;

    // while (!__sync_bool_compare_and_swap(write_addr, old_val, new_val)) {
    //     old_val = *write_addr;
    //     new_val = MAX(old_val, new_val);
    // }
    __sync_fetch_and_add(write_addr, 1);
}
