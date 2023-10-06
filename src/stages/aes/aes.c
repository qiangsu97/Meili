/*
 * AES
 * 
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "aes.h"
#include "../../runtime/meili_runtime.h"
#include "../../utils/aes/aes_utils.h"


int
aes_init(struct pipeline_stage *self)
{
    /* allocate space for pipeline state */
    self->state = (struct aes_state *)malloc(sizeof(struct aes_state));
    struct aes_state *mystate = (struct aes_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    //memset(self->state, 0x00, sizeof(struct aes_state));
    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 
                      0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[16]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    memcpy(mystate->key, key, 16*sizeof(uint8_t));
    memcpy(mystate->iv, iv, 16*sizeof(uint8_t));
    return 0;
}

int
aes_free(struct pipeline_stage *self)
{
    struct aes_state *mystate = (struct aes_state *)self->state;
    free(mystate);
    return 0;
}

int
aes_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{

    struct aes_state *mystate = (struct aes_state *)self->state;
    char hash_out[21];
    char enc_buf[1500];
    const unsigned char *pkt;
    int length = 0;

    for(int i=0; i<nb_enq; i++){
        pkt = rte_pktmbuf_mtod(mbuf[i], const unsigned char *);
        length = mbuf[i]->data_len;
        /* we only implement key part of aes here */
        /* outbound */
        /* esp hdr encapsualtion omitted */
        //SHA1(hash_out, pkt, length);
        AES_CBC_encrypt_buffer(enc_buf, (uint8_t*)pkt, length, mystate->key, mystate->iv);    
        /* ip hdr encapsualtion omitted */

            
        /* inbound */
        /* strip ip hdr omitted */
        // SHA1(sha1_result, (char *)nfhdr->payload, ENCRYPT_LEN);
        // aes_cbc_decrypt(aes_result, nfhdr->payload, ENCRYPT_LEN);
        /* decapsulate esp hdr omitted */
    }

    *nb_deq = nb_enq;
    *mbuf_out = mbuf;
    
    return 0;
}


int
aes_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = aes_init;
	stage->funcs->pipeline_stage_free = aes_free;
	stage->funcs->pipeline_stage_exec = aes_exec;

	return 0;
}