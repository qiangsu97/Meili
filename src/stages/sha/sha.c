/*
 * ESP header and SHA
 * 
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "sha.h"
#include "../../runtime/meili_runtime.h"
#include "../../utils/sha/sha_utils.h"



int
sha_init(struct pipeline_stage *self)
{
    /* allocate space for pipeline state */
    self->state = (struct sha_state *)malloc(sizeof(struct sha_state));
    struct sha_state *mystate = (struct sha_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct sha_state));
    
    return 0;
}

int
sha_free(struct pipeline_stage *self)
{
    struct sha_state *mystate = (struct sha_state *)self->state;
    free(mystate);
    return 0;
}

int
sha_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{

    struct sha_state *mystate = (struct sha_state *)self->state;
    char hash_out[SHA_HASH_SIZE + 1];
    const unsigned char *pkt;
    int length = 0;

    for(int i=0; i<nb_enq; i++){
        pkt = rte_pktmbuf_mtod(mbuf[i], const unsigned char *);
        length = mbuf[i]->data_len;
        /* if in tunneling mode, encrypt the whole packet; if in transport mode, encrypt only the payload */
        // TODO: add esp header
        SHA1(hash_out, pkt, length);
    }
    
    *nb_deq = nb_enq;
    *mbuf_out = mbuf;
    
    return 0;
}


int
sha_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = sha_init;
	stage->funcs->pipeline_stage_free = sha_free;
	stage->funcs->pipeline_stage_exec = sha_exec;

	return 0;
}