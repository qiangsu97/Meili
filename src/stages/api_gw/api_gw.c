/*
 * API Gateway
 * - Rate limit and authentication
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "api_gw.h"
#include "../../pipeline.h"
#include "../../utils/sha/sha_utils.h"
#include "../../utils/rte_reorder/rte_reorder.h"



int
api_gw_init(struct pipeline_stage *self)
{
    uint64_t cycles;
    /* allocate space for pipeline state */
    self->state = (struct api_gw_state *)malloc(sizeof(struct api_gw_state));
    struct api_gw_state *mystate = (struct api_gw_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct api_gw_state));

    mystate->limiters = (rate_limiter_inst_t *)malloc(
        sizeof(rate_limiter_inst_t) * API_GW_RATE_LIMIT_NUM);

    for(int i=0; i<API_GW_RATE_LIMIT_NUM; i++){
        
        mystate->limiters[i].up_limit_slope = API_GW_UP_LIMIT_SLOPE;
        mystate->limiters[i].dn_limit_slope = API_GW_DN_LIMIT_SLOPE;
        mystate->limiters[i].last_output = 0;
        mystate->limiters[i].start_time_tick = cycles;


    }
    
    return 0;
}

int
api_gw_free(struct pipeline_stage *self)
{
    struct api_gw_state *mystate = (struct api_gw_state *)self->state;
    free(mystate);
    return 0;
}

static void
rate_lim(rate_limiter_inst_t *inst, 
         uint64_t current_time_tick, 
         float input)
{
	float err;
	float slope;
	float output;
	float dt;
	
	dt = (float)current_time_tick - (float)inst->last_time_tick;
	inst->last_time_tick = current_time_tick;
	
	if(dt == 0) {
		output = inst->last_output;
	} else {
		err = input - inst->last_output;
        if (dt != 0) { slope = err / dt; }

		if((slope > inst->up_limit_slope) && 
           (inst->up_limit_slope != 0)) {
			output = dt * inst->up_limit_slope + inst->last_output;
		} else if((slope < inst->dn_limit_slope) && 
                  (inst->dn_limit_slope != 0)) {
			output = dt * inst->dn_limit_slope + inst->last_output;
		} else {
			output = input;
		}
	}
	
	inst->last_output = output;
}

/* TODO:
 * This is a temporary implementation of API gateway. API gateway should be a L7 
 * application, but here we use L3 to simulate it, without socket processing context like read()/write().
 */
int
api_gw_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct api_gw_state *mystate = (struct api_gw_state *)self->state;
    char hash_out[SHA_HASH_SIZE + 1];
    const unsigned char *pkt;
    int length = 0;
    rate_limiter_inst_t *instance;
    uint64_t time_tick_now;
    unsigned int input_value;

    /* we assume that api calls are in payload part */
    time_tick_now = rte_rdtsc();
    for(int i=0; i<nb_enq; i++){
        /* if we are to operate on the payload part, prefetch the packet */
        pkt = rte_pktmbuf_mtod(mbuf[i], void *);
        rte_prefetch0(pkt);

        length = mbuf[i]->data_len;
        SHA1(hash_out, pkt, length);

        input_value = *rte_reorder_seqn(mbuf[i]);
        instance = &mystate->limiters[input_value % API_GW_RATE_LIMIT_NUM];
        rate_lim(instance, time_tick_now - instance->start_time_tick, 
                input_value);
    }
    
    

    *mbuf_out = mbuf;
    *nb_deq = nb_enq;
    
    return 0;
}


int
api_gw_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = api_gw_init;
	stage->funcs->pipeline_stage_free = api_gw_free;
	stage->funcs->pipeline_stage_exec = api_gw_exec;

	return 0;
}