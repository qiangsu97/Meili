/*
 * APP: IPsec Gateway
 * - DDoS detection and deep packet inspection
 * -> [DDoS] -> [Regex]
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include "app_ipsec_gw.h"
#include "../app_shared.h"
#include "../../runtime/meili_runtime.h"

int
app_ipsec_gw_init(struct pipeline_stage *self)
{   

    int ret;
    /* allocate space for pipeline state */
    self->state = (struct app_state *)malloc(sizeof(struct app_state));
    struct app_state *mystate = (struct app_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct app_state));
    ret = app_init_substages(self, app_ipsec_gw_stage_map, APP_IPSEC_GW_STAGE);
    
    return ret;
}

int
app_ipsec_gw_free(struct pipeline_stage *self)
{
    struct app_state *mystate = (struct app_state *)self->state;
    app_free_substages(mystate);
    free(mystate);
    return 0;
}


int
app_ipsec_gw_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct app_state *mystate = (struct app_state *)self->state;
    struct pipeline_stage *sub_stage;
    
    /* preserve the original value of mbuf_out, which is a valid rte_mbuf* array */
    struct rte_mbuf **mbuf_temp = *mbuf_out;

    /* regex and aes conduct out-of-order processing */
    /* DDoS */
    /* packet trans */
    sub_stage = mystate->stages[0];
    sub_stage->funcs->pipeline_stage_exec(sub_stage, mbuf, nb_enq, 
                            &mbuf, nb_deq); 
    /* *mbuf_out = mbuf */  

    /* regex */
    /* Regex, in this stage, only use *(&mbuf_temp) */
    sub_stage = mystate->stages[1];
    sub_stage->funcs->pipeline_stage_exec(sub_stage, mbuf, *nb_deq, 
                        &mbuf_temp, nb_deq);                    
    /* mbuf_temp is original *mbuf_out, dequeue packets are in it */

    /* SHA */
    sub_stage = mystate->stages[2];     
    sub_stage->funcs->pipeline_stage_exec(sub_stage, mbuf_temp, *nb_deq, 
                    &mbuf_temp, nb_deq);
    
    *mbuf_out = mbuf_temp; /* retrieve the original output array value */
    
    return 0;
}


int
app_ipsec_gw_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = app_ipsec_gw_init;
	stage->funcs->pipeline_stage_free = app_ipsec_gw_free;
	stage->funcs->pipeline_stage_exec = app_ipsec_gw_exec;

	return 0;
}