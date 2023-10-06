/*
 * APP: L7 Load Balancer
 * - http parser
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include "app_l7_lb.h"
#include "../app_shared.h"
#include "../../runtime/meili_runtime.h"
#include "../../utils/log/log.h"


int
app_l7_lb_init(struct pipeline_stage *self)
{   

    int ret;
    /* allocate space for pipeline state */
    self->state = (struct app_state *)malloc(sizeof(struct app_state));
    struct app_state *mystate = (struct app_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct app_state));
    ret = app_init_substages(self, app_l7_lb_stage_map, APP_L7_LB_NB_STAGE);

    return ret;
}

int
app_l7_lb_free(struct pipeline_stage *self)
{
    struct app_state *mystate = (struct app_state *)self->state;
    app_free_substages(mystate);
    free(mystate);
    return 0;
}


int
app_l7_lb_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct app_state *mystate = (struct app_state *)self->state;
    struct pipeline_stage *sub_stage;

    sub_stage = mystate->stages[0];
    sub_stage->funcs->pipeline_stage_exec(sub_stage, mbuf, nb_enq, 
                                mbuf_out, nb_deq);   
    
    return 0;
}


int
app_l7_lb_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = app_l7_lb_init;
	stage->funcs->pipeline_stage_free = app_l7_lb_free;
	stage->funcs->pipeline_stage_exec = app_l7_lb_exec;

	return 0;
}

