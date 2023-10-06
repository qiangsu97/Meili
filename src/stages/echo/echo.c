/*
 * Echo
 * - empty pipeline stage
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "echo.h"
#include "../../runtime/meili_runtime.h"
#include "../../utils/rte_reorder/rte_reorder.h"



int
echo_init(struct pipeline_stage *self)
{
    /* allocate space for pipeline state */
    self->state = (struct echo_state *)malloc(sizeof(struct echo_state));
    struct echo_state *mystate = (struct echo_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    //memset(self->state, 0x00, sizeof(struct echo_state));

    mystate->content = PRINT_CONTENT;

    return 0;
}

int
echo_free(struct pipeline_stage *self)
{
    struct echo_state *mystate = (struct echo_state *)self->state;
    free(mystate);
    return 0;
}

int
echo_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    //struct echo_state *mystate = (struct echo_state *)self->state;
    //printf("%s",mystate->content);
    // for(int i=0;i<nb_enq;i++){
    //     mbuf_out[i] = mbuf[i];
    // }
    // struct timespec req, rem;

    // req.tv_sec = 0;
    // req.tv_nsec = nb_enq * 1;
    // if(self->worker_qid == 2){
    //     sleep(1);
    // }
    //debug
    // if(nb_enq>0 && *rte_reorder_seqn(mbuf[0]) == 0){
    //     *nb_deq = 0;
    //     return 0;
    // }

    *mbuf_out = mbuf;
    *nb_deq = nb_enq;

    //nanosleep(&req, &rem);
    
    return 0;
}


int
echo_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = echo_init;
	stage->funcs->pipeline_stage_free = echo_free;
	stage->funcs->pipeline_stage_exec = echo_exec;

	return 0;
}