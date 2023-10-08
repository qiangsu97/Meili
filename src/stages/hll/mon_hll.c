/*
 * Monitor_hll
 * Flow stat measurement and tracking
 * Key algorithms: 
 *  1) cardinality (distinct flow) couting based on hyperloglog      
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "../../runtime/meili_runtime.h"
#include "mon_hll.h"
#include "../lib/hll/hll.h"
#include "../../utils/log/log.h"
#include "../../utils/flow_utils.h"
#include "../../utils/pkt_utils.h"



int
monitor_hll_init(struct pipeline_stage *self)
{   
    int ret;
    /* allocate space for pipeline state */
    self->state = (struct monitor_hll_state *)malloc(sizeof(struct monitor_hll_state));
    struct monitor_hll_state *mystate = (struct monitor_hll_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct monitor_hll_state));

    mystate->hll = (struct HLL *)malloc(sizeof(struct HLL));
    ret = hll_init(mystate->hll, 16);
    if(ret){
        MEILI_LOG_ERR("Initalizing hyperloglog failed");
        return -EINVAL;
    }

    return 0;
}

int
monitor_hll_free(struct pipeline_stage *self)
{
    struct monitor_hll_state *mystate = (struct monitor_hll_state *)self->state;
    hll_destroy(mystate->hll);
    free(mystate->hll);
    free(mystate);
    return 0;
}


int
monitor_hll_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct monitor_hll_state *mystate = (struct monitor_hll_state *)self->state;
    int i, k;
    uint32_t flow_id;

    int ret;
    int flag = 1;

    struct ipv4_5tuple five_tuple;

    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;


    for(k=0; k<nb_enq; k++){

        ipv4_hdr =  MBUF_IPV4_HDR(mbuf[k]);
        udp_hdr = MBUF_UDP_HDR(mbuf[k]);

        /* starting from the next_proto_id field */
        five_tuple.proto = ipv4_hdr->next_proto_id;
        five_tuple.src_addr = ipv4_hdr->src_addr;
        five_tuple.dst_addr = ipv4_hdr->dst_addr;
        five_tuple.src_port = udp_hdr->src_port;
        five_tuple.dst_port = udp_hdr->dst_port;
        
        //debug
        // printf("src_addr=%x\n",five_tuple.src_addr);

        hll_add(mystate->hll, &five_tuple, sizeof(five_tuple));
        

    }
    hll_count(mystate->hll);

    *mbuf_out = mbuf;
    *nb_deq = nb_enq;
    
    return 0;
}


int
monitor_hll_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = monitor_hll_init;
	stage->funcs->pipeline_stage_free = monitor_hll_free;
	stage->funcs->pipeline_stage_exec = monitor_hll_exec;

	return 0;
}