/*
 * Monitor_CMS
 * Flow stat measurement and tracking
 * Key algorithms: 
 *  1) per-flow counting based on count-min sketch
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "../../runtime/meili_runtime.h"
#include "mon_cms.h"
#include "../../utils/cms/count-min-sketch.h"
#include "../../utils/log/log.h"
#include "../../utils/flow_utils.h"
#include "../../utils/pkt_utils.h"



int
monitor_cms_init(struct pipeline_stage *self)
{   
    int ret;
    /* allocate space for pipeline state */
    self->state = (struct monitor_cms_state *)malloc(sizeof(struct monitor_cms_state));
    struct monitor_cms_state *mystate = (struct monitor_cms_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct monitor_cms_state));
    /* initalize count min skect */
    mystate->cm_sketch = (uint64_t *)malloc(sizeof(uint64_t) * CM_ROW_NUM * CM_COL_NUM);
    if(!mystate->cm_sketch){
        return -ENOMEM;
    }
    memset(mystate->cm_sketch, 0x00, sizeof(uint64_t) * CM_ROW_NUM * CM_COL_NUM);
    return 0;
}

int
monitor_cms_free(struct pipeline_stage *self)
{
    struct monitor_cms_state *mystate = (struct monitor_cms_state *)self->state;
    free(mystate->cm_sketch);
    free(mystate);
    return 0;
}


#define POLY 0x8408
/*
 *                                     16   12   5
 * This is the CCITT CRC 16 polynomial X  + X  + X  + 1.
 * This works out to be 0x1021, but the way the algorithm works
 * lets us use 0x8408 (the reverse of the bit pattern).  The high
 * bit is always assumed to be set, thus we only use 16 bits to
 * represent the 17 bit value.
 */
static uint32_t
crc16(struct ipv4_5tuple *tuple, 
      uint16_t length)
{
    uint8_t i;
    uint32_t data, crc = 0xffff;

    uint8_t *data_p = (uint8_t *)tuple;

    if (length == 0)
        return (~crc);

    do {
        for (i=0, data=(unsigned int)0xff & *data_p++; i < 8; i++, data >>= 1) {
            if ((crc & 0x0001) ^ (data & 0x0001)) {
                crc = (crc >> 1) ^ POLY;
            } else {  
                crc >>= 1;
            }
        }
    } while (--length);

    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xff);

    return (crc);
}


static uint32_t 
get_flow_id(struct ipv4_5tuple *five_tuple)
{
    return crc16(five_tuple, sizeof(struct ipv4_5tuple));
}

int
monitor_cms_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct monitor_cms_state *mystate = (struct monitor_cms_state *)self->state;
    int i, k;
    uint32_t flow_id;

    int ret;
    int flag = 1;

    struct ipv4_5tuple five_tuple;

    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;

    //struct hllhdr *hdr = mystate->hll_state;


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

        flow_id = get_flow_id(&five_tuple);

        for (i = 0; i < CM_ROW_NUM; i++) {
            cm_sketch_read(mystate->cm_sketch, i, flow_id);
        }

        for (i = 0; i < CM_ROW_NUM; i++) {
            cm_sketch_update(mystate->cm_sketch, i, flow_id);
        }
        
    }


    *mbuf_out = mbuf;
    *nb_deq = nb_enq;
    
    return 0;
}


int
monitor_cms_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = monitor_cms_init;
	stage->funcs->pipeline_stage_free = monitor_cms_free;
	stage->funcs->pipeline_stage_exec = monitor_cms_exec;

	return 0;
}