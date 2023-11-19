/*
 * DDoS
 *  - Key algorithm: entropy calculation
 */
#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include "ddos.h"
#include "../../runtime/meili_runtime.h"

static uint32_t 
count_bits_64(uint8_t *packet, 
              uint32_t p_len)
{
    uint64_t v, set_bits = 0;
    uint64_t *ptr = (uint64_t *) packet;
    uint64_t *end = (uint64_t *) (packet + p_len);

    while(end > ptr){
        v = *ptr++;
        v = v - ((v >> 1) & 0x5555555555555555);
        v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333);
        v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0F;
        set_bits += (v * 0x0101010101010101) >> (sizeof(v) - 1) * CHAR_BIT;
    }
    return set_bits;
}

static uint32_t
simple_entropy(uint32_t set_bits, 
               uint32_t total_bits)
{
    uint32_t ret;

    ret = (-set_bits) * (log2(set_bits) - log2(total_bits)) -
          (total_bits - set_bits) * (log2(total_bits - set_bits) - 
          log2(total_bits)) + log2(total_bits);

    return ret;
}


int
ddos_init(struct pipeline_stage *self)
{
    /* allocate space for pipeline state */
    self->state = (struct ddos_state *)malloc(sizeof(struct ddos_state));
    struct ddos_state *mystate = (struct ddos_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }

    memset(self->state, 0x00, sizeof(struct ddos_state));

    mystate->threshold = DDOS_DEFAULT_THRESH;
    mystate->p_window = DDOS_DEFAULT_WINDOW;
    mystate->p_set = calloc(mystate->p_window, sizeof(uint32_t));
    mystate->p_tot = calloc(mystate->p_window, sizeof(uint32_t));
    mystate->p_entropy = calloc(mystate->p_window, sizeof(uint32_t));
    mystate->head = 0;

    return 0;
}

int
ddos_free(struct pipeline_stage *self)
{
    struct ddos_state *mystate = (struct ddos_state *)self->state;
    free(mystate->p_set);
    free(mystate->p_tot);
    free(mystate->p_entropy);
    free(mystate);
    return 0;
}

int
ddos_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{

    char *payload = NULL;
    uint32_t p_len = 0;
    struct ddos_state *mystate = (struct ddos_state *)self->state;
    int flag = 0; // indicate whether there's an attack
    uint32_t bits;
    uint32_t set ;

    for(int i=0; i<nb_enq; i++){

        payload = rte_pktmbuf_mtod(mbuf[i], char *);
        p_len = mbuf[i]->data_len;
        bits = p_len * 8;
        set = count_bits_64((uint8_t *)payload, p_len);

        mystate->p_tot[mystate->head] = bits;
        mystate->p_set[mystate->head] = set;
        mystate->p_entropy[mystate->head] = simple_entropy(set, bits);
        mystate->packet_count++;

        if (mystate->packet_count >= mystate->p_window) {
            uint32_t k, total_set = 0, total_bits = 0, sum_entropy = 0;

            for (k = 0; k < mystate->p_window; k++) {
                total_set += mystate->p_set[k];
                total_bits += mystate->p_tot[k];
                sum_entropy += mystate->p_entropy[k];
            }

            uint32_t joint_entropy = simple_entropy(total_set, total_bits);
            if (mystate->threshold < (sum_entropy - joint_entropy)) {
                if (!flag) {
                    flag = 1;
                }
            }
        }
        mystate->head = (mystate->head + 1) % mystate->p_window;
    }

    *mbuf_out = mbuf;
    *nb_deq = nb_enq;
    return 0;
}


int
ddos_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = ddos_init;
	stage->funcs->pipeline_stage_free = ddos_free;
	stage->funcs->pipeline_stage_exec = ddos_exec;

	return 0;
}