#ifndef _INCLUDE_DDOS_H
#define _INCLUDE_DDOS_H

#include <stdint.h>
#include <rte_mbuf.h>

#define DDOS_DEFAULT_WINDOW 0xFFF
#define DDOS_DEFAULT_THRESH 1200

struct ddos_state {
    uint32_t threshold;
    uint32_t p_window;
    uint32_t *p_set;
    uint32_t *p_tot;
    uint32_t *p_entropy;
    uint32_t head;
    uint32_t packet_count;
};

// int ddos_init(struct pipeline_stage *self);
// int ddos_exec(struct pipeline_stage *self, struct rte_mbuf *mbuf);
// int ddos_free(struct pipeline_stage *self);

#endif /* _INCLUDE_DDOS_H */

