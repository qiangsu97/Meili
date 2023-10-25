#ifndef _INCLUDE_REGEX_BF_H
#define _INCLUDE_REGEX_BF_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "./stats.h"


struct regex_bf_state{
    regex_stats_t *regex_stats;
    int wait_on_dequeue;
};

#endif /* _INCLUDE_REGEX_BF_H */