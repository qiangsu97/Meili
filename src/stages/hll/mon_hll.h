#ifndef _INCLUDE_MON_HLL_H
#define _INCLUDE_MON_HLL_H

#include <stdint.h>
#include <rte_mbuf.h>

#include "../lib/hll/hll.h"

struct monitor_hll_state{
    struct HLL *hll;
};

#endif /* _INCLUDE_MON_HLL_H */