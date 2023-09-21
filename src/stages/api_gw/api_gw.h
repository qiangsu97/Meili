#ifndef _INCLUDE_API_GW_H
#define _INCLUDE_API_GW_H

#include <stdint.h>
#include <rte_mbuf.h>

#define API_GW_RATE_LIMIT_NUM 8
#define API_GW_UP_LIMIT_SLOPE 64 * 100000
#define API_GW_DN_LIMIT_SLOPE 64 * 1000

typedef struct
{
	float up_limit_slope;
	float dn_limit_slope;
	float last_output;
	uint64_t start_time_tick;
	uint64_t last_time_tick;
} rate_limiter_inst_t;

struct api_gw_state{
    rate_limiter_inst_t *limiters;
};


#endif /* _INCLUDE_API_GW_H */

