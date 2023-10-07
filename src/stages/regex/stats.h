
#ifndef _INCLUDE_REGEX_STATS_H_
#define _INCLUDE_REGEX_STATS_H_

#include <stdint.h>

#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

typedef struct regex_custom_rxp_exp_matches {
	uint64_t score7;
	uint64_t score6;
	uint64_t score4;
	uint64_t score0;
	uint64_t false_positives;
} rxp_exp_match_stats_t;

typedef struct regex_custom_rxp {
	uint64_t rx_invalid;
	uint64_t rx_timeout;
	uint64_t rx_max_match;
	uint64_t rx_max_prefix;
	uint64_t rx_resource_limit;
	uint64_t rx_idle;
	uint64_t tx_busy;
	uint64_t tot_lat;
	uint64_t max_lat;
	uint64_t min_lat;
	/* queuing time before get processed by this stage */
	uint64_t tot_in_lat;

	/* Expected match results. */
	rxp_exp_match_stats_t exp;
	rxp_exp_match_stats_t max_exp;

} rxp_stats_t;

typedef struct regex_custom_hs {
	uint64_t tot_lat;
	uint64_t max_lat;
	uint64_t min_lat;
} hs_stats_t;

typedef struct regex_dev_stats {
	union {
		struct {
			uint64_t rx_valid;
			uint64_t rx_buf_match_cnt;
			uint64_t rx_total_match;
			void *custom; /* Stats defined by dev in use. */
		};
		/* Ensure multiple cores don't access the same cache line. */
		unsigned char cache_align[CACHE_LINE_SIZE];
	};
} regex_stats_t;

#endif /* _INCLUDE_REGEX_STATS_H_ */