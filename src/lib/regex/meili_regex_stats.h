#ifndef _MEILI_REGEX_STATS_H
#define _MEILI_REGEX_STATS_H

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

#endif /* _MEILI_REGEX_STATS_H */