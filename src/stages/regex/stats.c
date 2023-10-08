#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#include "stats.h"
// #include "../../utils/conf.h"
#include "../../utils/utils.h"

// int
// stats_init(rb_conf *run_conf)
// {
// 	const int nq = run_conf->cores;
// 	rb_stats_t *stats;
// 	int i, j;

// 	struct regex_custom_rxp *custom;

// 	run_conf->input_pkt_stats = rte_zmalloc(NULL, sizeof(pkt_stats_t), 0);
// 	if (!run_conf->input_pkt_stats)
// 		goto err_input_pkt_stats;

// 	stats = rte_malloc(NULL, sizeof(*stats), 0);
// 	if (!stats)
// 		goto err_stats;

// 	stats->rm_stats = rte_zmalloc(NULL, sizeof(run_mode_stats_t) * nq, 128);
// 	if (!stats->rm_stats)
// 		goto err_rm_stats;

// 	stats->regex_stats = rte_zmalloc(NULL, sizeof(regex_stats_t) * nq, 64);
// 	if (!stats->regex_stats)
// 		goto err_regex_stats;

// 	for (i = 0; i < nq; i++) {
// 		regex_stats_t *reg = &stats->regex_stats[i];

// 		if (run_conf->regex_dev_type == REGEX_DEV_DPDK_REGEX ||
// 		    run_conf->regex_dev_type == REGEX_DEV_DOCA_REGEX) {
// 			reg->custom = rte_zmalloc(NULL, sizeof(rxp_stats_t), 0);
// 			if (!reg->custom){
// 				goto err_custom;
// 			}
// 			custom = (struct regex_custom_rxp *)reg->custom;
// 			custom->min_lat = UINT64_MAX;
// 			custom->max_lat = 0;
// 		} else if (run_conf->regex_dev_type == REGEX_DEV_HYPERSCAN) {
// 			reg->custom = rte_zmalloc(NULL, sizeof(hs_stats_t), 0);
// 			if (!reg->custom){
// 				goto err_custom;
// 			}
// 			// reg->custom->min_lat = UINT64_MAX;
// 			// reg->custom->max_lat = 0;
// 		}
// 	}

// 	run_conf->stats = stats;

// 	/* open a log file if neccessary */
// 	#ifdef ONLY_SPLIT_THROUGHPUT
// 	log_fp = fopen("throughput_log_2.txt", "w+");
// 	if(!log_fp){
// 		MEILI_LOG_ERR("Open log file failed");
// 		return -EINVAL;
// 	}
// 	#endif

// 	return 0;

// err_custom:
// 	for (j = 0; j < i; j++)
// 		rte_free(stats->regex_stats[j].custom);
// 	rte_free(stats->regex_stats);
// err_regex_stats:
// 	rte_free(stats->rm_stats);
// err_rm_stats:
// 	rte_free(stats);
// err_stats:
// 	rte_free(run_conf->input_pkt_stats);
// err_input_pkt_stats:
// 	MEILI_LOG_ERR("Memory failure when allocating stats.");

// 	return -ENOMEM;
// }

// static void
// stats_print_custom_rxp_deprecated(rb_stats_t *stats, int num_queues, bool print_exp_matches, enum meili_regex_dev dev,
// 		       uint32_t batches, bool lat_mode)
// {
// 	regex_stats_t *regex_stats = stats->regex_stats;
// 	run_mode_stats_t *run_stats = stats->rm_stats;
// 	rxp_stats_t *rxp_stats;
// 	rxp_stats_t rxp_total;
// 	uint64_t total_bufs;
// 	int i;

// 	int nb_samples = 0;

// 	memset(&rxp_total, 0, sizeof(rxp_total));
// 	rxp_total.min_lat = UINT64_MAX;
// 	total_bufs = 0;

// 	for (i = 0; i < num_queues; i++) {
// 		rxp_stats = (rxp_stats_t *)regex_stats[i].custom;

// 		/* sort time_diff_sample */
// 		qsort(rxp_stats->time_diff_sample,NUMBER_OF_SAMPLE,sizeof(uint64_t),cmpfunc);

// 		total_bufs += run_stats->tx_buf_cnt;

// 		rxp_total.rx_invalid += rxp_stats->rx_invalid;
// 		rxp_total.rx_timeout += rxp_stats->rx_timeout;
// 		rxp_total.rx_max_match += rxp_stats->rx_max_match;
// 		rxp_total.rx_max_prefix += rxp_stats->rx_max_prefix;
// 		rxp_total.rx_resource_limit += rxp_stats->rx_resource_limit;
// 		rxp_total.tx_busy += rxp_stats->tx_busy;
// 		rxp_total.rx_idle += rxp_stats->rx_idle;
// 		rxp_total.tot_lat += rxp_stats->tot_lat;
// 		if (rxp_stats->min_lat < rxp_total.min_lat)
// 			rxp_total.min_lat = rxp_stats->min_lat;
// 		if (rxp_stats->max_lat > rxp_total.max_lat)
// 			rxp_total.max_lat = rxp_stats->max_lat;

// 		rxp_total.exp.score7 += rxp_stats->exp.score7;
// 		rxp_total.exp.score6 += rxp_stats->exp.score6;
// 		rxp_total.exp.score4 += rxp_stats->exp.score4;
// 		rxp_total.exp.score0 += rxp_stats->exp.score0;
// 		rxp_total.exp.false_positives += rxp_stats->exp.false_positives;

// 		rxp_total.max_exp.score7 += rxp_stats->max_exp.score7;
// 		rxp_total.max_exp.score6 += rxp_stats->max_exp.score6;
// 		rxp_total.max_exp.score4 += rxp_stats->max_exp.score4;
// 		rxp_total.max_exp.score0 += rxp_stats->max_exp.score0;
// 		rxp_total.max_exp.false_positives += rxp_stats->max_exp.false_positives;
// 	}

// 	/* Get per core average for some of the total stats. */
// 	rxp_total.tx_busy /= num_queues;
// 	rxp_total.rx_idle /= num_queues;
// 	rxp_total.tot_lat = total_bufs ? rxp_total.tot_lat / total_bufs : 0;
// 	if (rxp_total.min_lat == UINT64_MAX)
// 		rxp_total.min_lat = 0;

// 	if (dev == REGEX_DEV_DPDK_REGEX)
// 		stats_print_banner("DPDK REGEX STATS", STATS_BANNER_LEN);
// 	else
// 		stats_print_banner("DOCA REGEX STATS", STATS_BANNER_LEN);
// 	fprintf(stdout,
// 		"|%*s|\n"
// 		"| INVALID RESPONSES:                %-42lu |\n"
// 		"| - TIMEOUT:                        %-42lu |\n"
// 		"| - MAX MATCHES:                    %-42lu |\n"
// 		"| - MAX PREFIXES:                   %-42lu |\n"
// 		"| - RESOURCE LIMIT:                 %-42lu |\n"
// 		"|%*s|\n"
// 		"| TX BUSY - AVE PER CORE (secs):    %-42.4f |\n"
// 		"|%*s|\n"
// 		"| RX IDLE - AVE PER CORE (secs):    %-42.4f |\n"
// 		"|%*s|\n" STATS_BORDER "\n",
// 		78, "", rxp_total.rx_invalid, rxp_total.rx_timeout, rxp_total.rx_max_match, rxp_total.rx_max_prefix,
// 		rxp_total.rx_resource_limit, 78, "", (double)rxp_total.tx_busy / rte_get_timer_hz(), 78, "",
// 		(double)rxp_total.rx_idle / rte_get_timer_hz(), 78, "");


// 	if (print_exp_matches) {
// 		fprintf(stdout, "\nExpected Match Report:\n");
// 		fprintf(stdout, "Info: Score_table(7:0) = {%lu, %lu, 0, %lu, 0, 0, 0, %lu}, false_positives = %lu\n",
// 			rxp_total.exp.score7, rxp_total.exp.score6, rxp_total.exp.score4, rxp_total.exp.score0,
// 			rxp_total.exp.false_positives);
// 		fprintf(stdout,
// 			"Info: Score_table_max(7:0) = {%lu, %lu, 0, %lu, 0, 0, 0, %lu}, false_positives = %lu\n\n",
// 			rxp_total.max_exp.score7, rxp_total.max_exp.score6, rxp_total.max_exp.score4,
// 			rxp_total.max_exp.score0, rxp_total.max_exp.false_positives);
// 	}
// }

// static void
// stats_print_custom_hs(rb_stats_t *stats, int num_queues, uint32_t batches)
// {
// 	regex_stats_t *regex_stats = stats->regex_stats;
// 	run_mode_stats_t *run_stats = stats->rm_stats;
// 	hs_stats_t *hs_stats;
// 	hs_stats_t hs_total;
// 	uint64_t total_bufs;
// 	int i;

// 	memset(&hs_total, 0, sizeof(hs_total));
// 	hs_total.min_lat = UINT64_MAX;
// 	total_bufs = 0;

// 	for (i = 0; i < num_queues; i++) {
// 		hs_stats = (hs_stats_t *)regex_stats[i].custom;
// 		total_bufs += run_stats->tx_buf_cnt;

// 		hs_total.tot_lat += hs_stats->tot_lat;
// 		if (hs_stats->min_lat < hs_total.min_lat)
// 			hs_total.min_lat = hs_stats->min_lat;
// 		if (hs_stats->max_lat > hs_total.max_lat)
// 			hs_total.max_lat = hs_stats->max_lat;
// 	}

// 	hs_total.tot_lat = total_bufs ? hs_total.tot_lat / total_bufs : 0;
// 	if (hs_total.min_lat == UINT64_MAX)
// 		hs_total.min_lat = 0;

// 	stats_print_banner("HYPERSCAN STATS", STATS_BANNER_LEN);
// 	fprintf(stdout,
// 		"|%*s|\n"
// 		"| PER PACKET LATENCY - BATCH SIZE:  %-42u |\n"
// 		"| - MAX LATENCY (usecs):            %-42.4f |\n"
// 		"| - MIN LATENCY (usecs):            %-42.4f |\n"
// 		"| - AVERAGE LATENCY (usecs):        %-42.4f |\n"
// 		"|%*s|\n" STATS_BORDER "\n",
// 		78, "", batches, (double)hs_total.max_lat / rte_get_timer_hz() * 1000000.0,
// 		(double)hs_total.min_lat / rte_get_timer_hz() * 1000000.0,
// 		(double)hs_total.tot_lat / rte_get_timer_hz() * 1000000.0, 78, "");
// }

// static void
// stats_print_custom(rb_conf *run_conf, rb_stats_t *stats, int num_queues)
// {
// 	if (run_conf->regex_dev_type == REGEX_DEV_DPDK_REGEX || run_conf->regex_dev_type == REGEX_DEV_DOCA_REGEX)
// 		stats_print_custom_rxp(stats, num_queues, run_conf->input_exp_matches, run_conf->regex_dev_type,
// 				       run_conf->input_batches, run_conf->latency_mode);
// 	else if (run_conf->regex_dev_type == REGEX_DEV_HYPERSCAN)
// 		stats_print_custom_hs(stats, num_queues, run_conf->input_batches);
// }


// static void
// stats_print_common_stats(rb_stats_t *stats, int num_queues, double time)
// {
// 	regex_stats_t *regex_stats = stats->regex_stats;
// 	run_mode_stats_t *rm_stats = stats->rm_stats;
// 	run_mode_stats_t total_rm;
// 	regex_stats_t total_regex;
// 	pkt_stats_t *pkt_stats;
// 	pkt_stats_t *total_pkt;
// 	double ave_length;
// 	double byte_match;
// 	double reg_perf;
// 	double reg_rate;
// 	double rx_perf;
// 	double rx_rate;
// 	int i;

// 	memset(&total_rm, 0, sizeof(total_rm));
// 	memset(&total_regex, 0, sizeof(total_regex));
// 	total_pkt = &total_rm.pkt_stats;

// 	for (i = 0; i < num_queues; i++) {
// 		pkt_stats = &rm_stats[i].pkt_stats;

// 		total_rm.rx_buf_cnt += rm_stats[i].rx_buf_cnt;
// 		total_rm.rx_buf_bytes += rm_stats[i].rx_buf_bytes;
// 		total_rm.tx_buf_cnt += rm_stats[i].tx_buf_cnt;
// 		total_rm.tx_buf_bytes += rm_stats[i].tx_buf_bytes;
// 		total_rm.tx_batch_cnt += rm_stats[i].tx_batch_cnt;

// 		total_regex.rx_valid += regex_stats[i].rx_valid;
// 		total_regex.rx_buf_match_cnt += regex_stats[i].rx_buf_match_cnt;
// 		total_regex.rx_total_match += regex_stats[i].rx_total_match;

// 		total_pkt->valid_pkts += pkt_stats->valid_pkts;
// 		total_pkt->unsupported_pkts += pkt_stats->unsupported_pkts;
// 		total_pkt->no_payload += pkt_stats->no_payload;
// 		total_pkt->invalid_pkt += pkt_stats->invalid_pkt;
// 		total_pkt->thres_drop += pkt_stats->thres_drop;
// 		total_pkt->vlan += pkt_stats->vlan;
// 		total_pkt->qnq += pkt_stats->qnq;
// 		total_pkt->ipv4 += pkt_stats->ipv4;
// 		total_pkt->ipv6 += pkt_stats->ipv6;
// 		total_pkt->tcp += pkt_stats->tcp;
// 		total_pkt->udp += pkt_stats->udp;
// 	}

// 	ave_length = total_rm.tx_buf_cnt ? (double)total_rm.tx_buf_bytes / total_rm.tx_buf_cnt : 0;
// 	byte_match = total_regex.rx_total_match ? (double)total_rm.tx_buf_bytes / total_regex.rx_total_match : 0;
// 	reg_perf = ((total_rm.tx_buf_bytes * 8) / time) / GIGA;
// 	rx_perf = ((total_rm.rx_buf_bytes * 8) / time) / GIGA;
// 	reg_rate = (total_rm.tx_buf_cnt / time) / MEGA;
// 	rx_rate = (total_rm.rx_buf_cnt / time) / MEGA;

// 	stats_print_banner("RUN OVERVIEW", STATS_BANNER_LEN);
// 	fprintf(stdout,
// 		"|%*s|\n"
// 		"| - RAW DATA PROCESSING -%*s|\n"
// 		"|%*s|\n"
// 		"| TOTAL PKTS:     %-20lu  "
// 		"  QNQ:            %-20lu |\n"
// 		"| TOTAL BYTES     %-20lu  "
// 		"  VLAN:           %-20lu |\n"
// 		"| VALID PKTS:     %-20lu  "
// 		"  IPV4:           %-20lu |\n"
// 		"| UNSUPPORTED:    %-20lu  "
// 		"  IPV6:           %-20lu |\n"
// 		"| NO PAYLOAD:     %-20lu  "
// 		"  TCP:            %-20lu |\n"
// 		"| UNDER THRES:    %-20lu  "
// 		"  UDP:            %-20lu |\n"
// 		"|%*s|\n",
// 		78, "", 54, "", 78, "", total_rm.rx_buf_cnt, total_pkt->qnq, total_rm.rx_buf_bytes, total_pkt->vlan,
// 		total_pkt->valid_pkts, total_pkt->ipv4, total_pkt->unsupported_pkts, total_pkt->ipv6,
// 		total_pkt->no_payload, total_pkt->tcp, total_pkt->thres_drop, total_pkt->udp, 78, "");

// 	/* Only report throughput stats if duration is long enough. */
// 	if (time > 0.1)
// 		fprintf(stdout,
// 			"| PACKET PROCESSING RATE (Mpps):    %-42.4f |\n"
// 			"| PACKET PROCESSING PERF (Gb/s):    %-42.4f |\n",
// 			rx_rate, rx_perf);
// 	else
// 		fprintf(stdout, "| PACKET PROCESSING RATE (Mpps):    N/A (run time must be > 0.1 secs)          |\n"
// 				"| PACKET PROCESSING PERF (Gb/s):    N/A (run time must be > 0.1 secs)          |\n");

// 	fprintf(stdout,
// 		"|%*s|\n"
// 		"|%*s|\n"
// 		"| - REGEX PROCESSING -   %*s|\n"
// 		"|%*s|\n"
// 		"| TOTAL REGEX BUFFERS:              %-42lu |\n"
// 		"| TOTAL REGEX BYTES:                %-42lu |\n"
// 		"| TOTAL REGEX BATCHES:              %-42lu |\n"
// 		"| VALID REGEX RESPONSES:            %-42lu |\n"
// 		"| REGEX RESPONSES WITH MATCHES:     %-42lu |\n"
// 		"| TOTAL REGEX MATCHES:              %-42lu |\n"
// 		"|%*s|\n"
// 		"| AVERAGE REGEX BUFFER LENGTH:      %-42.2f |\n"
// 		"| MATCH TO BYTE RATIO:              %-42.2f |\n"
// 		"|%*s|\n",
// 		78, "", 78, "", 54, "", 78, "", total_rm.tx_buf_cnt, total_rm.tx_buf_bytes, total_rm.tx_batch_cnt,
// 		total_regex.rx_valid, total_regex.rx_buf_match_cnt, total_regex.rx_total_match, 78, "", ave_length,
// 		byte_match, 78, "");

// 	/* Only report throughput stats if duration is long enough. */
// 	if (time > 0.1)
// 		fprintf(stdout,
// 			"| REGEX BUFFER RATE (Mbps):         %-42.4f |\n"
// 			"| REGEX PERFORMANCE (Gb/s):         %-42.4f |\n"
// 			"|%*s|\n"
// 			"| MAX REGEX BUFFER RATE (Mbps):     %-42.4f |\n"
// 			"| MAX REGEX PERFORMANCE (Gb/s):     %-42.4f |\n",
// 			reg_rate, reg_perf, 78, "", max_split_rate, max_split_perf);
// 	else
// 		fprintf(stdout,
// 			"| REGEX BUFFER RATE (Mbps):         "
// 			"N/A (run time must be > 0.1 secs)          |\n"
// 			"| REGEX PERFORMANCE (Gb/s):         "
// 			"N/A (run time must be > 0.1 secs)          |\n"
// 			"|%*s|\n"
// 			"| MAX REGEX BUFFER RATE (Mbps):     "
// 			"N/A (run time must be > 0.1 secs)          |\n"
// 			"| MAX REGEX PERFORMANCE (Gb/s):     "
// 			"N/A (run time must be > 0.1 secs)          |\n",
// 			78, "");

// 	fprintf(stdout,
// 		"|%*s|\n"
// 		"| TOTAL DURATION (secs):            %-42.4f |\n"
// 		"|%*s|\n" STATS_BORDER "\n",
// 		78, "", time, 78, "");
// }

// void
// regex_stats_clean(rb_conf *run_conf)
// {
// 	rb_stats_t *stats = run_conf->stats;
// 	uint32_t i;

// 	for (i = 0; i < run_conf->cores; i++)
// 		rte_free(stats->regex_stats[i].custom);

// 	rte_free(stats->rm_stats);
// 	rte_free(stats->regex_stats);
// 	rte_free(stats);
// 	rte_free(run_conf->input_pkt_stats);
// }