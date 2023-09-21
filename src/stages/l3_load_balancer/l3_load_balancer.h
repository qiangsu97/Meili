#ifndef _INCLUDE_L3_LB_H
#define _INCLUDE_L3_LB_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "../../utils/flow_utils.h"
#include "../../utils/pkt_utils.h"

#define L3_LB_MAX_FT_SIZE 128
#define L3_LB_EXPIRE_CYCLES 32

#define L3_LB_IP_SERVER (uint32_t) RTE_IPV4(1, 1, 1, 1)
#define L3_LB_IP_CLIENT (uint32_t) RTE_IPV4(1, 1, 1, 2)
#define L3_LB_DPDK_PORT_SERVER 2
#define L3_LB_DPDK_PORT_CLIENT 5

#define L3_LB_NB_BACKEND 8

struct l3_lb_flow_stats{
    uint8_t dest;
    uint8_t s_addr_bytes[MEILI_ETHER_ADDR_LEN];
    uint64_t last_pkt_cycles;
    bool is_active;
};

/* Struct for backend servers */
struct l3_lb_backend_server {
    uint8_t d_addr_bytes[MEILI_ETHER_ADDR_LEN];
    uint32_t d_ip;
};

struct l3_lb_state{
    struct flow_table *ft;
    /* for cleaning up connections */
    uint16_t num_stored;
    uint64_t elapsed_cycles;
    //uint64_t last_cycles;
    uint32_t expire_time;

    /* backend server information */
    uint8_t server_count;
    struct l3_lb_backend_server *server;

    /* port and ip values of the server itself */
    uint32_t ip_lb_server;
    uint32_t ip_lb_client;
    uint8_t server_port;
    uint8_t client_port;

};

#endif /* _INCLUDE_L3_LB_H */

