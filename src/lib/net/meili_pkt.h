#ifndef _MEILI_PKT_H
#define _MEILI_PKT_H

#include "./meili_net.h"

#ifdef MEILI_PKT_DPDK_BACKEND

#define MEILI_ETHER_ADDR_LEN RTE_ETHER_ADDR_LEN

#define IP_PROTO_TCP 0x06
#define IP_PROTO_UDP 0x11
#define IPV4_VERSION_IHL 69
#define IPV4_TTL 64


typedef struct rte_mbuf meili_pkt; 
typedef struct rte_ether_hdr meili_ether_hdr; 
typedef struct rte_ipv4_hdr meili_ipv4_hdr; 
typedef struct rte_tcp_hdr meili_tcp_hdr;
typedef struct rte_udp_hdr meili_udp_hdr;


/* pkt to char buf */
#define meili_pkt_payload(x) rte_pktmbuf_mtod(x, const unsigned char *)

/* pkt length */
#define meili_pkt_payload_len(x)    x->data_len

/* pkt hdrs */
#define MEILI_UDP_HDR(pkt)  (meili_udp_hdr*) (rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
#define MEILI_TCP_HDR(pkt)  (meili_tcp_hdr*) (rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
#define MEILI_IPV4_HDR(pkt) (meili_ipv4_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr))
#define MEILI_ETH_HDR(pkt)  (meili_ether_hdr*) (rte_pktmbuf_mtod(pkt, uint8_t*))



#else      
typedef struct _meili_pkt{
    int place_holder;
}meili_pkt;  
#endif

#endif /* _MEILI_PKT_H */