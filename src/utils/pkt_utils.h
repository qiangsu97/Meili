#ifndef _INCLUDE_PKT_UTILS_H
#define _INCLUDE_PKT_UTILS_H

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define MEILI_ETHER_ADDR_LEN RTE_ETHER_ADDR_LEN

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

#define SUPPORTS_IPV4_CHECKSUM_OFFLOAD (1 << 0)
#define SUPPORTS_TCP_CHECKSUM_OFFLOAD (1 << 1)
#define SUPPORTS_UDP_CHECKSUM_OFFLOAD (1 << 2)

#define PROTO_UDP 0x11
/* 69 = 0100 0101 */
#define IPV4_VERSION_IHL 69
#define IPV4_TTL 64
// #define UDP_SAMPLE_SRC_PORT 12345
// #define UDP_SAMPLE_DST_PORT 54321
// #define IPV4_SAMPLE_SRC (uint32_t) RTE_IPV4(10, 0, 0, 1)
// #define IPV4_SAMPLE_DST (uint32_t) RTE_IPV4(10, 0, 0, 2)
//#define SAMPLE_NIC_PORT 0

struct meili_pkt{
    uint8_t mac_sa[MEILI_ETHER_ADDR_LEN];
    uint8_t mac_da[MEILI_ETHER_ADDR_LEN];
    uint32_t sa;
    uint32_t da;
    uint16_t sp;
    uint16_t dp;
    uint8_t proto;
    
    uint32_t length;

    void *user_ptr;
};

#define MBUF_UDP_HDR(pkt) (struct rte_udp_hdr*) (rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
#define MBUF_TCP_HDR(pkt) (struct rte_tcp_hdr*) (rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))
#define MBUF_IPV4_HDR(pkt) (struct rte_ipv4_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr))
#define MBUF_ETH_HDR(pkt) (struct rte_ether_hdr*) rte_pktmbuf_mtod(pkt, uint8_t*);

struct rte_ether_hdr* pkt_ether_hdr(struct rte_mbuf* pkt);
struct rte_ipv4_hdr* pkt_ipv4_hdr(struct rte_mbuf* pkt);
struct rte_tcp_hdr* pkt_tcp_hdr(struct rte_mbuf* pkt);
struct rte_udp_hdr* pkt_udp_hdr(struct rte_mbuf* pkt);

int pkt_is_tcp(struct rte_mbuf* pkt);
int pkt_is_udp(struct rte_mbuf* pkt);
int pkt_is_ipv4(struct rte_mbuf* pkt);

int util_get_app_layer_payload(const unsigned char *packet, uint32_t *pay_len, int *rte_ptype);

int ipv4_str_to_uint32(char* ip_str, uint32_t* dest);

void pkt_set_checksums(struct rte_mbuf* pkt);

int add_udp_hdr(struct rte_mbuf *pkt, struct meili_pkt *info);
int fill_ether_hdr(struct rte_ether_hdr* eth_hdr, struct meili_pkt *info);
int fill_ipv4_hdr(struct rte_ipv4_hdr* iph, struct meili_pkt *info);
int fill_udp_hdr(struct rte_udp_hdr* udp_hdr, struct meili_pkt *info);

#endif