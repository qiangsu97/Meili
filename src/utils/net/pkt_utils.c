#include "pkt_utils.h"
#include "port_utils.h"

#include <rte_branch_prediction.h>
#include <rte_mbuf.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <rte_memcpy.h>
#include <rte_mempool.h>



static inline int
util_parse_udp(const unsigned char *packet __rte_unused, uint32_t *pay_len, int *rte_ptype)
{
	/* UDP has constant size. */
	uint16_t offset = sizeof(struct rte_udp_hdr);

	if (*pay_len < offset)
		return -EINVAL;

	*pay_len = *pay_len - offset;
	*rte_ptype |= RTE_PTYPE_L4_UDP;

	return offset;
}

static inline int
util_parse_tcp(const unsigned char *packet, uint32_t *pay_len, int *rte_ptype)
{
	const struct rte_tcp_hdr *tcp = (const struct rte_tcp_hdr *)packet;
	uint16_t offset = 0;

	offset = (tcp->data_off & 0xf0) >> 2;
	if (*pay_len < offset)
		return -EINVAL;

	*pay_len = *pay_len - offset;
	*rte_ptype |= RTE_PTYPE_L4_TCP;

	return offset;
}

static inline int
util_parse_ipv6(const unsigned char *packet, uint32_t *pay_len, int *rte_ptype)
{
	const struct rte_ipv6_hdr *ipv6 = (const struct rte_ipv6_hdr *)packet;
	uint16_t offset;
	int ret;

	/* Currently not supporting extension headers. */
	offset = sizeof(struct rte_ipv6_hdr);

	/* In IPv6 payload does not include the IP header. */
	*pay_len = rte_be_to_cpu_16(ipv6->payload_len);
	*rte_ptype |= RTE_PTYPE_L3_IPV6;

	switch (ipv6->proto) {
	case IPPROTO_TCP:
		ret = util_parse_tcp(&packet[offset], pay_len, rte_ptype);
		if (ret < 0)
			return ret;
		return offset += ret;
	case IPPROTO_UDP:
		ret = util_parse_udp(&packet[offset], pay_len, rte_ptype);
		if (ret < 0)
			return ret;
		return offset += ret;
	default:
		return -EINVAL;
	}
}

static inline int
util_parse_ipv4(const unsigned char *packet, uint32_t *pay_len, int *rte_ptype)
{
	const struct rte_ipv4_hdr *ipv4 = (const struct rte_ipv4_hdr *)packet;
	uint16_t offset;
	int ret;

	offset = ipv4->version_ihl & 0xf;
	if (offset < 5)
		return -EINVAL;

	offset *= 4;

	/* In IPv4 total length includes the IP header. */
	*pay_len = rte_be_to_cpu_16(ipv4->total_length) - offset;
	*rte_ptype |= RTE_PTYPE_L3_IPV4;

	switch (ipv4->next_proto_id) {
	case IPPROTO_TCP:
		ret = util_parse_tcp(&packet[offset], pay_len, rte_ptype);
		if (ret < 0)
			return ret;
		return offset += ret;

	case IPPROTO_UDP:
		*rte_ptype |= RTE_PTYPE_L3_IPV4;
		ret = util_parse_udp(&packet[offset], pay_len, rte_ptype);
		if (ret < 0)
			return ret;
		return offset += ret;

	default:
		return -EINVAL;
	}
}

static inline uint16_t
util_parse_vlan(const unsigned char *packet, uint16_t *proto, int *rte_ptype)
{
	const struct rte_vlan_hdr *vlan = (const struct rte_vlan_hdr *)packet;
	uint16_t offset;

	offset = sizeof(struct rte_vlan_hdr);
	*proto = vlan->eth_proto;

	/* Allow qnq with max of 2. */
	if (*proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
		offset += sizeof(struct rte_vlan_hdr);
		*proto = vlan->eth_proto;
		*rte_ptype |= RTE_PTYPE_L2_ETHER_QINQ;
	} else {
		*rte_ptype |= RTE_PTYPE_L2_ETHER_VLAN;
	}

	return offset;
}

/* Parse layers 2-4 into mask and return payload pointer along with length. */
int
util_get_app_layer_payload(const unsigned char *packet, uint32_t *pay_len, int *rte_ptype)
{
	const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)packet;
	uint16_t ether_type;
	uint16_t offset;
	int ret;

	ether_type = eth->ether_type;
	offset = sizeof(struct rte_ether_hdr);

	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
		offset += util_parse_vlan(&packet[offset], &ether_type, rte_ptype);

	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		ret = util_parse_ipv4(&packet[offset], pay_len, rte_ptype);
		if (ret < 0)
			return ret;
		return offset += ret;
	} else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		ret = util_parse_ipv6(&packet[offset], pay_len, rte_ptype);
		if (ret < 0)
			return ret;
		return offset += ret;
	} else {
		return -EINVAL;
	}
}



int
onvm_pkt_set_mac_addr(struct rte_mbuf* pkt, unsigned src_port_id, unsigned dst_port_id, struct port_info* ports) {
        struct rte_ether_hdr* eth;

        if (unlikely(pkt == NULL)) {  // We do not expect to swap macs for empty packets
                return -1;
        }

        /*
         * Get the ethernet header from the pkt
         */
        eth = pkt_ether_hdr(pkt);

        /*
         * Get the MAC addresses of the src and destination NIC ports,
         * and set the ethernet header's fields to them.
         */
        rte_ether_addr_copy(&ports->mac[src_port_id], &eth->s_addr);
        rte_ether_addr_copy(&ports->mac[dst_port_id], &eth->d_addr);

        return 0;
}

int
onvm_pkt_swap_src_mac_addr(struct rte_mbuf* pkt, unsigned dst_port_id, struct port_info* ports) {
        struct rte_ether_hdr* eth;

        if (unlikely(pkt == NULL)) {  // We do not expect to swap macs for empty packets
                return -1;
        }

        /*
         * Get the ethernet header from the pkt
         */
        eth = pkt_ether_hdr(pkt);

        /*
         * Copy the source mac address to the destination field.
         */
        rte_ether_addr_copy(&eth->s_addr, &eth->d_addr);

        /*
         * Get the mac address of the specified destination port id
         * and set the source field to it.
         */
        rte_ether_addr_copy(&ports->mac[dst_port_id], &eth->s_addr);

        return 0;
}

int
onvm_pkt_swap_dst_mac_addr(struct rte_mbuf* pkt, unsigned src_port_id, struct port_info* ports) {
        struct rte_ether_hdr* eth;

        if (unlikely(pkt == NULL)) {  // We do not expect to swap macs for empty packets
                return -1;
        }

        /*
         * Get the ethernet header from the pkt
         */
        eth = pkt_ether_hdr(pkt);

        /*
         * Copy the destination mac address to the source field.
         */
        rte_ether_addr_copy(&eth->d_addr, &eth->s_addr);

        /*
         * Get the mac address of specified source port id
         * and set the destination field to it.
         */
        rte_ether_addr_copy(&ports->mac[src_port_id], &eth->d_addr);

        return 0;
}

struct rte_ether_hdr*
pkt_ether_hdr(struct rte_mbuf* pkt) {
        if (unlikely(pkt == NULL)) {
                return NULL;
        }
        return rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
}

struct rte_tcp_hdr*
pkt_tcp_hdr(struct rte_mbuf* pkt) {
        struct rte_ipv4_hdr* ipv4 = pkt_ipv4_hdr(pkt);

        if (unlikely(
                ipv4 ==
                NULL)) {  // Since we aren't dealing with IPv6 packets for now, we can ignore anything that isn't IPv4
                return NULL;
        }

        if (ipv4->next_proto_id != IP_PROTOCOL_TCP) {
                return NULL;
        }

        uint8_t* pkt_data =
                rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
        return (struct rte_tcp_hdr*)pkt_data;
}

struct rte_udp_hdr*
pkt_udp_hdr(struct rte_mbuf* pkt) {
        struct rte_ipv4_hdr* ipv4 = pkt_ipv4_hdr(pkt);

        if (unlikely(
                ipv4 ==
                NULL)) {  // Since we aren't dealing with IPv6 packets for now, we can ignore anything that isn't IPv4
                return NULL;
        }

        if (ipv4->next_proto_id != IP_PROTOCOL_UDP) {
                return NULL;
        }

        uint8_t* pkt_data =
                rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr);
        return (struct rte_udp_hdr*)pkt_data;
}

struct rte_ipv4_hdr*
pkt_ipv4_hdr(struct rte_mbuf* pkt) {
        struct rte_ipv4_hdr* ipv4 =
                (struct rte_ipv4_hdr*)(rte_pktmbuf_mtod(pkt, uint8_t*) + sizeof(struct rte_ether_hdr));

        /* In an IP packet, the first 4 bits determine the version.
         * The next 4 bits are called the Internet Header Length, or IHL.
         * DPDK's ipv4_hdr struct combines both the version and the IHL into one uint8_t.
         */
        uint8_t version = (ipv4->version_ihl >> 4) & 0b1111;
        if (unlikely(version != 4)) {
                return NULL;
        }
        return ipv4;
}

int
pkt_is_tcp(struct rte_mbuf* pkt) {
        return pkt_tcp_hdr(pkt) != NULL;
}

int
pkt_is_udp(struct rte_mbuf* pkt) {
        return pkt_udp_hdr(pkt) != NULL;
}

int
pkt_is_ipv4(struct rte_mbuf* pkt) {
        return pkt_ipv4_hdr(pkt) != NULL;
}

// void
// onvm_pkt_print(struct rte_mbuf* pkt) {
//         struct rte_ipv4_hdr* ipv4 = pkt_ipv4_hdr(pkt);
//         if (likely(ipv4 != NULL)) {
//                 onvm_pkt_print_ipv4(ipv4);
//         }

//         struct rte_tcp_hdr* tcp = pkt_tcp_hdr(pkt);
//         if (tcp != NULL) {
//                 onvm_pkt_print_tcp(tcp);
//         }

//         struct rte_udp_hdr* udp = pkt_udp_hdr(pkt);
//         if (udp != NULL) {
//                 onvm_pkt_print_udp(udp);
//         }
// }

// void
// onvm_pkt_print_tcp(struct rte_tcp_hdr* hdr) {
//         printf("Source Port: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->src_port));
//         printf("Destination Port: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->dst_port));
//         printf("Sequence number: %" PRIu32 "\n", rte_be_to_cpu_32(hdr->sent_seq));
//         printf("Acknowledgement number: %" PRIu32 "\n", rte_be_to_cpu_32(hdr->recv_ack));
//         printf("Data offset: %" PRIu8 "\n", hdr->data_off);

//         /* TCP defines 9 different 1-bit flags, but DPDK's flags field only leaves room for 8.
//          * I think DPDK's struct puts the first flag in the last bit of the data offset field.
//          */
//         uint16_t flags = ((hdr->data_off << 8) | hdr->tcp_flags) & 0b111111111;

//         printf("Flags: %" PRIx16 "\n", flags);
//         printf("\t(");
//         if ((flags >> 8) & 0x1)
//                 printf("NS,");
//         if ((flags >> 7) & 0x1)
//                 printf("CWR,");
//         if ((flags >> 6) & 0x1)
//                 printf("ECE,");
//         if ((flags >> 5) & 0x1)
//                 printf("URG,");
//         if ((flags >> 4) & 0x1)
//                 printf("ACK,");
//         if ((flags >> 3) & 0x1)
//                 printf("PSH,");
//         if ((flags >> 2) & 0x1)
//                 printf("RST,");
//         if ((flags >> 1) & 0x1)
//                 printf("SYN,");
//         if (flags & 0x1)
//                 printf("FIN,");
//         printf(")\n");

//         printf("Window Size: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->rx_win));
//         printf("Checksum: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->cksum));
//         printf("Urgent Pointer: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->tcp_urp));
// }

// void
// onvm_pkt_print_udp(struct rte_udp_hdr* hdr) {
//         printf("Source Port: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->src_port));
//         printf("Destination Port: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->dst_port));
//         printf("Length: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->dgram_len));
//         printf("Checksum: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->dgram_cksum));
// }

// void
// onvm_pkt_print_ipv4(struct rte_ipv4_hdr* hdr) {
//         printf("IHL: %" PRIu8 "\n", hdr->version_ihl & 0b1111);
//         printf("DSCP: %" PRIu8 "\n", hdr->type_of_service & 0b111111);
//         printf("ECN: %" PRIu8 "\n", (hdr->type_of_service >> 6) & 0b11);
//         printf("Total Length: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->total_length));
//         printf("Identification: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->packet_id));

//         uint8_t flags = (hdr->fragment_offset >> 13) & 0b111;  // there are three 1-bit flags, but only 2 are used
//         printf("Flags: %" PRIx8 "\n", flags);
//         printf("\t(");
//         if ((flags >> 1) & 0x1)
//                 printf("DF,");
//         if (flags & 0x1)
//                 printf("MF,");
//         printf("\n");

//         printf("Fragment Offset: %" PRIu16 "\n", rte_be_to_cpu_16(hdr->fragment_offset) & 0b1111111111111);
//         printf("TTL: %" PRIu8 "\n", hdr->time_to_live);
//         printf("Protocol: %" PRIu8, hdr->next_proto_id);

//         if (hdr->next_proto_id == IP_PROTOCOL_TCP) {
//                 printf(" (TCP)");
//         }

//         if (hdr->next_proto_id == IP_PROTOCOL_UDP) {
//                 printf(" (UDP)");
//         }

//         printf("\n");

//         printf("Header Checksum: %" PRIu16 "\n", hdr->hdr_checksum);
//         printf("Source IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 ")\n", hdr->src_addr,
//                hdr->src_addr & 0xFF, (hdr->src_addr >> 8) & 0xFF, (hdr->src_addr >> 16) & 0xFF,
//                (hdr->src_addr >> 24) & 0xFF);
//         printf("Destination IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 ")\n", hdr->dst_addr,
//                hdr->dst_addr & 0xFF, (hdr->dst_addr >> 8) & 0xFF, (hdr->dst_addr >> 16) & 0xFF,
//                (hdr->dst_addr >> 24) & 0xFF);
// }

// void
// onvm_pkt_print_ether(struct rte_ether_hdr* hdr) {
//         const char* type = NULL;
//         if (unlikely(hdr == NULL)) {
//                 return;
//         }
//         printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->s_addr.addr_bytes[0], hdr->s_addr.addr_bytes[1],
//                hdr->s_addr.addr_bytes[2], hdr->s_addr.addr_bytes[3], hdr->s_addr.addr_bytes[4],
//                hdr->s_addr.addr_bytes[5]);
//         printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->d_addr.addr_bytes[0], hdr->d_addr.addr_bytes[1],
//                hdr->d_addr.addr_bytes[2], hdr->d_addr.addr_bytes[3], hdr->d_addr.addr_bytes[4],
//                hdr->d_addr.addr_bytes[5]);
//         switch (hdr->ether_type) {
//                 case RTE_ETHER_TYPE_IPV4:
//                         type = "IPv4";
//                         break;
//                 case RTE_ETHER_TYPE_IPV6:
//                         type = "IPv6";
//                         break;
//                 case RTE_ETHER_TYPE_ARP:
//                         type = "ARP";
//                         break;
//                 case RTE_ETHER_TYPE_RARP:
//                         type = "Reverse ARP";
//                         break;
//                 case RTE_ETHER_TYPE_VLAN:
//                         type = "VLAN";
//                         break;
//                 case RTE_ETHER_TYPE_1588:
//                         type = "1588 Precise Time";
//                         break;
//                 case RTE_ETHER_TYPE_SLOW:
//                         type = "Slow";
//                         break;
//                 case RTE_ETHER_TYPE_TEB:
//                         type = "Transparent Ethernet Bridging (TEP)";
//                         break;
//                 default:
//                         type = "unknown";
//                         break;
//         }
//         printf("Type: %s\n", type);
// }

int
ipv4_str_to_uint32(char* ip_str, uint32_t* dest) {
        int ret;
        int ip[4];

        if (ip_str == NULL || dest == NULL) {
                return -1;
        }

        ret = sscanf(ip_str, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]);
        if (ret != 4) {
                return -1;
        }
        *dest = RTE_IPV4(ip[0], ip[1], ip[2], ip[3]);
        return 0;
}

void
onvm_pkt_parse_char_ip(char* ip_dest, uint32_t ip_src) {
        snprintf(ip_dest, 16, "%u.%u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF,
                (ip_src >> 8) & 0xFF, ip_src & 0xFF);
}

int
onvm_pkt_parse_mac(char* mac_str, uint8_t* dest) {
        int ret, i;
        int mac[RTE_ETHER_ADDR_LEN];

        if (mac_str == NULL || dest == NULL) {
                return -1;
        }

        ret = sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if (ret != RTE_ETHER_ADDR_LEN) {
                return -1;
        }

        for (i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
                dest[i] = mac[i];
        }
        return 0;
}

uint32_t
onvm_pkt_get_checksum_offload_flags(uint8_t port_id) {
        struct rte_eth_dev_info dev_info;
        uint32_t hw_offload_flags = 0;

        rte_eth_dev_info_get(port_id, &dev_info);

        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
                hw_offload_flags |= SUPPORTS_IPV4_CHECKSUM_OFFLOAD;
        }
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) {
                hw_offload_flags |= SUPPORTS_TCP_CHECKSUM_OFFLOAD;
        }
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) {
                hw_offload_flags |= SUPPORTS_UDP_CHECKSUM_OFFLOAD;
        }
        return hw_offload_flags;
}

/**
 * Calculates TCP or UDP checksum.
 * This is the same implementation as rte_ipv4_udptcp_cksum(),
 * except that this implementation can process packets with IP options.
 */
static uint16_t
calculate_tcpudp_cksum(const struct rte_ipv4_hdr* ip, const void* l4_hdr, const uint32_t l3_len, uint8_t protocol) {
        uint32_t cksum = 0;
        uint32_t l4_len = ip->total_length - l3_len;

        /* pseudo header checksum */
        struct {
                uint32_t saddr;
                uint32_t daddr;
                uint8_t reserved; /* all zeros */
                uint8_t protocol;
                uint16_t total_length; /* the length of the TCP/UDP header and data */
        } __attribute__((__packed__)) ph;

        ph.saddr = ip->src_addr;
        ph.daddr = ip->dst_addr;
        ph.reserved = 0;
        ph.protocol = protocol;
        ph.total_length = (uint16_t)l4_len;

        cksum += rte_raw_cksum(&ph, sizeof(ph));

        /* packet checksum */
        cksum += rte_raw_cksum(l4_hdr, l4_len);

        while (cksum & 0xffff0000) {
                cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
        }
        return ~cksum;
}

/**
 * Calculates IP checksum.
 * This is the same implementation as rte_ipv4_cksum(),
 * exception that this implementation can process packets with IP options.
 */
static uint16_t
calculate_ip_cksum(const struct rte_ipv4_hdr* ip, const uint32_t l3_len) {
        uint16_t cksum = rte_raw_cksum(ip, l3_len);
        return (cksum == 0xffff) ? cksum : ~cksum;
}

void
pkt_set_checksums(struct rte_mbuf* pkt) {
        //uint32_t hw_cksum_support = onvm_pkt_get_checksum_offload_flags(pkt->port);
        uint32_t hw_cksum_support = 0;
        struct rte_ipv4_hdr* ip = pkt_ipv4_hdr(pkt);
        struct rte_tcp_hdr* tcp = pkt_tcp_hdr(pkt);
        struct rte_udp_hdr* udp = pkt_udp_hdr(pkt);

        if (ip != NULL) {
                ip->hdr_checksum = 0;
                pkt->l2_len = sizeof(struct rte_ether_hdr);
                pkt->l3_len = (ip->version_ihl & 0b1111) * 4;
                pkt->ol_flags |= PKT_TX_IPV4;

                if (tcp != NULL) {
                        tcp->cksum = 0;
                        pkt->l4_len = (tcp->data_off >> 4) & 0b1111;

                        if (hw_cksum_support & SUPPORTS_TCP_CHECKSUM_OFFLOAD) {
                                tcp->cksum = rte_ipv4_phdr_cksum(ip, pkt->ol_flags);
                                pkt->ol_flags |= PKT_TX_TCP_CKSUM;
                        } else {
                                /* software TCP checksumming */
                                tcp->cksum = calculate_tcpudp_cksum(ip, tcp, pkt->l3_len, IP_PROTOCOL_TCP);
                        }
                }

                if (udp != NULL) {
                        udp->dgram_cksum = 0;
                        pkt->l4_len = 8;

                        if (hw_cksum_support & SUPPORTS_UDP_CHECKSUM_OFFLOAD) {
                                udp->dgram_cksum = rte_ipv4_phdr_cksum(ip, pkt->ol_flags);
                                pkt->ol_flags |= PKT_TX_UDP_CKSUM;
                        } else {
                                /* software UDP checksumming */
                                udp->dgram_cksum = calculate_tcpudp_cksum(ip, udp, pkt->l3_len, IP_PROTOCOL_UDP);
                        }
                }

                if (hw_cksum_support & SUPPORTS_IPV4_CHECKSUM_OFFLOAD) {
                        pkt->ol_flags |= PKT_TX_IP_CKSUM;
                } else {
                        /* software IP checksumming */
                        ip->hdr_checksum = calculate_ip_cksum(ip, pkt->l3_len);
                }
        }
}

int
onvm_pkt_swap_ether_hdr(struct rte_ether_hdr* ether_hdr) {
        int i;
        struct rte_ether_addr temp_ether_addr;

        for (i = 0; i < RTE_ETHER_ADDR_LEN; ++i) {
                temp_ether_addr.addr_bytes[i] = ether_hdr->s_addr.addr_bytes[i];
                ether_hdr->s_addr.addr_bytes[i] = ether_hdr->d_addr.addr_bytes[i];
        }

        for (i = 0; i < RTE_ETHER_ADDR_LEN; ++i) {
                ether_hdr->d_addr.addr_bytes[i] = temp_ether_addr.addr_bytes[i];
        }

        return 0;
}

int
onvm_pkt_swap_ip_hdr(struct rte_ipv4_hdr* ip_hdr) {
        uint32_t temp_ip;

        temp_ip = ip_hdr->src_addr;
        ip_hdr->src_addr = ip_hdr->dst_addr;
        ip_hdr->dst_addr = temp_ip;

        return 0;
}

int
onvm_pkt_swap_tcp_hdr(struct rte_tcp_hdr* tcp_hdr) {
        uint16_t temp_port;

        temp_port = tcp_hdr->src_port;
        tcp_hdr->src_port = tcp_hdr->dst_port;
        tcp_hdr->dst_port = temp_port;

        return 0;
}

struct rte_mbuf*
onvm_pkt_generate_tcp(struct rte_mempool* pktmbuf_pool, struct rte_tcp_hdr* tcp_hdr, struct rte_ipv4_hdr* iph,
                      struct rte_ether_hdr* eth_hdr, uint8_t* options, size_t option_len, uint8_t* payload,
                      size_t payload_len) {
        struct rte_mbuf* pkt;
        uint8_t* pkt_payload;
        uint8_t* tcp_options;
        struct rte_tcp_hdr* pkt_tcp_hdr;
        struct rte_ipv4_hdr* pkt_iph;
        struct rte_ether_hdr* pkt_eth_hdr;

        printf("Forming TCP packet, option_len %zu, payload_len %zu\n", option_len, payload_len);

        pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        if (pkt == NULL) {
                return NULL;
        }

        pkt->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
        pkt->l2_len = sizeof(struct rte_ether_hdr);
        pkt->l3_len = sizeof(struct rte_ipv4_hdr);

        if (payload_len > 0) {
                /* Set payload data */
                pkt_payload = (uint8_t*)rte_pktmbuf_prepend(pkt, payload_len);
                if (pkt_payload == NULL) {
                        printf("Failed to prepend data. Consider splitting up the packet.\n");
                        return NULL;
                }
                rte_memcpy(pkt_payload, payload, payload_len);
        }

        if (option_len > 0) {
                /* Set payload data */
                tcp_options = (uint8_t*)rte_pktmbuf_prepend(pkt, option_len);
                if (tcp_options == NULL) {
                        printf("Failed to prepend data. Consider splitting up the packet.\n");
                        return NULL;
                }
                rte_memcpy(tcp_options, options, option_len);
        }

        /* Set tcp hdr */
        printf("TCP SIZE -> %lu\n", sizeof(*tcp_hdr));
        pkt_tcp_hdr = (struct rte_tcp_hdr*)rte_pktmbuf_prepend(pkt, sizeof(*tcp_hdr));
        if (pkt_tcp_hdr == NULL) {
                printf("Failed to prepend data. Consider splitting up the packet.\n");
                return NULL;
        }
        rte_memcpy(pkt_tcp_hdr, tcp_hdr, sizeof(*tcp_hdr));  // + option_len);

        /* Set ip hdr */
        pkt_iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(pkt, sizeof(*iph));
        if (pkt_iph == NULL) {
                printf("Failed to prepend data. Consider splitting up the packet.\n");
                return NULL;
        }
        rte_memcpy(pkt_iph, iph, sizeof(*iph));

        /* Set eth hdr */
        pkt_eth_hdr = (struct rte_ether_hdr*)rte_pktmbuf_prepend(pkt, sizeof(*eth_hdr));
        if (pkt_eth_hdr == NULL) {
                printf("Failed to prepend data. Consider splitting up the packet.\n");
                return NULL;
        }
        rte_memcpy(pkt_eth_hdr, eth_hdr, sizeof(*eth_hdr));

        pkt->pkt_len = pkt->data_len;
        iph->total_length = rte_cpu_to_be_16(payload_len + option_len + sizeof(struct rte_tcp_hdr) +
                                             sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr));
        printf("Pkt len %d, total iph len %lu\n", pkt->pkt_len,
               payload_len + option_len + sizeof(struct rte_tcp_hdr) +
               sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_ether_hdr));

        /* Handle checksuming */
        pkt_set_checksums(pkt);

        return pkt;
}

int
fill_udp_hdr(struct rte_udp_hdr* udp_hdr, struct meili_pkt *info) {
        udp_hdr->src_port = rte_cpu_to_be_16(info->sp);
        udp_hdr->dst_port = rte_cpu_to_be_16(info->dp);
        udp_hdr->dgram_cksum = 0;
        /* dgram length = udp hdr length + payload length */
        udp_hdr->dgram_len = rte_cpu_to_be_16(info->length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));
        return 0;
}

int
fill_ipv4_hdr(struct rte_ipv4_hdr* iph, struct meili_pkt *info) {
        iph->src_addr = rte_cpu_to_be_32(info->sa);
        iph->dst_addr = rte_cpu_to_be_32(info->da);
        iph->next_proto_id = info->proto;
        iph->version_ihl = IPV4_VERSION_IHL;
        iph->time_to_live = IPV4_TTL;
        iph->hdr_checksum = 0;

        return 0;
}

int
fill_ether_hdr(struct rte_ether_hdr* eth_hdr, struct meili_pkt *info) {
        int i;

        /* Set ether header */
        //rte_ether_addr_copy(&ports->mac[port], &eth_hdr->s_addr);
        
        for (i = 0; i < MEILI_ETHER_ADDR_LEN; ++i) {
                eth_hdr->s_addr.addr_bytes[i] = info->mac_sa[i];
                eth_hdr->d_addr.addr_bytes[i] = info->mac_da[i];
        }
        
        /* should be determined by info */
        eth_hdr->ether_type = rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);

        return 0;
}

int add_udp_hdr(struct rte_mbuf *pkt, struct meili_pkt *info) {
        //struct onvm_pkt_meta* pmeta = NULL;
        
        struct rte_udp_hdr *udp_hdr = MBUF_UDP_HDR(pkt);
        struct rte_ipv4_hdr *iph = MBUF_IPV4_HDR(pkt);
        struct rte_ether_hdr *eth_hdr = MBUF_ETH_HDR(pkt);
        //struct rte_ether_addr d_addr = {.addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

        if(unlikely(!pkt)){
                return -EINVAL;
        }
        /* check data length */
        // pkt->data_len;

        fill_udp_hdr(udp_hdr, info);
        fill_ipv4_hdr(iph, info);
        fill_ether_hdr(eth_hdr, info);

        return 0;
}

// struct rte_mbuf*
// onvm_pkt_generate_udp_sample(struct rte_mempool* pktmbuf_pool) {
//         struct onvm_pkt_meta* pmeta = NULL;
//         struct rte_mbuf* pkt;
//         struct rte_udp_hdr udp_hdr;
//         struct rte_ipv4_hdr iph;
//         struct rte_ether_hdr eth_hdr;
//         struct rte_ether_addr d_addr = {.addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
//         char sample_msg[32] = "UDP packet sent from ONVM.";
//         size_t payload_len = sizeof(sample_msg);

//         onvm_pkt_fill_udp(&udp_hdr, UDP_SAMPLE_SRC_PORT, UDP_SAMPLE_DST_PORT, payload_len);
//         onvm_pkt_fill_ipv4(&iph, IPV4_SAMPLE_SRC, IPV4_SAMPLE_DST, PROTO_UDP);
//         onvm_pkt_fill_ether(&eth_hdr, SAMPLE_NIC_PORT, &d_addr, ports);

//         pkt = onvm_pkt_generate_udp(pktmbuf_pool, &udp_hdr, &iph, &eth_hdr, (uint8_t*)sample_msg, payload_len);
//         if (pkt == NULL) {
//                 return NULL;
//         }

//         /* Set packet dest */
//         pmeta = onvm_get_pkt_meta(pkt);
//         pmeta->destination = SAMPLE_NIC_PORT;
//         pmeta->action = ONVM_NF_ACTION_OUT;

//         return pkt;
// }

struct rte_mbuf*
onvm_pkt_generate_udp(struct rte_mempool* pktmbuf_pool, struct rte_udp_hdr* udp_hdr, struct rte_ipv4_hdr* iph,
                      struct rte_ether_hdr* eth_hdr, uint8_t* payload, size_t payload_len) {
        struct rte_mbuf* pkt;
        uint8_t* pkt_payload;
        struct rte_udp_hdr* pkt_udp_hdr;
        struct rte_ipv4_hdr* pkt_iph;
        struct rte_ether_hdr* pkt_eth_hdr;

        pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        if (pkt == NULL) {
                return NULL;
        }

        pkt->ol_flags = PKT_TX_IP_CKSUM | PKT_TX_IPV4 | PKT_TX_UDP_CKSUM;
        pkt->l2_len = sizeof(struct rte_ether_hdr);
        pkt->l3_len = sizeof(struct rte_ipv4_hdr);

        /* Set payload data */
        pkt_payload = (uint8_t*)rte_pktmbuf_prepend(pkt, payload_len);
        if (pkt_payload == NULL) {
                printf("Failed to prepend data. Consider splitting up the packet.\n");
                return NULL;
        }
        rte_memcpy(pkt_payload, payload, payload_len);

        /* Set udp hdr */
        pkt_udp_hdr = (struct rte_udp_hdr*)rte_pktmbuf_prepend(pkt, sizeof(*udp_hdr));
        if (pkt_udp_hdr == NULL) {
                printf("Failed to prepend data. Consider splitting up the packet.\n");
                return NULL;
        }
        rte_memcpy(pkt_udp_hdr, udp_hdr, sizeof(*udp_hdr));

        /* Set ip hdr */
        pkt_iph = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(pkt, sizeof(*iph));
        if (pkt_iph == NULL) {
                printf("Failed to prepend data. Consider splitting up the packet.\n");
                return NULL;
        }
        rte_memcpy(pkt_iph, iph, sizeof(*iph));

        /* Set eth hdr */
        pkt_eth_hdr = (struct rte_ether_hdr*)rte_pktmbuf_prepend(pkt, sizeof(*eth_hdr));
        if (pkt_eth_hdr == NULL) {
                printf("Failed to prepend data. Consider splitting up the packet.\n");
                return NULL;
        }
        rte_memcpy(pkt_eth_hdr, eth_hdr, sizeof(*eth_hdr));

        pkt->pkt_len = pkt->data_len;
        iph->total_length = rte_cpu_to_be_16(pkt->pkt_len - sizeof(struct rte_ether_hdr));

        /* Handle checksuming */
        pkt_set_checksums(pkt);

        return pkt;
}