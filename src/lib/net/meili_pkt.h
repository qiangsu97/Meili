#ifndef _MEILI_PKT_H
#define _MEILI_PKT_H

#define DPDK_BACKEND


#ifdef DPDK_BACKEND
typedef struct rte_mbuf meili_pkt; 
#define meili_pkt_payload(x) rte_pktmbuf_mtod(x, const unsigned char *)
#define meili_pkt_payload_len(x)    x->data_len

#else      
typedef struct _meili_pkt{
    int place_holder;
}meili_pkt;  
#endif

#endif /* _MEILI_PKT_H */