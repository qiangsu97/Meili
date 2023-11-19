#ifndef _INCLUDE_MEILI_H_
#define _INCLUDE_MEILI_H_

#define DPDK_BACKEND

/* structs */
#ifdef DPDK_BACKEND
#define meili_pkt struct rte_mbuf
#else      
typedef struct _meili_pkt{
    int place_holder;
}meili_pkt;  
#endif


/* Meili APIs */
typedef struct _meili_apis{
    void *pkt_trans;
    void *pkt_flt;
    void *flow_ext;
    void *flow_trans; 
    void *reg_sock;
    void *epoll;
    void *regex;
    void *AES;
    void *compression;
}meili_apis;




#endif /* _INCLUDE_MEILI_H_ */