#ifndef _INCLUDE_MEILI_H_
#define _INCLUDE_MEILI_H_

#define MEILI_STATE_DECLS(x) struct (x)##_state {
#define MEILI_STATE_DECLS_END };

#define MEILI_INIT(x) int (x)##_init(struct pipeline_stage *self){

#define MEILI_FREE(x) int (x)##_free(struct pipeline_stage *self){

#define MEILI_EXEC(x)  int (x)##_exec(struct pipeline_stage *self, \
                            struct rte_mbuf **mbuf,                                   \
                            int nb_enq,                                               \
                            struct rte_mbuf ***mbuf_out,                              \
                            int *nb_deq){meili_apis Meili = self->apis;

#define MEILI_END_DECLS  return 0;}


#define MEILI_REGISTER(x) int meili_pipeline_stage_func_reg(struct pipeline_stage *stage) \
{\
	stage->funcs->pipeline_stage_init = (x)##_init;\
	stage->funcs->pipeline_stage_free = (x)##_free;\
	stage->funcs->pipeline_stage_exec = (x)##_exec;\
    return 0;\
}

#define DPDK_BACKEND


#ifdef DPDK_BACKEND
#define meili_pkt struct rte_mbuf
#define meili_pkt_payload(x) rte_pktmbuf_mtod(x, char *)
#define meili_pkt_payload_len(x)    x->data_len

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