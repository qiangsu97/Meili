#ifndef _INCLUDE_MEILI_H_
#define _INCLUDE_MEILI_H_

#include "./net/meili_pkt.h"
#include "../runtime/pipeline.h"

#define MEILI_STATE_DECLS(x) struct x##_state {
#define MEILI_STATE_DECLS_END };

#define MEILI_INIT(x) int x##_stage_init(struct pipeline_stage *self){

#define MEILI_FREE(x) int x##_stage_free(struct pipeline_stage *self){

#define MEILI_EXEC(x)  int x##_stage_exec(struct pipeline_stage *self, \
                            meili_pkt *pkt){meili_apis Meili = *((meili_apis *)self->apis);

#define MEILI_END_DECLS  return 0;}

#define MEILI_REGISTER(x) int meili_pipeline_stage_func_reg(struct pipeline_stage *stage){ \
                                stage->funcs->pipeline_stage_init = x##_stage_init;\
	                            stage->funcs->pipeline_stage_free = x##_stage_free;\
	                            stage->funcs->pipeline_stage_exec = x##_stage_exec;}
 


/* Meili APIs */
typedef struct _meili_apis{
    void (*pkt_trans)();
    void (*pkt_flt)(struct pipeline_stage *self, int (*check)(struct pipeline_stage *self, meili_pkt *pkt), meili_pkt *pkt);
    void (*flow_ext)();
    void (*flow_trans)(); 
    void (*reg_sock)();
    void (*epoll)();
    void (*regex)();
    void (*AES)();
    void (*compression)();
}meili_apis;



#endif /* _INCLUDE_MEILI_H_ */