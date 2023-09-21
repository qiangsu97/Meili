#ifndef _INCLUDE_APP_SHARED_H
#define _INCLUDE_APP_SHARED_H
#include <stdint.h>
#include <rte_mbuf.h>
#include "../pipeline.h"
#include "../utils/rxpb_log.h"

#define APP_MAX_STAGE 8 

struct app_state{
    struct pipeline_stage *stages[APP_MAX_STAGE];
    int nb_stage;
};


/* only initialize neccessary states, no need to connect rings */
int app_init_substages(struct pipeline_stage *self, 
                       enum pipeline_type *type_map, int nb_stage);
void app_free_substages(struct app_state *mystate);


#endif /* _INCLUDE_APP_SHARED_H */