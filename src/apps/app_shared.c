
#include "app_shared.h"

/* only initialize neccessary states, no need to connect rings */
int app_init_substages(struct pipeline_stage *self, 
                       enum pipeline_type *type_map, int nb_stage){
    
    struct app_state *mystate = (struct app_state *)self->state;
    struct pipeline_stage *sub_stage;
    int ret;
    for(int i=0; i<nb_stage; i++){
        sub_stage = (struct pipeline_stage *)malloc(sizeof(struct pipeline_stage));
        mystate->stages[i] = sub_stage;
        sub_stage->pl = self->pl;
        sub_stage->core_id = self->core_id;
        sub_stage->worker_qid = self->worker_qid;
        ret = pipeline_stage_init_safe(sub_stage, type_map[i]);  
        if(ret){
            PL_LOG_ERR("Error when initalizing sub-stage");
            return ret;
        }        
    }
    mystate->nb_stage = nb_stage;   
    self->has_substage = true;           
    return 0;
}

/* only initialize neccessary states, no need to connect rings */
void app_free_substages(struct app_state *mystate){

    int ret;
    for(int i=0; i<mystate->nb_stage; i++){
        free(mystate->stages[i]);        
    }             
    return;
}