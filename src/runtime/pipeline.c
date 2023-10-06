#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <rte_errno.h>

#include "pipeline.h"
#include "run_mode.h"
#include "apps/app_shared.h"

#include "../packet_ordering/packet_ordering.h"
#include "../packet_timestamping/packet_timestamping.h"
#include "../utils/input.h"


typedef int (*pl_register_functions)(struct pipeline_stage *);

pl_register_functions pl_reg_funcs[PL_NB_OF_STAGE_TYPES] = {
    echo_pipeline_stage_func_reg,
    ddos_pipeline_stage_func_reg,
    regex_bf_pipeline_stage_func_reg,
    compress_bf_pipeline_stage_func_reg,
    aes_pipeline_stage_func_reg,
    sha_pipeline_stage_func_reg,
    firewall_acl_pipeline_stage_func_reg,
    monitor_cms_pipeline_stage_func_reg,
    monitor_hll_pipeline_stage_func_reg,
    l3_lb_pipeline_stage_func_reg,
    api_gw_pipeline_stage_func_reg,
    http_parser_pipeline_stage_func_reg,
    app_ids_pipeline_stage_func_reg,
    app_ipcomp_gw_pipeline_stage_func_reg,
    app_ipsec_gw_pipeline_stage_func_reg,
    app_fw_pipeline_stage_func_reg,
    app_flow_mon_pipeline_stage_func_reg,
    app_api_gw_pipeline_stage_func_reg,
    app_l7_lb_pipeline_stage_func_reg,
    NULL
};

static int
init_dpdk(struct pipeline_conf *run_conf)
{
	int ret;

	if (run_conf->dpdk_argc <= 1) {
		MEILI_LOG_ERR("Too few DPDK parameters.");
		return -EINVAL;
	}

	ret = rte_eal_init(run_conf->dpdk_argc, run_conf->dpdk_argv);

	/* Return num of params on success. */
	return ret < 0 ? -rte_errno : 0;
}

/* Init neccessary dpdk environments and construct pipeline */
int pipeline_runtime_init(struct pipeline *pl, struct pipeline_conf *run_conf, char *err){
    int ret = 0;
    /* initalize dpdk related environment */
    ret = init_dpdk(run_conf);
	if (ret) {
		snprintf(err, ERR_STR_SIZE, "Failed to init DPDK");
		goto clean_conf;
	}

	/* Confirm there are enough DPDK lcores for user core request. */
	if (run_conf->cores > rte_lcore_count()) {
		MEILI_LOG_WARN_REC(run_conf, "requested cores (%d) > dpdk lcores (%d) - using %d.", run_conf->cores,
				  rte_lcore_count(), rte_lcore_count());
		run_conf->cores = rte_lcore_count();
	}

	ret = stats_init(run_conf);
	if (ret) {
		snprintf(err, ERR_STR_SIZE, "Failed initialising stats");
		goto clean_conf;
	}

    /* Register input init function according to command line arguments. Input methods can be 
     * 1) INPUT_TEXT_FILE       Load txt file into memory. Note that for txt files, it may take up large space.
     * 2) INPUT_PCAP_FILE       Load pcap file into memory. Note that for pcap files, it may take up large space.
     * 3) INPUT_LIVE            Use dpdk port to receive pkts. 
     * 4) INPUT_JOB_FORMAT      
     * 5) INPUT_REMOTE_MMAP
    */
	ret = input_register(run_conf);
	if (ret) {
		snprintf(err, ERR_STR_SIZE, "Input registration error");
		goto clean_stats;
	}

	ret = input_init(run_conf);
	if (ret) {
		snprintf(err, ERR_STR_SIZE, "Input method initialization failed");
		goto clean_stats;
	}

    /* construct pipeline topo */
	/* populate pipeline fields first */
	// pl.nb_pl_stages = 2;
	// pl.stage_types[0] = PL_REGEX_BF;
	// pl.stage_types[1] = PL_DDOS;
    // pl.nb_inst_per_pl_stage[0] = 1;
	// pl.nb_inst_per_pl_stage[1] = 4;

    /* construct pipeline topo based on pl.conf file */
	ret = pipeline_init_safe(pl, PL_CONFIG_PATH);
	if (ret) {
		snprintf(err, ERR_STR_SIZE, "Pipeline initialising failed");
		
		goto clean_pipeline;
	}

    /* register main thread run function based on input mode (local txt/pcap, dpdk port, ...) */
    ret = run_mode_register(pl);
	if (ret) {
		snprintf(err, ERR_STR_SIZE, "Run mode registration error");
		goto clean_pipeline;
	}

    MEILI_LOG_INFO("Pipeline runtime initalization finished");
    goto end;

clean_pipeline:
	pipeline_free(pl);
clean_input:
	input_clean(run_conf);
clean_stats:
	stats_clean(run_conf);
clean_conf:
	conf_clean(run_conf);
end:
    return ret;
}

/* REGISTER FUNCTION HERE */
int pipeline_stage_register_safe(struct pipeline_stage *self, enum pipeline_type pp_type){
    /* register all functions for this pipeline */
    if(pl_reg_funcs[pp_type](self)){
        return pl_reg_funcs[pp_type](self);
    }

    return -EINVAL;

}

/*  pipeline_stage_init_safe
 *  - allocate space for and initialize some fields of a pipeline_stage structure
 *  - fields that are not initalized here: core_id(init before launching), worker_qid(init before launching), pl(init by pipeline topo init)
 */
int pipeline_stage_init_safe(struct pipeline_stage *self, enum pipeline_type pp_type){
    
    int ret;
    struct pipeline_func * funcs = (struct pipeline_func *)malloc(sizeof(struct pipeline_func));
    /* allocate space for funcs */
    self->funcs = funcs;

    if(!self->funcs){
        return -ENOMEM;
    }

    /* general fields a pipeline stage must have */
    self->type = pp_type;
    self->batch_size = DEFAULT_BATCH_SIZE;
    self->has_substage = false;
    #ifdef SHARED_BUFFER
    self->ring_in = NULL;
    self->ring_out = NULL;
    #else
    self->nb_ring_in = 0;
    self->nb_ring_out = 0;
    #endif
	
    /* register timestamping module */
    //ret = pkt_ts_init(&self->ts_start_offset);
    //	if(ret){
    //		return -EINVAL;
    //	}
    //ret = pkt_ts_init(&self->ts_end_offset);
    //	if(ret){
    //		return -EINVAL;
    //	}


    /* register functions for this stage */
    pipeline_stage_register_safe(self, pp_type);

    /* type-specific initialization */
	if (funcs->pipeline_stage_init){
        return funcs->pipeline_stage_init(self);
    }
		
    return -EINVAL;
}

int pipeline_stage_free_safe(struct pipeline_stage *self){

    struct pipeline_func *funcs = self->funcs;

    /* type-specific free */
	if (funcs->pipeline_stage_free){
        if(funcs->pipeline_stage_free(self)){
            return -EINVAL;
        }
    }
    else{
        return -EINVAL;
    }

    free(self->funcs);
    /* we assume all pp stages are allocated using malloc */
    free(self);

    // if(self->ring_in){
    //     rte_ring_free(self->ring_in);
    // }
    // if(self->ring_out){
    //     rte_ring_free(self->ring_out);
    // }

    /* for rte-related space, i.e. ring_in and ring_out, main() uses rte_eal_cleanup() to free */
    return 0;   
		
}

/* pipeline processing operation on a single mbuf object */
int pipeline_stage_exec_safe(struct pipeline_stage *self, 
                            struct rte_mbuf **mbuf,
                            int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq){

    struct pipeline_func *funcs = self->funcs;

	if(funcs->pipeline_stage_exec){
        return funcs->pipeline_stage_exec(self, mbuf, nb_enq, mbuf_out, nb_deq);
    }
		
    return -EINVAL;
}

/* worker function for a pipeline */
#ifdef SHARED_BUFFER 
int pipeline_stage_run_safe(struct pipeline_stage *self){
    int burst_size = self->batch_size;
    struct rte_ring *ring_in = self->ring_in;
    struct rte_ring *ring_out = self->ring_out;

    

    struct rte_mbuf *mbufs_in[MAX_PKTS_BURST];
    struct rte_mbuf *mbufs_out_static[MAX_PKTS_BURST];

    struct rte_mbuf **mbufs_out = mbufs_out_static;


    int out_num = 0;

    struct pipeline *pl = (struct pipeline *)self->pl;
    struct pipeline_conf *pl_conf = &(pl->pl_conf);

    int qid = self->worker_qid;
    rb_stats_t *stats = pl_conf->stats;
	run_mode_stats_t *rm_stats = &stats->rm_stats[qid];

    if(!ring_in || !ring_out){
        return -EINVAL;
    }

    int nb_deq = 0;
    int nb_enq = 0;
    int to_enq = 0;
    int tot_enq = 0;

    // main loop of pipeline stage
    while(!force_quit && pl_conf->running == true){
        /* read packets from ring_in */
        nb_deq = rte_ring_dequeue_burst(ring_in, (void *)mbufs_in, burst_size, NULL);
        for(int k=0; k<nb_deq ; k++){
            //printf("updating stats for core %d\n",qid);
            rm_stats->rx_buf_bytes += mbufs_in[k]->data_len;
        }
        rm_stats->rx_buf_cnt += nb_deq;
        //pkt_ts_exec(self->ts_start_offset, mbufs_in, nb_deq);

        /* process packets */
        pipeline_stage_exec_safe(self, mbufs_in, nb_deq, &mbufs_out, &out_num);


        /* put packets into ring_out */
        tot_enq = 0;
        while(out_num > 0){
            // if(self->core_id == 2){
            //     printf("out_num=%d\n",out_num);
            // }
            to_enq = RTE_MIN(out_num, burst_size);
            nb_enq = rte_ring_enqueue_burst(ring_out, (void *)(&mbufs_out[tot_enq]), to_enq, NULL);
            tot_enq += nb_enq;
            out_num -= nb_enq;
        }
        /* update stats */
        //pkt_ts_exec(self->ts_end_offset, mbufs_out, tot_enq);

        for(int k=0; k<tot_enq ; k++){
            //printf("updating stats for core %d\n",qid);
            rm_stats->tx_buf_bytes += mbufs_out[k]->data_len;
        }
        rm_stats->tx_buf_cnt += tot_enq;
        
    }

    return 0;
}
#else
int pipeline_stage_run_safe(struct pipeline_stage *self){
    int burst_size = self->batch_size;
    struct rte_ring **ring_in_array = self->ring_in;
    struct rte_ring **ring_out_array = self->ring_out;
    struct rte_ring *ring_in = NULL;
    struct rte_ring *ring_out = NULL;
    int nb_ring_in = self->nb_ring_in;
    int nb_ring_out = self->nb_ring_out;
    int ring_in_index = 0;
    int ring_out_index = 0;

    

    struct rte_mbuf *mbufs_in[MAX_PKTS_BURST];
    struct rte_mbuf *mbufs_out_static[MAX_PKTS_BURST];

    struct rte_mbuf **mbufs_out = mbufs_out_static;


    int out_num = 0;

    struct pipeline *pl = (struct pipeline *)self->pl;
    struct pipeline_conf *pl_conf = &(pl->pl_conf);

    int qid = self->worker_qid;
    rb_stats_t *stats = pl_conf->stats;
	run_mode_stats_t *rm_stats = &stats->rm_stats[qid];

    if(!nb_ring_in || !nb_ring_out){
        return -EINVAL;
    }

    int nb_deq = 0;
    int nb_enq = 0;
    int to_enq = 0;
    int tot_enq = 0;

    // main loop of pipeline stage
    while(!force_quit && pl_conf->running == true){
        /* read packets from ring_in in a round-robin manner */
        ring_in = ring_in_array[ring_in_index];
        nb_deq = rte_ring_dequeue_burst(ring_in, (void *)mbufs_in, burst_size, NULL);
        ring_in_index = (ring_in_index+1)%nb_ring_in;

        /* TODO: only add this logic to stages that process packets without using external accelerators because accelerator can also dequeue previous pkts without enqueue this batch of pkts. */
        // if(!nb_deq){
        //     goto increment_out_index;
        // }

        //pkt_ts_exec(self->ts_start_offset, mbufs_in, nb_deq);
        /* process packets */
        pipeline_stage_exec_safe(self, mbufs_in, nb_deq, &mbufs_out, &out_num);

        //pkt_ts_exec(self->ts_end_offset, mbufs_out, out_num);

        /* put packets into ring_out in a round-robin manner */
        ring_out = ring_out_array[ring_out_index];
        
        tot_enq = 0;
        while(out_num > 0) {
            to_enq = RTE_MIN(out_num, burst_size);
            nb_enq = rte_ring_enqueue_burst(ring_out, (void *)(&mbufs_out[tot_enq]), to_enq, NULL);
            tot_enq += nb_enq;
            out_num -= nb_enq;
        }
        ring_out_index = (ring_out_index+1)%nb_ring_out;
        /* update statics */
        for(int k=0; k<tot_enq ; k++){
            //printf("updating stats for core %d\n",qid);
            rm_stats->tx_buf_bytes += mbufs_out[k]->data_len;
        }
        rm_stats->tx_buf_cnt += tot_enq;
        
    }

    return 0;
}
#endif


int pipeline_init_safe(struct pipeline *pl, char *config_path){
    /* TODO optional: connect pipeline stages based on DAG, currently we connect them using very simple topo(fully connected topo) */
    
    FILE *fp;
    char buf[CONFIG_BUF_LEN];
    int k=0;
    char *token;
    char *line;
    
    int nb_pl_stages = 0 ;
    enum pipeline_type *stage_types =NULL;
    int *nb_inst_per_pl_stage = NULL;
    struct pipeline_stage *self = NULL;
    struct pipeline_stage *child = NULL;

    char ring_name[64];

    struct pipeline_conf *run_conf = &(pl->pl_conf);

    /* assign initial value for each stage to NULL */
    pl->nb_pl_stages = 0;
    pl->nb_pl_stage_inst = 0;
    
    pl->mbuf_pool = NULL;

    pl->ts_start_offset = 0;
    pl->ts_end_offset = 0;

    memset(&pl->seq_stage, 0x00, sizeof(struct pipeline_stage));
    memset(&pl->reorder_stage, 0x00, sizeof(struct pipeline_stage));


    char pool_name[50];
    char stage_type_name[32];

    int ret = 0;

    /* Read pipeline topo from pl.conf */
    MEILI_LOG_INFO("Initializing pl from file %s\n",config_path);
    fp = fopen(config_path,"r"); 
    if(fp == NULL){
        MEILI_LOG_ERR("Failed to load pl config file!");
        return -EINVAL;
    }

    while(!feof(fp)){
        if(pl->nb_pl_stages >= NB_PIPELINE_STAGE_MAX){
            MEILI_LOG_WARN("# of stages exceeding pre-defined threshold");
            break;
        }

        if(fgets(buf, CONFIG_BUF_LEN, fp) == NULL){break;}
        if(buf[0] == '#' || buf[0] == '\0' || buf[0] == '\n'){;}
        else
        {   
	        line = strtok(buf,"\n");		
            token = strtok(line," ");
            GET_STAGE_TYPE_NUMBER(token , &pl->stage_types[k]);
            //debug 
            //printf("%s ",token);

            if(pl->stage_types[k] >= PL_NB_OF_STAGE_TYPES){
                MEILI_LOG_ERR("stage type of stage %d is invalid", k);
                pl->stage_types[k] = PL_NB_OF_STAGE_TYPES-1;
                return -EINVAL;
            }

            token = strtok(NULL," ");
	        //debug
            //printf("%s\n",token);
            pl->nb_inst_per_pl_stage[k] = atoi(token);
            if(pl->nb_inst_per_pl_stage[k] > NB_INSTANCE_PER_PIPELINE_STAGE_MAX){
                MEILI_LOG_WARN("# of stage instances of stage %d exceeding pre-defined threshold", k);   
                return -EINVAL; 
            }
            
            pl->nb_pl_stage_inst += pl->nb_inst_per_pl_stage[k];
            k++;
            pl->nb_pl_stages++;
        } 
    }
    fclose(fp); 

    /* Assign parsed value from .conf topo */
    nb_pl_stages = pl->nb_pl_stages;
    stage_types = pl->stage_types;
    nb_inst_per_pl_stage = pl->nb_inst_per_pl_stage;

    /* Allocate space for mempool if using local run mode */
    if(run_conf->input_mode != INPUT_TEXT_FILE && run_conf->input_mode != INPUT_PCAP_FILE){
        pl->mbuf_pool = NULL;
    }
    else{
        sprintf(pool_name, "PRELOADED POOL");
        MEILI_LOG_INFO("creating mbuf pool, pool size: %d, mbuf szie: %d",MBUF_POOL_SIZE,MBUF_SIZE);
        /* Pool size should be > dpdk descriptor queue. */
        //pl->mbuf_pool = rte_pktmbuf_pool_create(pool_name, MBUF_POOL_SIZE, MBUF_CACHE_SIZE, 0, RTE_PKTMBUF_HEADROOM + run_conf->input_buf_len, rte_socket_id());
        pl->mbuf_pool = rte_pktmbuf_pool_create(pool_name, MBUF_POOL_SIZE, MBUF_CACHE_SIZE, 0, MBUF_SIZE, rte_socket_id());
        if (!pl->mbuf_pool) {
            MEILI_LOG_ERR("Failed to create mbuf pool.");
            return -EINVAL;
        }
    }

    /*----------------------------Start of per-stage initialization----------------------------------------*/
    /* Print initialization info beforehand */
    MEILI_LOG_INFO("Initializing pipeline stages...");
  
    /* Check if pl parameters for stages(number, ...) are valid */
    if(nb_pl_stages > NB_PIPELINE_STAGE_MAX || nb_pl_stages < 0 ){
        return -EINVAL;
    }

    /* Init each stage */
    for(int i=0; i<nb_pl_stages ; i++){

        if(nb_inst_per_pl_stage[i] > NB_INSTANCE_PER_PIPELINE_STAGE_MAX
        || nb_inst_per_pl_stage[i] < 0){
            return -EINVAL;
        }
        
       // pl->nb_pl_stage_inst += nb_inst_per_pl_stage[i];
        for(int j=0; j<nb_inst_per_pl_stage[i]; j++){
             /* allocated space for each stage */
            self = (struct pipeline_stage *)malloc(sizeof(struct pipeline_stage));
            
            self->pl = (void *)pl;

            /* debug for inter-stage interference */
            // if(j!=0){
            //     ret = pipeline_stage_init_safe(self, PL_ECHO);
            // }
            // else{
            //     ret = pipeline_stage_init_safe(self, stage_types[i]);
            // }
            ret = pipeline_stage_init_safe(self, stage_types[i]);

            if(ret){
                GET_STAGE_TYPE_STRING(stage_types[i],stage_type_name);
                MEILI_LOG_ERR("Initialization for %s pipeline stage failed",stage_type_name);
                return ret;
            }
            pl->stages[i][j] = self;
            
        }
    }

    /* Init special stages: timestamping start/end, sequencing and reordering */
    pl->seq_stage.type = PL_MAIN;
    pl->reorder_stage.type = PL_MAIN;

    ret = pkt_ts_init(&pl->ts_start_offset);
	if(ret){
		return -EINVAL;
	}
    ret = pkt_ts_init(&pl->ts_end_offset);
	if(ret){
		return -EINVAL;
	}

	ret = seq_init(&pl->seq_stage);
	if(ret){
		return -EINVAL;
	}
	ret = reorder_init(&pl->reorder_stage);
	if(ret){
		return -EINVAL;
	}

    MEILI_LOG_INFO("Seq and reorder initialized");

    /*----------------------------End of per-stage initialization----------------------------------------*/

    /*----------------------------Start of topology construction-----------------------------------------*/
    /* Create head ring_in/tail ring_out for PL. Rings are shared. */
    #ifdef SHARED_BUFFER
    MEILI_LOG_INFO("Using shared ring buffer for inter-core communication");
    pl->ring_in = rte_ring_create("head_ring_in", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_MC_HTS_DEQ);
    /* another mode of shared rte ring */
    //pl->ring_in = rte_ring_create("head_ring_in", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_MC_RTS_DEQ);
    
    if(!pl->ring_in){
        return -ENOMEM;
    }

    if(nb_pl_stages == 0){
        /* no worker stages */
        pl->ring_out = pl->ring_in;
    }
    else{
        pl->ring_out = rte_ring_create("tail_ring_out", RING_SIZE, rte_socket_id(),RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);
        //pl->ring_out = rte_ring_create("tail_ring_out", RING_SIZE, rte_socket_id(),RING_F_MP_RTS_ENQ | RING_F_SC_DEQ);
        if(!pl->ring_out){
            return -ENOMEM;
        }
        
        /* connect head ring_in to first stages */
        for(int j=0; j<nb_inst_per_pl_stage[0]; j++){
            self = pl->stages[0][j];
            self->ring_in = pl->ring_in;
        }

        /* connect tail ring_out to last stages */
        for(int j=0; j<nb_inst_per_pl_stage[nb_pl_stages-1]; j++){
            self = pl->stages[nb_pl_stages-1][j];
            self->ring_out = pl->ring_out;
        }
    }

    #else
    /* Create head ring_in/tail ring_out for PL. Rings are NOT shared. */
    MEILI_LOG_INFO("Using separated ring buffer for inter-core communication");
    if(nb_pl_stages == 0){
        /* no worker stages */
        pl->ring_in[0] = rte_ring_create("head_ring_in", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
        if(!pl->ring_in[0]){
            return -ENOMEM;
        }
        pl->ring_out[0] = pl->ring_in[0];
    }
    else{
        /* connect head ring_in to first stages */
        for(int j=0; j<nb_inst_per_pl_stage[0]; j++){
            snprintf(ring_name,64,"head_ring_in_%d", j);
            pl->ring_in[j] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
    
            if(!pl->ring_in[j]){
                return -ENOMEM;
            }
            self = pl->stages[0][j];
            self->ring_in[0] = pl->ring_in[j];
            self->nb_ring_in++;
        }

        /* connect tail ring_out to last stages */
        for(int j=0; j<nb_inst_per_pl_stage[nb_pl_stages-1]; j++){
            snprintf(ring_name,64,"tail_ring_out_%d", j);
            pl->ring_out[j] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
            if(!pl->ring_out[j]){
                return -ENOMEM;
            }
            self = pl->stages[nb_pl_stages-1][j];
            self->ring_out[0] = pl->ring_out[j];
            self->nb_ring_out++;
        }
    }
    #endif
    MEILI_LOG_INFO("Main thread in_ring/out_ring initialized");
    

    /* For intermediatte stages, allocate ring_in/ring_out and connect */
    #ifdef SHARED_BUFFER 
    /* Shared rings. */

    /* TODO(optional): add a field that record parent/child */

    for(int i=0; i<nb_pl_stages-1 ; i++){
        if(nb_inst_per_pl_stage[i] < nb_inst_per_pl_stage[i+1]){
            for(int j=0; j<nb_inst_per_pl_stage[i]; j++){
                self = pl->stages[i][j];

                /* allocate space for ring_out */
                self->ring_out = rte_ring_create("", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_MC_HTS_DEQ);
                //self->ring_out = rte_ring_create("", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_MC_RTS_DEQ);
                
                /* could be used to test if shared ring of main thread is the bottleneck (by using seprate ring between workers only) */
                //self->ring_out = rte_ring_create("", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_SC_DEQ);
                if (self->ring_out == NULL){
                    return -ENOMEM;
                }
            }

            for(int j=0; j<nb_inst_per_pl_stage[i+1]; j++){
                self = pl->stages[i+1][j];
                /* connect ring_in to previous ring_out */
                self->ring_in = pl->stages[i][j%nb_inst_per_pl_stage[i]]->ring_out;
            }
        }
        else{
            for(int j=0; j<nb_inst_per_pl_stage[i+1]; j++){
                self = pl->stages[i+1][j];

                /* allocate space for ring_out */
                self->ring_in = rte_ring_create("", RING_SIZE, rte_socket_id(),RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);
                //self->ring_in = rte_ring_create("", RING_SIZE, rte_socket_id(),RING_F_MP_RTS_ENQ | RING_F_SC_DEQ);

                /* could be used to test if shared ring of main thread is the bottleneck (by using seprate ring between workers only) */
                //self->ring_out = rte_ring_create("", RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
                if (self->ring_in == NULL){
                    return -ENOMEM;
                }
            }

            for(int j=0; j<nb_inst_per_pl_stage[i]; j++){
                self = pl->stages[i][j];
                /* connect ring_in to previous ring_out */
                self->ring_out = pl->stages[i+1][j%nb_inst_per_pl_stage[i+1]]->ring_in;
            }
        }
    }
    
    #else
    /* Separate rings. */
    /* Queues are all sp/sc, so we adopt fully connected topo for (n,m) */
    /* TODO(optional): when assigning cores to workers, take into consideration the microarch, i.e., core 2 and core 3 worker should have connection.  */
    /* create i+1 ring_in, and put these rings into i ring_out */
    for(int i=0; i<nb_pl_stages-1 ; i++){

        for(int j=0; j<nb_inst_per_pl_stage[i]; j++){
            self = pl->stages[i][j];
            for(int k=0; k<nb_inst_per_pl_stage[i+1]; k++){
                child = pl->stages[i+1][k];
                snprintf(ring_name,64,"inter_worker_ring_%d_%d_%d_%d", i, i+1, j, k);
                //debug
                MEILI_LOG_INFO("creating inter-stage buffer:%s",ring_name);
                self->ring_out[self->nb_ring_out] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),RING_F_SP_ENQ | RING_F_SC_DEQ);
                if (self->ring_out == NULL){
                    return -ENOMEM;
                }
                
                child->ring_in[child->nb_ring_in] = self->ring_out[self->nb_ring_out];
                self->nb_ring_out++;
                child->nb_ring_in++;
            }
        }
    }
    #endif

    /*----------------------------End of topology construction-----------------------------------------*/

    /* Print pipeline topology */
    MEILI_LOG_INFO("Pipeline stages initialized");
    MEILI_LOG_INFO("Total %d stage(s)", nb_pl_stages);
    printf("%8s %16s %16s %16s %16s\n","Stage","Type","# Instance","# RING_IN","# RING_OUT");
    #ifdef SHARED_BUFFER
    for(int i=0; i<nb_pl_stages; i++){
        self = pl->stages[i][0];
        printf("%8d ", i);
        PRINT_STAGE_TYPE(stage_types[i]);
        printf("%16d %16d %16d\n", nb_inst_per_pl_stage[i], 1, 1);
        
    }
    #else
    for(int i=0; i<nb_pl_stages; i++){
        self = pl->stages[i][0];
        printf("%8d ", i);
        PRINT_STAGE_TYPE(stage_types[i]);
        printf("%16d %16d %16d\n", nb_inst_per_pl_stage[i], 1, 1);
        
    }
    #endif

    return 0;
}

int pipeline_free(struct pipeline *pl){
    int nb_pl_stages = pl->nb_pl_stages;
    enum pipeline_type *stage_types = pl->stage_types;
    int *nb_inst_per_pl_stage = pl->nb_inst_per_pl_stage;
    struct pipeline_stage *self = NULL;

    int ret = 0;

    /* free each stage */
    for(int i=0; i<nb_pl_stages ; i++){
        for(int j=0; j<nb_inst_per_pl_stage[i]; j++){
            self = pl->stages[i][j];
            ret = pipeline_stage_free_safe(self);
            // if(ret){
            //     return ret;
            // }
        }
    }

    /* free stage-specific states */
    seq_free(&pl->seq_stage);
    reorder_free(&pl->reorder_stage);

    /* free rings*/
    // if(pl->ring_in){
    //     rte_ring_free(pl->ring_in);
    // }
    // if(pl->ring_out){
    //     rte_ring_free(pl->ring_out);
    // }
    
    /* free mempool */
    if(pl->mbuf_pool){
        rte_mempool_free(pl->mbuf_pool);
    }
}

static int
launch_worker(void *args)
{
	struct pipeline_stage *self = args;
	int ret;
    
    MEILI_LOG_INFO("worker qid %d on socket %d launched",self->worker_qid, rte_socket_id());
	/* Kick off a pipeline stage thread for this worker. */
    ret = pipeline_stage_run_safe(self);

    //printf("worker finished\n");

	return ret;
}


int pipeline_post_search(struct pipeline *pl){
    struct pipeline_stage *seq_stage;
	struct pipeline_stage *reorder_stage = &pl->reorder_stage;

	struct rte_mbuf *mbuf[MAX_PKTS_BURST];
	struct rte_mbuf *mbuf_out[MAX_PKTS_BURST];

    int batch_size = pl->pl_conf.input_batches;

    int batch_cnt = -1;
	int nb_deq;

    int ring_out_index = 0;
    int nb_ring_out = pl->nb_inst_per_pl_stage[pl->nb_pl_stages-1];

    /* flush all packets from the pipeline */
    while(batch_cnt != 0){
        //test
        #ifdef SHARED_BUFFER
        batch_cnt = rte_ring_dequeue_burst(pl->ring_out,(void *)mbuf_out, batch_size, NULL);
        #else
        batch_cnt = rte_ring_dequeue_burst(pl->ring_out[ring_out_index],(void *)mbuf_out, batch_size, NULL);
        ring_out_index = (ring_out_index+1)%nb_ring_out;
        #endif

        // test
	    //reorder_exec(reorder_stage, mbuf, batch_cnt, mbuf_out, &nb_deq);
        nb_deq = batch_cnt;

        for (int i = 0; i < nb_deq; i++) {
            // rm_stats->tx_buf_cnt++;
            // rm_stats->tx_buf_bytes += mbuf_out[i]->data_len;
            /* here we simply free the mbuf */
            if (rte_mbuf_refcnt_read(mbuf_out[i]) == 1) {
                //printf("freeing pkts\n");
                rte_pktmbuf_detach_extbuf(mbuf_out[i]);
                rte_pktmbuf_free(mbuf_out[i]);
            }
        }
    }
    
    return 0;
}

int pipeline_run(struct pipeline *pl){
    unsigned int lcore_id;
    /* main core takes 0 */
	uint32_t worker_qid = 0;

    struct pipeline_conf *pl_conf = &(pl->pl_conf);
    rb_stats_t *stats = pl->pl_conf.stats;

    struct pipeline_conf *run_conf = &(pl->pl_conf);
    

    int nb_pl_stages = pl->nb_pl_stages;
    int *nb_inst_per_pl_stage = pl->nb_inst_per_pl_stage;
    struct pipeline_stage *self = NULL;

    int ret;
    char err[ERR_STR_SIZE] = {0};

    int i=0;
    int j=0;

    
    // launch workers and main core
    MEILI_LOG_INFO("Total cores: %d", pl_conf->cores);
    MEILI_LOG_INFO("Total stage instances: %d", pl->nb_pl_stage_inst);
    if (pl->nb_pl_stage_inst >= pl_conf->cores){
        MEILI_LOG_ERR("Not enough cores for workers");
        return -EINVAL; 
    }

    run_conf->running = true;

    // allocate core for each pipeline stage
    // lcore_id - the id of assigned lcore
    // worker_qid - the id of stats recording
    worker_qid = 1;
    
    RTE_LCORE_FOREACH_WORKER(lcore_id) {

        if(i >= nb_pl_stages){
            printf("Lcores more than # of PL stages\n");
            break;
        }

        self = pl->stages[i][j];

		stats->rm_stats[worker_qid].lcore_id = lcore_id;
        stats->rm_stats[worker_qid].self = self;

		self->core_id = lcore_id;
        self->worker_qid = worker_qid;

        /* if the stage has substage, assign core id and worker qid as well */
        if(self->has_substage){
            struct app_state *mystate = (struct app_state *)self->state;
            for(int sub_index=0; sub_index<mystate->nb_stage; sub_index++){
                mystate->stages[sub_index]->core_id = lcore_id;
                mystate->stages[sub_index]->worker_qid = worker_qid;    
            }
        }

        worker_qid++;
        #ifndef BASELINE_MODE
        MEILI_LOG_INFO("starting core %d, worker_qid %d", lcore_id, self->worker_qid);
		ret = rte_eal_remote_launch(launch_worker, self, lcore_id);
        if(ret){
            MEILI_LOG_ERR("Failed to launch core %d, worker_qid %d", lcore_id, self->worker_qid);
            goto post_run;
        }
        #endif

        /* launch next pl stage */
        j++;
        if(j >= nb_inst_per_pl_stage[i]){
            j = 0;
            i++;
        }
	}
   

	/* Start processing on the main lcore. */
	/* traffic is always received on main core and can be split to other cores */

    stats->rm_stats[0].self = &pl->seq_stage;

    MEILI_LOG_INFO("starting on main core...");
    ret = run_mode_launch(pl);
	

    /* main thread finished processing */
post_run:
    /* set running flag to false to notice all workers of end of run */
    run_conf->running = false;

	if (ret) {
        MEILI_LOG_ERR("Failure in run mode");
	}

    //printf("main thread running=%d, finished running\n",run_conf->running);
    
	/* Wait on results from any ops that are in flight. */
	pipeline_post_search(pl);

	/* Wait on all threads/lcore processing to complete. */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		ret = rte_eal_wait_lcore(lcore_id);
        MEILI_LOG_INFO("Core %d finished processing", lcore_id);
		if(ret) {
            snprintf(err, ERR_STR_SIZE, "Lcore %u returned a runtime error", lcore_id);
            MEILI_LOG_ERR("Lcore %u returned a runtime error", lcore_id);
        }		
	}

    return ret;
}


void 
stats_update_time_main(struct rte_mbuf **mbuf, int nb_mbuf, struct pipeline *pl)
{
	struct pipeline_conf *run_conf = &pl->pl_conf;
	regex_stats_t *stats = &run_conf->stats->regex_stats[0];
	rxp_stats_t *rxp_stats = (rxp_stats_t *)stats->custom;

	uint64_t time_diff;
	uint64_t time_end, time_start;

	uint32_t seq_num;
	int sample;
    int sample_index;

	int offset1;
	int offset2;

    struct pipeline_stage *self;
    struct pipeline_stage *parent;

	// struct pkt_ts_state *mystate1 = (struct pkt_ts_state *)pl->ts_start_stage.state;
	// struct pkt_ts_state *mystate2 = (struct pkt_ts_state *)pl->ts_end_stage.state;

    
	for(int i=0; i<nb_mbuf; i++){
		/* Calculate and store latency of packet through HW. */
		//time_mbuf = util_get_64_bit_from_2_32(&mbuf->dynfield1[DF_TIME_HIGH]);

		// OR
        stats = &run_conf->stats->regex_stats[0];
	    rxp_stats = (rxp_stats_t *)stats->custom;
        offset1 = pl->ts_start_offset;
	    offset2 = pl->ts_end_offset;

		time_start  = *(RTE_MBUF_DYNFIELD(mbuf[i], offset1, uint64_t *));
		time_end = *(RTE_MBUF_DYNFIELD(mbuf[i], offset2, uint64_t *));
		
		time_diff = (time_end - time_start);

		rxp_stats->tot_lat += time_diff;
		if (time_diff < rxp_stats->min_lat)
			rxp_stats->min_lat = time_diff;
		if (time_diff > rxp_stats->max_lat)
			rxp_stats->max_lat = time_diff;
        
        #ifdef PKT_LATENCY_SAMPLE_ON
        rxp_stats->time_diff_sample[rxp_stats->nb_sampled & NUMBER_OF_SAMPLE] = time_diff;
        rxp_stats->nb_sampled++;  
        #endif
        
        #ifdef PKT_LATENCY_BREAKDOWN_ON
        /* record breakdown latency of pipeline stages */
        // seq_num = *rte_reorder_seqn(mbuf[i]);
		// sample = seq_num % NUMBER_OF_SAMPLE;
        /* pl's tot in latency, temporarily used for queuing latency between last stage and final processing */
        self = pl->stages[pl->nb_pl_stages-1][0];
        // mystate1 = (struct pkt_ts_state *)self->ts_start_stage.state;
        // mystate2 = (struct pkt_ts_state *)pl->ts_end_stage.state;
        offset1 = self->ts_end_offset;
        offset2 = pl->ts_end_offset;
        time_start  = *(RTE_MBUF_DYNFIELD(mbuf[i], offset1, uint64_t *));
        time_end = *(RTE_MBUF_DYNFIELD(mbuf[i], offset2, uint64_t *));
        
        time_diff = (time_end - time_start);

        rxp_stats->tot_in_lat += time_diff;

        /* traverse pl stages */
        // TODO: only register one dynfield for each layer of pipeline, instead of each instance
        for(int j=0; j<pl->nb_pl_stages; j++){
            for(int k=0; k<pl->nb_inst_per_pl_stage[j]; k++){
                // if(i=0){
                //     printf("self->worker_qid = %d\n",self->worker_qid);
                // }
                    self = pl->stages[j][k];
                	stats = &run_conf->stats->regex_stats[self->worker_qid];
	                rxp_stats = (rxp_stats_t *)stats->custom;
                    //mystate1 = (struct pkt_ts_state *)self->ts_start_stage.state;

                    /* self's tot in latency */
                    if(j==0){
                        //mystate2 = (struct pkt_ts_state *)pl->ts_start_stage.state;
                        offset2 = pl->ts_start_offset;
                    }
                    else{
                        parent = pl->stages[j-1][0];
                        //mystate2 = (struct pkt_ts_state *)parent->ts_end_stage.state;
                        offset2 = parent->ts_end_offset;
                    }
                    offset1 = self->ts_start_offset;
	                
                    time_end  = *(RTE_MBUF_DYNFIELD(mbuf[i], offset1, uint64_t *));
                    time_start = *(RTE_MBUF_DYNFIELD(mbuf[i], offset2, uint64_t *));
                    
                    time_diff = (time_end - time_start);

                    rxp_stats->tot_in_lat += time_diff;

                    /* self's tot latency */
                    //mystate2 = (struct pkt_ts_state *)self->ts_end_stage.state;
                    offset2 = self->ts_end_offset;
                    time_start = *(RTE_MBUF_DYNFIELD(mbuf[i], offset1, uint64_t *));
                    time_end = *(RTE_MBUF_DYNFIELD(mbuf[i], offset2, uint64_t *));
                    
                    time_diff = (time_end - time_start);

                    rxp_stats->tot_lat += time_diff;
            }
        }   
    #endif 
	}

}


void
extbuf_free_cb(void *addr __rte_unused, void *fcb_opaque __rte_unused)
{
}
