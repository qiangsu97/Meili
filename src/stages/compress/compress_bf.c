/*
 * compress_bf
 * - data compress_bfion leveraging hardware accelerator on Bluefield-2    
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_compressdev.h>
#include "compress_bf.h"
#include "../../pipeline.h"
#include "../../utils/log/log.h"
#include "../../utils/rte_reorder/rte_reorder.h"


struct rte_mbuf *test_mbufs[64];

// TODO
static int
compress_check_capabilities(struct compress_bf_state *mystate, uint8_t cdev_id)
{
	const struct rte_compressdev_capabilities *cap;

	cap = rte_compressdev_capability_get(cdev_id, mystate->algo);

	if (cap == NULL) {
		MEILI_LOG_ERR("Compress device does not support DEFLATE");
		return -1;
	}

	uint64_t comp_flags = cap->comp_feature_flags;

	/* Huffman encoding */
	if (mystate->algo_config.huffman_enc == RTE_COMP_HUFFMAN_FIXED &&
			(comp_flags & RTE_COMP_FF_HUFFMAN_FIXED) == 0) {
		MEILI_LOG_ERR("Compress device does not supported Fixed Huffman");
		return -1;
	}

	if (mystate->algo_config.huffman_enc == RTE_COMP_HUFFMAN_DYNAMIC &&
			(comp_flags & RTE_COMP_FF_HUFFMAN_DYNAMIC) == 0) {
		MEILI_LOG_ERR("Compress device does not supported Dynamic Huffman");
		return -1;
	}

	// /* Window size */
	// if (mystate->window_sz != -1) {
	// 	if (param_range_check(mystate->window_sz, &cap->window_size)
	// 			< 0) {
	// 		MEILI_LOG_ERR(
	// 			"Compress device does not support "
	// 			"this window size\n");
	// 		return -1;
	// 	}
	// } else
	// 	/* Set window size to PMD maximum if none was specified */
	// 	mystate->window_sz = cap->window_size.max;

	/* Check if chained mbufs is supported */
	//printf("max_sgl_segs setting: %d\n",mystate->max_sgl_segs);
	if (mystate->max_sgl_segs > 1  &&
			(comp_flags & RTE_COMP_FF_OOP_SGL_IN_SGL_OUT) == 0) {
		MEILI_LOG_WARN("Compress device does not support "
				"chained mbufs. Max SGL segments set to 1");
		mystate->max_sgl_segs = 1;
	}

	/* Level 0 support */
	if (mystate->level_lst.min == 0 &&
			(comp_flags & RTE_COMP_FF_NONCOMPRESSED_BLOCKS) == 0) {
		MEILI_LOG_ERR("Compress device does not support "
				"level 0 (no compression)");
		return -1;
	}

	return 0;
}

void
compress_state_default(struct compress_bf_state *mystate)
{	
	mystate->cdev_id = 0;
	const struct rte_compressdev_capabilities *cap 
	 			= rte_compressdev_capability_get(mystate->cdev_id, RTE_COMP_ALGO_DEFLATE);
	
	strlcpy(mystate->driver_name, "mlx5", sizeof(mystate->driver_name));

	mystate->algo= RTE_COMP_ALGO_DEFLATE;
	mystate->algo_config.huffman_enc = RTE_COMP_HUFFMAN_DYNAMIC;
	mystate->test_op = COMPRESS_ONLY;

	mystate->window_sz = cap->window_size.max;
	mystate->buf_id = 0;
	mystate->out_seg_sz = 2048;
	mystate->max_sgl_segs = 1;

	mystate->level = RTE_COMP_LEVEL_MIN;
	mystate->level_lst.min = RTE_COMP_LEVEL_MIN;
	mystate->level_lst.max = RTE_COMP_LEVEL_MAX;
	mystate->level_lst.inc = 0;
	mystate->use_external_mbufs = 0;

}

static int
initialize_compressdev(struct pipeline_stage *self)
				 //uint8_t *enabled_cdevs)
{
	struct compress_bf_state *mystate = (struct compress_bf_state *)self->state;
	uint8_t enabled_cdev_count, nb_lcores, cdev_id;
	unsigned int i, j;
	int ret;
	uint8_t enabled_cdevs[RTE_COMPRESS_MAX_DEVS];

	enabled_cdev_count = rte_compressdev_devices_get(mystate->driver_name,
			enabled_cdevs, RTE_COMPRESS_MAX_DEVS);
	if (enabled_cdev_count == 0) {
		MEILI_LOG_ERR("No compress devices type %s available,"
				    " please check the list of specified devices in EAL section",
				mystate->driver_name);
		return -EINVAL;
	}

	// //nb_lcores = rte_lcore_count() - 1;
	// nb_lcores = rte_lcore_count();
	// printf("nb_lcores=%d\n",nb_lcores);
	/*
	 * Use fewer devices,
	 * if there are more available than cores.
	 */
	// if (enabled_cdev_count > nb_lcores) {
	// 	if (nb_lcores == 0) {
	// 		MEILI_LOG_ERR( "Cannot run with 0 cores! Increase the number of cores\n");
	// 		return -EINVAL;
	// 	}
	// 	enabled_cdev_count = nb_lcores;
	// 	MEILI_LOG_ERR(INFO, USER1,
	// 		"There's more available devices than cores!"
	// 		" The number of devices has been aligned to %d cores\n",
	// 		nb_lcores);
	// }

	/* use one of the cdev */
	/* TODO: load balancing if there are more than one cdev */
	cdev_id = enabled_cdevs[0];
	mystate->cdev_id = cdev_id;

	struct rte_compressdev_info cdev_info;
	int socket_id = rte_compressdev_socket_id(cdev_id);

	rte_compressdev_info_get(cdev_id, &cdev_info);
	//printf("max_nb_queue_pairs: %d\n",cdev_info.max_nb_queue_pairs);
	if (!cdev_info.max_nb_queue_pairs) {
		MEILI_LOG_ERR("The maximum number of queue pairs per device is zero.");
		return -EINVAL;
	}

	// if (cdev_info.max_nb_queue_pairs
	// 	&& mystate->nb_qps > cdev_info.max_nb_queue_pairs) {
	// 	MEILI_LOG_ERR("Number of needed queue pairs is higher "
	// 		"than the maximum number of queue pairs "
	// 		"per device.");
	// 	return -EINVAL;
	// }

	if (compress_check_capabilities(mystate, cdev_id) < 0){
		return -EINVAL;
	}
		
	/* Configure compressdev */
	/* TODO: this part should be moved to runtime configuration of the whole pipeline,
	 *		as different application may share the compress device, and the device need to be 
	 *		confgiured only once before applications start to utilize the accelerators
	 */
	struct rte_compressdev_config config = {
		.socket_id = socket_id,
		//.nb_queue_pairs = mystate->nb_qps,
		.nb_queue_pairs = 1,
		.max_nb_priv_xforms = NUM_MAX_XFORMS,
		.max_nb_streams = 0
	};
	// mystate->nb_qps = config.nb_queue_pairs;

	if (rte_compressdev_configure(cdev_id, &config) < 0) {
		MEILI_LOG_ERR("Compress device %d configuration failed",cdev_id);
		return -EINVAL;
	}

	for (j = 0; j < 1; j++) {
		ret = rte_compressdev_queue_pair_setup(cdev_id, j,
				NUM_MAX_INFLIGHT_OPS, socket_id);
		if (ret < 0) {
			MEILI_LOG_ERR("Failed to setup queue pair %u on compressdev %u",j, cdev_id);
			return -EINVAL;
		}
		mystate->dev_qid = j;
	}

	ret = rte_compressdev_start(cdev_id);
	if (ret < 0) {
		MEILI_LOG_ERR("Failed to start device %u: error %d\n", cdev_id, ret);
		return -EPERM;
	}
	

	return enabled_cdev_count;
}


int
compress_bf_init(struct pipeline_stage *self)
{
    /* allocate space for pipeline state */
    self->state = (struct compress_bf_state *)malloc(sizeof(struct compress_bf_state));
    struct compress_bf_state *mystate = (struct compress_bf_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    //memset(self->state, 0x00, sizeof(struct compress_bf_state));


    /* initialize fields */
	int dev_id = 0;
	int nb_compressdevs = 0;

	compress_state_default(mystate);

	nb_compressdevs = initialize_compressdev(self);

	if (nb_compressdevs < 1) {
		MEILI_LOG_ERR("No available compression device");
		return -EINVAL;
	}
	
	struct rte_comp_xform xform = (struct rte_comp_xform) {
		.type = RTE_COMP_COMPRESS,
		.compress = {
			.algo = RTE_COMP_ALGO_DEFLATE,
			//.algo = RTE_COMP_ALGO_LZ4,
			.deflate.huffman = mystate->algo_config.huffman_enc,
			//.lz4.flags = 
			.level = mystate->level,
			.window_size = mystate->window_sz,
			.chksum = RTE_COMP_CHECKSUM_NONE,
			.hash_algo = RTE_COMP_HASH_ALGO_NONE
		}
	};


	if (rte_compressdev_private_xform_create(dev_id, &xform, &mystate->priv_xform) < 0) {
		MEILI_LOG_ERR("Private xform could not be created");
		return -EINVAL;
	}

	/* allocate space for compression operations */
	mystate->ops = (struct rte_comp_op **)rte_zmalloc_socket(NULL,
					sizeof(struct rte_comp_op *) * self->batch_size, 0, rte_socket_id());
	mystate->deq_ops = (struct rte_comp_op **)rte_zmalloc_socket(NULL,
				sizeof(struct rte_comp_op *) * self->batch_size, 0, rte_socket_id());
	
	for(int i=0; i<self->batch_size ; i++){
		mystate->ops[i] = (struct rte_comp_op *)rte_malloc(NULL, sizeof(struct rte_comp_op), 0);
		if (!mystate->ops[i]){
			MEILI_LOG_ERR("Allocation of input compression operations failed");
			return -ENOMEM;
		}	
	}

	// test
	char pool_name[128];
	uint8_t *data_addr;
	struct rte_mempool *mbuf_pool = NULL;
	// char input_data_ptr[1024];
	// memset(input_data_ptr, 0x00, 1024);
	// snprintf(pool_name, sizeof(pool_name), "decomp_buf_pool_%u_qp_%u",
	// 		0, 0);
	// // mbuf_pool = pl->mbuf_pool;
	// rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(pool_name,
	// 			1024,
	// 			0, 0,
	// 			1024,
	// 			rte_socket_id());
	// struct pipeline *pl = (struct pipeline *)self->pl;
		
	// //debug
	// snprintf(pool_name, sizeof(pool_name), "debug_pool_%u_qp_%u",
	// 		0, 0);
	// //struct rte_mempool *mbuf_pool = pl->mbuf_pool;
	// mbuf_pool = rte_pktmbuf_pool_create(pool_name,
	// 			2048,
	// 			0, 0,
	// 			2048,
	// 			rte_socket_id());

	// for(int i=0; i<64; i++){
	// 	test_mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
	// 	if(!test_mbufs[i]){
	// 		printf("Could not allocate mbuf\n");
	// 		return -1;
	// 	}
	// 	test_mbufs[i]->data_len = 1024;
    //     test_mbufs[i]->pkt_len = 1024;
	// 	data_addr = rte_pktmbuf_mtod(test_mbufs[i], char *);
	// 	// data_addr = (uint8_t *) rte_pktmbuf_append(
	// 	// 			test_mbufs[i], 1024);
	// 	// if (data_addr == NULL) {
	// 	// 	printf("Could not append data\n");
	// 	// 	return -1;
	// 	// }
	// 	//rte_memcpy(data_addr, input_data_ptr, 1024);
	// }

	/* allocate space for destination bufs for storing compressed/decompressed result */
	snprintf(pool_name, sizeof(pool_name), "comp_buf_pool_%u_qp_%u",
			0, 0);
	//struct rte_mempool *mbuf_pool = pl->mbuf_pool;
	mbuf_pool = rte_pktmbuf_pool_create(pool_name,
				2048,
				0, 0,
				2048,
				rte_socket_id());
	
	for(int i=0; i<NB_OUTPUT_BUFS_MAX ; i++){
		mystate->output_bufs[i] = rte_pktmbuf_alloc(mbuf_pool);
		if (!mystate->output_bufs[i]){
			MEILI_LOG_ERR("Allocation of output compressed/decompressed bufs failed");
			return -ENOMEM;
		}	
		mystate->output_bufs[i]->data_len = mystate->out_seg_sz;
		mystate->output_bufs[i]->pkt_len = mystate->out_seg_sz;
	}

	

	// data_addr = (uint8_t *) rte_pktmbuf_append(
	// 				mem->comp_bufs[i],
	// 				mystate->out_seg_sz);
	// if (data_addr == NULL) {
	// 	MEILI_LOG_ERR( "Could not append data\n");
	// 	return -1;
	// }


	mystate->wait_on_dequeue = 0;

    return 0;
}

int
compress_bf_free(struct pipeline_stage *self)
{
    struct compress_bf_state *mystate = (struct compress_bf_state *)self->state;

	rte_compressdev_stop(mystate->cdev_id);
	rte_compressdev_close(mystate->cdev_id);
    
	rte_compressdev_private_xform_free(mystate->cdev_id, mystate->priv_xform);
	
	for(int i=0; i<self->batch_size ; i++){
		rte_free(mystate->ops[i]);	
	}
	rte_free(mystate->ops);

	// for(int i=0; i<NB_OUTPUT_BUFS_MAX ; i++){
	// 	rte_free(mystate->output_bufs[i]);
	// }

	free(mystate);
    return 0;
}



static void
compress_bf_dequeue(struct pipeline_stage *self, int nb_enq,
                            struct rte_mbuf **mbuf_out,
                            int *nb_deq)
{
	
	struct compress_bf_state *mystate = (struct compress_bf_state*)self->state;
	int qid = mystate->dev_qid;
	int cdev_id = mystate->cdev_id;
	// regex_stats_t *stats = mystate->regex_stats;

	// rxp_stats_t *rxp_stats = (rxp_stats_t *)stats->custom;

	struct rte_comp_op **ops;
	uint16_t tot_dequeued = 0;

	struct rte_mbuf *mbuf;

	int batch_size = self->batch_size;

	/* lat mode off, nb_enq should always be zero */
	uint16_t wait_on_dequeue = nb_enq;
	
	uint16_t num_dequeued;
	int out_offset = *nb_deq;

	ops = mystate->deq_ops;

	/* Poll the device until no more matches are received. */
	do {
		num_dequeued = rte_compressdev_dequeue_burst(cdev_id, qid, ops, batch_size);
		if(num_dequeued>0){
			//printf("dequeue=%d\n",num_dequeued);
			;
		}
		

		for (int i = 0; i < num_dequeued; i++) {
			mbuf = ops[i]->m_src;
			/* put mbuf into out buffer */
			mbuf_out[out_offset + i] = mbuf;
			
			// TODO: add post-processing
			//compress_bf_process_resp(qid, ops[i], stats);
			rte_pktmbuf_free(ops[i]->m_dst);
			
		}

		tot_dequeued += num_dequeued;
		out_offset += num_dequeued;

	} while (tot_dequeued < wait_on_dequeue);

	/* update # of dequeued mbufs, out_offset is assigned as nb_deq previously, so assign updated value back to nb_deq */
	*nb_deq = out_offset;
}


static inline int
compress_bf_enq_deq_ops(struct pipeline_stage *self, int nb_enq,
                            struct rte_mbuf **mbuf_out,
                            int *nb_deq)

{
	//int qid = self->worker_qid;
	
	struct compress_bf_state *mystate = (struct compress_bf_state*)self->state;
	int batch_size = self->batch_size;
	int qid = mystate->dev_qid;
	int cdev_id = mystate->cdev_id;

	//rxp_stats_t *rxp_stats = (rxp_stats_t *)stats->custom;
	//uint16_t to_enqueue = core_vars[qid].op_offset;
	uint16_t to_enqueue = nb_enq;

	struct rte_comp_op **ops;
	uint16_t num_enqueued = 0;
	uint16_t num_ops;

	uint16_t ret;

    /* do not turn on lat mode so do not wait until all ops of this round to dequeue and process in a pipeline manner */
	bool lat_mode = 0;

	//printf("nb_enq=%d, op_offset=%d, to_enqueue=%d\n",nb_enq,core_vars[qid].op_offset,to_enqueue);
	/* Loop until all ops are enqueued. */

	//debug
	//nb_enq = 64;


	to_enqueue = nb_enq;

	while (num_enqueued < nb_enq) {
		//printf("enqueuing\n");
		ops = &mystate->ops[num_enqueued];
		
		/* Note that to_enqueue is always <= batch_size of this pl stage */
		num_ops = RTE_MIN(batch_size, to_enqueue);
		// printf("cdev_id=%d, qid=%d\n",cdev_id, qid);
		// printf("num_ops=%d\n",num_ops);
		//printf("in: sample seq num=%d\n",*rte_reorder_seqn(ops[0]->m_src));
		ret = rte_compressdev_enqueue_burst(cdev_id, qid, ops, num_ops);

		//debug
		//ret = rte_compressdev_enqueue_burst(cdev_id, qid, ops, 1);
		//printf("enqueue=%d\n",ret);

		num_enqueued += ret;
		to_enqueue -= ret;
		//printf("dequeuing\n");
		/* dequeue operations and put them into mbuf_out, update *nb_deq at the same time */
		compress_bf_dequeue(self, 0, mbuf_out, nb_deq);
	}
	
	//core_vars[qid].total_enqueued += num_enqueued;


	return 0;
}

int compress_bf_prep_op(struct rte_mbuf **mbufs, int total_ops, struct pipeline_stage *self){
	
	struct compress_bf_state *mystate = (struct compress_bf_state *)self->state;
	
	struct rte_mbuf **output_bufs = mystate->output_bufs;
	uint32_t buf_id = mystate->buf_id;
	void *priv_xform = mystate->priv_xform;
	uint32_t out_seg_sz = mystate->out_seg_sz;
	struct rte_comp_op **ops = mystate->ops;

	
	//debug 
	//total_ops = 64;

	for (int op_id = 0; op_id < total_ops; op_id++) {

		/* Reset all data in output buffers */
		struct rte_mbuf *m = output_bufs[buf_id];
		//m->pkt_len = out_seg_sz * m->nb_segs;
		m->pkt_len = out_seg_sz;
		//printf("%d\n",m->nb_segs);
		// while (m) {
		// 	m->data_len = m->buf_len - m->data_off;
		// 	m = m->next;
		// }

		ops[op_id]->m_src = mbufs[op_id];
		//debug
		//ops[op_id]->m_src = test_mbufs[op_id];
		ops[op_id]->src.offset = 0;
		ops[op_id]->src.length = rte_pktmbuf_pkt_len(mbufs[op_id]);
		//printf("length=%d\n",rte_pktmbuf_pkt_len(mbufs[op_id]));
		// debug
		//ops[op_id]->src.length = rte_pktmbuf_pkt_len(test_mbufs[op_id]);
		//printf("length=%d\n",rte_pktmbuf_pkt_len(test_mbufs[op_id]));

		ops[op_id]->m_dst = output_bufs[buf_id];
		//ops[op_id]->dst.offset = 0;
		ops[op_id]->op_type = RTE_COMP_OP_STATELESS;
		ops[op_id]->flush_flag = RTE_COMP_FLUSH_FINAL;
		ops[op_id]->input_chksum = buf_id;
		ops[op_id]->private_xform = priv_xform;

		buf_id = (buf_id+1)%NB_OUTPUT_BUFS_MAX;
	}
	mystate->buf_id = buf_id;
}


int
compress_bf_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    int qid = self->worker_qid;

	struct compress_bf_state *mystate = (struct compress_bf_state*)self->state;
	// regex_stats_t *stats = mystate->regex_stats;

	// uint16_t per_q_offset = core_vars[qid].op_offset;
	// int q_offset = qid * max_batch_size;

	//struct pipeline *pl = self->pl;
	
	// if(nb_enq>0){
	// 	printf("exec start: sample seq num=%d\n",*rte_reorder_seqn(mbuf[0]));
	// }
	

	*nb_deq = 0;
	if(nb_enq<=0 && mystate->wait_on_dequeue>0){
		compress_bf_dequeue(self, 0, *mbuf_out, nb_deq);
		// //debug
		// *mbuf_out = mbuf;
		// *nb_deq = nb_enq;
		mystate->wait_on_dequeue = mystate->wait_on_dequeue - *nb_deq;
		return 0;
	}
	else if(nb_enq<=0 && mystate->wait_on_dequeue<=0){
		return 0;
	}

	/* prepare compression operations */
	/* Get the next free op for this queue and prep request. */
	//for(int i=0; i<nb_enq; i++){
	compress_bf_prep_op(mbuf, nb_enq, self);
		//(core_vars[qid].op_offset)++;/* set the offset, which is the total number of ops to enqueue this round */
	//}

	// if(*rte_reorder_seqn(mbuf[0]) == 0){
	// 	printf("compress receive seq num sample=%d\n",*rte_reorder_seqn(mbuf[0]));
	// }
	/* Send the batched ops - this resets the ops array. */
	*nb_deq = 0;
	compress_bf_enq_deq_ops(self, nb_enq, *mbuf_out, nb_deq);
	mystate->wait_on_dequeue += nb_enq;
	// for(int i=0; i<*nb_deq; i++){
	// 	if(*rte_reorder_seqn((*mbuf_out)[i]) == 0){
	// 		printf("compress processed seq num sample=%d\n",*rte_reorder_seqn((*mbuf_out)[i]));
	// 	}
	// }
	
	//debug
	// *mbuf_out = mbuf;
	// *nb_deq = nb_enq;
	// if(*nb_deq>0){
	// 	printf("nb_deq = %d, out: sample seq num=%d\n",*nb_deq, *rte_reorder_seqn((*mbuf_out)[0]));
    
	// }
    return 0;
}


int
compress_bf_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = compress_bf_init;
	stage->funcs->pipeline_stage_free = compress_bf_free;
	stage->funcs->pipeline_stage_exec = compress_bf_exec;

	return 0;
}