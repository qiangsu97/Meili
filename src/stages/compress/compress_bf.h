#ifndef _INCLUDE_COMPRESS_H
#define _INCLUDE_COMPRESS_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_compressdev.h>

#define NB_OUTPUT_BUFS_MAX 1024

#define NUM_MAX_XFORMS 16
#define NUM_MAX_INFLIGHT_OPS 512

#define MAX_RANGE_LIST		32

/* Cleanup state machine */
enum cleanup_st {
	ST_CLEAR = 0,
	ST_TEST_DATA,
	ST_COMPDEV,
	ST_INPUT_DATA,
	ST_MEMORY_ALLOC,
	ST_DURING_TEST
};

enum comp_operation {
	COMPRESS_ONLY,
	DECOMPRESS_ONLY,
	COMPRESS_DECOMPRESS
};

struct range_list {
	uint8_t min;
	uint8_t max;
	uint8_t inc;
	uint8_t count;
	uint8_t list[MAX_RANGE_LIST];
};



struct compress_bf_state{
    char driver_name[RTE_DEV_NAME_MAX_LEN];
    int cdev_id;
    //uint16_t nb_qps;
    unsigned int dev_qid;

	/* enqueue batch size */
	int batch_size;

    /* compression algorithm */
    enum rte_comp_algorithm algo;

    /* parameters for deflate and lz4 respectively */
    union {
        enum rte_comp_huffman huffman_enc;
        uint8_t flags;
    }algo_config;

    /* compression operations buffer */
    struct rte_comp_op **ops;
    enum comp_operation test_op;
    struct rte_comp_op **deq_ops;

    /* ring buffer to store compressed result */
    struct rte_mbuf *output_bufs[NB_OUTPUT_BUFS_MAX];
    uint32_t buf_id; /* output buf index */
    uint32_t out_seg_sz;

    /* xform for compression */
    void *priv_xform;
	
	uint16_t max_sgl_segs;
	uint32_t total_segs;

	int window_sz;
	struct range_list level_lst;
	uint8_t level;
	int use_external_mbufs;

	double ratio;
	enum cleanup_st cleanup;

	int wait_on_dequeue;
};

#endif /* _INCLUDE_COMPRESS_H */

