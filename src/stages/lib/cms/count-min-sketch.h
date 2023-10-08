/*
 * Count-min Sketch header
 */
#ifndef _COUNT_MIN_SKETCH
#define _COUNT_MIN_SKETCH
#include <stdint.h>

// #define CM_ROW_NUM 6
#define CM_ROW_NUM 4
#define CM_COL_NUM 64 * 1024

// void     cm_sketch_init(uint64_t** cm_sketch);
// void     cm_sketch_free(uint64_t** cm_sketch);
uint64_t cm_sketch_read(uint64_t *cm_sketch, int row, uint32_t flow_id);
void     cm_sketch_update(uint64_t *cm_sketch, int row, uint32_t flow_id);

#endif /* _COUNT_MIN_SKETCH */
