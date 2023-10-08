#ifndef _INCLUDE_MONITOR_CMS_H
#define _INCLUDE_MONITOR_CMS_H

#include <stdint.h>
#include <rte_mbuf.h>


#include "../lib/cms/count-min-sketch.h"

struct monitor_cms_state{
    uint64_t *cm_sketch; 

};

#endif /* _INCLUDE_MONITOR_CMS_H */