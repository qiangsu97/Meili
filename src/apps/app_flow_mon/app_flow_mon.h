#ifndef _INCLUDE_APP_FLOW_MON_H
#define _INCLUDE_APP_FLOW_MON_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "../../runtime/meili_runtime.h"

#define APP_FLOW_MON_NB_STAGE 2

enum pipeline_type app_flow_mon_stage_map[APP_FLOW_MON_NB_STAGE] = {
    PL_MONITOR_CMS,
    PL_MONITOR_HLL
};

#endif/* _INCLUDE_APP_FLOW_MON_H */
