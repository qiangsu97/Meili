#ifndef _INCLUDE_FW_H
#define _INCLUDE_FW_H


#include <stdint.h>
#include <rte_mbuf.h>
#include "../../runtime/meili_runtime.h"

#define APP_FW_NB_STAGE 2

enum pipeline_type app_fw_stage_map[APP_FW_NB_STAGE] = {
    PL_MONITOR_HLL,
    PL_FIREWALL_ACL
};

#endif /* _INCLUDE_FW_H */
