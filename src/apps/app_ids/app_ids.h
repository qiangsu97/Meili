#ifndef _INCLUDE_APP_IDS_H
#define _INCLUDE_APP_IDS_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "../../pipeline.h"

#define APP_IDS_NB_STAGE 3

enum pipeline_type app_ids_stage_map[APP_IDS_NB_STAGE] = {
    PL_MONITOR_CMS,
    PL_DDOS,
    PL_REGEX_BF
};



#endif/* _INCLUDE_APP_IDS_H */