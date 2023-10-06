#ifndef _INCLUDE_IPCOMP_GW_H
#define _INCLUDE_IPCOMP_GW_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "../../runtime/meili_runtime.h"

#define APP_IPCOMP_GW_NB_STAGE 2

enum pipeline_type app_ipcomp_gw_stage_map[APP_IPCOMP_GW_NB_STAGE] = {
    PL_DDOS,
    PL_COMPRESS_BF
};

#endif /* _INCLUDE_IPCOMP_GW_H */