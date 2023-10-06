#ifndef _INCLUDE_APP_API_GW_H
#define _INCLUDE_APP_API_GW_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "../../runtime/meili_runtime.h"

#define APP_API_GW_NB_STAGE 1

enum pipeline_type app_api_gateway_stage_map[APP_API_GW_NB_STAGE] = {
    PL_API_GATEWAY
};

// struct app_api_gw_state{
//     int placeholder;
// };


#endif/* _INCLUDE_APP_API_GW_H */
