#ifndef _INCLUDE_APP_L7_LB_H
#define _INCLUDE_APP_L7_LB_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "../../runtime/meili_runtime.h"

#define APP_L7_LB_NB_STAGE 1

enum pipeline_type app_l7_lb_stage_map[APP_L7_LB_NB_STAGE] = {
    PL_HTTP_PARSER
};

// struct app_api_gw_state{
//     int placeholder;
// };


#endif/* _INCLUDE_APP_L7_LB_H */
