#ifndef _INCLUDE_APP_IPSEC_GW_H
#define _INCLUDE_APP_IPSEC_GW_H

#include <stdint.h>
#include <rte_mbuf.h>
#include "../../pipeline.h"

#define APP_IPSEC_GW_STAGE (4-1) /* AES is using a remote accelerator */

enum pipeline_type app_ipsec_gw_stage_map[APP_IPSEC_GW_STAGE + 1] = {
    PL_DDOS,
    PL_REGEX_BF,
    PL_SHA,
    PL_AES
};

// struct app_ids_state{
//     int placeholder;
// };


#endif/* _INCLUDE_APP_IPSEC_GW_H */