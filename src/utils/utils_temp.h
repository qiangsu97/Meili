

#ifndef _INCLUDE_UTILS_TEMP_H_
#define _INCLUDE_UTILS_TEMP_H_

#include <stdint.h>
#include <string.h>
#include "./cJSON/cJSON.h"

#define WARNING_MARKER "\n******************************************************************\n"


/* json file processing */
cJSON* until_parse_json_file(const char* filename);
int json_get_item_count(cJSON* config); 



#endif /* _INCLUDE_UTILS_TEMP_H_ */
