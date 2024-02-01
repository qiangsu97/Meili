#include <stdio.h>
#include <stdlib.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "../lib/log/meili_log.h"
#include "utils_temp.h"
#include "./cJSON/cJSON.h"


cJSON* until_parse_json_file(const char* filename) {
        if (IS_NULL_OR_EMPTY_STRING(filename)) {
                return NULL;
        }

        FILE* fp = NULL;
        int file_length = 0;
        char temp_buf[255];
        char* tmp = NULL;
        char* line = NULL;
        char* json_str = NULL;
        int str_len = 0;

        fp = fopen(filename, "r");
        if (!fp) {
                return NULL;
        }

        fseek(fp, 0L, SEEK_END);
        file_length = ftell(fp);
        rewind(fp);

        json_str = (char*)malloc(file_length + 1);
        if (!json_str) {
                printf("Unable to allocate space for json_str\n");
                fclose(fp);
                return NULL;
        }
        tmp = json_str;

        while ((line = fgets(temp_buf, file_length, fp)) != NULL) {
                str_len = (int)strlen(line);
                memcpy(tmp, line, str_len);
                tmp += str_len;
        }

        json_str[file_length] = '\0';
        fclose(fp);

        return cJSON_Parse(json_str);
}


int
json_get_item_count(cJSON* config) {
        int arg_count = 0;

        if (config == NULL) {
                return 0;
        }

        if (config->child == NULL) {
                return 0;
        }

        cJSON* current = config->child;
        while (current != NULL) {
                ++arg_count;
                current = current->next;
        }

        return arg_count;
}
