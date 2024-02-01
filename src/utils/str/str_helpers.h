#ifndef _STR_HELPERS_H
#define _STR_HELPERS_H

#define MASK_UPPER_32  0xFFFFFFFF00000000LL
#define MASK_LOWER_32  0xFFFFFFFFLL

#define IS_NULL_OR_EMPTY_STRING(s) ((s) == NULL || strncmp(s, "", 1) == 0 ? 1 : 0)

int util_load_file_to_buffer(const char *file, char **buf, uint64_t *buf_len, uint32_t max_len);

char *util_trim_whitespace(char *input);

int util_str_to_dec(char *str, long *output, int max_bytes);

#endif