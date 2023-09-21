#ifndef _INCLUDE_ECHO_H
#define _INCLUDE_ECHO_H

#include <stdint.h>
#include <rte_mbuf.h>

#define PRINT_CONTENT "this is a test pipeline stage\n"

struct echo_state{
    char *content; 
};

#endif /* _INCLUDE_ECHO_H */

