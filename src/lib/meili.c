#include <stdlib.h>
#include <stdio.h>

#include "meili.h"

volatile struct _meili_apis Meili;

/* pkt_trans
*   - Run a packet transformation operation specified by UCO.  
*/

/* pkt_flt
*   - Filter packets with the operation specified by UCO.
*/

/* flow_ext
*   - Construct flows from a stream based on UCO.
*/


/* flow_trans
*   - Run a flow transformation operation specified by UCO.
*/

/* reg_sock
*   - Register an established socket to Meili.
*/

/* epoll
*   - Process an event on the socket with the operation specified by UCO.
*/

/* regex
*   - The built-in Regular Expression API.   
*/
/* AES
*   - The built-in AES Encryption API.
*/
/* compression
*   - The built-in Compression API.
*/

void register_meili_apis(){
    Meili.pkt_trans     = pkt_trans;
    Meili.pkt_flt       = pkt_flt;
    Meili.flow_ext      = flow_ex;
    Meili.flow_trans    = flow_trans; 
    Meili.reg_sock      = reg_sock;
    Meili.epoll         = epoll;
    Meili.regex         = regex;
    Meili.AES           = AES;
    Meili.compression   = compression;
    return;
}