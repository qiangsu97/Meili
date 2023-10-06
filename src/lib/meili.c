#include <stdlib.h>
#include <stdio.h>

#include "meili.h"

volatile struct _meili_apis Meili;

/* pkt_trans
*   - Run a packet transformation operation specified by UCO.  
*/
void pkt_trans(){};

/* pkt_flt
*   - Filter packets with the operation specified by UCO.
*/
void pkt_flt(){};

/* flow_ext
*   - Construct flows from a stream based on UCO.
*/
void flow_ext(){};

/* flow_trans
*   - Run a flow transformation operation specified by UCO.
*/
void flow_trans(){};

/* reg_sock
*   - Register an established socket to Meili.
*/
void reg_sock(){};

/* epoll
*   - Process an event on the socket with the operation specified by UCO.
*/
void epoll(){};

/* regex
*   - The built-in Regular Expression API.   
*/
void regex(){};

/* AES
*   - The built-in AES Encryption API.
*/
void AES(){};

/* compression
*   - The built-in Compression API.
*/
void compression(){};

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