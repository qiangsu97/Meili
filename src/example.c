/* Intrusion Detection */

#include "./lib/meili.h"
#include "./runtime/meili_runtime.h"
#include "example.h"


MEILI_INIT(EXAMPLE)
/* allocate space for pipeline state */
self->state = (struct (EXAMPLE)_state *)malloc(sizeof(struct (EXAMPLE)_state));
struct (EXAMPLE)_state *mystate = (struct (EXAMPLE)_state *)self->state;
if(!mystate){
    return -ENOMEM;
}

memset(self->state, 0x00, sizeof(struct (EXAMPLE)_state));

mystate->threshold = DDOS_DEFAULT_THRESH;
mystate->p_window = DDOS_DEFAULT_WINDOW;
mystate->p_set = calloc(mystate->p_window, sizeof(uint32_t));
mystate->p_tot = calloc(mystate->p_window, sizeof(uint32_t));
mystate->p_entropy = calloc(mystate->p_window, sizeof(uint32_t));
mystate->head = 0;

return 0;
MEILI_END_DECLS


MEILI_FREE(EXAMPLE)
struct (EXAMPLE)_state *mystate = (struct (EXAMPLE)_state *)self->state;
free(mystate->p_set);
free(mystate->p_tot);
free(mystate->p_entropy);
free(mystate);
return 0;
MEILI_END_DECLS


// Meili dataplane API invocation
MEILI_EXEC(EXAMPLE)
Meili.pkt_flt(self, ddos_check, pkt);
// Meili.pkt_flt(void *url_check, pkt);
// Meili.pkt_trans(void *ipsec, pkt);
// Meili.AES(pkt, ERY_TAG,int BLK_SIZE);
MEILI_END_DECLS

MEILI_REGISTER(EXAMPLE)