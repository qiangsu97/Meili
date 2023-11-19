/* Intrusion Detection */

#include "./lib/meili.h"
#include "./runtime/meili_runtime.h"
#include "example.h"


MEILI_INIT(EXAMPLE)
MEILI_END_DECLS

MEILI_FREE(EXAMPLE)
MEILI_END_DECLS


// Meili dataplane API invocation
MEILI_EXEC(EXAMPLE)
Meili.pkt_flt(self, ddos_check, pkt);
// Meili.pkt_flt(void *url_check, pkt);
// Meili.pkt_trans(void *ipsec, pkt);
// Meili.AES(pkt, ERY_TAG,int BLK_SIZE);
MEILI_END_DECLS