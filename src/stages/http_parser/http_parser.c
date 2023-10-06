/*
 * Stage: http parser
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include "http_parser.h"
#include "../../utils/http_utils/http_parser_utils.h"
#include "../../utils/pkt_utils.h"
#include "../../runtime/meili_runtime.h"
#include "../../utils/log/log.h"

/* avoid name conflict with library */
int
_http_parser_init(struct pipeline_stage *self)
{   

    int ret;
    /* allocate space for pipeline state */
    self->state = (struct http_parser_state *)malloc(sizeof(struct http_parser_state));
    struct http_parser_state *mystate = (struct http_parser_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct http_parser_state));

    /* one reques parser and one repsponse parser */  
    http_parser_init(&mystate->req_parser, HTTP_REQUEST);
    http_parser_init(&mystate->resp_parser, HTTP_RESPONSE);

    return 0;
}

int
_http_parser_free(struct pipeline_stage *self)
{
    struct http_parser_state *mystate = (struct http_parser_state *)self->state;
    free(mystate);
    return 0;
}


int
_http_parser_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct http_parser_state *mystate = (struct http_parser_state *)self->state;
    struct pipeline_stage *sub_stage;
    char *app_data;
    const unsigned char *pkt;
    int pay_len;
    int ptype;
    int pay_off;
    int ret;

    int nparsed;

    enum http_errno err;

    /* strip header, data should be read using read(), here we simualte instead. */
    for(int i=0; i<nb_enq; i++){
        rte_prefetch0(rte_pktmbuf_mtod(mbuf[i], void *));
    }
    for(int i=0; i<nb_enq; i++){
        if(!pkt_is_udp(mbuf[i])){
            continue;
        }
        pkt = rte_pktmbuf_mtod(mbuf[i], const unsigned char *);
        pay_off = util_get_app_layer_payload(pkt, &pay_len, &ptype);
        if (pay_off < 0) {
            /* skip invalid pkts */
            MEILI_LOG_WARN("Unsupported packet detected during parsing app layer payload");
            continue;
        }
        else if(pay_len == 0){
            MEILI_LOG_WARN("App layer zero length payload detected during parsing app layer payload");
            continue;
        }

        // debug
        // printf("pay_off = %d, pay_len = %d\n", pay_off, pay_len);
        // printf("[%.*s]\n",pay_len, &pkt[pay_off]);

        /* parse with http parser */
        // //char *test = "GET / HTTP/1.1\r\n\r\n";
        // char *test = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        // //char *test = "GET / HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n";
        // pay_len = strlen(test);
        // nparsed = http_parser_execute(&mystate->req_parser, &settings, 
        //                         test, pay_len);
        
        
        nparsed = http_parser_execute(&mystate->req_parser, &settings, 
                                      &pkt[pay_off], pay_len);
        err = HTTP_PARSER_ERRNO(&mystate->req_parser);
        // //debug
        // printf("state: %d\n",mystate->req_parser.state);
        if(err != HPE_OK || nparsed != pay_len){
            MEILI_LOG_WARN("HTTP request parser returns error: %d",err);
            //printf("%d\n",HPE_INVALID_HEADER_TOKEN);
            // mystate->req_parser.state = s_start_req;
            // mystate->req_parser.http_errno = HPE_OK;
        }

    }
    



    /* try parse different types */

    *mbuf_out = mbuf;
    *nb_deq = nb_enq;
    
    return 0;
}


int
http_parser_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = _http_parser_init;
	stage->funcs->pipeline_stage_free = _http_parser_free;
	stage->funcs->pipeline_stage_exec = _http_parser_exec;

	return 0;
}