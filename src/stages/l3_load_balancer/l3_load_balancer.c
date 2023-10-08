/*
 * L3 Load Balancer
 * - Rount-robin load balancer, rewrite pkt 
 */
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "l3_load_balancer.h"
#include "../../runtime/meili_runtime.h"
#include "../../utils/flow_utils.h"
#include "../../utils/pkt_utils.h"
#include "../../utils/port_utils.h"
#include "../../utils/log/log.h"


int
l3_lb_init(struct pipeline_stage *self)
{
    /* allocate space for pipeline state */
    self->state = (struct l3_lb_state *)malloc(sizeof(struct l3_lb_state));
    struct l3_lb_state *mystate = (struct l3_lb_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }
    memset(self->state, 0x00, sizeof(struct l3_lb_state));

    
    mystate->ft = flow_table_create(L3_LB_MAX_FT_SIZE, sizeof(struct l3_lb_flow_stats));
    if (!mystate->ft) {
        return -EINVAL;
    }

    mystate->num_stored = 0;
    mystate->expire_time = L3_LB_EXPIRE_CYCLES;
    mystate->elapsed_cycles = rte_get_tsc_cycles();

    mystate->server_count = L3_LB_NB_BACKEND;

    mystate->server = (struct l3_lb_backend_server *)malloc(mystate->server_count * sizeof(struct l3_lb_backend_server));
    /* initialize the metadata of each backend server */
    memset(mystate->server, 0x00, mystate->server_count * sizeof(struct l3_lb_backend_server));
    //for 

    mystate->ip_lb_server = L3_LB_IP_SERVER;
    mystate->ip_lb_client = L3_LB_IP_CLIENT;
    mystate->server_port = L3_LB_DPDK_PORT_SERVER;
    mystate->client_port = L3_LB_DPDK_PORT_CLIENT;

    //printf("init finished\n");
    return 0;
}

int
l3_lb_free(struct pipeline_stage *self)
{
    struct l3_lb_state *mystate = (struct l3_lb_state *)self->state;
    
    if(mystate->ft){
        flow_table_free(mystate->ft);
    }
    if(mystate->server){
        free(mystate->server);
    }
    
    free(mystate);
    return 0;
}

/*
 * Updates flow info to be "active" or "expired"
 */
static int
update_status(struct l3_lb_state *mystate , struct l3_lb_flow_stats *data) {

    if (unlikely(data == NULL || mystate == NULL)) {
        return -1;
    }
    if ((mystate->elapsed_cycles - data->last_pkt_cycles) / rte_get_timer_hz() >= mystate->expire_time) {
        data->is_active = 0;
    } else {
        data->is_active = 1;
    }

    return 0;
}

/*
 * Clears expired entries from the flow table
 */
static int
clear_entries(struct l3_lb_state *mystate) {
    if (unlikely(mystate == NULL)) {
            return -1;
    }

    printf("Clearing expired entries\n");
    struct l3_lb_flow_stats *data = NULL;
    struct ipv4_5tuple *key = NULL;
    uint32_t next = 0;
    int ret = 0;

    while (flow_table_iterate(mystate->ft, (const void **)&key, (void **)&data, &next) > -1) {
        if (update_status(mystate, data) < 0) {
            return -1;
        }

        if (!data->is_active) {
            ret = flow_table_remove_key(mystate->ft, key);
            mystate->num_stored--;
            if (ret < 0) {
                printf("Key should have been removed, but was not\n");
                mystate->num_stored++;
            }
        }
    }

    return 0;
}

/*
 * Adds an entry to the flow table. It first checks if the table is full, and
 * if so, it calls clear_entries() to free up space.
 */
static int
table_add_entry(struct ipv4_5tuple *key, struct l3_lb_state *mystate, struct l3_lb_flow_stats **flow) {
    struct l3_lb_flow_stats *data = NULL;

    if (unlikely(key == NULL || mystate == NULL)) {
            return -1;
    }

    if (L3_LB_MAX_FT_SIZE - 1 - mystate->num_stored == 0) {
        int ret = clear_entries(mystate);
        if (ret < 0) {
            return -1;
        }
    }

    int tbl_index = flow_table_add_key(mystate->ft, key, (char **)&data);
    if (tbl_index < 0) {
        return -1;
    }

    mystate->num_stored++;
    data->dest = mystate->num_stored % mystate->server_count;
    data->last_pkt_cycles = mystate->elapsed_cycles;
    data->is_active = false;

    *flow = data;

    return 0;
}


/*
 * Looks up a packet hash to see if there is a matching key in the table.
 * If it finds one, it updates the metadata associated with the key entry,
 * and if it doesn't, it calls table_add_entry() to add it to the table.
 */
static int
table_lookup_entry(struct rte_mbuf *pkt, struct l3_lb_state *mystate, struct l3_lb_flow_stats **flow) {
    struct l3_lb_flow_stats *data = NULL;
    struct ipv4_5tuple key;

    if (unlikely(pkt == NULL || mystate == NULL || flow == NULL)) {
            return -1;
    }

    int ret = flow_table_fill_key_symmetric(&key, pkt);
    if (ret < 0){
        return -1;
    }
            
    int tbl_index = flow_table_lookup_key(mystate->ft, &key, (char **)&data);
    if (tbl_index == -ENOENT) {
        return table_add_entry(&key, mystate, flow);
    } else if (tbl_index < 0) {
        printf("Some other error occurred with the packet hashing\n");
        return -1;
    } else {
        data->last_pkt_cycles = mystate->elapsed_cycles;
        *flow = data;
        return 0;
    }
}


int
l3_lb_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct l3_lb_state *mystate = (struct l3_lb_state *)self->state;

    static uint32_t counter = 0;
    struct rte_ipv4_hdr *ip;
    struct rte_ether_hdr *ehdr;
    struct l3_lb_flow_stats *flow_info;
    int i,j,ret;

    struct rte_mbuf *pkt = NULL;

    
    mystate->elapsed_cycles = rte_get_tsc_cycles();
        
    
    for(i=0; i<nb_enq; i++){
        pkt = mbuf[i];
        ehdr = MBUF_ETH_HDR(pkt);
        ip = MBUF_IPV4_HDR(pkt);

        // /* Ignore packets without ip header, also ignore packets with invalid ip */
        // if (ip == NULL || ip->src_addr == 0 || ip->dst_addr == 0) {
        //         meta->action = ONVM_NF_ACTION_DROP;
        //         meta->destination = 0;
        //         return 0;
        // }
        /*
         * Before hashing remove the Load Balancer ip from the pkt so that both
         * connections from client -> lbr and lbr <- server
         * will have the same hash
         */
        if (mbuf[i]->port == mystate->client_port) {
            ip->dst_addr = 0;
        } else {
            ip->src_addr = 0;
        }

        /* Get the packet flow entry */
        ret = table_lookup_entry(pkt, mystate, &flow_info);
        if (ret == -1) {
            return -EINVAL;
        }

        /* If the flow entry is new, save the client/server mac address(src side) information */
        if (flow_info->is_active == 0) {
            flow_info->is_active = 1;
            for (j = 0; j < MEILI_ETHER_ADDR_LEN; j++) {
                flow_info->s_addr_bytes[j] = ehdr->s_addr.addr_bytes[j];
            }
        }

        if (pkt->port == mystate->server_port) {
            /* backend server -> lb_server_port -> lb_client_port -> client */
            //if (get_port_macaddr(mystate->client_port, &ehdr->s_addr) == -1) {
            if (get_fake_macaddr(&ehdr->s_addr) == -1) {    
                MEILI_LOG_ERR("Failed to obtain MAC address");
                return -EINVAL;
            }
            for (j = 0; j < MEILI_ETHER_ADDR_LEN; j++) {
                /* server to client, so destination mac is the mac of client */
                ehdr->d_addr.addr_bytes[j] = flow_info->s_addr_bytes[j];
            }

            //ip->src_addr = mystate->ip_lb_client;

            // Note: src_addr / dst_addr may be modified by load balancer
            //ip->src_addr = rte_cpu_to_be_32(mystate->ip_lb_client);      
            
        } 
        else {
            /* client -> lb, should be delivered to corresponding backend server */
            //if (get_port_macaddr(mystate->server_port, &ehdr->s_addr) == -1) {
            if (get_fake_macaddr(&ehdr->s_addr) == -1) { 
                MEILI_LOG_ERR("Failed to obtain MAC address");
                return -EINVAL;
            }
            for (j = 0; j < MEILI_ETHER_ADDR_LEN; j++) {
                ehdr->d_addr.addr_bytes[j] = mystate->server[flow_info->dest].d_addr_bytes[j];
            }

            // Note: src_addr / dst_addr may be modified by load balancer
            //ip->dst_addr = rte_cpu_to_be_32(mystate->server[flow_info->dest].d_ip);
        }

        // /* Changing the pkt ip header so we want to recalculate pkt checksums */
        // //pkt_set_checksums(pkt);
        // ;
    }

    //printf("batch processed\n");

    *mbuf_out = mbuf;
    *nb_deq = nb_enq;

    
    return 0;
}


int
l3_lb_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = l3_lb_init;
	stage->funcs->pipeline_stage_free = l3_lb_free;
	stage->funcs->pipeline_stage_exec = l3_lb_exec;

	return 0;
}