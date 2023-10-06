/*
 * FIREWALL ACL
 * Use DPDK ACL library to provide security check on packet headers
 */
#include <pthread.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <rte_acl.h>
#include <arpa/inet.h>
#include "firewall_acl.h"
#include "../../runtime/meili_runtime.h"
#include "../../utils/cJSON/cJSON.h"
#include "../../utils/utils.h"
#include "../../utils/pkt_utils.h"
#include "../../utils/flow_utils.h"
#include "../../utils/log/log.h"

typedef int (*parse_5tuple)(char *text, struct acl_rule *rule);

static const char cb_port_delim[] = ":";

pthread_mutex_t mutex_fw = PTHREAD_MUTEX_INITIALIZER;
struct rte_acl_ctx *shared_acx = NULL;

// struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
// 	{
// 		.type = RTE_ACL_FIELD_TYPE_BITMASK,
// 		.size = sizeof(uint8_t),
// 		.field_index = PROTO_FIELD_IPV4,
// 		.input_index = RTE_ACL_IPV4VLAN_PROTO,
// 		.offset = 0,
// 	},
// 	{
// 		.type = RTE_ACL_FIELD_TYPE_MASK,
// 		.size = sizeof(uint32_t),
// 		.field_index = SRC_FIELD_IPV4,
// 		.input_index = RTE_ACL_IPV4VLAN_SRC,
// 		.offset = offsetof(struct rte_ipv4_hdr, src_addr) -
// 			offsetof(struct rte_ipv4_hdr, next_proto_id),
// 	},
// 	{
// 		.type = RTE_ACL_FIELD_TYPE_MASK,
// 		.size = sizeof(uint32_t),
// 		.field_index = DST_FIELD_IPV4,
// 		.input_index = RTE_ACL_IPV4VLAN_DST,
// 		.offset = offsetof(struct rte_ipv4_hdr, dst_addr) -
// 			offsetof(struct rte_ipv4_hdr, next_proto_id),
// 	},
// 	{
// 		.type = RTE_ACL_FIELD_TYPE_RANGE,
// 		.size = sizeof(uint16_t),
// 		.field_index = SRCP_FIELD_IPV4,
// 		.input_index = RTE_ACL_IPV4VLAN_PORTS,
// 		.offset = sizeof(struct rte_ipv4_hdr) -
// 			offsetof(struct rte_ipv4_hdr, next_proto_id),
// 	},
// 	{
// 		.type = RTE_ACL_FIELD_TYPE_RANGE,
// 		.size = sizeof(uint16_t),
// 		.field_index = DSTP_FIELD_IPV4,
// 		.input_index = RTE_ACL_IPV4VLAN_PORTS,
// 		.offset = sizeof(struct rte_ipv4_hdr) -
// 			offsetof(struct rte_ipv4_hdr, next_proto_id) +
// 			sizeof(uint16_t),
// 	},
// };

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = 0,
		.offset = offsetof(struct search_key, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = 1,
		.offset = offsetof(struct search_key, src_addr),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = 2,
		.offset = offsetof(struct search_key, dst_addr),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = 3,
		.offset = offsetof(struct search_key, src_port),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = 3,
		.offset = offsetof(struct search_key, dst_port),
	},
	// {
	// 	.type = RTE_ACL_FIELD_TYPE_BITMASK,
	// 	.size = sizeof(uint32_t),
	// 	.field_index = TEST1_FIELD_IPV4,
	// 	.input_index = 4,
	// 	.offset = offsetof(struct search_key, test1),
	// },
	// {
	// 	.type = RTE_ACL_FIELD_TYPE_BITMASK,
	// 	.size = sizeof(uint32_t),
	// 	.field_index = TEST2_FIELD_IPV4,
	// 	.input_index = 5,
	// 	.offset = offsetof(struct search_key, test2),
	// },
	// {
	// 	.type = RTE_ACL_FIELD_TYPE_BITMASK,
	// 	.size = sizeof(uint8_t),
	// 	.field_index = TCP_FLAG_IPV4,
	// 	.input_index = 6,
	// 	.offset = offsetof(struct search_key, tcp_flag),
	//},
};

static int
parse_ipv4_net(char *in, uint32_t *addr, uint32_t *mask_len)
{
	char *sa, *sm, *sv;
	uint32_t m, v;

	const char *dlm = "/";

	sv = NULL;
	sa = strtok_r(in, dlm, &sv);
	if (sa == NULL)
		return -EINVAL;
	sm = strtok_r(NULL, dlm, &sv);
	if (sm == NULL)
		return -EINVAL;

	if (inet_pton(AF_INET, sa, &v) != 1)
		return -EINVAL;

	addr[0] = rte_be_to_cpu_32(v);

	GET_CB_FIELD(sm, m, 0, sizeof(uint32_t) * CHAR_BIT, 0);
	mask_len[0] = m;

	return 0;
}

/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
static int
parse_cb_ipv4_rule(char *str, struct acl_rule *v)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";

	/*
	 * Skip leading '@'
	 */
	if (strchr(str, '@') != str)
		return -EINVAL;

	s = str + 1;

	for (i = 0; i != RTE_DIM(in); i++) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
		s = NULL;
	}

	rc = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&v->field[SRC_FIELD_IPV4].value.u32,
			&v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		MEILI_LOG_ERR("Failed to read source address/mask: %s",
			in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&v->field[DST_FIELD_IPV4].value.u32,
			&v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		MEILI_LOG_ERR("Failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return rc;
	}

	/* source port. */
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
		v->field[SRCP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
		v->field[SRCP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	/* destination port. */
	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
		v->field[DSTP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
		v->field[DSTP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].value.u8,
		0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].mask_range.u8,
		0, UINT8_MAX, 0);
	
	// /* test */
	// GET_CB_FIELD(in[CB_FLD_TEST1], v->field[TEST1_FIELD_IPV4].value.u32,
	// 	0, UINT32_MAX, '/');
	// GET_CB_FIELD(in[CB_FLD_TEST1], v->field[TEST1_FIELD_IPV4].mask_range.u32,
	// 	0, UINT32_MAX, 0);
	
	// /* test */
	// GET_CB_FIELD(in[CB_FLD_TEST2], v->field[TEST2_FIELD_IPV4].value.u32,
	// 	0, UINT32_MAX, '/');
	// GET_CB_FIELD(in[CB_FLD_TEST2], v->field[TEST2_FIELD_IPV4].mask_range.u32,
	// 	0, UINT32_MAX, 0);

	// /* tcp flag */
	// GET_CB_FIELD(in[CB_FLD_TCP_FLAG], v->field[TCP_FLAG_IPV4].value.u8,
	// 	0, UINT8_MAX, '/');
	// GET_CB_FIELD(in[CB_FLD_TCP_FLAG], v->field[TCP_FLAG_IPV4].mask_range.u8,
	// 	0, UINT8_MAX, 0);

	return 0;
}

static int
skip_line(const char *buf)
{
	uint32_t i;

	for (i = 0; isspace(buf[i]) != 0; i++)
		;

	if (buf[i] == 0 || buf[i] == COMMENT_LEAD_CHAR)
		return 1;

	return 0;
}

static int
add_cb_rules(FILE *f, struct firewall_acl_state *mystate)
{
	int rc;
	uint32_t i, k, n;
	struct acl_rule v;
	parse_5tuple parser;
    struct rte_acl_ctx *ctx = mystate->acx;

	char line[ACL_LINE_MAX];

	static const parse_5tuple parser_func[] = {
		[IPV6_FRMT_NONE] = parse_cb_ipv4_rule,
		// [IPV6_FRMT_U32] = parse_cb_ipv6_u32_rule,
		// [IPV6_FRMT_U64] = parse_cb_ipv6_u64_rule,
	};

	memset(&v, 0, sizeof(v));
	parser = parser_func[mystate->ipv6];

	k = 0;
	for (i = 1; fgets(line, sizeof(line), f) != NULL; i++) {

		if (skip_line(line) != 0) {
			k++;
			continue;
		}

		n = i - k;
		rc = parser(line, &v);
		if (rc != 0) {
			MEILI_LOG_ERR("line %u: parse_cb_ipv4_rule"
				" failed, error code: %d (%s)",
				i, rc, strerror(-rc));
			return rc;
		}

		//v.data.category_mask = RTE_LEN2MASK(RTE_ACL_MAX_CATEGORIES, typeof(v.data.category_mask));
		v.data.category_mask = RTE_LEN2MASK(DEFAULT_ACL_SEARCH_CATEGORIES, typeof(v.data.category_mask));
		v.data.priority = RTE_ACL_MAX_PRIORITY - n;
		v.data.userdata = n;

		rc = rte_acl_add_rules(ctx, (struct rte_acl_rule *)&v, 1);
		mystate->nb_rules++;
		if (rc != 0) {
			MEILI_LOG_ERR("line %u: failed to add rules "
				"into ACL context, error code: %d (%s)",
				i, rc, strerror(-rc));
			return rc;
		}
	}

	return 0;
}

int
firewall_acl_init(struct pipeline_stage *self)
{
    char name[64];
    int ret = 0;
	FILE *f;
    


    struct rte_acl_config cfg;
	memset(&cfg, 0, sizeof(cfg));

    /* allocate space for pipeline state */
    self->state = (struct firewall_acl_state *)malloc(sizeof(struct firewall_acl_state));
    struct firewall_acl_state *mystate = (struct firewall_acl_state *)self->state;
    if(!mystate){
        return -ENOMEM;
    }

    memset(self->state, 0x00, sizeof(struct firewall_acl_state));
    

    // MEILI_LOG_INFO("total rules:%d",mystate->nb_rules);
    // if(ret){
    //     return -EINVAL;
    // }

    snprintf(mystate->name, sizeof(mystate->name), "fw_acl_%d_%" PRIu64, rte_lcore_id(), rte_get_tsc_cycles());

    mystate->rule_file = ACL_RULE_FILE_PATH;
    mystate->prm = (struct rte_acl_param *)malloc(sizeof(struct rte_acl_param));
    mystate->alg = acl_alg[0]; /* default algorithm */  
    mystate->ipv6 = 0;
	mystate->nb_rules = 0;

    //mystate->num_categories = NB_ACL_CATEGORIES;
	mystate->num_categories = DEFAULT_ACL_SEARCH_CATEGORIES;
   
    /* max memory limit for internal run-time structures. */
    mystate->max_size = MAX_ACL_RUNTIME_SIZE;
    mystate->max_nb_rules = MAX_ACL_NB_RULES;

    mystate->nb_pkt_drop = 0;
    mystate->nb_pkt_pass = 0;


	/* setup ACL build cfgs */
	// if (mystate->ipv6 == IPV6_FRMT_U32) {
	// 	cfg.num_fields = RTE_DIM(ipv6_defs);
	// 	memcpy(&cfg.defs, ipv6_defs, sizeof(ipv6_defs));
	// } else if (mystate->ipv6 == IPV6_FRMT_U64) {
	// 	cfg.num_fields = RTE_DIM(ipv6_u64_defs);
	// 	memcpy(&cfg.defs, ipv6_u64_defs, sizeof(ipv6_u64_defs));
	// } else {
    cfg.num_fields = RTE_DIM(ipv4_defs);
    memcpy(&cfg.defs, ipv4_defs, sizeof(ipv4_defs));
	//}
	cfg.num_categories = mystate->num_categories;
	//cfg.max_size = mystate->max_size;

	/* setup ACL creation parameters. Total four fields */
    mystate->prm->name = mystate->name;
    mystate->prm->socket_id = rte_socket_id();
	mystate->prm->rule_size = RTE_ACL_RULE_SZ(cfg.num_fields);
	mystate->prm->max_rule_num = mystate->max_nb_rules;

    /* create acl context */
	

	pthread_mutex_lock(&mutex_fw);
	if(shared_acx == NULL){
		mystate->acx = rte_acl_create(mystate->prm);
		if (mystate->acx == NULL){
			MEILI_LOG_ERR("Failed to create ACL context");
			return -EINVAL;
		}
		/* set default classify method for this context. */
		if (mystate->alg.alg != RTE_ACL_CLASSIFY_DEFAULT) {
			MEILI_LOG_INFO("Setting up acl method %s",mystate->alg.name);
			ret = rte_acl_set_ctx_classify(mystate->acx, mystate->alg.alg);
			if (ret != 0){
				MEILI_LOG_ERR("Failed to setup %s method for ACL context", mystate->alg.name);
				return -EINVAL;
			}
		}

	
		


		/* add ACL rules. */
		f = fopen(mystate->rule_file, "r");
		if (f == NULL){
			MEILI_LOG_ERR("Failed to open file %s\n",mystate->rule_file);
			return -EINVAL;
		}


		ret = add_cb_rules(f, mystate);
		if (ret != 0){
			MEILI_LOG_ERR("Failed to add rules into ACL context\n");
			return -EINVAL;
		}
		MEILI_LOG_INFO("Total %d rules parsed",mystate->nb_rules);
			

		fclose(f);

		/* perform build. */
		ret = rte_acl_build(mystate->acx, &cfg);

		// dump_verbose(DUMP_NONE, stdout,
		// 	"rte_acl_build(%u) finished with %d\n",
		// 	mystate->bld_categories, ret);

		rte_acl_dump(mystate->acx);

		if (ret != 0){
			MEILI_LOG_ERR("Failed to build search context\n");
			return -EINVAL;
		}
		shared_acx = mystate->acx;
	}
	else{
		mystate->acx = shared_acx;
	}
		
	for(int i=0; i<ACL_SEARCH_RESULT_NUM ; i++){
		mystate->search_data[i] = (struct search_key *)malloc(sizeof(struct search_key));
	}

	pthread_mutex_unlock(&mutex_fw);
	

    return 0;
}

int
firewall_acl_free(struct pipeline_stage *self)
{
    struct firewall_acl_state *mystate = (struct firewall_acl_state *)self->state;
	if(mystate->prm){
		free(mystate->prm);
	}
    if (mystate->acx) {
        rte_acl_free(mystate->acx);
    }

	for(int i=0; i<ACL_SEARCH_RESULT_NUM ; i++){
		free(mystate->search_data[i]);
	}

    
    free(mystate);
    return 0;
}

int
firewall_acl_exec(struct pipeline_stage *self, struct rte_mbuf **mbuf, int nb_enq,
                            struct rte_mbuf ***mbuf_out,
                            int *nb_deq)
{
    struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
    uint32_t rule = 0;
    int ret;
    struct firewall_acl_state *mystate = (struct firewall_acl_state *)self->state;

    //const uint8_t *mystate->search_data[ACL_SEARCH_RESULT_NUM];
	
    uint32_t search_result[ACL_SEARCH_RESULT_NUM];

    for(int i=0; i<nb_enq; i++) {
        /* prepare the input for a batch */
        /* should have a ipv4 classifier here */
        // if (!pkt_is_ipv4(pkt)) {
        //     ;
        // }

        ipv4_hdr = MBUF_IPV4_HDR(mbuf[i]);
		tcp_hdr = MBUF_TCP_HDR(mbuf[i]);
        /* starting from the next_proto_id field */
        //mystate->search_data[i] = &ipv4_hdr->next_proto_id;
		mystate->search_data[i]->proto = ipv4_hdr->next_proto_id;
		mystate->search_data[i]->src_addr = ipv4_hdr->src_addr;
		mystate->search_data[i]->dst_addr = ipv4_hdr->dst_addr;
		mystate->search_data[i]->src_port = tcp_hdr->src_port;
		mystate->search_data[i]->dst_port = tcp_hdr->dst_port;
		mystate->search_data[i]->dst_port = tcp_hdr->dst_port;
		// mystate->search_data[i]->test1 = tcp_hdr->sent_seq;
		// mystate->search_data[i]->test2 = tcp_hdr->recv_ack;
		// mystate->search_data[i]->tcp_flag = tcp_hdr->tcp_flags;
        //printf("ip addr: %x\n",rte_be_to_cpu_32(ipv4_hdr->src_addr));
        

        // if(ret){
        //     /* -EINVAL for incorrect arguments, -ENOENT on lookup miss */
        //     //printf("miss\n");
        //     mystate->nb_pkt_drop++;
        // }
        // else if(rule == PKT_DROP){
        //     //printf("hit but drop\n");
        //     mystate->nb_pkt_drop++;
        // }
        // else{
        //     //printf("hit and pass\n");
        //     mystate->nb_pkt_pass++;
        // }
    }
    /* process a batch */
	// for(int i=0; i<nb_enq; i++){
	// 	rte_acl_classify(
    //                 mystate->acx,
    //                 (const uint8_t **)(&mystate->search_data[i]),
    //                 &search_result[i],
    //                 1,
    //                 DEFAULT_ACL_SEARCH_CATEGORIES);
	// }

	rte_acl_classify(
				mystate->acx,
				(const uint8_t **)mystate->search_data,
				search_result,
				nb_enq,
				DEFAULT_ACL_SEARCH_CATEGORIES);

	// for(int i=0; i<ACL_SEARCH_RESULT_NUM; i++){
	// 	printf("%d ",search_result[i]);
	// }
	// printf("\n");
	
	
    


    /* we still pass all the packets to next stage */
    *mbuf_out = mbuf;
    *nb_deq = nb_enq;

    
    return 0;
}


int
firewall_acl_pipeline_stage_func_reg(struct pipeline_stage *stage)
{
	stage->funcs->pipeline_stage_init = firewall_acl_init;
	stage->funcs->pipeline_stage_free = firewall_acl_free;
	stage->funcs->pipeline_stage_exec = firewall_acl_exec;

	return 0;
}