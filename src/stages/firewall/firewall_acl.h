#ifndef _INCLUDE_FIREWALL_ACL_H
#define _INCLUDE_FIREWALL_ACL_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_acl.h>


/* parse rule file */
#define COMMENT_LEAD_CHAR	'#'

#define NAME_BUF_SIZE 64
#define ACL_LINE_MAX 512

#define ACL_RULE_FILE_PATH "./src/stages/firewall/fw_acl_rules"

#define NB_ACL_CATEGORIES 16
#define DEFAULT_ACL_SEARCH_CATEGORIES 1
#define MAX_ACL_RUNTIME_SIZE 128
#define MAX_ACL_NB_RULES 100000

#define RULE_FILE_PATH "/root/SmartNIC/meili/pl_exp/fw_rules.json" 

#define ACL_SEARCH_RESULT_NUM 128


struct search_key{
	uint8_t proto;
	uint32_t src_addr;
	uint32_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
	// uint32_t test1;
	// uint32_t test2;
	// uint8_t tcp_flag;
};

#define GET_CB_FIELD(in, fd, base, lim, dlm)	do {            \
	unsigned long val;                                      \
	char *end;                                              \
	errno = 0;                                              \
	val = strtoul((in), &end, (base));                      \
	if (errno != 0 || end[0] != (dlm) || val > (lim))       \
		return -EINVAL;                                 \
	(fd) = (typeof(fd))val;                                 \
	(in) = end + 1;                                         \
} while (0)

/* Struct for the firewall_acl rules */
RTE_ACL_RULE_DEF(acl_rule, RTE_ACL_MAX_FIELDS);

/* rule fileds */
enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT_LOW,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_HIGH,
	CB_FLD_DST_PORT_LOW,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_HIGH,
	CB_FLD_PROTO,
	// CB_FLD_TEST1,
	// CB_FLD_TEST2,
	// CB_FLD_TCP_FLAG,
	CB_FLD_NUM,
};

enum {
    PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	// TEST1_FIELD_IPV4,
	// TEST2_FIELD_IPV4,
	// TCP_FLAG_IPV4,
	NUM_FIELDS_IPV4
};

// enum {
// 	RTE_ACL_IPV4VLAN_PROTO,
// 	RTE_ACL_IPV4VLAN_VLAN,
// 	RTE_ACL_IPV4VLAN_SRC,
// 	RTE_ACL_IPV4VLAN_DST,
// 	RTE_ACL_IPV4VLAN_PORTS,
// 	RTE_ACL_IPV4VLAN_NUM
// };

/* ipv6 field values of mfirewall_acl_state */
enum {
	IPV6_FRMT_NONE,
	IPV6_FRMT_U32,
	IPV6_FRMT_U64,
};





/* acl algorithms */
struct acl_alg {
	const char *name;
	enum rte_acl_classify_alg alg;
};

static const struct acl_alg acl_alg[] = {
    {
    	.name = "default",
		.alg = RTE_ACL_CLASSIFY_DEFAULT,
	},
	{
		.name = "scalar",
		.alg = RTE_ACL_CLASSIFY_SCALAR,
	},
	{
		.name = "sse",
		.alg = RTE_ACL_CLASSIFY_SSE,
	},
	{
		.name = "avx2",
		.alg = RTE_ACL_CLASSIFY_AVX2,
	},
	{
		.name = "neon",
		.alg = RTE_ACL_CLASSIFY_NEON,
	},
	{
		.name = "altivec",
		.alg = RTE_ACL_CLASSIFY_ALTIVEC,
	},
	{
		.name = "avx512x16",
		.alg = RTE_ACL_CLASSIFY_AVX512X16,
	},
	{
		.name = "avx512x32",
		.alg = RTE_ACL_CLASSIFY_AVX512X32,
	},
};


#define FW_ACL_DEFAULT_SEARCH_BUFF_SZ 512

struct firewall_acl_state{
    char         *rule_file;
    char name[64];
    struct rte_acl_ctx *acx;
    struct rte_acl_param *prm;
    struct acl_alg      alg;
    uint32_t            num_categories;
    size_t              max_size;
    int                 max_nb_rules;
    int                 nb_rules;
    int32_t            ipv6;
    int nb_pkt_drop;
    int nb_pkt_pass;

	struct search_key *search_data[FW_ACL_DEFAULT_SEARCH_BUFF_SZ];

	// const char         *rule_file;
	// const char         *trace_file;
	// size_t              max_size;
	// uint32_t            bld_categories;
	// uint32_t            run_categories;
	// uint32_t            nb_rules;
	// uint32_t            nb_traces;
	// uint32_t            trace_step;
	// uint32_t            trace_sz;
	// uint32_t            iter_num;
	// uint32_t            verbose;
	//uint32_t            ipv6;
	
	//uint32_t            used_traces;
	//void               *traces;
	
};

#endif /* _INCLUDE_FIREWALL_ACL_H */