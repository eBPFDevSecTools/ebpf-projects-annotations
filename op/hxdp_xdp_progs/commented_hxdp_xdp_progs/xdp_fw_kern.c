#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include "xdp_fw_common.h"


//#define DEBUG 1
#ifdef  DEBUG

#define bpf_debug(fmt, ...)						\
			({							\
				char ____fmt[] = fmt;				\
				bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
			})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 27,
  "endLine": 41,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_fw_kern.c",
  "funcName": "biflow",
  "developer_inline_comments": [
    {
      "start_line": 14,
      "end_line": 14,
      "text": "//#define DEBUG 1"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct flow_ctx_table_key *flow_key"
  ],
  "output": "staticinlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "sock_ops",
    "flow_dissector",
    "xdp",
    "lwt_in",
    "kprobe",
    "socket_filter",
    "cgroup_skb",
    "sk_skb",
    "perf_event",
    "lwt_xmit",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "cgroup_sysctl",
    "cgroup_device",
    "tracepoint",
    "lwt_out",
    "sched_act",
    "cgroup_sock",
    "lwt_seg6local",
    "raw_tracepoint",
    "sched_cls",
    "sk_reuseport"
  ],
  "source": [
    "static inline void biflow (struct flow_ctx_table_key *flow_key)\n",
    "{\n",
    "    u32 swap;\n",
    "    if (flow_key->ip_src > flow_key->ip_dst) {\n",
    "        swap = flow_key->ip_src;\n",
    "        flow_key->ip_src = flow_key->ip_dst;\n",
    "        flow_key->ip_dst = swap;\n",
    "    }\n",
    "    if (flow_key->l4_src > flow_key->l4_dst) {\n",
    "        swap = flow_key->l4_src;\n",
    "        flow_key->l4_src = flow_key->l4_dst;\n",
    "        flow_key->l4_dst = swap;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    {}
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
static inline void biflow(struct flow_ctx_table_key *flow_key){
	u32 swap;
	if (flow_key->ip_src > flow_key->ip_dst){
		swap = flow_key->ip_src;
		flow_key->ip_src = flow_key->ip_dst;
		flow_key->ip_dst = swap;
	}

	if (flow_key->l4_src  > flow_key->l4_dst){
		swap = flow_key->l4_src;
		flow_key->l4_src = flow_key->l4_dst;
		flow_key->l4_dst = swap;
	}

}

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 10,
};

struct bpf_map_def SEC("maps") flow_ctx_table = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_ctx_table_key),
	.value_size = sizeof(struct flow_ctx_table_leaf),
	.max_entries = 1024,
};


SEC("xdp_fw")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    },
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    },
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 59,
  "endLine": 162,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_fw_kern.c",
  "funcName": "xdp_fw_prog",
  "developer_inline_comments": [
    {
      "start_line": 79,
      "end_line": 81,
      "text": "/*  remember, to see printk \n\t * sudo cat /sys/kernel/debug/tracing/trace_pipe\n\t */"
    },
    {
      "start_line": 92,
      "end_line": 92,
      "text": "//\tif (!ntohs(ethernet->h_proto))"
    },
    {
      "start_line": 93,
      "end_line": 93,
      "text": "//\t\tgoto EOP;"
    },
    {
      "start_line": 126,
      "end_line": 126,
      "text": "/* flow key */"
    },
    {
      "start_line": 151,
      "end_line": 151,
      "text": "//ctx->ingress_ifindex ;"
    }
  ],
  "updateMaps": [
    " flow_ctx_table"
  ],
  "readMaps": [
    "  flow_ctx_table"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_redirect",
    "bpf_map_update_elem",
    "bpf_redirect_map",
    "XDP_PASS",
    "XDP_DROP",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int xdp_fw_prog (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct flow_ctx_table_leaf new_flow = {0}\n",
    "    ;\n",
    "    struct flow_ctx_table_key flow_key = {0}\n",
    "    ;\n",
    "    struct flow_ctx_table_leaf *flow_leaf;\n",
    "    struct ethhdr *ethernet;\n",
    "    struct iphdr *ip;\n",
    "    struct udphdr *l4;\n",
    "    int ingress_ifindex;\n",
    "    uint64_t nh_off = 0;\n",
    "    u8 port_redirect = 0;\n",
    "    int ret = XDP_PASS;\n",
    "    u8 is_new_flow = 0;\n",
    "    int vport = 0;\n",
    "    bpf_debug (\"I'm in the pipeline\\n\");\n",
    "ethernet :\n",
    "    {\n",
    "        ethernet = data;\n",
    "        nh_off = sizeof (*ethernet);\n",
    "        if (data + nh_off > data_end)\n",
    "            goto EOP;\n",
    "        ingress_ifindex = ctx->ingress_ifindex;\n",
    "        bpf_debug (\"I'm eth\\n\");\n",
    "        switch (ntohs (ethernet->h_proto)) {\n",
    "        case ETH_P_IP :\n",
    "            goto ip;\n",
    "        default :\n",
    "            goto EOP;\n",
    "        }\n",
    "    }\n",
    "ip :\n",
    "    {\n",
    "        bpf_debug (\"I'm ip\\n\");\n",
    "        ip = data + nh_off;\n",
    "        nh_off += sizeof (*ip);\n",
    "        if (data + nh_off > data_end)\n",
    "            goto EOP;\n",
    "        switch (ip->protocol) {\n",
    "        case IPPROTO_TCP :\n",
    "            goto l4;\n",
    "        case IPPROTO_UDP :\n",
    "            goto l4;\n",
    "        default :\n",
    "            goto EOP;\n",
    "        }\n",
    "    }\n",
    "l4 :\n",
    "    {\n",
    "        bpf_debug (\"I'm l4\\n\");\n",
    "        l4 = data + nh_off;\n",
    "        nh_off += sizeof (*l4);\n",
    "        if (data + nh_off > data_end)\n",
    "            goto EOP;\n",
    "    }\n",
    "    bpf_debug (\"extracting flow key ... \\n\");\n",
    "    flow_key.ip_proto = ip->protocol;\n",
    "    flow_key.ip_src = ip->saddr;\n",
    "    flow_key.ip_dst = ip->daddr;\n",
    "    flow_key.l4_src = l4->source;\n",
    "    flow_key.l4_dst = l4->dest;\n",
    "    biflow (&flow_key);\n",
    "    if (ingress_ifindex == B_PORT) {\n",
    "        flow_leaf = bpf_map_lookup_elem (& flow_ctx_table, & flow_key);\n",
    "        if (flow_leaf)\n",
    "            return bpf_redirect_map (&tx_port, flow_leaf->out_port, 0);\n",
    "        else\n",
    "            return XDP_DROP;\n",
    "    }\n",
    "    else {\n",
    "        flow_leaf = bpf_map_lookup_elem (& flow_ctx_table, & flow_key);\n",
    "        if (!flow_leaf) {\n",
    "            new_flow.in_port = B_PORT;\n",
    "            new_flow.out_port = A_PORT;\n",
    "            bpf_map_update_elem (&flow_ctx_table, &flow_key, &new_flow, BPF_ANY);\n",
    "        }\n",
    "        return bpf_redirect_map (&tx_port, B_PORT, 0);\n",
    "    }\n",
    "EOP :\n",
    "    return XDP_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "biflow",
    "bpf_debug",
    "ntohs"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
  ],
  "AI_func_description": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": "",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
int xdp_fw_prog(struct xdp_md *ctx)
{
	
	void* data_end = (void*)(long)ctx->data_end;
	void* data         = (void*)(long)ctx->data;
	
	struct flow_ctx_table_leaf new_flow = {0};
	struct flow_ctx_table_key flow_key  = {0};
	struct flow_ctx_table_leaf *flow_leaf;

	struct ethhdr *ethernet;
	struct iphdr        *ip;
	struct udphdr      *l4;

	int ingress_ifindex;
	uint64_t nh_off = 0;
	u8 port_redirect = 0;
	int ret = XDP_PASS;
	u8 is_new_flow = 0;
	int vport = 0;
	/*  remember, to see printk 
	 * sudo cat /sys/kernel/debug/tracing/trace_pipe
	 */
	bpf_debug("I'm in the pipeline\n");

ethernet: {
	ethernet = data ;
	nh_off = sizeof(*ethernet);
	if (data  + nh_off  > data_end)
		goto EOP;
	
	
	ingress_ifindex = ctx->ingress_ifindex;
//	if (!ntohs(ethernet->h_proto))
//		goto EOP;
	
	bpf_debug("I'm eth\n");
	switch (ntohs(ethernet->h_proto)) {
		case ETH_P_IP:    goto ip;
		default:          goto EOP;
	}
}

ip: {
	bpf_debug("I'm ip\n");
	
	ip = data + nh_off;
	nh_off +=sizeof(*ip);
	if (data + nh_off  > data_end)
		goto EOP;

	switch (ip->protocol) {
		case IPPROTO_TCP: goto l4;
		case IPPROTO_UDP: goto l4;
		default:          goto EOP;
	}
}

l4: {
	bpf_debug("I'm l4\n");
	l4 = data + nh_off;
	nh_off +=sizeof(*l4);
	if (data + nh_off  > data_end)
		goto EOP;
}

	bpf_debug("extracting flow key ... \n");
	/* flow key */
	flow_key.ip_proto = ip->protocol;

	flow_key.ip_src = ip->saddr;
	flow_key.ip_dst = ip->daddr;
	flow_key.l4_src = l4->source;
	flow_key.l4_dst = l4->dest;

	biflow(&flow_key);
	



	if (ingress_ifindex == B_PORT){
		flow_leaf = bpf_map_lookup_elem(&flow_ctx_table, &flow_key);
			
		if (flow_leaf)
			return bpf_redirect_map(&tx_port,flow_leaf->out_port, 0);
		else 
			return XDP_DROP;
	} else {
		flow_leaf = bpf_map_lookup_elem(&flow_ctx_table, &flow_key);
			
		if (!flow_leaf){
			new_flow.in_port = B_PORT;
			new_flow.out_port = A_PORT; //ctx->ingress_ifindex ;
			bpf_map_update_elem(&flow_ctx_table, &flow_key, &new_flow, BPF_ANY);
		}
		
		return bpf_redirect_map(&tx_port, B_PORT, 0);
	}


EOP:
	return XDP_DROP;

}



char _license[] SEC("license") = "GPL";
