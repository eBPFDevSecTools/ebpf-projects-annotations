/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#define LOOP_LEN 32

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 256);
} rxcnt SEC(".maps");

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 26,
  "endLine": 40,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_csum_kern.c",
  "funcName": "swap_src_dst_mac",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": "/* Copyright (c) 2016 PLUMgrid\n *\n * This program is free software; you can redistribute it and/or\n * modify it under the terms of version 2 of the GNU General Public\n * License as published by the Free Software Foundation.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "sock_ops",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "socket_filter",
    "sk_reuseport",
    "tracepoint",
    "lwt_seg6local",
    "xdp",
    "cgroup_sock_addr",
    "perf_event",
    "raw_tracepoint",
    "cgroup_sysctl",
    "sk_skb",
    "lwt_in",
    "sk_msg",
    "sched_act",
    "cgroup_device",
    "kprobe",
    "flow_dissector",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "sched_cls"
  ],
  "source": [
    "static void swap_src_dst_mac (void *data)\n",
    "{\n",
    "    unsigned short *p = data;\n",
    "    unsigned short dst [3];\n",
    "    dst[0] = p[0];\n",
    "    dst[1] = p[1];\n",
    "    dst[2] = p[2];\n",
    "    p[0] = p[3];\n",
    "    p[1] = p[4];\n",
    "    p[2] = p[5];\n",
    "    p[3] = dst[0];\n",
    "    p[4] = dst[1];\n",
    "    p[5] = dst[2];\n",
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
static void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 42,
  "endLine": 45,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_csum_kern.c",
  "funcName": "csum_fold_helper",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 csum"
  ],
  "output": "static__always_inline__u16",
  "helper": [],
  "compatibleHookpoints": [
    "sock_ops",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "socket_filter",
    "sk_reuseport",
    "tracepoint",
    "lwt_seg6local",
    "xdp",
    "cgroup_sock_addr",
    "perf_event",
    "raw_tracepoint",
    "cgroup_sysctl",
    "sk_skb",
    "lwt_in",
    "sk_msg",
    "sched_act",
    "cgroup_device",
    "kprobe",
    "flow_dissector",
    "lwt_out",
    "cgroup_skb",
    "cgroup_sock",
    "sched_cls"
  ],
  "source": [
    "static __always_inline __u16 csum_fold_helper (__u32 csum)\n",
    "{\n",
    "    return ~((csum & 0xffff) + (csum >> 16));\n",
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
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "libbpf",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with bpf_l3_csum_replace() and bpf_l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with bpf_csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "bpf_csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 47,
  "endLine": 52,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_csum_kern.c",
  "funcName": "ipv4_csum",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *data_start",
    " int data_size",
    " __u32 *csum"
  ],
  "output": "static__always_inlinevoid",
  "helper": [
    "bpf_csum_diff"
  ],
  "compatibleHookpoints": [
    "lwt_out",
    "lwt_xmit",
    "sched_cls",
    "lwt_seg6local",
    "lwt_in",
    "sched_act",
    "xdp"
  ],
  "source": [
    "static __always_inline void ipv4_csum (void *data_start, int data_size, __u32 *csum)\n",
    "{\n",
    "    *csum = bpf_csum_diff (0, 0, data_start, data_size, *csum);\n",
    "    *csum = csum_fold_helper (*csum);\n",
    "}\n"
  ],
  "called_function_list": [
    "csum_fold_helper"
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
static __always_inline void ipv4_csum(void *data_start, int data_size,
				      __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

SEC("xdp_csum")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
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
  "startLine": 55,
  "endLine": 99,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_csum_kern.c",
  "funcName": "xdp_prog1",
  "developer_inline_comments": [
    {
      "start_line": 84,
      "end_line": 84,
      "text": "//\tswap_src_dst_mac(data);"
    },
    {
      "start_line": 85,
      "end_line": 85,
      "text": "//\trc = XDP_TX;"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  rxcnt"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "XDP_DROP",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int xdp_prog1 (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct ethhdr *eth = data;\n",
    "    struct iphdr *iph;\n",
    "    int rc = XDP_DROP;\n",
    "    long *value;\n",
    "    u16 h_proto;\n",
    "    u64 nh_off;\n",
    "    u32 dummy_int = 23;\n",
    "    __u32 csum = 0;\n",
    "    int i = 0;\n",
    "    nh_off = sizeof (*eth);\n",
    "    if (data + nh_off > data_end)\n",
    "        return rc;\n",
    "    h_proto = eth->h_proto;\n",
    "    if (h_proto != htons (ETH_P_IP))\n",
    "        return rc;\n",
    "    iph = data + nh_off;\n",
    "    nh_off += sizeof (*iph);\n",
    "    if (data + nh_off > data_end)\n",
    "        return rc;\n",
    "    for (i = 0; i < LOOP_LEN; i++) {\n",
    "        ipv4_csum (iph, sizeof (struct iphdr), &csum);\n",
    "        iph->check = csum;\n",
    "        value = bpf_map_lookup_elem (& rxcnt, & dummy_int);\n",
    "    }\n",
    "    value = bpf_map_lookup_elem (& rxcnt, & dummy_int);\n",
    "    if (value)\n",
    "        *value += 1;\n",
    "    return rc;\n",
    "}\n"
  ],
  "called_function_list": [
    "htons",
    "ipv4_csum"
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
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	int rc = XDP_DROP;
	long *value;
	u16 h_proto;
	u64 nh_off;
	u32 dummy_int = 23;
	__u32 csum = 0;
	int i = 0;
	
	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;
	
	if (h_proto != htons(ETH_P_IP))
		return rc;

	iph = data + nh_off;
	
	nh_off +=sizeof(*iph);
	if (data + nh_off  > data_end)
		return rc;
	
//	swap_src_dst_mac(data);
//	rc = XDP_TX;
	
	for (i = 0; i < LOOP_LEN ;i++){
		ipv4_csum(iph, sizeof(struct iphdr), &csum);
		iph->check = csum;
		value = bpf_map_lookup_elem(&rxcnt, &dummy_int);
	}
	
	value = bpf_map_lookup_elem(&rxcnt, &dummy_int);
	if (value)
		*value += 1;
	

	return rc;
}


char _license[] SEC("license") = "GPL";
