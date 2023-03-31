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
#include <bpf/bpf_helpers.h>

#include "xdp_map_access_common.h"


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct dummy_key);
	__type(value, long);
	__uint(max_entries, 256);
} rxcnt SEC(".maps");

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 38,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_map_access_kern.c",
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

SEC("xdp_map_acces")
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
  "startLine": 41,
  "endLine": 70,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_map_access_kern.c",
  "funcName": "xdp_prog1",
  "developer_inline_comments": [
    {
      "start_line": 57,
      "end_line": 57,
      "text": "//\tswap_src_dst_mac(data);"
    },
    {
      "start_line": 58,
      "end_line": 58,
      "text": "//\trc = XDP_TX;"
    }
  ],
  "updateMaps": [
    " rxcnt"
  ],
  "readMaps": [
    "  rxcnt"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "XDP_DROP",
    "bpf_map_lookup_elem",
    "bpf_map_update_elem"
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
    "    struct dummy_key key = {0}\n",
    "    ;\n",
    "    int rc = XDP_DROP;\n",
    "    long *value;\n",
    "    u16 h_proto;\n",
    "    u64 nh_off;\n",
    "    long dummy_value = 1;\n",
    "    nh_off = sizeof (*eth);\n",
    "    if (data + nh_off > data_end)\n",
    "        return rc;\n",
    "    h_proto = eth->h_proto;\n",
    "    key.key = 23;\n",
    "    value = bpf_map_lookup_elem (& rxcnt, & key);\n",
    "    if (value) {\n",
    "        *value += 1;\n",
    "    }\n",
    "    else {\n",
    "        bpf_map_update_elem (&rxcnt, &key, &dummy_value, BPF_ANY);\n",
    "    }\n",
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
	struct dummy_key key = {0};
	int rc = XDP_DROP;
	long *value;
	u16 h_proto;
	u64 nh_off;
	long dummy_value = 1;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

//	swap_src_dst_mac(data);
//	rc = XDP_TX;

	h_proto = eth->h_proto;
	key.key = 23;
	
	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (value){
		*value += 1;
	}else{
		bpf_map_update_elem(&rxcnt, &key, &dummy_value, BPF_ANY);
	}
	return rc;
}

char _license[] SEC("license") = "GPL";
