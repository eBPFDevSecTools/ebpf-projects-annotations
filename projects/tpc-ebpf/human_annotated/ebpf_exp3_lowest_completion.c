/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF SHORT FLOWS"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_exp3_lowest_completion.h"


/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Emulate a call to setsockopt() on the socket associated to <[ bpf_socket ]>(IP: 0) , which must be a full socket. The <[ level ]>(IP: 1) at which the option resides and the name <[ optname ]>(IP: 2) of the option must be specified , see setsockopt(2) for more information. The option value of length <[ optlen ]>(IP: 4) is pointed by optval. This helper actually implements a subset of setsockopt(). It supports the following levels: \u00b7 SOL_SOCKET , which supports the following optnames: SO_RCVBUF , SO_SNDBUF , SO_MAX_PACING_RATE , SO_PRIORITY , SO_RCVLOWAT , SO_MARK. \u00b7 IPPROTO_TCP , which supports the following optnames: TCP_CONGESTION , TCP_BPF_IW , TCP_BPF_SNDCWND_CLAMP. \u00b7 IPPROTO_IP , which supports <[ optname ]>(IP: 2) IP_TOS. \u00b7 IPPROTO_IPV6 , which supports <[ optname ]>(IP: 2) IPV6_TCLASS. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_setsockopt",
          "Input Params": [
            "{Type: struct bpf_sock_ops ,Var: *bpf_socket}",
            "{Type:  int ,Var: level}",
            "{Type:  int ,Var: optname}",
            "{Type:  char ,Var: *optval}",
            "{Type:  int ,Var: optlen}"
          ],
          "compatible_hookpoints": [
            "sock_ops"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 16,
  "endLine": 29,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_exp3_lowest_completion.c",
  "funcName": "move_path",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "  * This program is free software; you can redistribute it and/or * modify it under the terms of version 2 of the GNU General Public * License as published by the Free Software Foundation. "
    },
    {
      "start_line": 21,
      "end_line": 21,
      "text": " Check needed to avoid verifier complaining about unbounded access"
    },
    {
      "start_line": 22,
      "end_line": 22,
      "text": " The check needs to be placed very near the actual line"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct dst_infos *dst_infos",
    " __u32 key",
    " struct bpf_sock_ops *skops"
  ],
  "output": "static__inlineint",
  "helper": [
    "bpf_setsockopt"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "static __inline int move_path (struct dst_infos *dst_infos, __u32 key, struct bpf_sock_ops *skops)\n",
    "{\n",
    "    int rv = 1;\n",
    "    char cc [20];\n",
    "    struct ip6_srh_t *srh = NULL;\n",
    "    if (key >= 0 && key < MAX_SRH_BY_DEST) {\n",
    "        srh = &(dst_infos->srhs[key].srh);\n",
    "        rv = bpf_setsockopt (skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof (* srh));\n",
    "        bpf_debug (\"bpf_setsockopt !!!!! %d\\n\", rv);\n",
    "    }\n",
    "    return !!rv;\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_debug"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    }
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
static __inline int move_path(struct dst_infos *dst_infos, __u32 key, struct bpf_sock_ops *skops)
{
	int rv = 1;
	char cc[20];
	struct ip6_srh_t *srh = NULL;
	// Check needed to avoid verifier complaining about unbounded access
	// The check needs to be placed very near the actual line
	if (key >= 0 && key < MAX_SRH_BY_DEST) {
		srh = &(dst_infos->srhs[key].srh);
		rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		bpf_debug("bpf_setsockopt !!!!! %d\n", rv);
	}
	return !!rv;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
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
  "startLine": 31,
  "endLine": 52,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_exp3_lowest_completion.c",
  "funcName": "create_new_flow_infos",
  "developer_inline_comments": [
    {
      "start_line": 37,
      "end_line": 37,
      "text": "bpf_debug(\"flow not found, adding it\\n\");"
    },
    {
      "start_line": 42,
      "end_line": 42,
      "text": " Listening connections"
    },
    {
      "start_line": 44,
      "end_line": 44,
      "text": " Inititialize to 1 EXP3 weight and probabilities"
    },
    {
      "start_line": 48,
      "end_line": 48,
      "text": "bpf_debug(\"HHHHHHHHH FLOW src port %u - dst port %u\\n\", flow_id->local_port, flow_id->remote_port);"
    },
    {
      "start_line": 50,
      "end_line": 50,
      "text": " Insert flow to map"
    }
  ],
  "updateMaps": [
    " c_map"
  ],
  "readMaps": [
    " dt_map"
  ],
  "input": [
    "struct bpf_elf_map *dt_map",
    " struct bpf_elf_map *c_map",
    " struct flow_tuple *flow_id",
    " __u64 cur_time",
    " struct bpf_sock_ops *skops"
  ],
  "output": "staticint",
  "helper": [
    "bpf_map_update_elem",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "tracepoint",
    "socket_filter",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "cgroup_device",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static int create_new_flow_infos (struct bpf_elf_map *dt_map, struct bpf_elf_map *c_map, struct flow_tuple *flow_id, __u64 cur_time, struct bpf_sock_ops *skops)\n",
    "{\n",
    "    struct flow_infos *flow_info;\n",
    "    struct flow_infos new_flow;\n",
    "    int rv = 0;\n",
    "    memset (&new_flow, 0, sizeof (struct flow_infos));\n",
    "    new_flow.exp3_last_number_actions = 1;\n",
    "    new_flow.exp3_start_snd_nxt = skops->snd_nxt;\n",
    "    struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem (dt_map, flow_id->remote_addr);\n",
    "    if (!dst_infos)\n",
    "        return 1;\n",
    "    new_flow.exp3_last_probability.mantissa = LARGEST_BIT;\n",
    "    new_flow.exp3_last_probability.exponent = BIAS;\n",
    "    return bpf_map_update_elem (c_map, flow_id, &new_flow, BPF_ANY);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_debug",
    "memset"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    }
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
static int create_new_flow_infos(struct bpf_elf_map *dt_map, struct bpf_elf_map *c_map, struct flow_tuple *flow_id, __u64 cur_time, struct bpf_sock_ops *skops) {
	struct flow_infos *flow_info;
	struct flow_infos new_flow;
	int rv = 0;
	memset(&new_flow, 0, sizeof(struct flow_infos));

	//bpf_debug("flow not found, adding it\n");
	new_flow.exp3_last_number_actions = 1;
	new_flow.exp3_start_snd_nxt = skops->snd_nxt;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dt_map, flow_id->remote_addr);
	if (!dst_infos)
		return 1; // Listening connections

	// Inititialize to 1 EXP3 weight and probabilities
	new_flow.exp3_last_probability.mantissa = LARGEST_BIT;
	new_flow.exp3_last_probability.exponent = BIAS;

	//bpf_debug("HHHHHHHHH FLOW src port %u - dst port %u\n", flow_id->local_port, flow_id->remote_port);

	// Insert flow to map
	return bpf_map_update_elem(c_map, flow_id, &new_flow, BPF_ANY);
}

SEC("sockops")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
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
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "bcc",
          "FunctionName": "bpf_ktime_get_ns",
          "Return Type": "u64",
          "Description": "u64 bpf_ktime_get_ns(void) Return: u64 number of nanoseconds. Starts at system boot time but stops during suspend. Examples in situ: \"https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Aexamples&type=Code search /examples , \"https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Atools&type=Code search /tools ",
          "Return": "u64 number of nanoseconds",
          "Input Prameters": [],
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
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 55,
  "endLine": 146,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_exp3_lowest_completion.c",
  "funcName": "handle_sockop",
  "developer_inline_comments": [
    {
      "start_line": 68,
      "end_line": 68,
      "text": " Only execute the prog for scp "
    },
    {
      "start_line": 75,
      "end_line": 75,
      "text": "bpf_debug(\"HERE operation %d\\n\", op);"
    },
    {
      "start_line": 76,
      "end_line": 76,
      "text": " TODO Problem if listening connections => no destination defined !!!"
    },
    {
      "start_line": 77,
      "end_line": 77,
      "text": "bpf_debug(\"HERE flow creation\\n\");"
    },
    {
      "start_line": 87,
      "end_line": 87,
      "text": "bpf_debug(\"HERE flow created %d\\n\", BPF_SOCK_OPS_ALL_CB_FLAGS);"
    },
    {
      "start_line": 94,
      "end_line": 94,
      "text": "bpf_debug(\"operation: %d\\n\", op);"
    },
    {
      "start_line": 95,
      "end_line": 95,
      "text": "bpf_debug(\"snd_una: %lu rate : %lu interval: %lu\\n\", skops->snd_una, skops->rate_delivered, skops->rate_interval_us);"
    },
    {
      "start_line": 97,
      "end_line": 97,
      "text": " Call EXP3 for servers (because setting the SRH for request socks does not work)"
    },
    {
      "start_line": 105,
      "end_line": 105,
      "text": " Retrieve time for completion time (advantage: ignores SYN+ACK delay)"
    },
    {
      "start_line": 119,
      "end_line": 119,
      "text": " Change in the state of the TCP CONNECTION"
    },
    {
      "start_line": 120,
      "end_line": 120,
      "text": " This flow is closed, cleanup the maps"
    },
    {
      "start_line": 123,
      "end_line": 123,
      "text": "bpf_debug(\"close syn delay %llu\\n\", flow_info->established_timestamp);"
    },
    {
      "start_line": 124,
      "end_line": 124,
      "text": "bpf_debug(\"close rtt delay %llu\\n\", flow_info->rtt_timestamp);"
    },
    {
      "start_line": 125,
      "end_line": 125,
      "text": "bpf_debug(\"close delay %llu\\n\", flow_info->rtt_timestamp - flow_info->established_timestamp);"
    },
    {
      "start_line": 128,
      "end_line": 128,
      "text": " Store experience if we use EXP3, otherwise, pure random"
    },
    {
      "start_line": 131,
      "end_line": 131,
      "text": " Delete the flow from the flows map"
    },
    {
      "start_line": 133,
      "end_line": 133,
      "text": " Save updated weights"
    },
    {
      "start_line": 137,
      "end_line": 137,
      "text": " Save data"
    }
  ],
  "updateMaps": [
    "  short_conn_map",
    " short_conn_map",
    "  short_dest_map"
  ],
  "readMaps": [
    " short_conn_map",
    " short_dest_map"
  ],
  "input": [
    "struct bpf_sock_ops *skops"
  ],
  "output": "int",
  "helper": [
    "bpf_sock_ops_cb_flags_set",
    "bpf_map_delete_elem",
    "bpf_map_update_elem",
    "bpf_map_lookup_elem",
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "int handle_sockop (struct bpf_sock_ops *skops)\n",
    "{\n",
    "    struct dst_infos *dst_infos;\n",
    "    struct flow_infos *flow_info;\n",
    "    struct flow_tuple flow_id;\n",
    "    int op;\n",
    "    int rv = 0;\n",
    "    __u64 cur_time;\n",
    "    cur_time = bpf_ktime_get_ns ();\n",
    "    op = (int) skops->op;\n",
    "    if (skops->family != AF_INET6) {\n",
    "        skops->reply = -1;\n",
    "        return 0;\n",
    "    }\n",
    "    get_flow_id_from_sock (&flow_id, skops);\n",
    "    flow_info = (void *) bpf_map_lookup_elem (&short_conn_map, &flow_id);\n",
    "    if (!flow_info) {\n",
    "        if (create_new_flow_infos (&short_dest_map, &short_conn_map, &flow_id, cur_time, skops)) {\n",
    "            return 1;\n",
    "        }\n",
    "        flow_info = (void *) bpf_map_lookup_elem (&short_conn_map, &flow_id);\n",
    "        if (flow_info) {\n",
    "            dst_infos = (void *) bpf_map_lookup_elem (&short_dest_map, flow_id.remote_addr);\n",
    "            if (dst_infos) {\n",
    "                bpf_sock_ops_cb_flags_set (skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG | BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG));\n",
    "                skops->reply = rv;\n",
    "                return 0;\n",
    "            }\n",
    "        }\n",
    "        return 1;\n",
    "    }\n",
    "    switch (op) {\n",
    "    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB :\n",
    "        bpf_debug (\"passive established\\n\");\n",
    "        flow_info->srh_id = exp3_next_path (&short_dest_map, flow_info, flow_id.remote_addr);\n",
    "        dst_infos = (void *) bpf_map_lookup_elem (&short_dest_map, flow_id.remote_addr);\n",
    "        if (dst_infos) {\n",
    "            move_path (dst_infos, flow_info->srh_id, skops);\n",
    "            flow_info->exp3_start_snd_nxt = skops->snd_nxt;\n",
    "            flow_info->established_timestamp = cur_time;\n",
    "            flow_info->rtt_timestamp = cur_time;\n",
    "            if (flow_info->srh_id >= 0 && flow_info->srh_id <= MAX_SRH_BY_DEST - 1)\n",
    "                flow_info->exp3_curr_reward = dst_infos->srhs[flow_info->srh_id].curr_bw;\n",
    "            rv = bpf_map_update_elem (& short_conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "        }\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_RTT_CB :\n",
    "        flow_info->rtt_timestamp = cur_time;\n",
    "        rv = bpf_map_update_elem (& short_conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_STATE_CB :\n",
    "        if (skops->args[1] == BPF_TCP_CLOSE) {\n",
    "            bpf_debug (\"close: %d\\n\", skops->args[1]);\n",
    "            dst_infos = (void *) bpf_map_lookup_elem (&short_dest_map, flow_id.remote_addr);\n",
    "            if (dst_infos) {\n",
    "                if (USE_EXP3)\n",
    "                    exp3_reward_path (flow_info, dst_infos, skops);\n",
    "                bpf_map_delete_elem (&short_conn_map, &flow_id);\n",
    "                rv = bpf_map_update_elem (& short_dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);\n",
    "                if (rv)\n",
    "                    return 1;\n",
    "                take_snapshot (&short_stat_map, dst_infos, flow_info);\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    }\n",
    "    skops->reply = rv;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "move_path",
    "create_new_flow_infos",
    "bpf_debug",
    "inner_loop",
    "exp3_next_path",
    "get_flow_id_from_sock",
    "memcpy",
    "memset",
    "traceroute",
    "take_snapshot",
    "exp3_reward_path",
    "unroll"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
    }
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
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct dst_infos *dst_infos;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;

	int op;
	int rv = 0;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&short_conn_map, &flow_id);
	//bpf_debug("HERE operation %d\n", op);
	if (!flow_info) {  // TODO Problem if listening connections => no destination defined !!!
		//bpf_debug("HERE flow creation\n");
		if (create_new_flow_infos(&short_dest_map, &short_conn_map, &flow_id, cur_time, skops)) {
			return 1;
		}
		flow_info = (void *) bpf_map_lookup_elem(&short_conn_map, &flow_id);
		if (flow_info) {
			dst_infos = (void *) bpf_map_lookup_elem(&short_dest_map, flow_id.remote_addr);
			if (dst_infos) {
				bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG|BPF_SOCK_OPS_STATE_CB_FLAG));
				skops->reply = rv;
				//bpf_debug("HERE flow created %d\n", BPF_SOCK_OPS_ALL_CB_FLAGS);
				return 0;
			}
		}
		return 1;
	}

	//bpf_debug("operation: %d\n", op);
	//bpf_debug("snd_una: %lu rate : %lu interval: %lu\n", skops->snd_una, skops->rate_delivered, skops->rate_interval_us);
	switch (op) {
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // Call EXP3 for servers (because setting the SRH for request socks does not work)
			bpf_debug("passive established\n");
			flow_info->srh_id = exp3_next_path(&short_dest_map, flow_info, flow_id.remote_addr);
			dst_infos = (void *)bpf_map_lookup_elem(&short_dest_map, flow_id.remote_addr);
			if (dst_infos) {
				move_path(dst_infos, flow_info->srh_id, skops);
				flow_info->exp3_start_snd_nxt = skops->snd_nxt;

				// Retrieve time for completion time (advantage: ignores SYN+ACK delay)
				flow_info->established_timestamp = cur_time;
				flow_info->rtt_timestamp = cur_time;

				if (flow_info->srh_id >= 0 && flow_info->srh_id <= MAX_SRH_BY_DEST - 1)
					flow_info->exp3_curr_reward = dst_infos->srhs[flow_info->srh_id].curr_bw;

				rv = bpf_map_update_elem(&short_conn_map, &flow_id, flow_info, BPF_ANY);
			}
			break;
		case BPF_SOCK_OPS_RTT_CB:
			flow_info->rtt_timestamp = cur_time;
			rv = bpf_map_update_elem(&short_conn_map, &flow_id, flow_info, BPF_ANY);
			break;
		case BPF_SOCK_OPS_STATE_CB: // Change in the state of the TCP CONNECTION
			// This flow is closed, cleanup the maps
			if (skops->args[1] == BPF_TCP_CLOSE) {
				bpf_debug("close: %d\n", skops->args[1]);
				//bpf_debug("close syn delay %llu\n", flow_info->established_timestamp);
				//bpf_debug("close rtt delay %llu\n", flow_info->rtt_timestamp);
				//bpf_debug("close delay %llu\n", flow_info->rtt_timestamp - flow_info->established_timestamp);
				dst_infos = (void *) bpf_map_lookup_elem(&short_dest_map, flow_id.remote_addr);
				if (dst_infos) {
					// Store experience if we use EXP3, otherwise, pure random
					if (USE_EXP3)
						exp3_reward_path(flow_info, dst_infos, skops);
					// Delete the flow from the flows map
					bpf_map_delete_elem(&short_conn_map, &flow_id);
					// Save updated weights
					rv = bpf_map_update_elem(&short_dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
					if (rv)
						return 1;
					// Save data
					take_snapshot(&short_stat_map, dst_infos, flow_info);
				}
			}
			break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
