/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF LONG FLOWS"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_n_rto_changer.h"


/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 16,
  "endLine": 41,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_n_rto_changer.c",
  "funcName": "inner_loop",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "  * This program is free software; you can redistribute it and/or * modify it under the terms of version 2 of the GNU General Public * License as published by the Free Software Foundation. "
    },
    {
      "start_line": 23,
      "end_line": 23,
      "text": " Wrong SRH ID -> might be inconsistent state, so skip"
    },
    {
      "start_line": 24,
      "end_line": 24,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 25,
      "end_line": 25,
      "text": " Same SRH"
    },
    {
      "start_line": 26,
      "end_line": 26,
      "text": " 1"
    },
    {
      "start_line": 27,
      "end_line": 27,
      "text": "bpf_debug(\"Cannot find the SRH entry indexed at %d at a dest entry\\n\", i);"
    },
    {
      "start_line": 31,
      "end_line": 31,
      "text": " 1"
    },
    {
      "start_line": 32,
      "end_line": 32,
      "text": "bpf_debug(\"SRH entry indexed at %d by the dest entry is invalid\\n\", i);"
    },
    {
      "start_line": 33,
      "end_line": 33,
      "text": " Not a valid SRH for the destination"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 srh_id",
    " struct dst_infos *dst_infos"
  ],
  "output": "static__u32",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "socket_filter",
    "tracepoint",
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
    "static __u32 inner_loop (__u32 srh_id, struct dst_infos *dst_infos)\n",
    "{\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {\n",
    "        if (!dst_infos)\n",
    "            continue;\n",
    "        struct srh_record_t *srh_record = &dst_infos->srhs[i];\n",
    "        if (!srh_record || !srh_record->srh.type) {\n",
    "            continue;\n",
    "        }\n",
    "        if (!srh_record->is_valid) {\n",
    "            continue;\n",
    "        }\n",
    "        if (i > srh_id) {\n",
    "            return i;\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "",
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
static __u32 inner_loop(__u32 srh_id, struct dst_infos* dst_infos) {
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		if (!dst_infos)
			continue;
		struct srh_record_t *srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 1
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 1
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		if (i > srh_id) {
			return i;
		}
	}
	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
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
  "startLine": 43,
  "endLine": 76,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_n_rto_changer.c",
  "funcName": "move_path",
  "developer_inline_comments": [
    {
      "start_line": 52,
      "end_line": 52,
      "text": " Check needed to avoid verifier complaining about unbounded access"
    },
    {
      "start_line": 53,
      "end_line": 53,
      "text": " The check needs to be placed very near the actual line"
    },
    {
      "start_line": 60,
      "end_line": 60,
      "text": " Reset congestion control"
    },
    {
      "start_line": 61,
      "end_line": 61,
      "text": " TODO This removes the estimation of the RTT and puts a timeout of 1 seconds by default"
    },
    {
      "start_line": 62,
      "end_line": 62,
      "text": " It will do nothing if there is no actual change..."
    },
    {
      "start_line": 63,
      "end_line": 63,
      "text": " The problem is that it does not reset the retransmission timeout..."
    },
    {
      "start_line": 64,
      "end_line": 64,
      "text": "rv = bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));"
    },
    {
      "start_line": 65,
      "end_line": 65,
      "text": "if (!rv) {  TODO Handle case with reno as base congestion control"
    },
    {
      "start_line": 66,
      "end_line": 66,
      "text": "\trv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, tmp_cc, sizeof(tmp_cc));"
    },
    {
      "start_line": 67,
      "end_line": 67,
      "text": "\trv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));"
    },
    {
      "start_line": 68,
      "end_line": 68,
      "text": "}"
    },
    {
      "start_line": 71,
      "end_line": 71,
      "text": "bpf_debug(\"Set Path changed - returned %u\\n\", rv);"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " dst_map"
  ],
  "input": [
    "struct bpf_elf_map *dst_map",
    " void *id",
    " __u32 key",
    " struct bpf_sock_ops *skops"
  ],
  "output": "staticint",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_setsockopt"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "static int move_path (struct bpf_elf_map *dst_map, void *id, __u32 key, struct bpf_sock_ops *skops)\n",
    "{\n",
    "    int val = 1;\n",
    "    int rv = 1;\n",
    "    char cc [20];\n",
    "    char tmp_cc [5] = \"reno\";\n",
    "    struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem (dst_map, id);\n",
    "    if (dst_infos) {\n",
    "        struct ip6_srh_t *srh = NULL;\n",
    "        if (key >= 0 && key < MAX_SRH_BY_DEST) {\n",
    "            srh = &(dst_infos->srhs[key].srh);\n",
    "            rv = bpf_setsockopt (skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof (* srh));\n",
    "        }\n",
    "        if (!rv) {\n",
    "            if (!rv) {\n",
    "                rv = bpf_setsockopt (skops, SOL_TCP, TCP_PATH_CHANGED, & val, sizeof (val));\n",
    "            }\n",
    "        }\n",
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
static int move_path(struct bpf_elf_map *dst_map, void *id, __u32 key, struct bpf_sock_ops *skops)
{
	int val = 1;
	int rv = 1;
	char cc[20];
	char tmp_cc[5] = "reno";
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dst_map, id);
	if (dst_infos) {
		struct ip6_srh_t *srh = NULL;
		// Check needed to avoid verifier complaining about unbounded access
		// The check needs to be placed very near the actual line
		if (key >= 0 && key < MAX_SRH_BY_DEST) {
			srh = &(dst_infos->srhs[key].srh);
			rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		}

		if (!rv) {
			// Reset congestion control
			// TODO This removes the estimation of the RTT and puts a timeout of 1 seconds by default
			// It will do nothing if there is no actual change...
			// The problem is that it does not reset the retransmission timeout...
			//rv = bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
			//if (!rv) { // TODO Handle case with reno as base congestion control
			//	rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, tmp_cc, sizeof(tmp_cc));
			//	rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
			//}
			if (!rv) {
				rv = bpf_setsockopt(skops, SOL_TCP, TCP_PATH_CHANGED, &val, sizeof(val));
				//bpf_debug("Set Path changed - returned %u\n", rv);
			}
		}
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
  "startLine": 78,
  "endLine": 92,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_n_rto_changer.c",
  "funcName": "create_new_flow_infos",
  "developer_inline_comments": [
    {
      "start_line": 84,
      "end_line": 84,
      "text": " Timers"
    },
    {
      "start_line": 88,
      "end_line": 88,
      "text": " Listening connections"
    },
    {
      "start_line": 90,
      "end_line": 90,
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
    "    new_flow.last_move_time = cur_time;\n",
    "    struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem (dt_map, flow_id->remote_addr);\n",
    "    if (!dst_infos)\n",
    "        return 1;\n",
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

	// Timers
	new_flow.last_move_time = cur_time;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dt_map, flow_id->remote_addr);
	if (!dst_infos)
		return 1; // Listening connections

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
  "startLine": 95,
  "endLine": 263,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_n_rto_changer.c",
  "funcName": "handle_sockop",
  "developer_inline_comments": [
    {
      "start_line": 105,
      "end_line": 105,
      "text": " Only execute the prog for scp "
    },
    {
      "start_line": 115,
      "end_line": 115,
      "text": "bpf_debug(\"active SYN sent from %u\\n\", skops->local_port);"
    },
    {
      "start_line": 116,
      "end_line": 116,
      "text": " XXX No break; here"
    },
    {
      "start_line": 117,
      "end_line": 117,
      "text": " Call EXP4 for servers (because setting the SRH for request socks does not work)"
    },
    {
      "start_line": 141,
      "end_line": 141,
      "text": "if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)"
    },
    {
      "start_line": 142,
      "end_line": 142,
      "text": "\tbpf_debug(\"passive established - timer %llu\\n\", flow_info->last_move_time);"
    },
    {
      "start_line": 144,
      "end_line": 144,
      "text": " Change in the state of the TCP CONNECTION"
    },
    {
      "start_line": 145,
      "end_line": 145,
      "text": " This flow is closed, cleanup the maps"
    },
    {
      "start_line": 147,
      "end_line": 147,
      "text": "bpf_debug(\"Close\\n\");"
    },
    {
      "start_line": 151,
      "end_line": 151,
      "text": " Delete the flow from the flows map"
    },
    {
      "start_line": 152,
      "end_line": 152,
      "text": " take_snapshot(&stat_map, flow_info, &flow_id);"
    },
    {
      "start_line": 161,
      "end_line": 161,
      "text": "bpf_debug(\"Duplicated ack: nbr %llu for %llu\\n\", flow_info->retrans_count, skops->rcv_nxt);"
    },
    {
      "start_line": 163,
      "end_line": 163,
      "text": " Data was acked so issue was solved"
    },
    {
      "start_line": 171,
      "end_line": 171,
      "text": " TODO This number needs to be strictly lower than the RTO trigger..."
    },
    {
      "start_line": 172,
      "end_line": 172,
      "text": " It can work with equal values if bytes were in flight at the failure but never greater values"
    },
    {
      "start_line": 177,
      "end_line": 177,
      "text": " This assumes that SRH 0 is always valid"
    },
    {
      "start_line": 180,
      "end_line": 180,
      "text": "bpf_debug(\"DUP ACK - Change path to %u\\n\", key_dup);"
    },
    {
      "start_line": 183,
      "end_line": 183,
      "text": " This can't be helped"
    },
    {
      "start_line": 188,
      "end_line": 188,
      "text": " Move to the next path"
    },
    {
      "start_line": 192,
      "end_line": 192,
      "text": " Update flow informations"
    },
    {
      "start_line": 200,
      "end_line": 200,
      "text": " TODO Retransmission"
    },
    {
      "start_line": 205,
      "end_line": 205,
      "text": " TODO Remove ?"
    },
    {
      "start_line": 207,
      "end_line": 207,
      "text": " TODO Retransmission timeout"
    },
    {
      "start_line": 208,
      "end_line": 208,
      "text": " TODO The problem is that the connection is cut from the server to the client as well..."
    },
    {
      "start_line": 209,
      "end_line": 209,
      "text": " TODO So the server also needs this program (or a single-side cut)..."
    },
    {
      "start_line": 210,
      "end_line": 210,
      "text": " TODO But it won't work if the server is only acking because no eBPF is made..."
    },
    {
      "start_line": 216,
      "end_line": 216,
      "text": "bpf_debug(\"Params: %u %u %u\\n\", skops->args[0], skops->args[1], skops->args[2]);"
    },
    {
      "start_line": 219,
      "end_line": 219,
      "text": " Data was acked so issue was solved TODO Try with a delta of two packets"
    },
    {
      "start_line": 233,
      "end_line": 233,
      "text": " After three duplicated acknowledgments for the same data, switch path"
    },
    {
      "start_line": 235,
      "end_line": 235,
      "text": " This assumes that SRH 0 is always valid"
    },
    {
      "start_line": 238,
      "end_line": 238,
      "text": "bpf_debug(\"RTO - Change path to %u\\n\", key);"
    },
    {
      "start_line": 241,
      "end_line": 241,
      "text": " This can't be helped"
    },
    {
      "start_line": 246,
      "end_line": 246,
      "text": " Move to the next path"
    },
    {
      "start_line": 250,
      "end_line": 250,
      "text": " Update flow informations"
    }
  ],
  "updateMaps": [
    "  conn_map",
    " conn_map"
  ],
  "readMaps": [
    " conn_map",
    " dest_map"
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
    "    struct flow_infos *flow_info;\n",
    "    struct flow_tuple flow_id;\n",
    "    int rv = 0;\n",
    "    __u64 cur_time;\n",
    "    cur_time = bpf_ktime_get_ns ();\n",
    "    if (skops->family != AF_INET6) {\n",
    "        skops->reply = -1;\n",
    "        return 0;\n",
    "    }\n",
    "    get_flow_id_from_sock (&flow_id, skops);\n",
    "    flow_info = (void *) bpf_map_lookup_elem (&conn_map, &flow_id);\n",
    "    switch ((int) skops->op) {\n",
    "    case BPF_SOCK_OPS_TCP_CONNECT_CB :\n",
    "    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB :\n",
    "        if (!flow_info) {\n",
    "            if (create_new_flow_infos (&dest_map, &conn_map, &flow_id, cur_time, skops)) {\n",
    "                return 1;\n",
    "            }\n",
    "            flow_info = (void *) bpf_map_lookup_elem (&conn_map, &flow_id);\n",
    "            if (!flow_info) {\n",
    "                return 1;\n",
    "            }\n",
    "        }\n",
    "        bpf_debug (\"INIT CONN snd_cwnd: %u\\n\", skops->snd_cwnd);\n",
    "        flow_info->last_move_time = cur_time;\n",
    "        flow_info->srh_id = 0;\n",
    "        move_path (&dest_map, flow_id.remote_addr, flow_info->srh_id, skops);\n",
    "        rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "        if (rv)\n",
    "            return 1;\n",
    "        take_snapshot (&stat_map, flow_info, &flow_id, skops->op);\n",
    "        bpf_sock_ops_cb_flags_set (skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG | BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG));\n",
    "        skops->reply = rv;\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_STATE_CB :\n",
    "        if (skops->args[1] == BPF_TCP_CLOSE || skops->args[1] == BPF_TCP_CLOSE_WAIT || skops->args[1] == BPF_TCP_CLOSING || skops->args[1] == BPF_TCP_FIN_WAIT1 || skops->args[1] == BPF_TCP_FIN_WAIT2) {\n",
    "            if (!flow_info) {\n",
    "                return 0;\n",
    "            }\n",
    "            bpf_map_delete_elem (&conn_map, &flow_id);\n",
    "        }\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_DUPACK :\n",
    "        if (!flow_info) {\n",
    "            return 1;\n",
    "        }\n",
    "        flow_info->retrans_count += 1;\n",
    "        if (flow_info->last_rcv_nxt != skops->rcv_nxt) {\n",
    "            flow_info->last_rcv_nxt = skops->rcv_nxt;\n",
    "            flow_info->retrans_count = 1;\n",
    "            rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "            break;\n",
    "        }\n",
    "        if (flow_info->retrans_count < 2) {\n",
    "            rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "            break;\n",
    "        }\n",
    "        __u32 key_dup = 0;\n",
    "        struct dst_infos *dst_infos_dup = (void *) bpf_map_lookup_elem (&dest_map, flow_id.remote_addr);\n",
    "        key_dup = inner_loop (flow_info -> srh_id, dst_infos_dup);\n",
    "        if (key_dup == flow_info->srh_id) {\n",
    "            rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "            break;\n",
    "        }\n",
    "        bpf_debug (\"DUP ACK - Change path to %u\\n\", key_dup);\n",
    "        rv = move_path (& dest_map, flow_id.remote_addr, key_dup, skops);\n",
    "        if (!rv) {\n",
    "            flow_info->srh_id = key_dup;\n",
    "            flow_info->last_move_time = cur_time;\n",
    "            flow_info->retrans_count = 0;\n",
    "            bpf_debug (\"DUP ACK - Path changed to %u\\n\", key_dup);\n",
    "        }\n",
    "        take_snapshot (&stat_map, flow_info, &flow_id, skops->op);\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_RETRANS_CB :\n",
    "        if (!flow_info) {\n",
    "            return 0;\n",
    "        }\n",
    "        bpf_debug (\"Retransmission: for %llu\\n\", skops->snd_una);\n",
    "        take_snapshot (&stat_map, flow_info, &flow_id, skops->op);\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_RTO_CB :\n",
    "        if (!flow_info) {\n",
    "            return 1;\n",
    "        }\n",
    "        flow_info->retrans_count += 1;\n",
    "        bpf_debug (\"Retransmission timeout: nbr %llu for %llu\\n\", flow_info->retrans_count, skops->snd_una);\n",
    "        bpf_debug (\"snd_cwnd: %u - packets_out %u\\n\", skops->snd_cwnd, skops->packets_out);\n",
    "        if (flow_info->last_snd_una + 3000 < skops->snd_una) {\n",
    "            flow_info->last_snd_una = skops->snd_una;\n",
    "            flow_info->retrans_count = 1;\n",
    "            rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "            take_snapshot (&stat_map, flow_info, &flow_id, skops->op);\n",
    "            break;\n",
    "        }\n",
    "        if (flow_info->retrans_count < 3) {\n",
    "            rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "            take_snapshot (&stat_map, flow_info, &flow_id, skops->op);\n",
    "            break;\n",
    "        }\n",
    "        __u32 key = 0;\n",
    "        struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem (&dest_map, flow_id.remote_addr);\n",
    "        key = inner_loop (flow_info -> srh_id, dst_infos);\n",
    "        if (key == flow_info->srh_id) {\n",
    "            rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
    "            break;\n",
    "        }\n",
    "        bpf_debug (\"RTO - Change path to %u\\n\", key);\n",
    "        rv = move_path (& dest_map, flow_id.remote_addr, key, skops);\n",
    "        if (!rv) {\n",
    "            flow_info->srh_id = key;\n",
    "            flow_info->last_move_time = cur_time;\n",
    "            flow_info->retrans_count = 0;\n",
    "            bpf_debug (\"RTO - Path changed to %u\\n\", key);\n",
    "        }\n",
    "        take_snapshot (&stat_map, flow_info, &flow_id, skops->op);\n",
    "        rv = bpf_map_update_elem (& conn_map, & flow_id, flow_info, BPF_ANY);\n",
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
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;

	int rv = 0;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);

	switch ((int) skops->op) {
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			//bpf_debug("active SYN sent from %u\n", skops->local_port);
			// XXX No break; here
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // Call EXP4 for servers (because setting the SRH for request socks does not work)
			if (!flow_info) {
				if (create_new_flow_infos(&dest_map, &conn_map, &flow_id, cur_time, skops)) {
					return 1;
				}
				flow_info = (void *) bpf_map_lookup_elem(&conn_map, &flow_id);
				if (!flow_info) {
					return 1;
				}
			}
			bpf_debug("INIT CONN snd_cwnd: %u\n", skops->snd_cwnd);

			flow_info->last_move_time = cur_time;
			flow_info->srh_id = 0;
			move_path(&dest_map, flow_id.remote_addr, flow_info->srh_id, skops);
			rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			if (rv)
				return 1;

			take_snapshot(&stat_map, flow_info, &flow_id, skops->op);

			bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG|BPF_SOCK_OPS_STATE_CB_FLAG));
			skops->reply = rv;

			//if (skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
			//	bpf_debug("passive established - timer %llu\n", flow_info->last_move_time);
			break;
		case BPF_SOCK_OPS_STATE_CB: // Change in the state of the TCP CONNECTION
			// This flow is closed, cleanup the maps
			if (skops->args[1] == BPF_TCP_CLOSE || skops->args[1] == BPF_TCP_CLOSE_WAIT || skops->args[1] == BPF_TCP_CLOSING || skops->args[1] == BPF_TCP_FIN_WAIT1 || skops->args[1] == BPF_TCP_FIN_WAIT2) {
				//bpf_debug("Close\n");
				if (!flow_info) {
					return 0;
				}
				// Delete the flow from the flows map
				// take_snapshot(&stat_map, flow_info, &flow_id);
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		case BPF_SOCK_OPS_DUPACK:
			if (!flow_info) {
				return 1;
			}
			flow_info->retrans_count += 1;
			//bpf_debug("Duplicated ack: nbr %llu for %llu\n", flow_info->retrans_count, skops->rcv_nxt);

			if (flow_info->last_rcv_nxt != skops->rcv_nxt) { // Data was acked so issue was solved
				flow_info->last_rcv_nxt = skops->rcv_nxt;
				flow_info->retrans_count = 1;
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			if (flow_info->retrans_count < 2) {
				// TODO This number needs to be strictly lower than the RTO trigger...
				// It can work with equal values if bytes were in flight at the failure but never greater values
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			__u32 key_dup = 0; // This assumes that SRH 0 is always valid
			struct dst_infos *dst_infos_dup = (void *) bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			key_dup = inner_loop(flow_info->srh_id, dst_infos_dup);
			//bpf_debug("DUP ACK - Change path to %u\n", key_dup);

			if (key_dup == flow_info->srh_id) {
				// This can't be helped
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			// Move to the next path
			bpf_debug("DUP ACK - Change path to %u\n", key_dup);
			rv = move_path(&dest_map, flow_id.remote_addr, key_dup, skops);
			if (!rv) {
				// Update flow informations
				flow_info->srh_id = key_dup;
				flow_info->last_move_time = cur_time;
				flow_info->retrans_count = 0;
				bpf_debug("DUP ACK - Path changed to %u\n", key_dup);
			}
			take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
			break;
		case BPF_SOCK_OPS_RETRANS_CB: // TODO Retransmission
			if (!flow_info) {
				return 0;
			}
			bpf_debug("Retransmission: for %llu\n", skops->snd_una);
			take_snapshot(&stat_map, flow_info, &flow_id, skops->op); // TODO Remove ?
			break;
		case BPF_SOCK_OPS_RTO_CB: // TODO Retransmission timeout
			// TODO The problem is that the connection is cut from the server to the client as well...
			// TODO So the server also needs this program (or a single-side cut)...
			// TODO But it won't work if the server is only acking because no eBPF is made...
			if (!flow_info) {
				return 1;
			}
			flow_info->retrans_count += 1;
			bpf_debug("Retransmission timeout: nbr %llu for %llu\n", flow_info->retrans_count, skops->snd_una);
			//bpf_debug("Params: %u %u %u\n", skops->args[0], skops->args[1], skops->args[2]);
			bpf_debug("snd_cwnd: %u - packets_out %u\n", skops->snd_cwnd, skops->packets_out);

			if (flow_info->last_snd_una + 3000 < skops->snd_una) { // Data was acked so issue was solved TODO Try with a delta of two packets
				flow_info->last_snd_una = skops->snd_una;
				flow_info->retrans_count = 1;
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
				break;
			}

			if (flow_info->retrans_count < 3) { 
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
				break;
			}

			// After three duplicated acknowledgments for the same data, switch path

			__u32 key = 0; // This assumes that SRH 0 is always valid
			struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			key = inner_loop(flow_info->srh_id, dst_infos);
			//bpf_debug("RTO - Change path to %u\n", key);

			if (key == flow_info->srh_id) {
				// This can't be helped
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			// Move to the next path
			bpf_debug("RTO - Change path to %u\n", key);
			rv = move_path(&dest_map, flow_id.remote_addr, key, skops);
			if (!rv) {
				// Update flow informations
				flow_info->srh_id = key;
				flow_info->last_move_time = cur_time;
				flow_info->retrans_count = 0;
				bpf_debug("RTO - Path changed to %u\n", key);
			}
			take_snapshot(&stat_map, flow_info, &flow_id, skops->op);
			rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
