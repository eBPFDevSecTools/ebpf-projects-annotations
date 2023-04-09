/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF SECOND PATH"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_use_second_path.h"

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
  "startLine": 15,
  "endLine": 29,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_use_second_path.c",
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
    "    int rv = 1;\n",
    "    struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem (dst_map, id);\n",
    "    if (dst_infos) {\n",
    "        struct ip6_srh_t *srh = NULL;\n",
    "        if (key >= 0 && key < MAX_SRH_BY_DEST) {\n",
    "            srh = &(dst_infos->srhs[key].srh);\n",
    "            rv = bpf_setsockopt (skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof (* srh));\n",
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
      "description": "The move_path function looks up the destination information in dst_map using id as the key. If the lookup returns a non-NULL value, i.e. the destination is found, then the validity of key is checked.The key needs be greater than or equal to zero and less than MAX_SRH_BY_DEST. If the key is valid, the segment routing header information is stored and the socket options are set. The variable rv stores the return value of the bpf_setsockopt function. The bpf_setsockopt returns 0 on success, hence the move_path will return 1. If the dst_infos is NULL or invalid, the move_path function returns 0.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
      "date": "2023-04-09"
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
    int rv = 1;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dst_map, id);
	if (dst_infos) {
		struct ip6_srh_t *srh = NULL;
		// Check needed to avoid verifier complaining about unbounded access
		// The check needs to be placed very near the actual line
		if (key >= 0 && key < MAX_SRH_BY_DEST) {
			srh = &(dst_infos->srhs[key].srh);
			rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		}
	}
	return !!rv;
}

SEC("sockops")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
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
  "startLine": 32,
  "endLine": 58,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_use_second_path.c",
  "funcName": "handle_sockop",
  "developer_inline_comments": [
    {
      "start_line": 41,
      "end_line": 41,
      "text": " Only execute the prog for scp "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_ops *skops"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
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
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "int handle_sockop (struct bpf_sock_ops *skops)\n",
    "{\n",
    "    struct flow_tuple flow_id;\n",
    "    int rv = 0;\n",
    "    __u64 cur_time;\n",
    "    cur_time = bpf_ktime_get_ns ();\n",
    "    if (skops->family != AF_INET6) {\n",
    "        skops->reply = -1;\n",
    "        return 0;\n",
    "    }\n",
    "    get_flow_id_from_sock (&flow_id, skops);\n",
    "    switch ((int) skops->op) {\n",
    "    case BPF_SOCK_OPS_TCP_CONNECT_CB :\n",
    "    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB :\n",
    "        rv = move_path (&dest_map, flow_id.remote_addr, 1, skops);\n",
    "        bpf_debug (\"Move to path %d\\n\", rv);\n",
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
      "description": "The bpf_ktime_get_ns function returns the time elapsed since system boot, in nanoseconds. If the skops->family is not AF_INET6, the function terminates by returning 0. This is done to only allow flow for scp. Next, the get_flow_id_from_sock function fetches the current flow details from the socket. If the skops->op is set to either BPF_SOCK_OPS_TCP_CONNECT_CB(Calls BPF program right before an active connection is initialized) or BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB(Calls BPF program when a passive connection is established), then move_path is called with the current flow's remote address and key set to 1. move_path returns 1 on success, 0 on failure which is stored in the rv variable. This value is stored in skops->reply and the function returns 0.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
      "date": "2023-04-09"
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

	switch ((int) skops->op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			rv = move_path(&dest_map, flow_id.remote_addr, 1, skops);
            bpf_debug("Move to path %d\n", rv);
            break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";

