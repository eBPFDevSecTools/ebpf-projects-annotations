/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF TRACEROUTE"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_endian.h"
#include "kernel.h"

#define DEBUG 1 // Always prints
#include "ebpf_traceroute.h"

#define BASE_OP 50 // This value with the increment_hops cannot exceed 255: the maximum opcode to start the eBPF program

static int connection_number = 0;


/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Emulate a call to getsockopt() on the socket associated to <[ bpf_socket ]>(IP: 0) , which must be a full socket. The <[ level ]>(IP: 1) at which the option resides and the name <[ optname ]>(IP: 2) of the option must be specified , see getsockopt(2) for more information. The retrieved value is stored in the structure pointed by opval and of length optlen. This helper actually implements a subset of getsockopt(). It supports the following levels: \u00b7 IPPROTO_TCP , which supports <[ optname ]>(IP: 2) TCP_CONGESTION. \u00b7 IPPROTO_IP , which supports <[ optname ]>(IP: 2) IP_TOS. \u00b7 IPPROTO_IPV6 , which supports <[ optname ]>(IP: 2) IPV6_TCLASS. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_getsockopt",
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
            "read_sys_info"
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
  "startLine": 21,
  "endLine": 57,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_traceroute.c",
  "funcName": "traceroute",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "  * This program is free software; you can redistribute it and/or * modify it under the terms of version 2 of the GNU General Public * License as published by the Free Software Foundation. "
    },
    {
      "start_line": 13,
      "end_line": 13,
      "text": " Always prints"
    },
    {
      "start_line": 16,
      "end_line": 16,
      "text": " This value with the increment_hops cannot exceed 255: the maximum opcode to start the eBPF program"
    },
    {
      "start_line": 24,
      "end_line": 24,
      "text": " Get current Hop Limit"
    },
    {
      "start_line": 32,
      "end_line": 32,
      "text": " Change Hop Limit for probe"
    },
    {
      "start_line": 39,
      "end_line": 39,
      "text": " Send ack probe that should trigger "
    },
    {
      "start_line": 46,
      "end_line": 46,
      "text": " Reset Hop Limit"
    },
    {
      "start_line": 51,
      "end_line": 51,
      "text": " Start timer"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_ops *skops",
    " int increment_hops"
  ],
  "output": "staticint",
  "helper": [
    "bpf_getsockopt",
    "bpf_setsockopt"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "static int traceroute (struct bpf_sock_ops *skops, int increment_hops)\n",
    "{\n",
    "    int rv = 0;\n",
    "    int old_hops = 0;\n",
    "    rv = bpf_getsockopt (skops, SOL_IPV6, IPV6_UNICAST_HOPS, & old_hops, sizeof (int));\n",
    "    if (rv) {\n",
    "        bpf_debug (\"Cannot get Hop Limit: %d\\n\", rv);\n",
    "        return rv;\n",
    "    }\n",
    "    rv = bpf_setsockopt (skops, SOL_IPV6, IPV6_UNICAST_HOPS, & increment_hops, sizeof (int));\n",
    "    if (rv) {\n",
    "        bpf_debug (\"Cannot set Hop Limit to %d: %d\\n\", increment_hops, rv);\n",
    "        return rv;\n",
    "    }\n",
    "    rv = bpf_send_ack (skops);\n",
    "    if (rv) {\n",
    "        bpf_debug (\"Cannot send ack probe: %d\\n\", rv);\n",
    "        return rv;\n",
    "    }\n",
    "    rv = bpf_setsockopt (skops, SOL_IPV6, IPV6_UNICAST_HOPS, & old_hops, sizeof (int));\n",
    "    if (rv)\n",
    "        bpf_debug (\"Cannot reset Hop Limit to %d: %d\\n\", old_hops, rv);\n",
    "    rv = bpf_start_timer (skops, 10, BASE_OP + increment_hops);\n",
    "    if (rv)\n",
    "        bpf_debug (\"Failed to start timer with error: %d\\n\", rv);\n",
    "    return !!rv;\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_start_timer",
    "bpf_debug",
    "bpf_send_ack"
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
static int traceroute(struct bpf_sock_ops *skops, int increment_hops)
{
    int rv = 0;
    // Get current Hop Limit
    int old_hops = 0;
    rv = bpf_getsockopt(skops, SOL_IPV6, IPV6_UNICAST_HOPS, &old_hops, sizeof(int));
    if (rv) {
        bpf_debug("Cannot get Hop Limit: %d\n", rv);
        return rv;
    }

    // Change Hop Limit for probe
    rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_UNICAST_HOPS, &increment_hops, sizeof(int));
    if (rv) {
        bpf_debug("Cannot set Hop Limit to %d: %d\n", increment_hops, rv);
        return rv;
    }

    // Send ack probe that should trigger 
    rv = bpf_send_ack(skops);
    if (rv) {
        bpf_debug("Cannot send ack probe: %d\n", rv);
        return rv;
    }

    // Reset Hop Limit
    rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_UNICAST_HOPS, &old_hops, sizeof(int));
    if (rv)
        bpf_debug("Cannot reset Hop Limit to %d: %d\n", old_hops, rv);

    // Start timer
    rv = bpf_start_timer(skops, 10, BASE_OP + increment_hops);
    if (rv)
        bpf_debug("Failed to start timer with error: %d\n", rv);

    return !!rv;
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
  "startLine": 60,
  "endLine": 143,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_traceroute.c",
  "funcName": "handle_sockop",
  "developer_inline_comments": [
    {
      "start_line": 73,
      "end_line": 73,
      "text": " Only execute the prog for scp "
    },
    {
      "start_line": 81,
      "end_line": 81,
      "text": " IPerf client to server connection only"
    },
    {
      "start_line": 84,
      "end_line": 84,
      "text": " We did not receive an answer yet !"
    },
    {
      "start_line": 87,
      "end_line": 89,
      "text": " else if (op > BASE_OP) {        bpf_debug(\"Timeout debug: %d\\n\", op);    }"
    },
    {
      "start_line": 94,
      "end_line": 94,
      "text": " TODO Problem if listening connections => no destination defined !!!"
    },
    {
      "start_line": 97,
      "end_line": 97,
      "text": " Ignore iperf metadata connection"
    },
    {
      "start_line": 107,
      "end_line": 107,
      "text": " Start traceroute"
    },
    {
      "start_line": 114,
      "end_line": 114,
      "text": " An ICMP is received"
    },
    {
      "start_line": 122,
      "end_line": 122,
      "text": " Get the last Hop Limit tried"
    },
    {
      "start_line": 125,
      "end_line": 125,
      "text": " Continue traceroute"
    }
  ],
  "updateMaps": [
    " conn_map"
  ],
  "readMaps": [
    " conn_map"
  ],
  "input": [
    "struct bpf_sock_ops *skops"
  ],
  "output": "int",
  "helper": [
    "bpf_map_update_elem",
    "bpf_map_lookup_elem",
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
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
    "    int op;\n",
    "    int rv = 0;\n",
    "    __u64 cur_time;\n",
    "    struct ipv6hdr *ip6;\n",
    "    struct icmp6hdr *icmp;\n",
    "    struct flow_tuple flow_id;\n",
    "    struct flow_infos *flow_info;\n",
    "    cur_time = bpf_ktime_get_ns ();\n",
    "    op = (int) skops->op;\n",
    "    if (skops->family != AF_INET6) {\n",
    "        skops->reply = -1;\n",
    "        return 0;\n",
    "    }\n",
    "    get_flow_id_from_sock (&flow_id, skops);\n",
    "    flow_info = (void *) bpf_map_lookup_elem (&conn_map, &flow_id);\n",
    "    if (flow_id.remote_port != 5201)\n",
    "        return 0;\n",
    "    if (flow_info && op == BASE_OP + flow_info->increment_hops - 1) {\n",
    "        bpf_debug (\"Traceroute stopped\\n\");\n",
    "        return 0;\n",
    "    }\n",
    "    switch (op) {\n",
    "    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB :\n",
    "    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB :\n",
    "        if (!flow_info) {\n",
    "            connection_number++;\n",
    "            if (connection_number != 2)\n",
    "                return 0;\n",
    "            struct flow_infos new_flow;\n",
    "            int rv = 0;\n",
    "            new_flow.increment_hops = 1;\n",
    "            bpf_map_update_elem (&conn_map, &flow_id, &new_flow, BPF_ANY);\n",
    "            flow_info = (void *) bpf_map_lookup_elem (&conn_map, &flow_id);\n",
    "            if (!flow_info) {\n",
    "                return 1;\n",
    "            }\n",
    "        }\n",
    "        bpf_debug (\"Triggering traceroute\\n\");\n",
    "        rv = traceroute (skops, flow_info -> increment_hops);\n",
    "        flow_info->increment_hops++;\n",
    "        bpf_map_update_elem (&conn_map, &flow_id, flow_info, BPF_ANY);\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_PARSE_ICMP_CB :\n",
    "        if (!flow_info)\n",
    "            return 1;\n",
    "        ip6 = skops->skb_data;\n",
    "        if ((void *) (ip6 + 1) <= skops->skb_data_end) {\n",
    "            icmp = (struct icmp6hdr *) (ip6 + 1);\n",
    "            if ((void *) (icmp + 1) <= skops->skb_data_end) {\n",
    "                if (icmp->icmp6_type == ICMPV6_TIME_EXCEEDED) {\n",
    "                    bpf_debug (\"Hop %d is %pI6c\\n\", flow_info->increment_hops - 1, &ip6->saddr);\n",
    "                    traceroute (skops, flow_info->increment_hops);\n",
    "                    flow_info->increment_hops++;\n",
    "                    bpf_map_update_elem (&conn_map, &flow_id, flow_info, BPF_ANY);\n",
    "                }\n",
    "                else {\n",
    "                    bpf_debug (\"ICMP of type %u and code %u\\n\", icmp->icmp6_type, icmp->icmp6_code);\n",
    "                }\n",
    "            }\n",
    "            else {\n",
    "                bpf_debug (\"Not enough skb to read the ICMPv6 header\\n\");\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            bpf_debug (\"Not enough skb to read the IPv6 header\\n\");\n",
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
	int op;
	int rv = 0;
	__u64 cur_time;
    struct ipv6hdr *ip6;
    struct icmp6hdr *icmp;
	struct flow_tuple flow_id;
	struct flow_infos *flow_info;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);
    if (flow_id.remote_port != 5201)
        return 0; // IPerf client to server connection only

    if (flow_info && op == BASE_OP + flow_info->increment_hops - 1) {
        // We did not receive an answer yet !
        bpf_debug("Traceroute stopped\n");
        return 0;
    } /* else if (op > BASE_OP) {
        bpf_debug("Timeout debug: %d\n", op);
    }*/

	switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            if (!flow_info) {  // TODO Problem if listening connections => no destination defined !!!
                connection_number++;
                if (connection_number != 2)
                    return 0; // Ignore iperf metadata connection
                struct flow_infos new_flow;
                int rv = 0;
                new_flow.increment_hops = 1;
                bpf_map_update_elem(&conn_map, &flow_id, &new_flow, BPF_ANY);
                flow_info = (void *) bpf_map_lookup_elem(&conn_map, &flow_id);
                if (!flow_info) {
                    return 1;
                }
            }
            // Start traceroute
            bpf_debug("Triggering traceroute\n");
            rv = traceroute(skops, flow_info->increment_hops);
            flow_info->increment_hops++;
            bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
            break;
        case BPF_SOCK_OPS_PARSE_ICMP_CB:
            // An ICMP is received
            if (!flow_info)
                return 1;
            ip6 = skops->skb_data;
            if ((void *) (ip6 + 1) <= skops->skb_data_end) {
                icmp = (struct icmp6hdr *) (ip6 + 1);
                if ((void *) (icmp + 1) <= skops->skb_data_end) {
                    if (icmp->icmp6_type == ICMPV6_TIME_EXCEEDED) {
                        // Get the last Hop Limit tried
                        bpf_debug("Hop %d is %pI6c\n", flow_info->increment_hops - 1, &ip6->saddr);

                        // Continue traceroute
                        traceroute(skops, flow_info->increment_hops);
                        flow_info->increment_hops++;
                        bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
                    } else {
                        bpf_debug("ICMP of type %u and code %u\n", icmp->icmp6_type, icmp->icmp6_code);
                    }
                } else {
                    bpf_debug("Not enough skb to read the ICMPv6 header\n");
                }
            } else {
                bpf_debug("Not enough skb to read the IPv6 header\n");
            }
            break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
