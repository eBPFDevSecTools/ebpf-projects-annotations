/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF REVERSE SRH"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_reverse_srh.h"


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
  "startLine": 15,
  "endLine": 28,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_reverse_srh.c",
  "funcName": "move_path",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "  * This program is free software; you can redistribute it and/or * modify it under the terms of version 2 of the GNU General Public * License as published by the Free Software Foundation. "
    },
    {
      "start_line": 17,
      "end_line": 17,
      "text": " TODO Useful ?"
    },
    {
      "start_line": 19,
      "end_line": 19,
      "text": "bpf_debug(\"bpf_setsockopt !!!!! %d\\n\", rv);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ip6_srh_t *srh",
    " struct bpf_sock_ops *skops"
  ],
  "output": "staticint",
  "helper": [
    "bpf_setsockopt"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "static int move_path (struct ip6_srh_t *srh, struct bpf_sock_ops *skops)\n",
    "{\n",
    "    srh->nexthdr = 0;\n",
    "    int rv = bpf_setsockopt (skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof (* srh));\n",
    "    if (rv) {\n",
    "        bpf_debug (\"optval %p - optlen %llu\\n\", srh, sizeof (*srh));\n",
    "        bpf_debug (\"optlen %llu - header_len %u\\n\", sizeof (*srh), (srh->hdrlen + 1) << 3);\n",
    "        bpf_debug (\"next extension %u - rt_type %u\\n\", srh->nexthdr, srh->type);\n",
    "        bpf_debug (\"first segment %u - segments_left %u\\n\", srh->first_segment, srh->segments_left);\n",
    "        bpf_debug (\"max_last_entry %u\\n\", (srh->hdrlen / 2) - 1);\n",
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
static int move_path(struct ip6_srh_t *srh, struct bpf_sock_ops *skops)
{
    srh->nexthdr = 0; // TODO Useful ?
	int rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
    //bpf_debug("bpf_setsockopt !!!!! %d\n", rv);
    if (rv) {
        bpf_debug("optval %p - optlen %llu\n", srh, sizeof(*srh));
        bpf_debug("optlen %llu - header_len %u\n", sizeof(*srh), (srh->hdrlen+1) << 3);
        bpf_debug("next extension %u - rt_type %u\n", srh->nexthdr, srh->type);
        bpf_debug("first segment %u - segments_left %u\n", srh->first_segment, srh->segments_left);
        bpf_debug("max_last_entry %u\n", (srh->hdrlen / 2) - 1);
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
  "startLine": 31,
  "endLine": 108,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_reverse_srh.c",
  "funcName": "handle_sockop",
  "developer_inline_comments": [
    {
      "start_line": 45,
      "end_line": 45,
      "text": " Only execute the prog for scp "
    },
    {
      "start_line": 58,
      "end_line": 58,
      "text": " We cannot set a SRH on a request sock, only on a full sock"
    },
    {
      "start_line": 60,
      "end_line": 60,
      "text": " TODO Print Received SRH"
    },
    {
      "start_line": 63,
      "end_line": 63,
      "text": "bpf_debug(\"IP version %d\\n\", ip6->version);"
    },
    {
      "start_line": 66,
      "end_line": 66,
      "text": " There is a routing extension header that is readable"
    },
    {
      "start_line": 81,
      "end_line": 81,
      "text": " Copy each element in reverse, ignoring the segment at index 0 because it will be the destination"
    },
    {
      "start_line": 84,
      "end_line": 84,
      "text": " TODO "
    },
    {
      "start_line": 89,
      "end_line": 89,
      "text": " Check for the verifier"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_sock_ops *skops"
  ],
  "output": "int",
  "helper": [
    "bpf_ktime_get_ns",
    "bpf_setsockopt"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "int handle_sockop (struct bpf_sock_ops *skops)\n",
    "{\n",
    "    int op;\n",
    "    int val = 0;\n",
    "    int rv = 0;\n",
    "    __u64 cur_time;\n",
    "    struct ipv6hdr *ip6;\n",
    "    struct ip6_srh_t reversed_srh;\n",
    "    struct ip6_srh_t *skb_srh;\n",
    "    struct ip6_addr_t tmp;\n",
    "    cur_time = bpf_ktime_get_ns ();\n",
    "    op = (int) skops->op;\n",
    "    if (skops->family != AF_INET6) {\n",
    "        skops->reply = -1;\n",
    "        return 0;\n",
    "    }\n",
    "    switch (op) {\n",
    "    case BPF_SOCK_OPS_TCP_CONNECT_CB :\n",
    "    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB :\n",
    "        val = 1;\n",
    "        rv = bpf_setsockopt (skops, SOL_IPV6, IPV6_RECVRTHDR, & val, sizeof (int));\n",
    "        break;\n",
    "    case BPF_SOCK_OPS_PARSE_EXT_HDR_CB :\n",
    "        if (skops->is_fullsock) {\n",
    "            ip6 = (struct ipv6hdr *) skops->skb_data;\n",
    "            if (ip6 + 1 <= skops->skb_data_end && ip6->nexthdr == NEXTHDR_ROUTING) {\n",
    "                skb_srh = (struct ip6_srh_t *) (ip6 + 1);\n",
    "                if (((void *) (skb_srh + 1)) - sizeof (reversed_srh.segments) <= skops->skb_data_end && skb_srh->type == 4) {\n",
    "                    int skb_srh_size = (skb_srh->hdrlen + 1) << 3;\n",
    "                    if (((void *) skb_srh) + skb_srh_size > skops->skb_data_end) {\n",
    "                        bpf_debug (\"SRH cut in the middle\\n\");\n",
    "                        return 1;\n",
    "                    }\n",
    "                    if (skb_srh_size > sizeof (struct ip6_srh_t)) {\n",
    "                        bpf_debug (\"A too big SRH for the reserved size\\n\");\n",
    "                        return 1;\n",
    "                    }\n",
    "                    memset (&reversed_srh, 0, sizeof (reversed_srh));\n",
    "                    memcpy (&reversed_srh, skb_srh, 8);\n",
    "                    reversed_srh.segments_left = reversed_srh.first_segment;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "                    for (int i = 0; i < MAX_SEGS_NBR - 1; i++) {\n",
    "                        if (i < reversed_srh.first_segment) {\n",
    "                            if (skb_srh->segments + i + 2 <= skops->skb_data_end) {\n",
    "                                tmp = skb_srh->segments[i + 1];\n",
    "                                int idx = reversed_srh.first_segment - i;\n",
    "                                if (idx >= 0 && idx < MAX_SEGS_NBR) {\n",
    "                                    reversed_srh.segments[idx] = tmp;\n",
    "                                }\n",
    "                            }\n",
    "                        }\n",
    "                    }\n",
    "                    move_path (&reversed_srh, skops);\n",
    "                }\n",
    "                else {\n",
    "                    bpf_debug (\"Not enough space for IPv6 SRH\\n\");\n",
    "                }\n",
    "            }\n",
    "            else {\n",
    "                bpf_debug (\"No IPv6 SRH\\n\");\n",
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
	int op;
    int val = 0;
	int rv = 0;
	__u64 cur_time;
    struct ipv6hdr *ip6;
    struct ip6_srh_t reversed_srh;
    struct ip6_srh_t *skb_srh;
    struct ip6_addr_t tmp;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}

	switch (op) {
        case BPF_SOCK_OPS_TCP_CONNECT_CB:
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            val = 1;
            rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RECVRTHDR, &val, sizeof(int));
            break;
        case BPF_SOCK_OPS_PARSE_EXT_HDR_CB:
            // We cannot set a SRH on a request sock, only on a full sock
            if (skops->is_fullsock) {
                // TODO Print Received SRH
                ip6 = (struct ipv6hdr *) skops->skb_data;
	            if (ip6 + 1 <= skops->skb_data_end && ip6->nexthdr == NEXTHDR_ROUTING) {
                    //bpf_debug("IP version %d\n", ip6->version);
                    skb_srh = (struct ip6_srh_t *) (ip6 + 1);
                    if (((void *) (skb_srh + 1)) - sizeof(reversed_srh.segments) <= skops->skb_data_end && skb_srh->type == 4) {
                        // There is a routing extension header that is readable

                        int skb_srh_size = (skb_srh->hdrlen + 1) << 3;
                        if (((void *) skb_srh) + skb_srh_size > skops->skb_data_end) {
                            bpf_debug("SRH cut in the middle\n");
                            return 1;
                        }
                        if (skb_srh_size > sizeof(struct ip6_srh_t)) {
                            bpf_debug("A too big SRH for the reserved size\n");
                            return 1;
                        }
                        memset(&reversed_srh, 0, sizeof(reversed_srh));
                        memcpy(&reversed_srh, skb_srh, 8);
                        reversed_srh.segments_left = reversed_srh.first_segment;

                        // Copy each element in reverse, ignoring the segment at index 0 because it will be the destination
                        #pragma clang loop unroll(full)
                        for (int i = 0; i < MAX_SEGS_NBR - 1; i++) {
                            // TODO 
                            if (i < reversed_srh.first_segment) {
                                if (skb_srh->segments + i + 2 <= skops->skb_data_end) {
                                    tmp = skb_srh->segments[i + 1];
                                    int idx = reversed_srh.first_segment - i;
                                    if (idx >= 0 && idx < MAX_SEGS_NBR) { // Check for the verifier
                                        reversed_srh.segments[idx] = tmp;
                                    }
                                }
                            }
                        }
                        move_path(&reversed_srh, skops);
                    } else {
                        bpf_debug("Not enough space for IPv6 SRH\n");
                    }
                } else {
                    bpf_debug("No IPv6 SRH\n");
                }
            }
            break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
