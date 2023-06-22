#ifndef EBPF_UTILS_H
#define EBPF_UTILS_H

#include "bpf_helpers.h"
#include "floating_point.h"
#include "param.h"

/* Defining constant values */

#define IPPROTO_TCP 	6 /* TCP protocol in HDR */
#define AF_INET6 		10 /* IPv6 HDR */
#define SOL_IPV6 		41 /* IPv6 Sockopt */
#define SOL_SOCKET		1 /* Socket Sockopt */
#define SOL_TCP			6 /* TCP Sockopt */
#define SO_MAX_PACING_RATE	47 /* Max pacing rate for setsockopt */
#define IPV6_RTHDR 		57 /* SRv6 Option for sockopt */
#define ETH_HLEN 		14 /* Ethernet hdr length */
#define TCP_MAXSEG		2 /* Limit/Retrieve MSS */
#define TCP_CONGESTION  13 /* Change congestion control */
#define TCP_PATH_CHANGED 38 /* Notify TCP that kernel changed */
#define IPV6_RECVRTHDR	56	/* Trigger the save of the SRH */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define IPV6_UNICAST_HOPS	16	/* Hop limit */
#define ICMPV6_TIME_EXCEEDED	3 /* ICMPv6 Time Exceeded */
// #define DEBUG 			1
#define PIN_NONE		0
#define PIN_GLOBAL_NS	2
#define MAX_SRH			50
#define MAX_FLOWS		1024
#define MAX_SRH_BY_DEST 8
#define MAX_SEGS_NBR	10
#define MAX_EXPERTS MAX_SRH_BY_DEST + 2 // one expert telling 100% on a single path + one expert changing randomly + one random expert + one expert always stable

#define WAIT_BACKOFF 2 // Multiply by two the waiting time whenever a path change is made

// Stats
#define MAX_SNAPSHOTS 100 // TODO Fix - The max number fo snapshot to keep

/* eBPF definitions */

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({						\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);					\
			})
#else
#define bpf_debug(fmt, ...) { } while (0);
#endif

#define htonll(x) ((bpf_htonl(1)) == 1 ? (x) : ((uint64_t)bpf_htonl((x) & \
				0xFFFFFFFF) << 32) | bpf_htonl((x) >> 32))
#define ntohll(x) ((bpf_ntohl(1)) == 1 ? (x) : ((uint64_t)bpf_ntohl((x) & \
				0xFFFFFFFF) << 32) | bpf_ntohl((x) >> 32))

/* IPv6 address */
struct ip6_addr_t {
	unsigned long long hi;
	unsigned long long lo;
} __attribute__((packed));

/* SRH definition */
struct ip6_srh_t {
	unsigned char nexthdr;
	unsigned char hdrlen;
	unsigned char type;
	unsigned char segments_left;
	unsigned char first_segment;
	unsigned char flags;
	unsigned short tag;

	struct ip6_addr_t segments[MAX_SEGS_NBR];
} __attribute__((packed));

struct srh_record_t {
	__u32 srh_id;
	__u32 is_valid;
	__u64 curr_bw; // Mbps
	__u64 delay; // ms
	struct ip6_srh_t srh;
} __attribute__((packed));

struct flow_tuple {
	__u32 family;
	__u32 local_addr[4];
	__u32 remote_addr[4];
	__u32 local_port;
	__u32 remote_port;	
} __attribute__((packed));

#define exp3_weight_reset(flow_infos, idx) \
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) {\
		(flow_infos)->exp3_weight[idx].mantissa = LARGEST_BIT; \
		(flow_infos)->exp3_weight[idx].exponent = BIAS; \
	}

#define exp3_weight_set(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) {\
		(flow_infos)->exp3_weight[idx].mantissa = (value).mantissa; \
		(flow_infos)->exp3_weight[idx].exponent = (value).exponent; \
	}

#define exp3_weight_get(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) { \
		(value).mantissa = (flow_infos)->exp3_weight[idx].mantissa; \
		(value).exponent = (flow_infos)->exp3_weight[idx].exponent; \
	}


#define exp4_weight_set(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_EXPERTS - 1) {\
		(flow_infos)->exp4_weight[idx].mantissa = (value).mantissa; \
		(flow_infos)->exp4_weight[idx].exponent = (value).exponent; \
	}

#define exp4_weight_get(flow_infos, idx, value) \
	if (idx >= 0 && idx <= MAX_EXPERTS - 1) { \
		(value).mantissa = (flow_infos)->exp4_weight[idx].mantissa; \
		(value).exponent = (flow_infos)->exp4_weight[idx].exponent; \
	}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 132,
  "endLine": 145,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/utils.h",
  "funcName": "get_flow_id_from_sock",
  "developer_inline_comments": [
    {
      "start_line": 8,
      "end_line": 8,
      "text": " Defining constant values "
    },
    {
      "start_line": 10,
      "end_line": 10,
      "text": " TCP protocol in HDR "
    },
    {
      "start_line": 11,
      "end_line": 11,
      "text": " IPv6 HDR "
    },
    {
      "start_line": 12,
      "end_line": 12,
      "text": " IPv6 Sockopt "
    },
    {
      "start_line": 13,
      "end_line": 13,
      "text": " Socket Sockopt "
    },
    {
      "start_line": 14,
      "end_line": 14,
      "text": " TCP Sockopt "
    },
    {
      "start_line": 15,
      "end_line": 15,
      "text": " Max pacing rate for setsockopt "
    },
    {
      "start_line": 16,
      "end_line": 16,
      "text": " SRv6 Option for sockopt "
    },
    {
      "start_line": 17,
      "end_line": 17,
      "text": " Ethernet hdr length "
    },
    {
      "start_line": 18,
      "end_line": 18,
      "text": " Limit/Retrieve MSS "
    },
    {
      "start_line": 19,
      "end_line": 19,
      "text": " Change congestion control "
    },
    {
      "start_line": 20,
      "end_line": 20,
      "text": " Notify TCP that kernel changed "
    },
    {
      "start_line": 21,
      "end_line": 21,
      "text": " Trigger the save of the SRH "
    },
    {
      "start_line": 22,
      "end_line": 22,
      "text": " Routing header. "
    },
    {
      "start_line": 23,
      "end_line": 23,
      "text": " Hop limit "
    },
    {
      "start_line": 24,
      "end_line": 24,
      "text": " ICMPv6 Time Exceeded "
    },
    {
      "start_line": 25,
      "end_line": 25,
      "text": " #define DEBUG \t\t\t1"
    },
    {
      "start_line": 32,
      "end_line": 32,
      "text": " one expert telling 100% on a single path + one expert changing randomly + one random expert + one expert always stable"
    },
    {
      "start_line": 34,
      "end_line": 34,
      "text": " Multiply by two the waiting time whenever a path change is made"
    },
    {
      "start_line": 36,
      "end_line": 36,
      "text": " Stats"
    },
    {
      "start_line": 37,
      "end_line": 37,
      "text": " TODO Fix - The max number fo snapshot to keep"
    },
    {
      "start_line": 39,
      "end_line": 39,
      "text": " eBPF definitions "
    },
    {
      "start_line": 48,
      "end_line": 50,
      "text": " Only use this for debug output. Notice output from bpf_trace_printk() *  * end-up in /sys/kernel/debug/tracing/trace_pipe *   "
    },
    {
      "start_line": 66,
      "end_line": 66,
      "text": " IPv6 address "
    },
    {
      "start_line": 72,
      "end_line": 72,
      "text": " SRH definition "
    },
    {
      "start_line": 88,
      "end_line": 88,
      "text": " Mbps"
    },
    {
      "start_line": 89,
      "end_line": 89,
      "text": " ms"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct flow_tuple *flow_id",
    " struct bpf_sock_ops *skops"
  ],
  "output": "staticvoid",
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
    "static void get_flow_id_from_sock (struct flow_tuple *flow_id, struct bpf_sock_ops *skops)\n",
    "{\n",
    "    flow_id->family = skops->family;\n",
    "    flow_id->local_addr[0] = skops->local_ip6[0];\n",
    "    flow_id->local_addr[1] = skops->local_ip6[1];\n",
    "    flow_id->local_addr[2] = skops->local_ip6[2];\n",
    "    flow_id->local_addr[3] = skops->local_ip6[3];\n",
    "    flow_id->remote_addr[0] = skops->remote_ip6[0];\n",
    "    flow_id->remote_addr[1] = skops->remote_ip6[1];\n",
    "    flow_id->remote_addr[2] = skops->remote_ip6[2];\n",
    "    flow_id->remote_addr[3] = skops->remote_ip6[3];\n",
    "    flow_id->local_port = skops->local_port;\n",
    "    flow_id->remote_port = bpf_ntohl (skops->remote_port);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_ntohl"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "The get_flow_id_from_sock function captures the flow_tuple fields such as- local IPv6 address, remote IPv6 address, local and remote ports from the bpf_sock_ops structure. The remote port address is converted to host byte order before storing. This information is later helpful in controlling the flow of the packets based on the internal policies set in the network.",
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
static void get_flow_id_from_sock(struct flow_tuple *flow_id, struct bpf_sock_ops *skops)
{
	flow_id->family = skops->family;
	flow_id->local_addr[0] = skops->local_ip6[0];
	flow_id->local_addr[1] = skops->local_ip6[1];
	flow_id->local_addr[2] = skops->local_ip6[2];
	flow_id->local_addr[3] = skops->local_ip6[3];
	flow_id->remote_addr[0] = skops->remote_ip6[0];
	flow_id->remote_addr[1] = skops->remote_ip6[1];
	flow_id->remote_addr[2] = skops->remote_ip6[2];
	flow_id->remote_addr[3] = skops->remote_ip6[3];
	flow_id->local_port =  skops->local_port;
	flow_id->remote_port = bpf_ntohl(skops->remote_port);
}

#endif
