/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_DBG__
#define __LIB_DBG__

/* Trace types */
enum {
	DBG_UNSPEC,
	DBG_GENERIC, /* Generic, no message, useful to dump random integers */
	DBG_LOCAL_DELIVERY,
	DBG_ENCAP,
	DBG_LXC_FOUND,
	DBG_POLICY_DENIED,
	DBG_CT_LOOKUP,		/* unused */
	DBG_CT_LOOKUP_REV,	/* unused */
	DBG_CT_MATCH,
	DBG_CT_CREATED,		/* unused */
	DBG_CT_CREATED2,	/* unused */
	DBG_ICMP6_HANDLE,
	DBG_ICMP6_REQUEST,
	DBG_ICMP6_NS,
	DBG_ICMP6_TIME_EXCEEDED,
	DBG_CT_VERDICT,
	DBG_DECAP,
	DBG_PORT_MAP,
	DBG_ERROR_RET,
	DBG_TO_HOST,
	DBG_TO_STACK,
	DBG_PKT_HASH,
	DBG_LB6_LOOKUP_FRONTEND,
	DBG_LB6_LOOKUP_FRONTEND_FAIL,
	DBG_LB6_LOOKUP_BACKEND_SLOT,
	DBG_LB6_LOOKUP_BACKEND_SLOT_SUCCESS,
	DBG_LB6_LOOKUP_BACKEND_SLOT_V2_FAIL,
	DBG_LB6_LOOKUP_BACKEND_FAIL,
	DBG_LB6_REVERSE_NAT_LOOKUP,
	DBG_LB6_REVERSE_NAT,
	DBG_LB4_LOOKUP_FRONTEND,
	DBG_LB4_LOOKUP_FRONTEND_FAIL,
	DBG_LB4_LOOKUP_BACKEND_SLOT,
	DBG_LB4_LOOKUP_BACKEND_SLOT_SUCCESS,
	DBG_LB4_LOOKUP_BACKEND_SLOT_V2_FAIL,
	DBG_LB4_LOOKUP_BACKEND_FAIL,
	DBG_LB4_REVERSE_NAT_LOOKUP,
	DBG_LB4_REVERSE_NAT,
	DBG_LB4_LOOPBACK_SNAT,
	DBG_LB4_LOOPBACK_SNAT_REV,
	DBG_CT_LOOKUP4,
	DBG_RR_BACKEND_SLOT_SEL,
	DBG_REV_PROXY_LOOKUP,
	DBG_REV_PROXY_FOUND,
	DBG_REV_PROXY_UPDATE,
	DBG_L4_POLICY,
	DBG_NETDEV_IN_CLUSTER, /* arg1: security-context, arg2: unused */
	DBG_NETDEV_ENCAP4, /* arg1 encap lookup key, arg2: identity */
	DBG_CT_LOOKUP4_1,       /* arg1: saddr
				 * arg2: daddr
				 * arg3: (sport << 16) | dport
				 */
	DBG_CT_LOOKUP4_2,       /* arg1: (nexthdr << 8) | flags
				 * arg2: direction
				 * arg3: unused
				 */
	DBG_CT_CREATED4,        /* arg1: (unused << 16) | rev_nat_index
				 * arg2: src sec-id
				 * arg3: lb address
				 */
	DBG_CT_LOOKUP6_1,       /* arg1: saddr (last 4 bytes)
				 * arg2: daddr (last 4 bytes)
				 * arg3: (sport << 16) | dport
				 */
	DBG_CT_LOOKUP6_2,       /* arg1: (nexthdr << 8) | flags
				 * arg2: direction
				 * arg3: unused
				 */
	DBG_CT_CREATED6,        /* arg1: (unused << 16) | rev_nat_index
				 * arg2: src sec-id
				 * arg3: unused
				 */
	DBG_SKIP_PROXY,          /* arg1: ctx->tc_index
				  * arg2: unused
				  */
	DBG_L4_CREATE,		/* arg1: src sec-id
				 * arg2: dst sec-id
				 * arg3: (dport << 16) | protocol
				 */
	DBG_IP_ID_MAP_FAILED4,	/* arg1: daddr
				 * arg2: unused
				 * arg3: unused
				 */
	DBG_IP_ID_MAP_FAILED6,	/* arg1: daddr (last 4 bytes)
				 * arg2: unused
				 * arg3: unused
				 */
	DBG_IP_ID_MAP_SUCCEED4,	/* arg1: daddr
				 * arg2: identity
				 * arg3: unused
				 */
	DBG_IP_ID_MAP_SUCCEED6,	/* arg1: daddr (last 4 bytes)
				 * arg2: identity
				 * arg3: unused
				 */
	DBG_LB_STALE_CT,	/* arg1: svc rev_nat_id
				 * arg2: stale CT rev_nat_id
				 * arg3: unused
				 */
	DBG_INHERIT_IDENTITY,	/* arg1: ctx->mark
				 * arg2: unused
				 */
	DBG_SK_LOOKUP4,		/* arg1: saddr
				 * arg2: daddr
				 * arg3: (sport << 16) | dport
				 */
	DBG_SK_LOOKUP6,		/* arg1: saddr (last 4 bytes)
				 * arg2: daddr (last 4 bytes)
				 * arg3: (sport << 16) | dport
				 */
	DBG_SK_ASSIGN,		/* arg1: result
				 * arg2: unuseds
				 */
	DBG_L7_LB,		/* arg1: saddr (last 4 bytes for IPv6)
				 * arg2: daddr (last 4 bytes for IPv6)
				 * arg3: proxy port (in host byte order)
				 */
};

/* Capture types */
enum {
	DBG_CAPTURE_UNSPEC,
	DBG_CAPTURE_FROM_RESERVED1,
	DBG_CAPTURE_FROM_RESERVED2,
	DBG_CAPTURE_FROM_RESERVED3,
	DBG_CAPTURE_DELIVERY,
	DBG_CAPTURE_FROM_LB,
	DBG_CAPTURE_AFTER_V46,
	DBG_CAPTURE_AFTER_V64,
	DBG_CAPTURE_PROXY_PRE,
	DBG_CAPTURE_PROXY_POST,
	DBG_CAPTURE_SNAT_PRE,
	DBG_CAPTURE_SNAT_POST,
};

#ifndef EVENT_SOURCE
#define EVENT_SOURCE 0
#endif

#ifdef DEBUG
#include "events.h"
#endif

#ifdef DEBUG
#include "common.h"
#include "utils.h"

/* This takes both literals and modifiers, e.g.,
 * printk("hello\n");
 * printk("%d\n", ret);
 *
 * Three caveats when using this:
 * - message needs to end with newline
 *
 * - only a subset of specifier are supported:
 *   https://elixir.bootlin.com/linux/v5.7.7/source/kernel/trace/bpf_trace.c#L325
 *
 * - cannot use more than 3 format specifiers in the format string
 *   because BPF helpers take a maximum of 5 arguments
 */
# define printk(fmt, ...)					\
		({						\
			const char ____fmt[] = fmt;		\
			trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);		\
		})

struct debug_msg {
	NOTIFY_COMMON_HDR
	__u32		arg1;
	__u32		arg2;
	__u32		arg3;
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 183,
  "endLine": 194,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */"
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "/* Copyright Authors of Cilium */"
    },
    {
      "start_line": 7,
      "end_line": 7,
      "text": "/* Trace types */"
    },
    {
      "start_line": 10,
      "end_line": 10,
      "text": "/* Generic, no message, useful to dump random integers */"
    },
    {
      "start_line": 15,
      "end_line": 15,
      "text": "/* unused */"
    },
    {
      "start_line": 16,
      "end_line": 16,
      "text": "/* unused */"
    },
    {
      "start_line": 18,
      "end_line": 18,
      "text": "/* unused */"
    },
    {
      "start_line": 19,
      "end_line": 19,
      "text": "/* unused */"
    },
    {
      "start_line": 55,
      "end_line": 55,
      "text": "/* arg1: security-context, arg2: unused */"
    },
    {
      "start_line": 56,
      "end_line": 56,
      "text": "/* arg1 encap lookup key, arg2: identity */"
    },
    {
      "start_line": 57,
      "end_line": 60,
      "text": "/* arg1: saddr\n\t\t\t\t * arg2: daddr\n\t\t\t\t * arg3: (sport << 16) | dport\n\t\t\t\t */"
    },
    {
      "start_line": 61,
      "end_line": 64,
      "text": "/* arg1: (nexthdr << 8) | flags\n\t\t\t\t * arg2: direction\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 65,
      "end_line": 68,
      "text": "/* arg1: (unused << 16) | rev_nat_index\n\t\t\t\t * arg2: src sec-id\n\t\t\t\t * arg3: lb address\n\t\t\t\t */"
    },
    {
      "start_line": 69,
      "end_line": 72,
      "text": "/* arg1: saddr (last 4 bytes)\n\t\t\t\t * arg2: daddr (last 4 bytes)\n\t\t\t\t * arg3: (sport << 16) | dport\n\t\t\t\t */"
    },
    {
      "start_line": 73,
      "end_line": 76,
      "text": "/* arg1: (nexthdr << 8) | flags\n\t\t\t\t * arg2: direction\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 77,
      "end_line": 80,
      "text": "/* arg1: (unused << 16) | rev_nat_index\n\t\t\t\t * arg2: src sec-id\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 81,
      "end_line": 83,
      "text": "/* arg1: ctx->tc_index\n\t\t\t\t  * arg2: unused\n\t\t\t\t  */"
    },
    {
      "start_line": 84,
      "end_line": 87,
      "text": "/* arg1: src sec-id\n\t\t\t\t * arg2: dst sec-id\n\t\t\t\t * arg3: (dport << 16) | protocol\n\t\t\t\t */"
    },
    {
      "start_line": 88,
      "end_line": 91,
      "text": "/* arg1: daddr\n\t\t\t\t * arg2: unused\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 92,
      "end_line": 95,
      "text": "/* arg1: daddr (last 4 bytes)\n\t\t\t\t * arg2: unused\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 96,
      "end_line": 99,
      "text": "/* arg1: daddr\n\t\t\t\t * arg2: identity\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 100,
      "end_line": 103,
      "text": "/* arg1: daddr (last 4 bytes)\n\t\t\t\t * arg2: identity\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 104,
      "end_line": 107,
      "text": "/* arg1: svc rev_nat_id\n\t\t\t\t * arg2: stale CT rev_nat_id\n\t\t\t\t * arg3: unused\n\t\t\t\t */"
    },
    {
      "start_line": 108,
      "end_line": 110,
      "text": "/* arg1: ctx->mark\n\t\t\t\t * arg2: unused\n\t\t\t\t */"
    },
    {
      "start_line": 111,
      "end_line": 114,
      "text": "/* arg1: saddr\n\t\t\t\t * arg2: daddr\n\t\t\t\t * arg3: (sport << 16) | dport\n\t\t\t\t */"
    },
    {
      "start_line": 115,
      "end_line": 118,
      "text": "/* arg1: saddr (last 4 bytes)\n\t\t\t\t * arg2: daddr (last 4 bytes)\n\t\t\t\t * arg3: (sport << 16) | dport\n\t\t\t\t */"
    },
    {
      "start_line": 119,
      "end_line": 121,
      "text": "/* arg1: result\n\t\t\t\t * arg2: unuseds\n\t\t\t\t */"
    },
    {
      "start_line": 122,
      "end_line": 125,
      "text": "/* arg1: saddr (last 4 bytes for IPv6)\n\t\t\t\t * arg2: daddr (last 4 bytes for IPv6)\n\t\t\t\t * arg3: proxy port (in host byte order)\n\t\t\t\t */"
    },
    {
      "start_line": 128,
      "end_line": 128,
      "text": "/* Capture types */"
    },
    {
      "start_line": 156,
      "end_line": 168,
      "text": "/* This takes both literals and modifiers, e.g.,\n * printk(\"hello\\n\");\n * printk(\"%d\\n\", ret);\n *\n * Three caveats when using this:\n * - message needs to end with newline\n *\n * - only a subset of specifier are supported:\n *   https://elixir.bootlin.com/linux/v5.7.7/source/kernel/trace/bpf_trace.c#L325\n *\n * - cannot use more than 3 format specifiers in the format string\n *   because BPF helpers take a maximum of 5 arguments\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 type",
    " __u32 arg1",
    " __u32 arg2"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg (struct  __ctx_buff *ctx, __u8 type, __u32 arg1, __u32 arg2)\n",
    "{\n",
    "    struct debug_msg msg = {__notify_common_hdr (CILIUM_NOTIFY_DBG_MSG, type),\n",
    "        .arg1 = arg1,\n",
    "        .arg2 = arg2,}\n",
    "    ;\n",
    "    ctx_event_output (ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU, &msg, sizeof (msg));\n",
    "}\n"
  ],
  "called_function_list": [
    "__notify_common_hdr",
    "ctx_event_output"
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
static __always_inline void cilium_dbg(struct __ctx_buff *ctx, __u8 type,
				       __u32 arg1, __u32 arg2)
{
	struct debug_msg msg = {
		__notify_common_hdr(CILIUM_NOTIFY_DBG_MSG, type),
		.arg1	= arg1,
		.arg2	= arg2,
	};

	ctx_event_output(ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 196,
  "endLine": 208,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg3",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 type",
    " __u32 arg1",
    " __u32 arg2",
    " __u32 arg3"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg3 (struct  __ctx_buff *ctx, __u8 type, __u32 arg1, __u32 arg2, __u32 arg3)\n",
    "{\n",
    "    struct debug_msg msg = {__notify_common_hdr (CILIUM_NOTIFY_DBG_MSG, type),\n",
    "        .arg1 = arg1,\n",
    "        .arg2 = arg2,\n",
    "        .arg3 = arg3,}\n",
    "    ;\n",
    "    ctx_event_output (ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU, &msg, sizeof (msg));\n",
    "}\n"
  ],
  "called_function_list": [
    "__notify_common_hdr",
    "ctx_event_output"
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
static __always_inline void cilium_dbg3(struct __ctx_buff *ctx, __u8 type,
					__u32 arg1, __u32 arg2, __u32 arg3)
{
	struct debug_msg msg = {
		__notify_common_hdr(CILIUM_NOTIFY_DBG_MSG, type),
		.arg1	= arg1,
		.arg2	= arg2,
		.arg3	= arg3,
	};

	ctx_event_output(ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

struct debug_capture_msg {
	NOTIFY_CAPTURE_HDR
	__u32		arg1;
	__u32		arg2;
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 216,
  "endLine": 231,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg_capture2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 type",
    " __u32 arg1",
    " __u32 arg2"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg_capture2 (struct  __ctx_buff *ctx, __u8 type, __u32 arg1, __u32 arg2)\n",
    "{\n",
    "    __u64 ctx_len = ctx_full_len (ctx);\n",
    "    __u64 cap_len = min_t (__u64, TRACE_PAYLOAD_LEN, ctx_len);\n",
    "    struct debug_capture_msg msg = {__notify_common_hdr (CILIUM_NOTIFY_DBG_CAPTURE, type), __notify_pktcap_hdr (ctx_len, (__u16) cap_len),\n",
    "        .arg1 = arg1,\n",
    "        .arg2 = arg2,}\n",
    "    ;\n",
    "    ctx_event_output (ctx, &EVENTS_MAP, (cap_len << 32) | BPF_F_CURRENT_CPU, &msg, sizeof (msg));\n",
    "}\n"
  ],
  "called_function_list": [
    "__notify_common_hdr",
    "min_t",
    "__notify_pktcap_hdr",
    "ctx_full_len",
    "ctx_event_output"
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
static __always_inline void cilium_dbg_capture2(struct __ctx_buff *ctx, __u8 type,
						__u32 arg1, __u32 arg2)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, TRACE_PAYLOAD_LEN, ctx_len);
	struct debug_capture_msg msg = {
		__notify_common_hdr(CILIUM_NOTIFY_DBG_CAPTURE, type),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.arg1	= arg1,
		.arg2	= arg2,
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 233,
  "endLine": 237,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg_capture",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff *ctx",
    " __u8 type",
    " __u32 arg1"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg_capture (struct  __ctx_buff *ctx, __u8 type, __u32 arg1)\n",
    "{\n",
    "    cilium_dbg_capture2 (ctx, type, arg1, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg_capture2"
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
static __always_inline void cilium_dbg_capture(struct __ctx_buff *ctx, __u8 type,
					       __u32 arg1)
{
	cilium_dbg_capture2(ctx, type, arg1, 0);
}
#else
# define printk(fmt, ...)					\
		do { } while (0)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 242,
  "endLine": 246,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u8 type __maybe_unused",
    " __u32 arg1 __maybe_unused",
    " __u32 arg2 __maybe_unused"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg (struct  __ctx_buff * ctx __maybe_unused, __u8 type __maybe_unused, __u32 arg1 __maybe_unused, __u32 arg2 __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "__notify_common_hdr",
    "ctx_event_output"
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
static __always_inline
void cilium_dbg(struct __ctx_buff *ctx __maybe_unused, __u8 type __maybe_unused,
		__u32 arg1 __maybe_unused, __u32 arg2 __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 248,
  "endLine": 253,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg3",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u8 type __maybe_unused",
    " __u32 arg1 __maybe_unused",
    " __u32 arg2 __maybe_unused",
    " __u32 arg3 __maybe_unused"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg3 (struct  __ctx_buff * ctx __maybe_unused, __u8 type __maybe_unused, __u32 arg1 __maybe_unused, __u32 arg2 __maybe_unused, __u32 arg3 __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "__notify_common_hdr",
    "ctx_event_output"
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
static __always_inline
void cilium_dbg3(struct __ctx_buff *ctx __maybe_unused,
		 __u8 type __maybe_unused, __u32 arg1 __maybe_unused,
		 __u32 arg2 __maybe_unused, __u32 arg3 __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 255,
  "endLine": 259,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg_capture",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u8 type __maybe_unused",
    " __u32 arg1 __maybe_unused"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg_capture (struct  __ctx_buff * ctx __maybe_unused, __u8 type __maybe_unused, __u32 arg1 __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "cilium_dbg_capture2"
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
static __always_inline
void cilium_dbg_capture(struct __ctx_buff *ctx __maybe_unused,
			__u8 type __maybe_unused, __u32 arg1 __maybe_unused)
{
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 261,
  "endLine": 266,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/lib/dbg.h",
  "funcName": "cilium_dbg_capture2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __ctx_buff * ctx __maybe_unused",
    " __u8 type __maybe_unused",
    " __u32 arg1 __maybe_unused",
    " __u32 arg2 __maybe_unused"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "lwt_xmit",
    "lwt_out",
    "lwt_seg6local",
    "sk_skb",
    "sched_cls",
    "socket_filter",
    "sk_reuseport",
    "sk_msg",
    "kprobe",
    "xdp",
    "cgroup_skb",
    "raw_tracepoint_writable",
    "lwt_in",
    "perf_event",
    "cgroup_sock",
    "cgroup_sock_addr",
    "raw_tracepoint",
    "flow_dissector",
    "cgroup_sysctl",
    "sock_ops",
    "tracepoint",
    "sched_act",
    "cgroup_device"
  ],
  "source": [
    "static __always_inline void cilium_dbg_capture2 (struct  __ctx_buff * ctx __maybe_unused, __u8 type __maybe_unused, __u32 arg1 __maybe_unused, __u32 arg2 __maybe_unused)\n",
    "{\n",
    "}\n"
  ],
  "called_function_list": [
    "__notify_common_hdr",
    "min_t",
    "__notify_pktcap_hdr",
    "ctx_full_len",
    "ctx_event_output"
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
static __always_inline
void cilium_dbg_capture2(struct __ctx_buff *ctx __maybe_unused,
			 __u8 type __maybe_unused, __u32 arg1 __maybe_unused,
			 __u32 arg2 __maybe_unused)
{
}

#endif
#endif /* __LIB_DBG__ */