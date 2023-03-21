/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_CTX_COMMON_H_
#define __BPF_CTX_COMMON_H_

#include <linux/types.h>
#include <linux/bpf.h>

#include "../compiler.h"
#include "../errno.h"

#define __ctx_skb		1
#define __ctx_xdp		2

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 16,
  "endLine": 19,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "ctx_data",
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
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx"
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
    "static __always_inline void *ctx_data (const struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return (void *) (unsigned long) ctx->data;\n",
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
static __always_inline void *ctx_data(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 21,
  "endLine": 24,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "ctx_data_meta",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx"
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
    "static __always_inline void *ctx_data_meta (const struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return (void *) (unsigned long) ctx->data_meta;\n",
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
static __always_inline void *ctx_data_meta(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data_meta;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 26,
  "endLine": 29,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "ctx_data_end",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct  __ctx_buff *ctx"
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
    "static __always_inline void *ctx_data_end (const struct  __ctx_buff *ctx)\n",
    "{\n",
    "    return (void *) (unsigned long) ctx->data_end;\n",
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
static __always_inline void *ctx_data_end(const struct __ctx_buff *ctx)
{
	return (void *)(unsigned long)ctx->data_end;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 31,
  "endLine": 34,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/cilium/include/bpf/ctx/common.h",
  "funcName": "ctx_no_room",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *needed",
    " const void *limit"
  ],
  "output": "static__always_inlinebool",
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
    "static __always_inline bool ctx_no_room (const void *needed, const void *limit)\n",
    "{\n",
    "    return unlikely (needed > limit);\n",
    "}\n"
  ],
  "called_function_list": [
    "unlikely"
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
static __always_inline bool ctx_no_room(const void *needed, const void *limit)
{
	return unlikely(needed > limit);
}

#endif /* __BPF_CTX_COMMON_H_ */
