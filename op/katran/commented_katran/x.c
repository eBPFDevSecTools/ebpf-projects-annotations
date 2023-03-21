/* SPDX-License-Identifier: GPL-2.0 */

#include "decap_kern.c"

//#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>

SEC("xdp")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 9,
  "endLine": 13,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/katran/x.c",
  "funcName": "xdp_prog_simple",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "/* SPDX-License-Identifier: GPL-2.0 */"
    },
    {
      "start_line": 5,
      "end_line": 5,
      "text": "//#include <linux/bpf.h>"
    },
    {
      "start_line": 6,
      "end_line": 6,
      "text": "//#include <bpf/bpf_helpers.h>"
    },
    {
      "start_line": 12,
      "end_line": 12,
      "text": "//return XDP_PASS;"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_skb",
    "sched_cls",
    "raw_tracepoint",
    "cgroup_device",
    "sched_act",
    "perf_event",
    "lwt_xmit",
    "cgroup_sysctl",
    "sk_msg",
    "lwt_in",
    "cgroup_sock_addr",
    "sk_reuseport",
    "cgroup_skb",
    "lwt_out",
    "kprobe",
    "flow_dissector",
    "tracepoint",
    "socket_filter",
    "raw_tracepoint_writable",
    "sock_ops",
    "cgroup_sock",
    "xdp",
    "lwt_seg6local"
  ],
  "source": [
    "int xdp_prog_simple (struct xdp_md *ctx)\n",
    "{\n",
    "    return xdpdecap (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "xdpdecap"
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
int  xdp_prog_simple(struct xdp_md *ctx)
{
  return xdpdecap(ctx);
//return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
