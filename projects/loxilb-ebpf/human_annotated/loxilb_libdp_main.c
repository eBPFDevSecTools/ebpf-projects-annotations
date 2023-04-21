/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <stdio.h>

extern int loxilb_main(void *);

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 6,
  "endLine": 9,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/loxilb_libdp_main.c",
  "funcName": "main",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": " SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "int main ()\n",
    "{\n",
    "    return loxilb_main (NULL);\n",
    "}\n"
  ],
  "called_function_list": [
    "loxilb_main"
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
int main()
{
  return loxilb_main(NULL);
}
