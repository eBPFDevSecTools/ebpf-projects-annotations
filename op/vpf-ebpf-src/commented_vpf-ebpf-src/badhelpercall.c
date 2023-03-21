// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

static int (*ebpf_get_current_comm)(char* buffer, uint32_t buffer_size) = (void*) 16;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 15,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/vpf-ebpf-src/badhelpercall.c",
  "funcName": "func",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "// Copyright (c) Prevail Verifier contributors."
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": "// SPDX-License-Identifier: MIT"
    },
    {
      "start_line": 12,
      "end_line": 12,
      "text": "// The following should fail verification since it asks the helper"
    },
    {
      "start_line": 13,
      "end_line": 13,
      "text": "// to write past the end of the stack."
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
    "sk_msg",
    "lwt_out",
    "cgroup_sock_addr",
    "sk_reuseport",
    "flow_dissector",
    "tracepoint",
    "sched_cls",
    "kprobe",
    "cgroup_device",
    "xdp",
    "raw_tracepoint_writable",
    "cgroup_sysctl",
    "perf_event",
    "cgroup_skb",
    "sock_ops",
    "sched_act",
    "lwt_xmit",
    "lwt_in",
    "cgroup_sock",
    "lwt_seg6local",
    "raw_tracepoint",
    "sk_skb",
    "socket_filter"
  ],
  "source": [
    "int func ()\n",
    "{\n",
    "    char buffer [1];\n",
    "    return ebpf_get_current_comm (buffer, 20);\n",
    "}\n"
  ],
  "called_function_list": [
    "ebpf_get_current_comm",
    "ebpf_map_update_elem"
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
int func()
{
    char buffer[1];

    // The following should fail verification since it asks the helper
    // to write past the end of the stack.
    return ebpf_get_current_comm(buffer, 20);
}
