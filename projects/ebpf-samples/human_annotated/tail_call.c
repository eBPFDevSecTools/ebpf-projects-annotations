// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;

#define BPF_MAP_TYPE_PROG_ARRAY 3

typedef struct bpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
} bpf_map_def_t;

struct xdp_md;

static long (*bpf_tail_call)(void *ctx, struct bpf_map *prog_array_map, uint32_t index) = (void*) 12;

__attribute__((section("maps"), used)) struct bpf_map map = {
    BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t), 1};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_tail_call": [
      {
        "opVar": "    long error ",
        "inpVar": [
          " ctx",
          " &map",
          " 0"
        ]
      }
    ]
  },
  "startLine": 24,
  "endLine": 31,
  "File": "/root/examples/ebpf-samples/tail_call.c",
  "funcName": "caller",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "lwt_seg6local",
    "raw_tracepoint",
    "flow_dissector",
    "socket_filter",
    "sk_reuseport",
    "cgroup_sock",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "cgroup_skb",
    "perf_event",
    "raw_tracepoint_writable",
    "kprobe",
    "sched_cls",
    "sk_msg",
    "lwt_xmit",
    "cgroup_sock_addr",
    "tracepoint",
    "sock_ops",
    "lwt_in",
    "xdp"
  ],
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
      "description": "bpf_tail_call(ctx, &map, 0) helper function triggers a \"tail call\", i.e it jump into another eBPF program.map is a eBPF map which stores the following fields: type, key_size, alue_size, max_entries, map_flags, inner_map_idx, numa_node.The program attempts to jump into a program referenced at index=0 in map and passes a pointer to the context named ctx given input to the function.This program will return 0 if the call succeeds and the kernel immediately runs the first instruction of the new program. This is not a function call, and it never returns to the previous program. This will return a negative number in case the call fails",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "14.02.2023",
      "invocationParameters": ""
    }
  ]
} 
 OPENED COMMENT END 
 */ 
__attribute__((section("xdp_prog"), used)) int
caller(struct xdp_md* ctx)
{
    long error = bpf_tail_call(ctx, &map, 0);

    // bpf_tail_call failed at runtime.
    return (int)error;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 33,
  "endLine": 37,
  "File": "/root/examples/ebpf-samples/tail_call.c",
  "funcName": "callee",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "This is a callee function location which returns 42",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "14.02.2023"
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
__attribute__((section("xdp_prog/0"), used)) int
callee(struct xdp_md* ctx)
{
    return 42;
}
