// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

typedef unsigned int uint32_t;

typedef struct _bpf_map_def
{
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
} bpf_map_def_t;

typedef void* (*ebpf_map_lookup_elem_t)(bpf_map_def_t* map, void* key);
#define ebpf_map_lookup_elem ((ebpf_map_lookup_elem_t)1)

#pragma clang section data = "maps"
bpf_map_def_t test_map = {
    .type = 1, // BPF_MAP_TYPE_HASH
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1};

#pragma clang section text = "test"
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "    uint32_t* value ",
        "inpVar": [
          " e&test_map",
          " &key"
        ]
      }
    ]
  },
  "startLine": 28,
  "endLine": 40,
  "File": "/root/examples/ebpf-samples/nullmapref.c",
  "funcName": "test_repro",
  "updateMaps": [],
  "readMaps": [
    " test_map"
  ],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_device",
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
    "cgroup_sysctl",
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
      "description": "This function updates a value for key==1 in test_map.
                      Program defines variable 'uint32_t' of type unsigned int
                      and a structure _bpf_map_def of type bpf_map_def having 
                      elements type, key_size, value_size, max_entries, map_flags,
                      inner_map_idx and numa_node of type uint32_t each. Function
                      nullmapref_test_repro() takes as input a void pointer ctx. It
                      defines a variable key of type uint32_t with value 1. Then it
                      calls helper function ebpf_map_lookup_elem() to look for entry
                      associated to key in test_map and store the result in variable
                      'value' of type uint32_t. ebpf_map_lookup_elem can return NULL
                      if not found, so this unchecked dereference should fail 
                      verification. Then we update 'value' to 1. Function returns 0
                      on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "06.02.2023"
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
int
test_repro(void* ctx)
{
    uint32_t key = 1;

    uint32_t* value = ebpf_map_lookup_elem(&test_map, &key);

    // ebpf_map_lookup_elem can return NULL if not found,
    // so this unchecked dereference should fail verification.
    *value = 1;

    return 0;
}
