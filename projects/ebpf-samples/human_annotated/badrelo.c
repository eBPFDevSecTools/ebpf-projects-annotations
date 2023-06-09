// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct bpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
};

#define BPF_MAP_TYPE_ARRAY 2

__attribute__((section("maps"), used))
struct bpf_map map =
    {.type = BPF_MAP_TYPE_ARRAY,
     .key_size = sizeof(int),
     .value_size = 0,
     .max_entries = 1};

// This will be an unresolved symbol in the resulting .o file.
int bpf_map_update_elem(struct bpf_map* map, const void* key,
                        const void* value, uint64_t flags);

struct ctx;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_update_elem": [
      {
        "opVar": "NA",
        "inpVar": [
          "            return &map2",
          " const void*0",
          " const void*0",
          " 0"
        ]
      }
    ]
  },
  "startLine": 31,
  "endLine": 38,
  "File": "/root/examples/ebpf-samples/badrelo.c",
  "funcName": "func",
  "updateMaps": [
    " map2"
  ],
  "readMaps": [],
  "input": [
    "struct ctx *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_update_elem"
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
      "description": "Program defines structure bpf_map having elements type, key_size,
                      value_size, max_entries, map_flags, inner_map_idx and numa_node of 
                      size 32 units each. badrelo_func() takes a pointer ctx of type struct ctx 
                      as input. It creates a structure of type bpf_map 'map2' and calls the 
                      helper function bpf_map_update_elem() on map2. It returns an error 
                      because bpf_map_update_elem is defined in the program with respect
                      to the structure map not map2. bpf_map() is an element of type
                      BPF_MAP_TYPE_ARRAY. Function returns -1 because bpf_map_update_elem
                      is unsuccessful.",
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
int func(struct ctx* ctx)
{
    struct bpf_map map2;

    // And we can furthermore pass some bad parameters in here.  These
    // would be illegal to pass to bpf_map_update_elem if it were resolved.
    return bpf_map_update_elem(&map2, (const void*)0, (const void*)0, 0);
}
