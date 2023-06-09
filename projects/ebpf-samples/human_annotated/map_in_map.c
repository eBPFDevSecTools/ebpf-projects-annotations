typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct ebpf_map {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t inner_map_idx;
    uint32_t numa_node;
};

#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12

static void* (*bpf_map_lookup_elem)(struct ebpf_map* map, const void* key) = (void*) 1;

__attribute__((section("maps"), used))
struct ebpf_map array_of_maps =
    {.type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
     .key_size = sizeof(uint32_t),
     .value_size = sizeof(uint32_t),
     .max_entries = 1,
     .inner_map_idx = 1}; // (uint32_t)&inner_map};

__attribute__((section("maps"), used))
struct ebpf_map inner_map =
    {.type = BPF_MAP_TYPE_ARRAY,
     .key_size = sizeof(uint32_t),
     .value_size = sizeof(uint64_t),
     .max_entries = 1};


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
        "opVar": "    void* nolocal_lru_map ",
        "inpVar": [
          " &array_of_maps",
          " &outer_key"
        ]
      },
      {
        "opVar": "        void* ret ",
        "inpVar": [
          " nolocal_lru_map",
          " &inner_key"
        ]
      },
      {
        "opVar": "            ret ",
        "inpVar": [
          " &inner_map",
          " &inner_key"
        ]
      }
    ]
  },
  "startLine": 35,
  "endLine": 49,
  "File": "/root/examples/ebpf-samples/map_in_map.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [
    " array_of_maps",
    " nolocal_lru_map",
    "  inner_map"
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
      "description": "Program defines two variables: 'uint32_t' of type unsigned int 
                      and 'uint64_t'of type unsigned long. Program defines structure 
                      ebpf_map of type bpf_map_def having elements type, key_size, 
                      value_size, max_entries, map_flags, inner_map_idx and numa_node 
                      of type uint32_t each. It defines two macros 'BPF_MAP_TYPE_ARRAY'
                      as 2 and 'BPF_MAP_TYPE_ARRAY_OF_MAPS' as 12. Helper function 
                      bpf_map_lookup_elem() is used to look up outer_key and the result
                      is stored in a variable 'nolocal_lru_map'. If this is 1, i.e. 
                      outer_map lookup is successful, then we use the same helper to look 
                      for inner_key using nolocal_lru_map and the result is stored in ret. 
                      If ret is true, function returns 0. Else ret is updated to value 
                      obtained on calling inner_key with inner_map via bpf_map_lookup_elem() 
                      and then function returns 0.",
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
int func(void* ctx) {
    uint32_t outer_key = 0;
    void* nolocal_lru_map = bpf_map_lookup_elem(&array_of_maps, &outer_key);
    if (nolocal_lru_map) {
        uint32_t inner_key = 0;
        void* ret = bpf_map_lookup_elem(nolocal_lru_map, &inner_key);
        if (ret) {
            return 0;
        } else {
            ret = bpf_map_lookup_elem(&inner_map, &inner_key);
            return 0;
        }
    }
    return 0;
}
