// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

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

#define BPF_MAP_TYPE_RINGBUF 27

static long (*bpf_ringbuf_output)(void *ringbuf, void *data, uint64_t size, uint64_t flags) = (void *) 130;

__attribute__((section("maps"), used))
struct ebpf_map ring_buffer = {.type = BPF_MAP_TYPE_RINGBUF, .max_entries = 256 * 1024};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 32,
  "File": "/root/examples/ebpf-samples/ringbuf_uninit.c",
  "funcName": "test",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": " ebpf_map is a structure which stores following fields: type, key_size, value_size, max_entries, map_flags, inner_map_idx, numa_node.
                       ring_buffer is a eBPF ring buffer type map that contains upto 256*1024 entries.
                       bpf_ringbuf_output(&ring_buffer, &test, sizeof(test), 0) copies 8 bytes (i.e. sizeof(test)) from variable test into a ring buffer
                       ring_buffer. It will return 0 on successfully copying the data else returns 1 on failure.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
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
int
test(void* ctx)
{
    uint64_t test;
    // The following call should fail verification as test is not initialized.
    bpf_ringbuf_output(&ring_buffer, &test, sizeof(test), 0);

    return 0;
}
