// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

struct xdp_md {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
    uint32_t _1;
    uint32_t _2;
    uint32_t _3;
};

struct ctx;

__attribute__((section("xdp"), used))
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 18,
  "endLine": 27,
  "File": "/root/examples/ebpf-samples/packet_overflow.c",
  "funcName": "read_write_packet_start",
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
      "description": "struct xdp_md is an user-accessible metadata for the XDP packet hook.
                      This is used as an input parameter of the function read_write_packet_start(), to access the packet contents via the XDP context.
                      The packet contents are between ctx->data and ctx->data_end.
                      It checks packet bounds i.e if the start of the packet is greater than the end of the packet, it returns 1 i.e. error in retrieving the packet contents.
                      Else, it reads the integer content of the packet, increases the value by 1, and writes back to the packet.
                      On successfully writing the value in the packet it returns 0.",
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
int read_write_packet_start(struct xdp_md* ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (data > data_end)
        return 1;
    int value = *(int*)data;
    *(int*)data = value + 1;
    return 0;
}
