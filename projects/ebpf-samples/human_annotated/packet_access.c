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

static int (*get_prandom_u32)() = (void*)7;

__attribute__((section("xdp"), used))
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 18,
  "endLine": 58,
  "File": "/root/examples/ebpf-samples/packet_access.c",
  "funcName": "test_packet_access",
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
      "description": "The function checks whether the compiler generated assembly matches the handcrafted one.
                      A structure xdp_md is created to store data, data_end, data_meta, _1, _2, _3 of type uint32_t
                      This struct xdp_md is passed as argument to the function.
                      A random number is generated and saved in rand32 variable.
                      a offset is calulated and it is checked whether the data plus the offset is less than the data_end or not,
                      if it is less than data_end, 1 is returned and ptr value is updated to offset+data i.e. points to the next data.
                      Else the compiler executes a set of assembly as it is.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "02.02.2023"
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
int test_packet_access(struct xdp_md* ctx)
{
    uint32_t rand32 = get_prandom_u32();
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int offset = (rand32 & 0x0F) * 4;
    int* ptr;

    // We now do two code paths that should have identical results.
    if (rand32 & 1) {
        if (data + offset + sizeof(int) > data_end)
            return 1;
        ptr = offset + data;
        return *(int*)ptr;
        /* The above code results in the following assembly:
         *            r0 <<= 2
         *            r0 &= 60
         *            r1 = *(u32 *)(r6 + 0)
         *            r1 += r0    // In the ELSE clause below, this becomes
         *                        // "r0 += r1" then "r1 = r0".
         *            r0 = 1
         *            r2 = r1
         *            r2 += 4
         *            r3 = *(u32 *)(r6 + 4)
         *            if r2 > r3 goto +13
         *            r0 = *(u32 *)(r1 + 0)
         */
    } else {
        asm volatile("r0 <<= 2\n"
                     "r0 &= 60\n"
                     "r1 = *(u32 *)(r6 + 0)\n"
                     "r0 += r1\n" // In the IF clause above, these two instructions
                     "r1 = r0\n"  // are "r1 += r0".
                     "r0 = 1\n"
                     "r2 = r1\n"
                     "r2 += 4\n"
                     "r3 = *(u32 *)(r6 + 4)\n"
                     "if r2 > r3 goto +1\n"
                     "r0 = *(u32 *)(r1 + 0)\n");
    }
}
