// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

static int (*get_prandom_u32)() = (void*)7;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 19,
  "File": "/root/examples/ebpf-samples/stackok.c",
  "funcName": "func",
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
      "description": "An array of 256 bytes is initialized to 0.
                      A random value of 8 bytes is generated using get_prandom_u32() and stored in rand32 variable. 
                      The index is set to rand32 value which is in the interval [0,255].
                      The array element at the specified index is returned.",
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
int func(void* ctx)
{
   // Initialize an array of 256 bytes (to all zeroes in this example).
   char array[256] = "";

   // Set index to a random value in the interval [0,255].
   uint32_t rand32 = get_prandom_u32();
   uint32_t index = *(unsigned char*)&rand32;

   // Return the array element at the specified index.
   return array[index];
}
