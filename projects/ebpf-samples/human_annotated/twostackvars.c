// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

struct ctx;

static int (*get_prandom_u32)() = (void*)7;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 10,
  "endLine": 46,
  "File": "/root/examples/ebpf-samples/twostackvars.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ctx *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "The function func() takes the pointer to struct ctx as input parameter.
                      An integer array of size 16 is declared named stack_buffer.
                      An integer random value is generated of type uint32_t is generated using get_prandom_u32()
                      If the random value is non-zero, the first half of stack_buffer with index [0-7] is filled with random values.
                      The index variable is initalized with a value which is modulo 8 of rand32 variable i.e. any value from [0-7] is assigned to index.
                      The pointer ptr points to the address of that index in the stack_buffer.
                      Else if the random value is 0, the integer pointer stack_buffer2 points to the second half of the array stack_buffer[8].
                      The second half of the array is filled with random interger values whereas the first half values are unknown.
                      And the pointer ptr points to the first location of second half array of stack_buffer.
                      The function func finally returns the value pointed by ptr in the array.",
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
int func(struct ctx* ctx)
{
    int stack_buffer[16];
    int *ptr = (int*)0;

    uint32_t rand32 = get_prandom_u32();
    if (rand32 & 1) {
        // In this path we want ptr to point to one section
        // of stack space that is known to be a number, and have
        // the rest of the stack be unknown.
        for (int i = 0; i < 8; i++) {
            stack_buffer[i] = get_prandom_u32();
        }
        int index = rand32 % 8;
        ptr = &stack_buffer[index];

        // Do something with the pointer to force it to be saved in a
        // register before joining the two paths.
        ptr[index ^ 1] = 0;
    } else {
        // In this path we want ptr to point to a different section
        // of stack space that is known to be a number, and have
        // the rest of the stack be unknown.
        int* stack_buffer2 = &stack_buffer[8];
        for (int i = 0; i < 8; i++) {
            stack_buffer2[i] = get_prandom_u32();
        }
        ptr = &stack_buffer2[rand32 % 8];
    }

    // Here we want to dereference the pointer to get a number.
    // In both paths above, ptr safely points to a number, even
    // though each part of stack_buffer is not necessarily a number
    // at this point.

    return *ptr;
}
