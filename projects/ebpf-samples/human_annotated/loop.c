// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned char uint8_t;

struct test_md
{
    uint8_t* data_start;
    uint8_t* data_end;
};

#define ARRAY_LENGTH 40

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 13,
  "endLine": 31,
  "File": "/root/examples/ebpf-samples/loop.c",
  "funcName": "foo",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct test_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "Function writes 1 in each element of an array of size ARRAY_LENGTH and 
                      then returns the sum of elements of the array. Hence, in absence of errors,
                      the code should return ARRAY_LENGTH.Program defines a structure test_md
                      having two elements data_start and data_end of type uint8_t. uint8_t 
                      is defined earlier in the program  as variable type unsigned char. It
                      also defines a macro ARRAY_LENGTH of value 40. foo() takes as input a 
                      pointer ctx of type struct test_md. It has two variables named index
                      and cumul initialized as 0. It also defines an array of length 
                      ARRAY_LENGTH (i.e. 40) initialized as 0. Then the function runs a for 
                      loop over index = (0 to size of array) to check whether the difference 
                      of data_start and data_end is greater than value in 'index'. If yes it 
                      sets array at index value 'index' as 1. Finally it runs a for loop from
                      index = (0 to array size) and calculates the sum of all the elements.
                      Function returns this sum which is stored in 'cumul' on completion.",
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
__attribute__((section("test_md"), used)) int
foo(struct test_md* ctx)
{
    int index;
    int cumul = 0;
    uint8_t array[ARRAY_LENGTH] = {0};

    for (index = 0; index < sizeof(array); index++) {
        if ((ctx->data_start + index) >= ctx->data_end)
            break;

        array[index] = 1;
    }

    for (index = 0; index < sizeof(array); index++) {
        cumul += array[index];
    }
    return cumul;
}
