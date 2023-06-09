// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

static int (*ebpf_get_current_comm)(char* buffer, uint32_t buffer_size) = (void*) 16;

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Return Type": "int",
          "Description": "Copy the comm attribute of the current task into <[ buf ]>(IP: 0) of size_of_buf. The comm attribute contains the name of the executable (excluding the path) for the current task. The <[ size_of_buf ]>(IP: 1) must be strictly positive. On success , the helper makes sure that the <[ buf ]>(IP: 0) is NUL-terminated. On failure , it is filled with zeroes. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_get_current_comm",
          "Input Params": [
            "{Type: char ,Var: *buf}",
            "{Type:  u32 ,Var: size_of_buf}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_get_current_comm": [
      {
        "opVar": "NA",
        "inpVar": [
          "            return ebuffer",
          " 20"
        ]
      }
    ]
  },
  "startLine": 8,
  "endLine": 15,
  "File": "/root/examples/ebpf-samples/badhelpercall.c",
  "funcName": "func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "int",
  "helper": [
    "bpf_get_current_comm"
  ],
  "compatibleHookpoints": [
    "perf_event",
    "raw_tracepoint_writable",
    "tracepoint",
    "raw_tracepoint",
    "kprobe"
  ],
  "humanFuncDescription": [
    {
      "description": "badhelpercall_func() defines a character array 'buffer' of size 1.
                      It then calls the buffer for size 20 although it has
                      been defined above as size 16. Thus this will give
                      an error on calling ebpf_get_current_comm() helper
                      function with buffer and 20 as arguments.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
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
int func()
{
    char buffer[1];

    // The following should fail verification since it asks the helper
    // to write past the end of the stack.
    return ebpf_get_current_comm(buffer, 20);
}
