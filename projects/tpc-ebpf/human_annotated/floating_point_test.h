#ifndef FLOATING_POINT_TEST_H
#define FLOATING_POINT_TEST_H

#include "floating_point.h"
#include "utils.h"


/* Tests */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 10,
  "endLine": 63,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/floating_point_test.h",
  "funcName": "floating_test_to_floating",
  "developer_inline_comments": [
    {
      "start_line": 8,
      "end_line": 8,
      "text": " Tests "
    },
    {
      "start_line": 13,
      "end_line": 13,
      "text": "to_floating(0, 1, 1, &float_1);"
    },
    {
      "start_line": 14,
      "end_line": 14,
      "text": "bpf_printk(\"[conv] 0.1 == mantisse %llu - exponent %d\\n\", float_1.mantissa, float_1.exponent - BIAS);  0x%llx outside eBPF"
    },
    {
      "start_line": 15,
      "end_line": 15,
      "text": "floating_to_u32s(float_1, &integer_1, &decimal_1);"
    },
    {
      "start_line": 16,
      "end_line": 16,
      "text": "bpf_printk(\"[conv] 0.1 == %u.0*%u\\n\", integer_1, decimal_1);"
    },
    {
      "start_line": 18,
      "end_line": 18,
      "text": " 0x%llx outside eBPF"
    },
    {
      "start_line": 23,
      "end_line": 23,
      "text": "to_floating(5, 0, 1, &float_5);"
    },
    {
      "start_line": 24,
      "end_line": 24,
      "text": "bpf_printk(\"[conv] 5 == mantisse %llu - exponent %d\\n\", float_5.mantissa, float_5.exponent - BIAS);"
    },
    {
      "start_line": 25,
      "end_line": 25,
      "text": "floating_to_u32s(float_5, &integer_5, &decimal_5);"
    },
    {
      "start_line": 26,
      "end_line": 26,
      "text": "bpf_printk(\"[conv] 5 == %u.0*%u\\n\", integer_5, decimal_5);"
    },
    {
      "start_line": 32,
      "end_line": 62,
      "text": "floating float_05;    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));\tbpf_printk(\"[conv-kern] 0.5 == mantisse %llu - exponent %d\\n\", float_05.mantissa, float_05.exponent - BIAS);\t__u32 integer_05 = 0;\t__u32 decimal_05 = 0;\tfloating_to_u32s(float_05, &integer_05, &decimal_05);\tbpf_printk(\"[conv] 0.5 == %u.0*%u\\n\", integer_05, decimal_05);\tfloating float_55;    bpf_to_floating(5, 5, 1, &float_55, sizeof(floating));\tbpf_printk(\"[conv-kern] 5.5 == mantisse %llu - exponent %d\\n\", float_55.mantissa, float_55.exponent - BIAS);\t__u32 integer_55 = 0;\t__u32 decimal_55 = 0;\tfloating_to_u32s(float_55, &integer_55, &decimal_55);\tbpf_printk(\"[conv] 5.5 == %u.0*%u\\n\", integer_55, decimal_55);\tfloating float_005;    bpf_to_floating(0, 5, 2, &float_005, sizeof(floating));\tbpf_printk(\"[conv-kern] 0.05 == mantisse %llu - exponent %d\\n\", float_005.mantissa, float_005.exponent - BIAS);\t__u32 integer_005 = 0;\t__u32 decimal_005 = 0;\tfloating_to_u32s(float_005, &integer_005, &decimal_005);\tbpf_printk(\"[conv] 0.05 == %u.0*%u\\n\", integer_005, decimal_005);\tfloating float_10;    bpf_to_floating(10, 0, 1, &float_10, sizeof(floating));\tbpf_printk(\"[conv-kern] 10.0 == mantisse %llu - exponent %d\\n\", float_10.mantissa, float_10.exponent - BIAS);\t__u32 integer_10 = 0;\t__u32 decimal_10 = 0;\tfloating_to_u32s(float_10, &integer_10, &decimal_10);\tbpf_printk(\"[conv] 10.0 == %u.0*%u\\n\", integer_10, decimal_10);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "socket_filter",
    "tracepoint",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "cgroup_device",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static void floating_test_to_floating ()\n",
    "{\n",
    "    floating float_1;\n",
    "    __u32 number [2] = {0, 0};\n",
    "    bpf_to_floating (0, 1, 1, &float_1, sizeof (floating));\n",
    "    bpf_printk (\"[conv-kern] 0.1 == mantisse %llu - exponent %d\\n\", float_1.mantissa, float_1.exponent - BIAS);\n",
    "    bpf_floating_to_u32s (&float_1, sizeof (floating), (__u64 *) number, sizeof (number));\n",
    "    bpf_printk (\"[conv-kern] 0.1 == %u.0*%u\\n\", number[0], number[1]);\n",
    "    floating float_5;\n",
    "    bpf_to_floating (5, 0, 1, &float_5, sizeof (floating));\n",
    "    bpf_printk (\"[conv-kern] 5 == mantisse %llu - exponent %d\\n\", float_5.mantissa, float_5.exponent - BIAS);\n",
    "    bpf_floating_to_u32s (&float_5, sizeof (floating), (__u64 *) number, sizeof (number));\n",
    "    bpf_printk (\"[conv-kern] 5 == %u.0*%u\\n\", number[0], number[1]);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_printk",
    "bpf_floating_to_u32s",
    "bpf_to_floating"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
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
static void floating_test_to_floating() {
	floating float_1;
	__u32 number[2] = {0, 0};
    //to_floating(0, 1, 1, &float_1);
	//bpf_printk("[conv] 0.1 == mantisse %llu - exponent %d\n", float_1.mantissa, float_1.exponent - BIAS); // 0x%llx outside eBPF
	//floating_to_u32s(float_1, &integer_1, &decimal_1);
	//bpf_printk("[conv] 0.1 == %u.0*%u\n", integer_1, decimal_1);
    bpf_to_floating(0, 1, 1, &float_1, sizeof(floating));
	bpf_printk("[conv-kern] 0.1 == mantisse %llu - exponent %d\n", float_1.mantissa, float_1.exponent - BIAS); // 0x%llx outside eBPF
	bpf_floating_to_u32s(&float_1, sizeof(floating), (__u64 *) number, sizeof(number));
	bpf_printk("[conv-kern] 0.1 == %u.0*%u\n", number[0], number[1]);

	floating float_5;
    //to_floating(5, 0, 1, &float_5);
	//bpf_printk("[conv] 5 == mantisse %llu - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);
	//floating_to_u32s(float_5, &integer_5, &decimal_5);
	//bpf_printk("[conv] 5 == %u.0*%u\n", integer_5, decimal_5);
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	bpf_printk("[conv-kern] 5 == mantisse %llu - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);
	bpf_floating_to_u32s(&float_5, sizeof(floating), (__u64 *) number, sizeof(number));
	bpf_printk("[conv-kern] 5 == %u.0*%u\n", number[0], number[1]);

	/*floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	bpf_printk("[conv-kern] 0.5 == mantisse %llu - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);
	__u32 integer_05 = 0;
	__u32 decimal_05 = 0;
	floating_to_u32s(float_05, &integer_05, &decimal_05);
	bpf_printk("[conv] 0.5 == %u.0*%u\n", integer_05, decimal_05);

	floating float_55;
    bpf_to_floating(5, 5, 1, &float_55, sizeof(floating));
	bpf_printk("[conv-kern] 5.5 == mantisse %llu - exponent %d\n", float_55.mantissa, float_55.exponent - BIAS);
	__u32 integer_55 = 0;
	__u32 decimal_55 = 0;
	floating_to_u32s(float_55, &integer_55, &decimal_55);
	bpf_printk("[conv] 5.5 == %u.0*%u\n", integer_55, decimal_55);

	floating float_005;
    bpf_to_floating(0, 5, 2, &float_005, sizeof(floating));
	bpf_printk("[conv-kern] 0.05 == mantisse %llu - exponent %d\n", float_005.mantissa, float_005.exponent - BIAS);
	__u32 integer_005 = 0;
	__u32 decimal_005 = 0;
	floating_to_u32s(float_005, &integer_005, &decimal_005);
	bpf_printk("[conv] 0.05 == %u.0*%u\n", integer_005, decimal_005);

	floating float_10;
    bpf_to_floating(10, 0, 1, &float_10, sizeof(floating));
	bpf_printk("[conv-kern] 10.0 == mantisse %llu - exponent %d\n", float_10.mantissa, float_10.exponent - BIAS);
	__u32 integer_10 = 0;
	__u32 decimal_10 = 0;
	floating_to_u32s(float_10, &integer_10, &decimal_10);
	bpf_printk("[conv] 10.0 == %u.0*%u\n", integer_10, decimal_10);*/
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 65,
  "endLine": 93,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/floating_point_test.h",
  "funcName": "floating_test_add",
  "developer_inline_comments": [
    {
      "start_line": 71,
      "end_line": 71,
      "text": "bpf_printk(\"[add] 5 == mantisse 0x%llx - exponent %d\\n\", float_5.mantissa, float_5.exponent - BIAS);"
    },
    {
      "start_line": 75,
      "end_line": 75,
      "text": "bpf_printk(\"[add] 0.5 == mantisse 0x%llx - exponent %d\\n\", float_05.mantissa, float_05.exponent - BIAS);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "socket_filter",
    "tracepoint",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "cgroup_device",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static void floating_test_add ()\n",
    "{\n",
    "    __u32 add_dec [2] = {0, 0};\n",
    "    floating terms [2];\n",
    "    floating float_5;\n",
    "    bpf_to_floating (5, 0, 1, &float_5, sizeof (floating));\n",
    "    floating float_05;\n",
    "    bpf_to_floating (0, 5, 1, &float_05, sizeof (floating));\n",
    "    floating add;\n",
    "    terms[0].mantissa = float_5.mantissa;\n",
    "    terms[0].exponent = float_5.exponent;\n",
    "    terms[1].mantissa = float_05.mantissa;\n",
    "    terms[1].exponent = float_05.exponent;\n",
    "    bpf_floating_add (terms, sizeof (floating) * 2, &add, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&add, sizeof (floating), (__u64 *) add_dec, sizeof (add_dec));\n",
    "    bpf_printk (\"[add] 5 + 0.5 == 5.5 == %u.%u\\n\", add_dec[0], add_dec[1]);\n",
    "    terms[1].mantissa = float_5.mantissa;\n",
    "    terms[1].exponent = float_5.exponent;\n",
    "    terms[0].mantissa = float_05.mantissa;\n",
    "    terms[0].exponent = float_05.exponent;\n",
    "    bpf_floating_add (terms, sizeof (floating) * 2, &add, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&add, sizeof (floating), (__u64 *) add_dec, sizeof (add_dec));\n",
    "    bpf_printk (\"[add] 0.5 + 5 == 5.5 == %u.%u\\n\", add_dec[0], add_dec[1]);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_to_floating",
    "bpf_floating_to_u32s",
    "bpf_printk",
    "bpf_floating_add"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
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
static void floating_test_add() {
	__u32 add_dec [2] = {0, 0};
	floating terms [2];

	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[add] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[add] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating add;
	terms[0].mantissa = float_5.mantissa;
	terms[0].exponent = float_5.exponent;
	terms[1].mantissa = float_05.mantissa;
	terms[1].exponent = float_05.exponent;
	bpf_floating_add(terms, sizeof(floating) * 2, &add, sizeof(floating));
	bpf_floating_to_u32s(&add, sizeof(floating), (__u64 *) add_dec, sizeof(add_dec));
	bpf_printk("[add] 5 + 0.5 == 5.5 == %u.%u\n", add_dec[0], add_dec[1]);

	terms[1].mantissa = float_5.mantissa;
	terms[1].exponent = float_5.exponent;
	terms[0].mantissa = float_05.mantissa;
	terms[0].exponent = float_05.exponent;
	bpf_floating_add(terms, sizeof(floating) * 2, &add, sizeof(floating));
	bpf_floating_to_u32s(&add, sizeof(floating), (__u64 *) add_dec, sizeof(add_dec));
	bpf_printk("[add] 0.5 + 5 == 5.5 == %u.%u\n", add_dec[0], add_dec[1]);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 95,
  "endLine": 115,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/floating_point_test.h",
  "funcName": "floating_test_multiply",
  "developer_inline_comments": [
    {
      "start_line": 101,
      "end_line": 101,
      "text": "bpf_printk(\"[mult] 5 == mantisse 0x%llx - exponent %d\\n\", float_5.mantissa, float_5.exponent - BIAS);"
    },
    {
      "start_line": 105,
      "end_line": 105,
      "text": "bpf_printk(\"[mult] 0.5 == mantisse 0x%llx - exponent %d\\n\", float_05.mantissa, float_05.exponent - BIAS);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "static__always_inlinevoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "socket_filter",
    "tracepoint",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "cgroup_device",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static __always_inline void floating_test_multiply ()\n",
    "{\n",
    "    __u32 mult_dec [2] = {0, 0};\n",
    "    floating factors [2];\n",
    "    floating float_5;\n",
    "    bpf_to_floating (5, 0, 1, &float_5, sizeof (floating));\n",
    "    floating float_05;\n",
    "    bpf_to_floating (0, 5, 1, &float_05, sizeof (floating));\n",
    "    floating mult;\n",
    "    factors[0].mantissa = float_5.mantissa;\n",
    "    factors[0].exponent = float_5.exponent;\n",
    "    factors[1].mantissa = float_05.mantissa;\n",
    "    factors[1].exponent = float_05.exponent;\n",
    "    bpf_floating_multiply (factors, sizeof (floating) * 2, &mult, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&mult, sizeof (floating), (__u64 *) mult_dec, sizeof (mult_dec));\n",
    "    bpf_printk (\"[mult] 5 * 0.5 == 2.5 == %u.%u\\n\", mult_dec[0], mult_dec[1]);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_to_floating",
    "bpf_floating_multiply",
    "bpf_floating_to_u32s",
    "bpf_printk"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
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
static __always_inline void floating_test_multiply() {
	__u32 mult_dec [2] = {0, 0};
	floating factors [2];

	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[mult] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[mult] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating mult;
	factors[0].mantissa = float_5.mantissa;
	factors[0].exponent = float_5.exponent;
	factors[1].mantissa = float_05.mantissa;
	factors[1].exponent = float_05.exponent;
    bpf_floating_multiply(factors, sizeof(floating) * 2, &mult, sizeof(floating));
	bpf_floating_to_u32s(&mult, sizeof(floating), (__u64 *) mult_dec, sizeof(mult_dec));
	bpf_printk("[mult] 5 * 0.5 == 2.5 == %u.%u\n", mult_dec[0], mult_dec[1]);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 117,
  "endLine": 144,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/floating_point_test.h",
  "funcName": "floating_test_divide",
  "developer_inline_comments": [
    {
      "start_line": 122,
      "end_line": 122,
      "text": "bpf_printk(\"[div] 5 == mantisse 0x%llx - exponent %d\\n\", float_5.mantissa, float_5.exponent - BIAS);"
    },
    {
      "start_line": 126,
      "end_line": 126,
      "text": "bpf_printk(\"[div] 0.5 == mantisse 0x%llx - exponent %d\\n\", float_05.mantissa, float_05.exponent - BIAS);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "socket_filter",
    "tracepoint",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "cgroup_device",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static void floating_test_divide ()\n",
    "{\n",
    "    __u32 div_dec [2] = {0, 0};\n",
    "    floating operands [2];\n",
    "    floating float_5;\n",
    "    bpf_to_floating (5, 0, 1, &float_5, sizeof (floating));\n",
    "    floating float_05;\n",
    "    bpf_to_floating (0, 5, 1, &float_05, sizeof (floating));\n",
    "    floating div;\n",
    "    operands[0].mantissa = float_5.mantissa;\n",
    "    operands[0].exponent = float_5.exponent;\n",
    "    operands[1].mantissa = float_05.mantissa;\n",
    "    operands[1].exponent = float_05.exponent;\n",
    "    bpf_floating_divide (operands, sizeof (floating) * 2, &div, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&div, sizeof (floating), (__u64 *) div_dec, sizeof (div_dec));\n",
    "    bpf_printk (\"[div] 0.5 / 5 == 0.1 == %u.%u\\n\", div_dec[0], div_dec[1]);\n",
    "    operands[1].mantissa = float_5.mantissa;\n",
    "    operands[1].exponent = float_5.exponent;\n",
    "    operands[0].mantissa = float_05.mantissa;\n",
    "    operands[0].exponent = float_05.exponent;\n",
    "    bpf_floating_divide (operands, sizeof (floating) * 2, &div, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&div, sizeof (floating), (__u64 *) div_dec, sizeof (div_dec));\n",
    "    bpf_printk (\"[div] 5 / 0.5 == 10 == %u.%u\\n\", div_dec[0], div_dec[1]);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_to_floating",
    "bpf_floating_divide",
    "bpf_floating_to_u32s",
    "bpf_printk"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
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
static void floating_test_divide() {
	__u32 div_dec [2] = {0, 0};
	floating operands [2];
	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[div] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[div] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating div;
	operands[0].mantissa = float_5.mantissa;
	operands[0].exponent = float_5.exponent;
	operands[1].mantissa = float_05.mantissa;
	operands[1].exponent = float_05.exponent;
	bpf_floating_divide(operands, sizeof(floating) * 2, &div, sizeof(floating));
	bpf_floating_to_u32s(&div, sizeof(floating), (__u64 *) div_dec, sizeof(div_dec));
	bpf_printk("[div] 0.5 / 5 == 0.1 == %u.%u\n", div_dec[0], div_dec[1]);

	operands[1].mantissa = float_5.mantissa;
	operands[1].exponent = float_5.exponent;
	operands[0].mantissa = float_05.mantissa;
	operands[0].exponent = float_05.exponent;
	bpf_floating_divide(operands, sizeof(floating) * 2, &div, sizeof(floating));
	bpf_floating_to_u32s(&div, sizeof(floating), (__u64 *) div_dec, sizeof(div_dec));
	bpf_printk("[div] 5 / 0.5 == 10 == %u.%u\n", div_dec[0], div_dec[1]);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 146,
  "endLine": 165,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/floating_point_test.h",
  "funcName": "floating_test_exp",
  "developer_inline_comments": [
    {
      "start_line": 152,
      "end_line": 152,
      "text": "bpf_printk(\"[exp] 5 == mantisse 0x%llx - exponent %d\\n\", float_5.mantissa, float_5.exponent - BIAS);"
    },
    {
      "start_line": 156,
      "end_line": 156,
      "text": "bpf_printk(\"[exp] 0.5 == mantisse 0x%llx - exponent %d\\n\", float_05.mantissa, float_05.exponent - BIAS);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "socket_filter",
    "tracepoint",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "cgroup_device",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static void floating_test_exp ()\n",
    "{\n",
    "    __u32 exp_dec [2] = {0, 0};\n",
    "    floating result;\n",
    "    floating float_5;\n",
    "    bpf_to_floating (5, 0, 1, &float_5, sizeof (floating));\n",
    "    floating float_05;\n",
    "    bpf_to_floating (0, 5, 1, &float_05, sizeof (floating));\n",
    "    bpf_floating_e_power_a (&float_5, sizeof (floating), &result, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&result, sizeof (floating), (__u64 *) exp_dec, sizeof (exp_dec));\n",
    "    bpf_printk (\"[exp] e^5 == 148.413159102 == %u.%u\\n\", exp_dec[0], exp_dec[1]);\n",
    "    bpf_floating_e_power_a (&float_05, sizeof (floating), &result, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&result, sizeof (floating), (__u64 *) exp_dec, sizeof (exp_dec));\n",
    "    bpf_printk (\"[exp] e^0.5 == 1.648721270 == %u.%u\\n\", exp_dec[0], exp_dec[1]);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "bpf_to_floating",
    "bpf_floating_to_u32s",
    "bpf_floating_e_power_a",
    "bpf_printk"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
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
static void floating_test_exp() {
	__u32 exp_dec [2] = {0, 0};
	floating result;

	floating float_5;
    bpf_to_floating(5, 0, 1, &float_5, sizeof(floating));
	//bpf_printk("[exp] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    bpf_to_floating(0, 5, 1, &float_05, sizeof(floating));
	//bpf_printk("[exp] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	bpf_floating_e_power_a(&float_5, sizeof(floating), &result, sizeof(floating));
	bpf_floating_to_u32s(&result, sizeof(floating), (__u64 *) exp_dec, sizeof(exp_dec));
	bpf_printk("[exp] e^5 == 148.413159102 == %u.%u\n", exp_dec[0], exp_dec[1]);

	bpf_floating_e_power_a(&float_05, sizeof(floating), &result, sizeof(floating));
	bpf_floating_to_u32s(&result, sizeof(floating), (__u64 *) exp_dec, sizeof(exp_dec));
	bpf_printk("[exp] e^0.5 == 1.648721270 == %u.%u\n", exp_dec[0], exp_dec[1]);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 167,
  "endLine": 180,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/floating_point_test.h",
  "funcName": "floating_test_all",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "cgroup_sysctl",
    "socket_filter",
    "tracepoint",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "cgroup_device",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static int floating_test_all ()\n",
    "{\n",
    "    bpf_printk (\"[main] Before to floating\\n\");\n",
    "    floating_test_to_floating ();\n",
    "    bpf_printk (\"[main] Before divide\\n\");\n",
    "    floating_test_divide ();\n",
    "    bpf_printk (\"[main] Before multiply\\n\");\n",
    "    floating_test_multiply ();\n",
    "    bpf_printk (\"[main] Before add\\n\");\n",
    "    floating_test_add ();\n",
    "    bpf_printk (\"[main] Before exp\\n\");\n",
    "    floating_test_exp ();\n",
    "    bpf_printk (\"[main] All tests performed\\n\");\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "floating_test_divide",
    "floating_test_to_floating",
    "floating_test_exp",
    "floating_test_add",
    "floating_test_multiply",
    "bpf_printk"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
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
static int floating_test_all() {
    bpf_printk("[main] Before to floating\n");
	floating_test_to_floating();
    bpf_printk("[main] Before divide\n");
	floating_test_divide();
    bpf_printk("[main] Before multiply\n");
	floating_test_multiply();
    bpf_printk("[main] Before add\n");
	floating_test_add();
    bpf_printk("[main] Before exp\n");
	floating_test_exp();
    bpf_printk("[main] All tests performed\n");
	return 0;
}

#endif