/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1,
  "endLine": 4,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/bcc/hello_fields.c",
  "funcName": "hello",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "sk_skb",
    "raw_tracepoint",
    "cgroup_sock",
    "sock_ops",
    "cgroup_sysctl",
    "lwt_out",
    "sched_cls",
    "kprobe",
    "cgroup_sock_addr",
    "sk_reuseport",
    "cgroup_skb",
    "perf_event",
    "cgroup_device",
    "lwt_seg6local",
    "flow_dissector",
    "socket_filter",
    "lwt_in",
    "xdp",
    "sched_act",
    "lwt_xmit",
    "tracepoint",
    "raw_tracepoint_writable",
    "sk_msg"
  ],
  "source": [
    "int hello (void *ctx)\n",
    "{\n",
    "    bpf_trace_printk (\"Hello, World!\\\\n\");\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    {}
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
int hello(void *ctx) {
	bpf_trace_printk("Hello, World!\\n");
	return 0;
}
