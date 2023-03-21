//int hello (void *ctx)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2,
  "endLine": 6,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/bcc/trace_fields.c",
  "funcName": "hello",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "//int hello (void *ctx)"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "NA"
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
    "int hello ()\n",
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
int hello ()
{
	    bpf_trace_printk ("Hello, World!\\n");
	        return 0;
}
