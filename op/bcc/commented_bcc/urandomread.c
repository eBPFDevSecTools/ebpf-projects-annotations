/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1,
  "endLine": 5,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/bcc/urandomread.c",
  "funcName": "TRACEPOINT_PROBE",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "random",
    " urandom_read"
  ],
  "output": "NA",
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
    "TRACEPOINT_PROBE (random, urandom_read)\n",
    "{\n",
    "    bpf_trace_printk (\"%d\\\\n\", args->got_bits);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "lookup",
    "update"
  ],
  "call_depth": -1,
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
TRACEPOINT_PROBE (random, urandom_read)
{
	    bpf_trace_printk ("%d\\n", args->got_bits);
	        return 0;
}
