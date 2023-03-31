/* SPDX-License-Identifier: LGPL-2.1
 *
 * Based on Paul Hsieh's (LGPG 2.1) hash function
 * From: http://www.azillionmonkeys.com/qed/hash.html
 */

#define get16bits(d) (*((const __u16 *) (d)))

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 9,
  "endLine": 55,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/hash_func01.h",
  "funcName": "SuperFastHash",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": "/* SPDX-License-Identifier: LGPL-2.1\n *\n * Based on Paul Hsieh's (LGPG 2.1) hash function\n * From: http://www.azillionmonkeys.com/qed/hash.html\n */"
    },
    {
      "start_line": 20,
      "end_line": 20,
      "text": "/* Main loop */"
    },
    {
      "start_line": 30,
      "end_line": 30,
      "text": "/* Handle end cases */"
    },
    {
      "start_line": 46,
      "end_line": 46,
      "text": "/* Force \"avalanching\" of final 127 bits */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *data",
    " int len",
    " __u32 initval"
  ],
  "output": "static__always_inline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "cgroup_sock",
    "socket_filter",
    "lwt_xmit",
    "sk_skb",
    "tracepoint",
    "sched_act",
    "cgroup_skb",
    "sched_cls",
    "sk_msg",
    "raw_tracepoint_writable",
    "perf_event",
    "sk_reuseport",
    "lwt_out",
    "cgroup_device",
    "flow_dissector",
    "sock_ops",
    "kprobe",
    "lwt_seg6local",
    "lwt_in"
  ],
  "source": [
    "static __always_inline __u32 SuperFastHash (const char *data, int len, __u32 initval)\n",
    "{\n",
    "    __u32 hash = initval;\n",
    "    __u32 tmp;\n",
    "    int rem;\n",
    "    if (len <= 0 || data == NULL)\n",
    "        return 0;\n",
    "    rem = len & 3;\n",
    "    len >>= 2;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (; len > 0; len--) {\n",
    "        hash += get16bits (data);\n",
    "        tmp = (get16bits (data + 2) << 11) ^ hash;\n",
    "        hash = (hash << 16) ^ tmp;\n",
    "        data += 2 * sizeof (__u16);\n",
    "        hash += hash >> 11;\n",
    "    }\n",
    "    switch (rem) {\n",
    "    case 3 :\n",
    "        hash += get16bits (data);\n",
    "        hash ^= hash << 16;\n",
    "        hash ^= ((signed char) data[sizeof (__u16)]) << 18;\n",
    "        hash += hash >> 11;\n",
    "        break;\n",
    "    case 2 :\n",
    "        hash += get16bits (data);\n",
    "        hash ^= hash << 11;\n",
    "        hash += hash >> 17;\n",
    "        break;\n",
    "    case 1 :\n",
    "        hash += (signed char) *data;\n",
    "        hash ^= hash << 10;\n",
    "        hash += hash >> 1;\n",
    "    }\n",
    "    hash ^= hash << 3;\n",
    "    hash += hash >> 5;\n",
    "    hash ^= hash << 4;\n",
    "    hash += hash >> 17;\n",
    "    hash ^= hash << 25;\n",
    "    hash += hash >> 6;\n",
    "    return hash;\n",
    "}\n"
  ],
  "called_function_list": [
    "unroll",
    "get16bits"
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
static __always_inline
__u32 SuperFastHash (const char *data, int len, __u32 initval) {
	__u32 hash = initval;
	__u32 tmp;
	int rem;

	if (len <= 0 || data == NULL) return 0;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
#pragma clang loop unroll(full)
	for (;len > 0; len--) {
		hash  += get16bits (data);
		tmp    = (get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (__u16);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= ((signed char)data[sizeof (__u16)]) << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += (signed char)*data;
                hash ^= hash << 10;
                hash += hash >> 1;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}
