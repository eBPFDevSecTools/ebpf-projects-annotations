#ifndef EBPF_LONG_FLOWS_H
#define EBPF_LONG_FLOWS_H

#include "utils.h"

#define MIN_TIME_BEFORE_MOVING_NS 700000000UL // ns -> 700ms

struct flow_infos {
	__u32 srh_id;
	__u64 last_move_time; // == min(time of last RTT, time of last path change)
	__u64 rtt_count;
	__u32 retrans_count;
	__u64 last_rcv_nxt;
	__u64 last_snd_una;
} __attribute__((packed));

struct flow_snapshot {
	__u32 sequence; // 0 if never used -> we change the lowest sequence id
	__u64 time;
	struct flow_tuple flow_id;
	struct flow_infos flow;
	__u32 reason;
} __attribute__((packed));

struct dst_infos {
	struct ip6_addr_t dest;
	__u32 max_reward;
	struct srh_record_t srhs[MAX_SRH_BY_DEST];
} __attribute__((packed));

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
} __attribute__((packed));

struct snapshot_arg {
	struct flow_snapshot *new_snapshot;
	__u64 oldest_seq;
	__u32 best_idx;
	__u32 max_seq;
	__u32 setup;
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Project": "libbpf",
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_read"
          ]
        }
      ]
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "bcc",
          "FunctionName": "bpf_ktime_get_ns",
          "Return Type": "u64",
          "Description": "u64 bpf_ktime_get_ns(void) Return: u64 number of nanoseconds. Starts at system boot time but stops during suspend. Examples in situ: \"https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Aexamples&type=Code search /examples , \"https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Atools&type=Code search /tools ",
          "Return": "u64 number of nanoseconds",
          "Input Prameters": [],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 49,
  "endLine": 89,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_timeout_changer.h",
  "funcName": "take_snapshot",
  "developer_inline_comments": [
    {
      "start_line": 6,
      "end_line": 6,
      "text": " ns -> 700ms"
    },
    {
      "start_line": 10,
      "end_line": 10,
      "text": " == min(time of last RTT, time of last path change)"
    },
    {
      "start_line": 18,
      "end_line": 18,
      "text": " 0 if never used -> we change the lowest sequence id"
    },
    {
      "start_line": 66,
      "end_line": 66,
      "text": "#pragma clang loop unroll(full)"
    }
  ],
  "updateMaps": [
    " st_map"
  ],
  "readMaps": [
    " st_map"
  ],
  "input": [
    "struct bpf_elf_map *st_map",
    " struct flow_infos *flow_info",
    " struct flow_tuple *flow_id",
    " __u32 op"
  ],
  "output": "staticvoid",
  "helper": [
    "bpf_map_update_elem",
    "bpf_map_lookup_elem",
    "bpf_ktime_get_ns"
  ],
  "compatibleHookpoints": [
    "kprobe",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "sched_act",
    "tracepoint",
    "socket_filter",
    "xdp",
    "cgroup_sock_addr",
    "flow_dissector",
    "raw_tracepoint_writable",
    "perf_event",
    "sock_ops",
    "cgroup_skb",
    "lwt_seg6local",
    "sk_msg",
    "cgroup_sock",
    "lwt_in",
    "raw_tracepoint",
    "lwt_out",
    "lwt_xmit"
  ],
  "source": [
    "static void take_snapshot (struct bpf_elf_map *st_map, struct flow_infos *flow_info, struct flow_tuple *flow_id, __u32 op)\n",
    "{\n",
    "    struct flow_snapshot *curr_snapshot = NULL;\n",
    "    struct snapshot_arg arg = {\n",
    "        .new_snapshot = NULL,\n",
    "        .oldest_seq = 0,\n",
    "        .best_idx = 0,\n",
    "        .max_seq = 0}\n",
    "    ;\n",
    "    curr_snapshot = (void *) bpf_map_lookup_elem (st_map, &arg.best_idx);\n",
    "    if (curr_snapshot) {\n",
    "        arg.new_snapshot = curr_snapshot;\n",
    "        arg.oldest_seq = curr_snapshot->sequence;\n",
    "        arg.max_seq = curr_snapshot->sequence;\n",
    "    }\n",
    "    for (int i = 0; i <= MAX_SNAPSHOTS - 1; i++) {\n",
    "        int xxx = i;\n",
    "        curr_snapshot = (void *) bpf_map_lookup_elem (st_map, &xxx);\n",
    "        if (curr_snapshot) {\n",
    "            if (arg.max_seq < curr_snapshot->sequence) {\n",
    "                arg.max_seq = curr_snapshot->sequence;\n",
    "            }\n",
    "            if (arg.oldest_seq > curr_snapshot->sequence) {\n",
    "                arg.oldest_seq = curr_snapshot->sequence;\n",
    "                arg.new_snapshot = curr_snapshot;\n",
    "                arg.best_idx = xxx;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (arg.new_snapshot) {\n",
    "        memcpy (&arg.new_snapshot->flow, flow_info, sizeof (struct flow_infos));\n",
    "        memcpy (&arg.new_snapshot->flow_id, flow_id, sizeof (struct flow_tuple));\n",
    "        arg.new_snapshot->sequence = arg.max_seq + 1;\n",
    "        arg.new_snapshot->time = bpf_ktime_get_ns ();\n",
    "        arg.new_snapshot->reason = op;\n",
    "        bpf_map_update_elem (st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy",
    "",
    "bpf_debug"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "The function take_snapshot takes the snapshot or stores the current state of the flow. When the function is invoked with a reason(op) a map lookup is performed to check if a previous snapshot for the st_map exists, if so the current state is firstly saved before moving ahead. A amp lookup is performed with st_map and indices ranging from 0 to MAX_SNAPSHOTS-1 and stored in the curr_snapshot. The snapshot with the highest index signifies the latest snapshot. Fields pertaining to these such as sequence number,index etc is stored in arg.max_seq, arg.oldest_seq, arg.new_snapshot and arg.best_idx. If arg.new_snapshot is non-NULL, then the memory of the flow_info is copied into arg.new_snapshot->flow and the memory block of flow_id is stored into arg.new_snapshot->flow_id. This information along with the current system time, incremented sequence number and the reason is updated in the map.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
      "date": "2023-04-12"
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
static void take_snapshot(struct bpf_elf_map *st_map, struct flow_infos *flow_info, struct flow_tuple *flow_id, __u32 op)
{
	struct flow_snapshot *curr_snapshot = NULL;
	struct snapshot_arg arg = {
		.new_snapshot = NULL,
		.oldest_seq = 0,
		.best_idx = 0,
		.max_seq = 0
	};

	curr_snapshot = (void *) bpf_map_lookup_elem(st_map, &arg.best_idx);
	if (curr_snapshot) {
		arg.new_snapshot = curr_snapshot;
		arg.oldest_seq = curr_snapshot->sequence;
		arg.max_seq = curr_snapshot->sequence;
	}

	//#pragma clang loop unroll(full)
	for (int i = 0; i <= MAX_SNAPSHOTS - 1; i++) {
		int xxx = i;
		curr_snapshot = (void *) bpf_map_lookup_elem(st_map, &xxx);
		if (curr_snapshot) {
			if (arg.max_seq < curr_snapshot->sequence) {
				arg.max_seq = curr_snapshot->sequence;
			}
			if (arg.oldest_seq > curr_snapshot->sequence) {
				arg.oldest_seq = curr_snapshot->sequence;
				arg.new_snapshot = curr_snapshot;
				arg.best_idx = xxx;
			}
		}
	}
	if (arg.new_snapshot) {
		memcpy(&arg.new_snapshot->flow, flow_info, sizeof(struct flow_infos));
		memcpy(&arg.new_snapshot->flow_id, flow_id, sizeof(struct flow_tuple));
		arg.new_snapshot->sequence = arg.max_seq + 1;
		arg.new_snapshot->time = bpf_ktime_get_ns();
		arg.new_snapshot->reason = op;
		bpf_map_update_elem(st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);
	}
}

struct bpf_elf_map SEC("maps") conn_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct flow_tuple),
	.size_value	= sizeof(struct flow_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") dest_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(unsigned long long),  // XXX Only looks at the most significant 64 bits of the address
	.size_value	= sizeof(struct dst_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") stat_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct flow_snapshot),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_SNAPSHOTS,
};

#endif
