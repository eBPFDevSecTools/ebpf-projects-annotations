#ifndef EBPF_LONG_FLOWS_H
#define EBPF_LONG_FLOWS_H

#include "utils.h"

struct flow_infos {
	__u32 srh_id;
	__u64 rtt_count; // Count the number of RTT in the connection, this is useful to know if congestion signals are consecutive or not
	__u32 ecn_count; // Count the number of consecutive CWR sent (either from ECN or other causes)
	__u64 last_ecn_rtt; // The index of the last RTT were we sent an CWR
	__u32 exp3_last_number_actions;
	__u32 exp3_curr_reward;
	__u32 exp3_start_snd_nxt; // The reward is computed with the number of bytes exchanged during an amount of time
	floating exp3_last_probability;
	__u8 negative_reward; // boolean
} __attribute__((packed));

struct dst_infos {
	struct ip6_addr_t dest;
	__u32 max_reward;
	struct srh_record_t srhs[MAX_SRH_BY_DEST];
	floating exp3_weight[MAX_SRH_BY_DEST];
	u32 last_srtt[MAX_SRH_BY_DEST];
} __attribute__((packed));

struct flow_snapshot {
	__u32 sequence; // 0 if never used -> we change the lowest sequence id
	__u64 time;
	__u32 srh_id;
	__u32 reward;
	struct ip6_addr_t dest;
	floating exp3_weight[MAX_SRH_BY_DEST];
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
  "startLine": 53,
  "endLine": 96,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_exp3_lowest_delay.h",
  "funcName": "take_snapshot",
  "developer_inline_comments": [
    {
      "start_line": 8,
      "end_line": 8,
      "text": " Count the number of RTT in the connection, this is useful to know if congestion signals are consecutive or not"
    },
    {
      "start_line": 9,
      "end_line": 9,
      "text": " Count the number of consecutive CWR sent (either from ECN or other causes)"
    },
    {
      "start_line": 10,
      "end_line": 10,
      "text": " The index of the last RTT were we sent an CWR"
    },
    {
      "start_line": 13,
      "end_line": 13,
      "text": " The reward is computed with the number of bytes exchanged during an amount of time"
    },
    {
      "start_line": 15,
      "end_line": 15,
      "text": " boolean"
    },
    {
      "start_line": 27,
      "end_line": 27,
      "text": " 0 if never used -> we change the lowest sequence id"
    },
    {
      "start_line": 70,
      "end_line": 70,
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
    " struct dst_infos *dst_info",
    " struct flow_infos *flow_info"
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
    "static void take_snapshot (struct bpf_elf_map *st_map, struct dst_infos *dst_info, struct flow_infos *flow_info)\n",
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
    "        memcpy (&arg.new_snapshot->dest, &dst_info->dest, sizeof (struct ip6_addr_t));\n",
    "        memcpy (arg.new_snapshot->exp3_weight, dst_info->exp3_weight, sizeof (floating) * MAX_SRH_BY_DEST);\n",
    "        arg.new_snapshot->sequence = arg.max_seq + 1;\n",
    "        arg.new_snapshot->time = bpf_ktime_get_ns ();\n",
    "        arg.new_snapshot->srh_id = flow_info->srh_id;\n",
    "        arg.new_snapshot->reward = flow_info->exp3_curr_reward;\n",
    "        bpf_map_update_elem (st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);\n",
    "    }\n",
    "    else {\n",
    "        bpf_debug (\"HERE STAT FAIL\\n\");\n",
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
static void take_snapshot(struct bpf_elf_map *st_map, struct dst_infos *dst_info, struct flow_infos *flow_info)
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
		memcpy(&arg.new_snapshot->dest, &dst_info->dest, sizeof(struct ip6_addr_t));
		memcpy(arg.new_snapshot->exp3_weight, dst_info->exp3_weight, sizeof(floating) * MAX_SRH_BY_DEST);
		arg.new_snapshot->sequence = arg.max_seq + 1;
		arg.new_snapshot->time = bpf_ktime_get_ns();
		arg.new_snapshot->srh_id = flow_info->srh_id;
		arg.new_snapshot->reward = flow_info->exp3_curr_reward;
		bpf_map_update_elem(st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);
	} else {
		bpf_debug("HERE STAT FAIL\n");
	}
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 98,
  "endLine": 255,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_exp3_lowest_delay.h",
  "funcName": "exp3_reward_path",
  "developer_inline_comments": [
    {
      "start_line": 100,
      "end_line": 103,
      "text": "\ttheReward = reward(choice, t)\tweights[choice] *= math.exp(theReward / (probabilityDistribution[choice] * gamma_rev * numActions)) # important that we use estimated reward here!\t"
    },
    {
      "start_line": 118,
      "end_line": 118,
      "text": " Compute max reward (in ms)"
    },
    {
      "start_line": 119,
      "end_line": 119,
      "text": " TODO Hardcoded factor"
    },
    {
      "start_line": 123,
      "end_line": 123,
      "text": " Compute new reward (in ms)"
    },
    {
      "start_line": 125,
      "end_line": 125,
      "text": " TODO Hardcoded mean delay (should be a moving average)"
    },
    {
      "start_line": 126,
      "end_line": 126,
      "text": " TODO Hardcoded mean delay (should be a moving average)"
    },
    {
      "start_line": 129,
      "end_line": 129,
      "text": " TODO Hardcoded mean delay (should be a moving average)"
    },
    {
      "start_line": 133,
      "end_line": 133,
      "text": " TODO Remove"
    },
    {
      "start_line": 139,
      "end_line": 139,
      "text": " reward should be in [0, 1]"
    },
    {
      "start_line": 140,
      "end_line": 140,
      "text": " TODO Remove"
    },
    {
      "start_line": 141,
      "end_line": 141,
      "text": " TODO Remove"
    },
    {
      "start_line": 143,
      "end_line": 143,
      "text": " Compute new weight"
    },
    {
      "start_line": 145,
      "end_line": 145,
      "text": " TODO Remove"
    },
    {
      "start_line": 146,
      "end_line": 146,
      "text": " TODO Remove"
    },
    {
      "start_line": 148,
      "end_line": 148,
      "text": " TODO Remove"
    },
    {
      "start_line": 149,
      "end_line": 149,
      "text": " TODO Remove"
    },
    {
      "start_line": 151,
      "end_line": 151,
      "text": " TODO Remove"
    },
    {
      "start_line": 152,
      "end_line": 152,
      "text": " TODO Remove"
    },
    {
      "start_line": 157,
      "end_line": 157,
      "text": " TODO Remove"
    },
    {
      "start_line": 158,
      "end_line": 158,
      "text": " TODO Remove"
    },
    {
      "start_line": 163,
      "end_line": 163,
      "text": " TODO Remove"
    },
    {
      "start_line": 164,
      "end_line": 164,
      "text": " TODO Remove"
    },
    {
      "start_line": 167,
      "end_line": 167,
      "text": " TODO Remove"
    },
    {
      "start_line": 168,
      "end_line": 168,
      "text": " TODO Remove"
    },
    {
      "start_line": 171,
      "end_line": 171,
      "text": " Always true but this is for eBPF loader"
    },
    {
      "start_line": 173,
      "end_line": 173,
      "text": " TODO Remove"
    },
    {
      "start_line": 174,
      "end_line": 174,
      "text": " TODO Remove"
    },
    {
      "start_line": 177,
      "end_line": 177,
      "text": " If negative reward, divide because of a negative exponent ^^"
    },
    {
      "start_line": 183,
      "end_line": 183,
      "text": " TODO Remove"
    },
    {
      "start_line": 184,
      "end_line": 184,
      "text": " TODO Remove"
    },
    {
      "start_line": 185,
      "end_line": 185,
      "text": " TODO Remove"
    },
    {
      "start_line": 189,
      "end_line": 189,
      "text": " TODO Reset weights"
    },
    {
      "start_line": 195,
      "end_line": 195,
      "text": " Compiler cannot unroll otherwise"
    },
    {
      "start_line": 198,
      "end_line": 198,
      "text": " Wrong SRH ID -> might be inconsistent state, so skip"
    },
    {
      "start_line": 199,
      "end_line": 199,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 200,
      "end_line": 200,
      "text": " Same SRH"
    },
    {
      "start_line": 201,
      "end_line": 201,
      "text": " 1"
    },
    {
      "start_line": 202,
      "end_line": 202,
      "text": "bpf_debug(\"Cannot find the SRH entry indexed at %d at a dest entry\\n\", i);"
    },
    {
      "start_line": 206,
      "end_line": 206,
      "text": " 1"
    },
    {
      "start_line": 207,
      "end_line": 207,
      "text": "bpf_debug(\"SRH entry indexed at %d by the dest entry is invalid\\n\", i);"
    },
    {
      "start_line": 208,
      "end_line": 208,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 213,
      "end_line": 213,
      "text": " bpf_debug(\"HERE %llu %u\\n\", operands[1].mantissa, operands[1].exponent);  TODO Remove"
    },
    {
      "start_line": 214,
      "end_line": 214,
      "text": " TODO Remove"
    },
    {
      "start_line": 215,
      "end_line": 215,
      "text": " TODO Remove"
    },
    {
      "start_line": 224,
      "end_line": 224,
      "text": " Compiler cannot unroll otherwise"
    },
    {
      "start_line": 227,
      "end_line": 227,
      "text": " Wrong SRH ID -> might be inconsistent state, so skip"
    },
    {
      "start_line": 228,
      "end_line": 228,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 229,
      "end_line": 229,
      "text": " Same SRH"
    },
    {
      "start_line": 230,
      "end_line": 230,
      "text": " 1"
    },
    {
      "start_line": 231,
      "end_line": 231,
      "text": "bpf_debug(\"Cannot find the SRH entry indexed at %d at a dest entry\\n\", i);"
    },
    {
      "start_line": 235,
      "end_line": 235,
      "text": " 1"
    },
    {
      "start_line": 236,
      "end_line": 236,
      "text": "bpf_debug(\"SRH entry indexed at %d by the dest entry is invalid\\n\", i);"
    },
    {
      "start_line": 237,
      "end_line": 237,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 248,
      "end_line": 248,
      "text": " Minimum 1 for weights"
    },
    {
      "start_line": 252,
      "end_line": 252,
      "text": " TODO Remove"
    },
    {
      "start_line": 253,
      "end_line": 253,
      "text": " TODO Remove"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct flow_infos *flow_info",
    " struct dst_infos *dst_infos",
    " struct bpf_sock_ops *skops"
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
    "static void exp3_reward_path (struct flow_infos *flow_info, struct dst_infos *dst_infos, struct bpf_sock_ops *skops)\n",
    "{\n",
    "    floating gamma_rev;\n",
    "    floating reward;\n",
    "    floating exponent_den_factor;\n",
    "    floating exponent_den;\n",
    "    floating nbr_actions;\n",
    "    floating exponent;\n",
    "    floating weight_factor;\n",
    "    floating float_tmp, float_tmp2;\n",
    "    floating operands [2];\n",
    "    __u32 decimal [2];\n",
    "    __u32 srtt;\n",
    "    floating max_reward;\n",
    "    bpf_to_floating (MAX_REWARD_FACTOR, 0, 1, &max_reward, sizeof (floating));\n",
    "    GAMMA_REV (gamma_rev);\n",
    "    srtt = (skops->srtt_us >> 3) / 1000;\n",
    "    if (srtt <= 23) {\n",
    "        flow_info->exp3_curr_reward = 23 - srtt;\n",
    "        flow_info->negative_reward = 0;\n",
    "    }\n",
    "    else {\n",
    "        flow_info->exp3_curr_reward = srtt - 23;\n",
    "        flow_info->negative_reward = 1;\n",
    "    }\n",
    "    bpf_debug (\"HERE reward %u for path %u - negative ? %d\\n\", flow_info->exp3_curr_reward, flow_info->srh_id, flow_info->negative_reward);\n",
    "    bpf_to_floating (flow_info->exp3_curr_reward, 0, 1, &reward, sizeof (floating));\n",
    "    bpf_to_floating (flow_info->exp3_last_number_actions, 1, 0, &nbr_actions, sizeof (floating));\n",
    "    set_floating (operands[0], reward);\n",
    "    set_floating (operands[1], max_reward);\n",
    "    bpf_floating_divide (operands, sizeof (floating) * 2, &reward, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&reward, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-norm-reward %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    set_floating (operands[0], flow_info->exp3_last_probability);\n",
    "    bpf_floating_to_u32s (&flow_info->exp3_last_probability, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-exponent_den_factor %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    set_floating (operands[1], gamma_rev);\n",
    "    bpf_floating_to_u32s (&gamma_rev, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-exponent_den_factor %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    bpf_floating_multiply (operands, sizeof (floating) * 2, &exponent_den_factor, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&exponent_den_factor, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-exponent_den_factor %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    set_floating (operands[0], exponent_den_factor);\n",
    "    set_floating (operands[1], nbr_actions);\n",
    "    bpf_floating_multiply (operands, sizeof (floating) * 2, &exponent_den, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&exponent_den, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-exponent_den %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    set_floating (operands[0], reward);\n",
    "    set_floating (operands[1], exponent_den);\n",
    "    bpf_floating_divide (operands, sizeof (floating) * 2, &exponent, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&exponent, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-exponent %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    bpf_floating_e_power_a (&exponent, sizeof (floating), &weight_factor, sizeof (floating));\n",
    "    bpf_floating_to_u32s (&weight_factor, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-factor %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    __u32 idx = flow_info->srh_id;\n",
    "    if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) {\n",
    "        exp3_weight_get (dst_infos, idx, float_tmp);\n",
    "        bpf_floating_to_u32s (&float_tmp, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "        bpf_debug (\"HERE-old-weight %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "        set_floating (operands[0], float_tmp);\n",
    "        set_floating (operands[1], weight_factor);\n",
    "        if (flow_info->negative_reward) {\n",
    "            bpf_floating_divide (operands, sizeof (floating) * 2, &float_tmp2, sizeof (floating));\n",
    "        }\n",
    "        else {\n",
    "            bpf_floating_multiply (operands, sizeof (floating) * 2, &float_tmp2, sizeof (floating));\n",
    "        }\n",
    "        bpf_debug (\"HERE-new-weight %llu %u\\n\", float_tmp2.mantissa, float_tmp2.exponent);\n",
    "        bpf_floating_to_u32s (&float_tmp2, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "        bpf_debug (\"HERE-new-weight %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "        exp3_weight_set (dst_infos, idx, float_tmp2);\n",
    "    }\n",
    "    floating sum;\n",
    "    bpf_to_floating (0, 0, 1, &sum, sizeof (floating));\n",
    "    struct srh_record_t *srh_record = NULL;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {\n",
    "        int xxx = i;\n",
    "        srh_record = &dst_infos->srhs[i];\n",
    "        if (!srh_record || !srh_record->srh.type) {\n",
    "            continue;\n",
    "        }\n",
    "        if (!srh_record->is_valid) {\n",
    "            continue;\n",
    "        }\n",
    "        set_floating (operands[0], sum);\n",
    "        exp3_weight_get (dst_infos, xxx, operands[1]);\n",
    "        bpf_floating_to_u32s (&operands[1], sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "        bpf_debug (\"BEFORE-1 %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "        bpf_floating_add (operands, sizeof (floating) * 2, &sum, sizeof (floating));\n",
    "    }\n",
    "    floating nbr_tokens;\n",
    "    bpf_to_floating (NBR_TOKENS, 0, 1, &nbr_tokens, sizeof (floating));\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {\n",
    "        int xxx = i;\n",
    "        srh_record = &dst_infos->srhs[i];\n",
    "        if (!srh_record || !srh_record->srh.type) {\n",
    "            continue;\n",
    "        }\n",
    "        if (!srh_record->is_valid) {\n",
    "            continue;\n",
    "        }\n",
    "        exp3_weight_get (dst_infos, xxx, operands[0]);\n",
    "        set_floating (operands[1], nbr_tokens);\n",
    "        bpf_floating_multiply (operands, sizeof (floating) * 2, &float_tmp, sizeof (floating));\n",
    "        set_floating (operands[0], float_tmp);\n",
    "        set_floating (operands[1], sum);\n",
    "        bpf_floating_divide (operands, sizeof (floating) * 2, &float_tmp, sizeof (floating));\n",
    "        if (float_tmp.exponent >= BIAS) {\n",
    "            exp3_weight_set (dst_infos, xxx, float_tmp);\n",
    "        }\n",
    "        else {\n",
    "            exp3_weight_reset (dst_infos, xxx);\n",
    "        }\n",
    "        exp3_weight_get (dst_infos, xxx, float_tmp);\n",
    "        bpf_floating_to_u32s (&float_tmp, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "        bpf_debug (\"AFTER-1 %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "GAMMA_REV",
    "set_floating",
    "exp3_weight_get",
    "bpf_debug",
    "bpf_to_floating",
    "exp3_weight_reset",
    "bpf_floating_divide",
    "bpf_floating_multiply",
    "bpf_floating_to_u32s",
    "unroll",
    "exp3_weight_set",
    "bpf_floating_e_power_a",
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
static void exp3_reward_path(struct flow_infos *flow_info, struct dst_infos *dst_infos, struct bpf_sock_ops *skops)
{
	/*
	theReward = reward(choice, t)
	weights[choice] *= math.exp(theReward / (probabilityDistribution[choice] * gamma_rev * numActions)) # important that we use estimated reward here!
	*/
	floating gamma_rev;
	floating reward;
	floating exponent_den_factor;
	floating exponent_den;
	floating nbr_actions;
	floating exponent;
	floating weight_factor;
	floating float_tmp, float_tmp2;
	floating operands[2];
	__u32 decimal[2];
	__u32 srtt;

	floating max_reward;

	// Compute max reward (in ms)
	bpf_to_floating(MAX_REWARD_FACTOR, 0, 1, &max_reward, sizeof(floating)); // TODO Hardcoded factor

	GAMMA_REV(gamma_rev);

	// Compute new reward (in ms)
	srtt = (skops->srtt_us >> 3) / 1000;
	if (srtt <= 23) { // TODO Hardcoded mean delay (should be a moving average)
		flow_info->exp3_curr_reward = 23 - srtt; // TODO Hardcoded mean delay (should be a moving average)
		flow_info->negative_reward = 0;
	} else {
		flow_info->exp3_curr_reward = srtt - 23; // TODO Hardcoded mean delay (should be a moving average)
		flow_info->negative_reward = 1;
	}

	bpf_debug("HERE reward %u for path %u - negative ? %d\n", flow_info->exp3_curr_reward, flow_info->srh_id, flow_info->negative_reward); // TODO Remove
	bpf_to_floating(flow_info->exp3_curr_reward, 0, 1, &reward, sizeof(floating));
	bpf_to_floating(flow_info->exp3_last_number_actions, 1, 0, &nbr_actions, sizeof(floating));

	set_floating(operands[0], reward);
	set_floating(operands[1], max_reward);
	bpf_floating_divide(operands, sizeof(floating) * 2, &reward, sizeof(floating)); // reward should be in [0, 1]
	bpf_floating_to_u32s(&reward, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-norm-reward %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	// Compute new weight
	set_floating(operands[0], flow_info->exp3_last_probability);
	bpf_floating_to_u32s(&flow_info->exp3_last_probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den_factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	set_floating(operands[1], gamma_rev);
	bpf_floating_to_u32s(&gamma_rev, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den_factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	bpf_floating_multiply(operands, sizeof(floating) * 2, &exponent_den_factor, sizeof(floating));
	bpf_floating_to_u32s(&exponent_den_factor, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den_factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	set_floating(operands[0], exponent_den_factor);
	set_floating(operands[1], nbr_actions);
	bpf_floating_multiply(operands, sizeof(floating) * 2, &exponent_den, sizeof(floating));
	bpf_floating_to_u32s(&exponent_den, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent_den %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	set_floating(operands[0], reward);
	set_floating(operands[1], exponent_den);
	bpf_floating_divide(operands, sizeof(floating) * 2, &exponent, sizeof(floating));
	bpf_floating_to_u32s(&exponent, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-exponent %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	bpf_floating_e_power_a(&exponent, sizeof(floating), &weight_factor, sizeof(floating));
	bpf_floating_to_u32s(&weight_factor, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-factor %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	__u32 idx = flow_info->srh_id;
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) { // Always true but this is for eBPF loader
		exp3_weight_get(dst_infos, idx, float_tmp);
		bpf_floating_to_u32s(&float_tmp, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-old-weight %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		set_floating(operands[0], float_tmp);
		set_floating(operands[1], weight_factor);
		// If negative reward, divide because of a negative exponent ^^
		if (flow_info->negative_reward) {
			bpf_floating_divide(operands, sizeof(floating) * 2, &float_tmp2, sizeof(floating));
		} else {
			bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp2, sizeof(floating));
		}
		bpf_debug("HERE-new-weight %llu %u\n", float_tmp2.mantissa, float_tmp2.exponent); // TODO Remove
		bpf_floating_to_u32s(&float_tmp2, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-new-weight %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		exp3_weight_set(dst_infos, idx, float_tmp2);
	}

	// TODO Reset weights
	floating sum;
	bpf_to_floating(0, 0, 1, &sum, sizeof(floating));
	struct srh_record_t *srh_record = NULL;
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 1
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 1
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		set_floating(operands[0], sum);
		exp3_weight_get(dst_infos, xxx, operands[1]);
		// bpf_debug("HERE %llu %u\n", operands[1].mantissa, operands[1].exponent); // TODO Remove
		bpf_floating_to_u32s(&operands[1], sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("BEFORE-1 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

		bpf_floating_add(operands, sizeof(floating) * 2, &sum, sizeof(floating));
	}

	floating nbr_tokens;
	bpf_to_floating(NBR_TOKENS, 0, 1, &nbr_tokens, sizeof(floating));
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 1
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 1
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}
		exp3_weight_get(dst_infos, xxx, operands[0]);
		set_floating(operands[1], nbr_tokens);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		set_floating(operands[0], float_tmp);
		set_floating(operands[1], sum);
		bpf_floating_divide(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		if (float_tmp.exponent >= BIAS) {
			exp3_weight_set(dst_infos, xxx, float_tmp);
		} else {
			exp3_weight_reset(dst_infos, xxx); // Minimum 1 for weights
		}

		exp3_weight_get(dst_infos, xxx, float_tmp);
		bpf_floating_to_u32s(&float_tmp, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("AFTER-1 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	}
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "bcc",
          "FunctionName": "bpf_get_prandom_u32",
          "Return Type": "u32",
          "Description": "u32 bpf_get_prandom_u32 Returns a pseudo-random u32. Example in situ: \"https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Aexamples&type=Code search /examples , \"https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Atools&type=Code search /tools ",
          "Return": "Returns a pseudo-random u32",
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
    },
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
    }
  ],
  "helperCallParams": {},
  "startLine": 257,
  "endLine": 394,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/tpc-ebpf/original_source/ebpf_exp3_lowest_delay.h",
  "funcName": "exp3_next_path",
  "developer_inline_comments": [
    {
      "start_line": 259,
      "end_line": 278,
      "text": "\tdef distr(weights, gamma=0.0):\t\ttheSum = float(sum(weights))\t\treturn tuple((1.0 - gamma) * (w / theSum) + (gamma / len(weights)) for w in weights)\tdef exp3(numActions, reward, gamma):\t\tweights = [1.0] * numActions\t\tt = 0\t\twhile True:\t\t\tprobabilityDistribution = distr(weights, gamma)\t\t\tchoice = draw(probabilityDistribution)\t\t\ttheReward = reward(choice, t)\t\t\testimatedReward = theReward / probabilityDistribution[choice]\t\t\tweights[choice] *= math.exp(estimatedReward * gamma / numActions) # important that we use estimated reward here!\t\t\tyield choice, theReward, estimatedReward, weights\t\t\tt = t + 1\t"
    },
    {
      "start_line": 293,
      "end_line": 293,
      "text": "bpf_debug(\"Cannot find the destination entry => Cannot find another SRH\\n\");"
    },
    {
      "start_line": 297,
      "end_line": 297,
      "text": " Compute the sum of weights"
    },
    {
      "start_line": 303,
      "end_line": 303,
      "text": " Compiler cannot unroll otherwise"
    },
    {
      "start_line": 306,
      "end_line": 306,
      "text": " Wrong SRH ID -> might be inconsistent state, so skip"
    },
    {
      "start_line": 307,
      "end_line": 307,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 308,
      "end_line": 308,
      "text": " Same SRH"
    },
    {
      "start_line": 309,
      "end_line": 309,
      "text": " 1"
    },
    {
      "start_line": 310,
      "end_line": 310,
      "text": "bpf_debug(\"Cannot find the SRH entry indexed at %d at a dest entry\\n\", i);"
    },
    {
      "start_line": 314,
      "end_line": 314,
      "text": " 1"
    },
    {
      "start_line": 315,
      "end_line": 315,
      "text": "bpf_debug(\"SRH entry indexed at %d by the dest entry is invalid\\n\", i);"
    },
    {
      "start_line": 316,
      "end_line": 316,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 321,
      "end_line": 321,
      "text": "bpf_debug(\"HERE %llu %u\\n\", operands[1].mantissa, operands[1].exponent);  TODO Remove"
    },
    {
      "start_line": 322,
      "end_line": 322,
      "text": " TODO Remove"
    },
    {
      "start_line": 323,
      "end_line": 323,
      "text": " TODO Remove"
    },
    {
      "start_line": 328,
      "end_line": 328,
      "text": " TODO Remove"
    },
    {
      "start_line": 329,
      "end_line": 329,
      "text": " TODO Remove"
    },
    {
      "start_line": 330,
      "end_line": 330,
      "text": " TODO Remove"
    },
    {
      "start_line": 332,
      "end_line": 332,
      "text": " Compute the probabilities"
    },
    {
      "start_line": 346,
      "end_line": 346,
      "text": " No problem if FLOAT_MULT < UIN32T_MAX"
    },
    {
      "start_line": 351,
      "end_line": 351,
      "text": " Compiler cannot unroll otherwise"
    },
    {
      "start_line": 354,
      "end_line": 354,
      "text": " Wrong SRH ID -> might be inconsistent state, so skip"
    },
    {
      "start_line": 355,
      "end_line": 355,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 356,
      "end_line": 356,
      "text": " Same SRH"
    },
    {
      "start_line": 357,
      "end_line": 357,
      "text": " 2"
    },
    {
      "start_line": 358,
      "end_line": 358,
      "text": "bpf_debug(\"Cannot find the SRH entry indexed at %d at a dest entry\\n\", i);"
    },
    {
      "start_line": 362,
      "end_line": 362,
      "text": " 2"
    },
    {
      "start_line": 363,
      "end_line": 363,
      "text": " Not a valid SRH for the destination"
    },
    {
      "start_line": 366,
      "end_line": 366,
      "text": " prob[i] = (1.0 - gamma) * (w[i] / theSum) + (gamma / len(weights))"
    },
    {
      "start_line": 371,
      "end_line": 371,
      "text": "exp3_weight_get(dst_infos, yyy, operands[0]);"
    },
    {
      "start_line": 381,
      "end_line": 381,
      "text": " No need to take the integer part since these are numbers in [0, 1["
    },
    {
      "start_line": 382,
      "end_line": 382,
      "text": " TODO Remove"
    },
    {
      "start_line": 384,
      "end_line": 384,
      "text": " TODO Remove"
    },
    {
      "start_line": 385,
      "end_line": 385,
      "text": " We found the chosen one"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " dt_map"
  ],
  "input": [
    "struct bpf_elf_map *dt_map",
    " struct flow_infos *flow_info",
    " __u32 *dst_addr"
  ],
  "output": "static__u32",
  "helper": [
    "bpf_get_prandom_u32",
    "bpf_map_lookup_elem"
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
    "static __u32 exp3_next_path (struct bpf_elf_map *dt_map, struct flow_infos *flow_info, __u32 *dst_addr)\n",
    "{\n",
    "    floating operands [2];\n",
    "    floating gamma;\n",
    "    GAMMA (gamma);\n",
    "    __u32 decimal [2];\n",
    "    decimal[0] = 0;\n",
    "    decimal[1] = 0;\n",
    "    __u32 chosen_id = 0, current_delay = 0;\n",
    "    struct srh_record_t *srh_record = NULL;\n",
    "    struct dst_infos *dst_infos = NULL;\n",
    "    dst_infos = (void *) bpf_map_lookup_elem (dt_map, dst_addr);\n",
    "    if (!dst_infos) {\n",
    "        return chosen_id;\n",
    "    }\n",
    "    floating sum;\n",
    "    bpf_to_floating (0, 0, 1, &sum, sizeof (floating));\n",
    "    __u32 nbr_valid_paths = 0;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {\n",
    "        int xxx = i;\n",
    "        srh_record = &dst_infos->srhs[i];\n",
    "        if (!srh_record || !srh_record->srh.type) {\n",
    "            continue;\n",
    "        }\n",
    "        if (!srh_record->is_valid) {\n",
    "            continue;\n",
    "        }\n",
    "        set_floating (operands[0], sum);\n",
    "        exp3_weight_get (dst_infos, xxx, operands[1]);\n",
    "        bpf_floating_to_u32s (&operands[1], sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "        bpf_debug (\"HERE-2 %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "        bpf_floating_add (operands, sizeof (floating) * 2, &sum, sizeof (floating));\n",
    "        nbr_valid_paths += 1;\n",
    "    }\n",
    "    bpf_floating_to_u32s (&sum, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "    bpf_debug (\"HERE-sum %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "    bpf_debug (\"HERE-nbr-valid-paths %u\\n\", nbr_valid_paths);\n",
    "    floating probability;\n",
    "    floating one_minus_gamma;\n",
    "    ONE_MINUS_GAMMA (one_minus_gamma);\n",
    "    floating weight_times_gama;\n",
    "    floating term1;\n",
    "    floating valid_paths;\n",
    "    bpf_to_floating (nbr_valid_paths, 0, 1, &valid_paths, sizeof (floating));\n",
    "    floating term2;\n",
    "    set_floating (operands[0], gamma);\n",
    "    set_floating (operands[1], valid_paths);\n",
    "    bpf_floating_divide (operands, sizeof (floating) * 2, &term2, sizeof (floating));\n",
    "    __u64 pick = ((__u64) bpf_get_prandom_u32 ()) % FLOAT_MULT;\n",
    "    __u64 accumulator = 0;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {\n",
    "        int yyy = i;\n",
    "        srh_record = &dst_infos->srhs[i];\n",
    "        if (!srh_record || !srh_record->srh.type) {\n",
    "            continue;\n",
    "        }\n",
    "        if (!srh_record->is_valid) {\n",
    "            continue;\n",
    "        }\n",
    "        set_floating (operands[0], one_minus_gamma);\n",
    "        exp3_weight_get (dst_infos, yyy, operands[1]);\n",
    "        bpf_floating_multiply (operands, sizeof (floating) * 2, &weight_times_gama, sizeof (floating));\n",
    "        set_floating (operands[0], weight_times_gama);\n",
    "        set_floating (operands[1], sum);\n",
    "        bpf_floating_divide (operands, sizeof (floating) * 2, &term1, sizeof (floating));\n",
    "        set_floating (operands[0], term1);\n",
    "        set_floating (operands[1], term2);\n",
    "        bpf_floating_add (operands, sizeof (floating) * 2, &probability, sizeof (floating));\n",
    "        bpf_floating_to_u32s (&probability, sizeof (floating), (__u64 *) decimal, sizeof (decimal));\n",
    "        accumulator += decimal[1];\n",
    "        bpf_debug (\"HERE-probability %llu.%llu\\n\", decimal[0], decimal[1]);\n",
    "        if (pick < accumulator) {\n",
    "            bpf_debug (\"Chosen %llu\\n\", accumulator);\n",
    "            chosen_id = i;\n",
    "            set_floating (flow_info->exp3_last_probability, probability);\n",
    "            break;\n",
    "        }\n",
    "    }\n",
    "    flow_info->exp3_last_number_actions = nbr_valid_paths;\n",
    "    return chosen_id;\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "set_floating",
    "ONE_MINUS_GAMMA",
    "exp3_weight_get",
    "bpf_debug",
    "GAMMA",
    "bpf_to_floating",
    "bpf_floating_divide",
    "bpf_floating_multiply",
    "bpf_floating_to_u32s",
    "unroll",
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
static __u32 exp3_next_path(struct bpf_elf_map *dt_map, struct flow_infos *flow_info, __u32 *dst_addr)
{
	/*
	def distr(weights, gamma=0.0):
		theSum = float(sum(weights))
		return tuple((1.0 - gamma) * (w / theSum) + (gamma / len(weights)) for w in weights)

	def exp3(numActions, reward, gamma):
		weights = [1.0] * numActions

		t = 0
		while True:
			probabilityDistribution = distr(weights, gamma)
			choice = draw(probabilityDistribution)
			theReward = reward(choice, t)

			estimatedReward = theReward / probabilityDistribution[choice]
			weights[choice] *= math.exp(estimatedReward * gamma / numActions) # important that we use estimated reward here!

			yield choice, theReward, estimatedReward, weights
			t = t + 1
	*/
	floating operands[2];
	floating gamma;
	GAMMA(gamma);

	__u32 decimal[2];
	decimal[0] = 0;
	decimal[1] = 0;

	__u32 chosen_id = 0, current_delay = 0;
	struct srh_record_t *srh_record = NULL;
	struct dst_infos *dst_infos = NULL;

	dst_infos = (void *) bpf_map_lookup_elem(dt_map, dst_addr);
	if (!dst_infos) {
		//bpf_debug("Cannot find the destination entry => Cannot find another SRH\n");
		return chosen_id;
	}

	// Compute the sum of weights
	floating sum;
	bpf_to_floating(0, 0, 1, &sum, sizeof(floating));
	__u32 nbr_valid_paths = 0;
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 1
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 1
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		set_floating(operands[0], sum);
		exp3_weight_get(dst_infos, xxx, operands[1]);
		//bpf_debug("HERE %llu %u\n", operands[1].mantissa, operands[1].exponent); // TODO Remove
		bpf_floating_to_u32s(&operands[1], sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-2 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		bpf_floating_add(operands, sizeof(floating) * 2, &sum, sizeof(floating));
		nbr_valid_paths += 1;
	}

	bpf_floating_to_u32s(&sum, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-sum %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	bpf_debug("HERE-nbr-valid-paths %u\n", nbr_valid_paths); // TODO Remove

	// Compute the probabilities
	floating probability;
	floating one_minus_gamma;
	ONE_MINUS_GAMMA(one_minus_gamma);
	floating weight_times_gama;
	floating term1;
	floating valid_paths;
	bpf_to_floating(nbr_valid_paths, 0, 1, &valid_paths, sizeof(floating));
	floating term2;

	set_floating(operands[0], gamma);
	set_floating(operands[1], valid_paths);
	bpf_floating_divide(operands, sizeof(floating) * 2, &term2, sizeof(floating));

	__u64 pick = ((__u64) bpf_get_prandom_u32()) % FLOAT_MULT; // No problem if FLOAT_MULT < UIN32T_MAX
	__u64 accumulator = 0;

	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int yyy = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 2
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 2
			continue; // Not a valid SRH for the destination
		}

		// prob[i] = (1.0 - gamma) * (w[i] / theSum) + (gamma / len(weights))
		set_floating(operands[0], one_minus_gamma);
		exp3_weight_get(dst_infos, yyy, operands[1]);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &weight_times_gama, sizeof(floating));

		//exp3_weight_get(dst_infos, yyy, operands[0]);
		set_floating(operands[0], weight_times_gama);
		set_floating(operands[1], sum);
		bpf_floating_divide(operands, sizeof(floating) * 2, &term1, sizeof(floating));

		set_floating(operands[0], term1);
		set_floating(operands[1], term2);
		bpf_floating_add(operands, sizeof(floating) * 2, &probability, sizeof(floating));

		bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
		accumulator += decimal[1]; // No need to take the integer part since these are numbers in [0, 1[
		bpf_debug("HERE-probability %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		if (pick < accumulator) {
			bpf_debug("Chosen %llu\n", accumulator); // TODO Remove
			// We found the chosen one
			chosen_id = i;
			set_floating(flow_info->exp3_last_probability, probability);
			break;
		}
	}

	flow_info->exp3_last_number_actions = nbr_valid_paths;
	return chosen_id;
}

struct bpf_elf_map SEC("maps") short_conn_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct flow_tuple),
	.size_value	= sizeof(struct flow_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") short_dest_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(unsigned long long),  // XXX Only looks at the most significant 64 bits of the address
	.size_value	= sizeof(struct dst_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") short_stat_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct flow_snapshot),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_SNAPSHOTS,
};

#endif
