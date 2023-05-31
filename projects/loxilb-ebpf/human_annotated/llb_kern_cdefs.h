/*
 *  llb_dp_cdefs.h: Loxilb eBPF/XDP utility functions 
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#ifndef __LLB_DP_CDEFS_H__
#define __LLB_DP_CDEFS_H__

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/common_pdi.h"
#include "../common/llb_dp_mdi.h"
#include "../common/llb_dpapi.h"

#ifndef __stringify
# define __stringify(X)   #X
#endif

#ifndef __section
# define __section(NAME)            \
  __attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)          \
  __section(__stringify(ID) "/" __stringify(KEY))
#endif

#define PGM_ENT0    0
#define PGM_ENT1    1

#define SAMPLE_SIZE 64ul
#define MAX_CPUS    128

#ifndef lock_xadd
#define lock_xadd(ptr, val)              \
   ((void)__sync_fetch_and_add(ptr, val))
#endif

struct ll_xmdpi
{
  __u16 iport;
  __u16 oport;
  __u32 skip;
};

struct ll_xmdi {
  union {
      __u64 xmd;
    struct ll_xmdpi pi;
  };
} __attribute__((aligned(4)));

#ifdef HAVE_LEGACY_BPF_MAPS

struct bpf_map_def SEC("maps") intf_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct intf_key),
  .value_size = sizeof(struct dp_intf_tact),
  .max_entries = LLB_INTF_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") intf_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index xdp_ifidx */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTERFACES,
};

struct bpf_map_def SEC("maps") bd_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index bd_id */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTF_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") pkt_ring = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(__u32),
  .max_entries = MAX_CPUS,
};

struct bpf_map_def SEC("maps") pkts = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index xdp_ifidx */
  .value_size = sizeof(struct ll_dp_pmdi),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") fcas = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_fc_tacts),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") xfis = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),  /* Index CPU idx */
  .value_size = sizeof(struct xfi),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") tx_intf_map = {
  .type = BPF_MAP_TYPE_DEVMAP,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = LLB_INTERFACES,
};

struct bpf_map_def SEC("maps") tx_intf_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index xdp_ifidx */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTERFACES,
};

struct bpf_map_def SEC("maps") tx_bd_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Index bd_id */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_INTF_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") smac_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_smac_key),
  .value_size = sizeof(struct dp_smac_tact),
  .max_entries = LLB_SMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") dmac_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_dmac_key),
  .value_size = sizeof(struct dp_dmac_tact),
  .max_entries = LLB_DMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") tmac_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_tmac_key),
  .value_size = sizeof(struct dp_tmac_tact),
  .max_entries = LLB_TMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") tmac_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* tmac index */
  .value_size = sizeof(struct ll_dp_pmdi),
  .max_entries = LLB_TMAC_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") nh_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(struct dp_nh_key),
  .value_size = sizeof(struct dp_nh_tact),
  .max_entries = LLB_NH_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") ct_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_ct_key),
  .value_size = sizeof(struct dp_ct_tact),
  .max_entries = LLB_CT_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") ct_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_CT_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") nat_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_nat_key),
  .value_size = sizeof(struct dp_nat_tacts),
  .max_entries = LLB_NATV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") nat_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_NATV4_STAT_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v4_map = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct dp_rtv4_key),
  .value_size = sizeof(struct dp_rt_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_RTV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v4_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_RTV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v6_map = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct dp_rtv6_key),
  .value_size = sizeof(struct dp_rt_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_RTV6_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") rt_v6_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_RTV6_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") mirr_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_mirr_tact),
  .max_entries = LLB_MIRR_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") sess_v4_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_sess4_key),
  .value_size = sizeof(struct dp_sess_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_SESS_MAP_ENTRIES 
};

struct bpf_map_def SEC("maps") sess_v4_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_SESS_MAP_ENTRIES 
};

struct bpf_map_def SEC("maps") fc_v4_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_fcv4_key),
  .value_size = sizeof(struct dp_fc_tacts),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_FCV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") fc_v4_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_FCV4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") fw_v4_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_fwv4_ent),
  .max_entries = LLB_FW4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") fw_v4_stats_map = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),  /* Counter Index */
  .value_size = sizeof(struct dp_pb_stats),
  .max_entries = LLB_FW4_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") pgm_tbl = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries =  LLB_PGM_MAP_ENTRIES
};

struct bpf_map_def SEC("maps") polx_map = { 
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_pol_tact),
  .max_entries =  LLB_POL_MAP_ENTRIES 
}; 

struct bpf_map_def SEC("maps") xfck = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),  /* Index CPU idx */
  .value_size = sizeof(struct dp_fcv4_key),
  .max_entries = 1,
};

#else /* New BTF definitions */

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct intf_key);
        __type(value,       struct dp_intf_tact);
        __uint(max_entries, LLB_INTERFACES);
} intf_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTERFACES);
} intf_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTF_MAP_ENTRIES);
} bd_stats_map SEC(".maps");

/*
struct {
        __uint(type,        BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __type(key,         int);
        __type(value,       __u32);
        __uint(max_entries, MAX_CPUS);
} pkt_ring SEC(".maps");
*/

struct bpf_map_def SEC("maps") pkt_ring = {
          .type             = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
          .key_size         = sizeof(int),
          .value_size       = sizeof(__u32),
          .max_entries      = MAX_CPUS,
};

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct ll_dp_pmdi);
        __uint(max_entries, 1);
} pkts SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_fc_tacts);
        __uint(max_entries, 1);
} fcas SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         int);
        __type(value,       struct xfi);
        __uint(max_entries, 1);
} xfis SEC(".maps");

/*
struct {
        __uint(type,        BPF_MAP_TYPE_DEVMAP);
        __type(key,         int);
        __type(value,       int);
        __uint(max_entries, LLB_INTERFACES);
} tx_intf_map SEC(".maps");
*/

struct bpf_map_def SEC("maps") tx_intf_map = {
  .type                     = BPF_MAP_TYPE_DEVMAP,
  .key_size                 = sizeof(int),
  .value_size               = sizeof(int),
  .max_entries              = LLB_INTERFACES,
};

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTF_MAP_ENTRIES);
} tx_intf_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_INTF_MAP_ENTRIES);
} tx_bd_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_smac_key);
        __type(value,       struct dp_smac_tact);
        __uint(max_entries, LLB_SMAC_MAP_ENTRIES);
} smac_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_dmac_key);
        __type(value,       struct dp_dmac_tact);
        __uint(max_entries, LLB_DMAC_MAP_ENTRIES);
} dmac_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_tmac_key);
        __type(value,       struct dp_tmac_tact);
        __uint(max_entries, LLB_TMAC_MAP_ENTRIES);
} tmac_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_TMAC_MAP_ENTRIES);
} tmac_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         struct dp_nh_key);
        __type(value,       struct dp_nh_tact);
        __uint(max_entries, LLB_NH_MAP_ENTRIES);
} nh_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_ct_key);
        __type(value,       struct dp_ct_tact);
        __uint(max_entries, LLB_CT_MAP_ENTRIES);
} ct_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_CT_MAP_ENTRIES);
} ct_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_nat_key);
        __type(value,       struct dp_nat_tacts);
        __uint(max_entries, LLB_NATV4_MAP_ENTRIES);
} nat_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_NATV4_MAP_ENTRIES);
} nat_stats_map SEC(".maps");

/*
struct {
        __uint(type,        BPF_MAP_TYPE_LPM_TRIE);
        __type(key,         struct dp_rtv4_key);
        __type(value,       struct dp_rt_tact);
        __uint(max_entries, LLB_RTV4_MAP_ENTRIES);
} rt_v4_map SEC(".maps");
*/

struct bpf_map_def SEC("maps") rt_v4_map = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct dp_rtv4_key),
  .value_size = sizeof(struct dp_rt_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_RTV4_MAP_ENTRIES
};

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_RTV4_MAP_ENTRIES);
} rt_v4_stats_map SEC(".maps");

struct bpf_map_def SEC("maps") rt_v6_map = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct dp_rtv6_key),
  .value_size = sizeof(struct dp_rt_tact),
  .map_flags = BPF_F_NO_PREALLOC,
  .max_entries = LLB_RTV6_MAP_ENTRIES
};

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_RTV6_MAP_ENTRIES);
} rt_v6_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_mirr_tact);
        __uint(max_entries, LLB_MIRR_MAP_ENTRIES);
} mirr_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_sess4_key);
        __type(value,       struct dp_sess_tact);
        __uint(max_entries, LLB_SESS_MAP_ENTRIES);
} sess_v4_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_SESS_MAP_ENTRIES);
} sess_v4_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_HASH);
        __type(key,         struct dp_fcv4_key);
        __type(value,       struct dp_fc_tacts);
        __uint(max_entries, LLB_FCV4_MAP_ENTRIES);
} fc_v4_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_FCV4_MAP_ENTRIES);
} fc_v4_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_fwv4_ent);
        __uint(max_entries, LLB_FW4_MAP_ENTRIES);
} fw_v4_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pb_stats);
        __uint(max_entries, LLB_FW4_MAP_ENTRIES);
} fw_v4_stats_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PROG_ARRAY);
        __type(key,         __u32);
        __type(value,       __u32);
        __uint(max_entries, LLB_PGM_MAP_ENTRIES);
} pgm_tbl SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       struct dp_pol_tact);
        __uint(max_entries, LLB_POL_MAP_ENTRIES);
} polx_map SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         int);
        __type(value,       struct dp_fcv4_key);
        __uint(max_entries, 1);
} xfck SEC(".maps");

struct {
        __uint(type,        BPF_MAP_TYPE_ARRAY);
        __type(key,         __u32);
        __type(value,       __u32);
        __uint(max_entries, LLB_CRC32C_ENTRIES);
} crc32c_map SEC(".maps");

#endif

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
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 568,
  "endLine": 631,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_map_stats",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_dp_cdefs.h: Loxilb eBPF/XDP utility functions  *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 71,
      "end_line": 71,
      "text": " Index xdp_ifidx "
    },
    {
      "start_line": 78,
      "end_line": 78,
      "text": " Index bd_id "
    },
    {
      "start_line": 92,
      "end_line": 92,
      "text": " Index xdp_ifidx "
    },
    {
      "start_line": 106,
      "end_line": 106,
      "text": " Index CPU idx "
    },
    {
      "start_line": 120,
      "end_line": 120,
      "text": " Index xdp_ifidx "
    },
    {
      "start_line": 127,
      "end_line": 127,
      "text": " Index bd_id "
    },
    {
      "start_line": 155,
      "end_line": 155,
      "text": " tmac index "
    },
    {
      "start_line": 176,
      "end_line": 176,
      "text": " Counter Index "
    },
    {
      "start_line": 190,
      "end_line": 190,
      "text": " Counter Index "
    },
    {
      "start_line": 205,
      "end_line": 205,
      "text": " Counter Index "
    },
    {
      "start_line": 220,
      "end_line": 220,
      "text": " Counter Index "
    },
    {
      "start_line": 242,
      "end_line": 242,
      "text": " Counter Index "
    },
    {
      "start_line": 257,
      "end_line": 257,
      "text": " Counter Index "
    },
    {
      "start_line": 271,
      "end_line": 271,
      "text": " Counter Index "
    },
    {
      "start_line": 292,
      "end_line": 292,
      "text": " Index CPU idx "
    },
    {
      "start_line": 297,
      "end_line": 297,
      "text": " New BTF definitions "
    },
    {
      "start_line": 320,
      "end_line": 327,
      "text": "struct {        __uint(type,        BPF_MAP_TYPE_PERF_EVENT_ARRAY);        __type(key,         int);        __type(value,       __u32);        __uint(max_entries, MAX_CPUS);} pkt_ring SEC(\".maps\");"
    },
    {
      "start_line": 357,
      "end_line": 364,
      "text": "struct {        __uint(type,        BPF_MAP_TYPE_DEVMAP);        __type(key,         int);        __type(value,       int);        __uint(max_entries, LLB_INTERFACES);} tx_intf_map SEC(\".maps\");"
    },
    {
      "start_line": 450,
      "end_line": 457,
      "text": "struct {        __uint(type,        BPF_MAP_TYPE_LPM_TRIE);        __type(key,         struct dp_rtv4_key);        __type(value,       struct dp_rt_tact);        __uint(max_entries, LLB_RTV4_MAP_ENTRIES);} rt_v4_map SEC(\".maps\");"
    }
  ],
  "updateMaps": [
    " map"
  ],
  "readMaps": [
    " map"
  ],
  "input": [
    "struct xdp_md *ctx",
    " struct xfi *xf",
    " int xtbl",
    " int cidx"
  ],
  "output": "staticvoid__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_map_update_elem"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "cgroup_device",
    "lwt_xmit",
    "cgroup_sock",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "cgroup_sysctl",
    "sk_msg",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "perf_event",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static void __always_inline dp_do_map_stats (struct xdp_md *ctx, struct xfi *xf, int xtbl, int cidx)\n",
    "{\n",
    "    struct dp_pb_stats *pb;\n",
    "    struct dp_pb_stats pb_new;\n",
    "    void *map = NULL;\n",
    "    int key = cidx;\n",
    "    switch (xtbl) {\n",
    "    case LL_DP_RTV4_STATS_MAP :\n",
    "        map = &rt_v4_stats_map;\n",
    "        break;\n",
    "    case LL_DP_RTV6_STATS_MAP :\n",
    "        map = &rt_v6_stats_map;\n",
    "        break;\n",
    "    case LL_DP_CT_STATS_MAP :\n",
    "        map = &ct_stats_map;\n",
    "        break;\n",
    "    case LL_DP_INTF_STATS_MAP :\n",
    "        map = &intf_stats_map;\n",
    "        break;\n",
    "    case LL_DP_TX_INTF_STATS_MAP :\n",
    "        map = &tx_intf_stats_map;\n",
    "        break;\n",
    "    case LL_DP_BD_STATS_MAP :\n",
    "        map = &bd_stats_map;\n",
    "        break;\n",
    "    case LL_DP_TX_BD_STATS_MAP :\n",
    "        map = &tx_bd_stats_map;\n",
    "        break;\n",
    "    case LL_DP_TMAC_STATS_MAP :\n",
    "        map = &tmac_stats_map;\n",
    "        break;\n",
    "    case LL_DP_SESS4_STATS_MAP :\n",
    "        map = &sess_v4_stats_map;\n",
    "        break;\n",
    "    case LL_DP_NAT_STATS_MAP :\n",
    "        map = &nat_stats_map;\n",
    "        break;\n",
    "    case LL_DP_FW4_STATS_MAP :\n",
    "        map = &fw_v4_stats_map;\n",
    "        break;\n",
    "    default :\n",
    "        return;\n",
    "    }\n",
    "    pb = bpf_map_lookup_elem (map, & key);\n",
    "    if (pb) {\n",
    "        pb->bytes += xf->pm.py_bytes;\n",
    "        pb->packets += 1;\n",
    "        LL_DBG_PRINTK (\"[STAT] %d %llu %llu\\n\", key, pb->bytes, pb->packets);\n",
    "        return;\n",
    "    }\n",
    "    pb_new.bytes = xf->pm.py_bytes;\n",
    "    ;\n",
    "    pb_new.packets = 1;\n",
    "    bpf_map_update_elem (map, &key, &pb_new, BPF_ANY);\n",
    "    return;\n",
    "}\n"
  ],
  "called_function_list": [
    "LL_DBG_PRINTK"
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
static void __always_inline
dp_do_map_stats(struct xdp_md *ctx,  
                struct xfi *xf,
                int xtbl,
                int cidx)
{
  struct dp_pb_stats *pb;
  struct dp_pb_stats pb_new;
  void *map = NULL;
  int key = cidx;

  switch (xtbl) {
  case LL_DP_RTV4_STATS_MAP:
    map = &rt_v4_stats_map;
    break;
  case LL_DP_RTV6_STATS_MAP:
    map = &rt_v6_stats_map;
    break;
  case LL_DP_CT_STATS_MAP:
    map = &ct_stats_map;
    break;
  case LL_DP_INTF_STATS_MAP:
    map = &intf_stats_map;
    break;
  case LL_DP_TX_INTF_STATS_MAP:
    map = &tx_intf_stats_map;
    break;
  case LL_DP_BD_STATS_MAP:
    map = &bd_stats_map;
    break;
  case LL_DP_TX_BD_STATS_MAP:
    map = &tx_bd_stats_map;
    break;
  case LL_DP_TMAC_STATS_MAP:
    map = &tmac_stats_map;
    break;
  case LL_DP_SESS4_STATS_MAP:
    map = &sess_v4_stats_map;
    break;
  case LL_DP_NAT_STATS_MAP:
    map = &nat_stats_map;
    break;
  case LL_DP_FW4_STATS_MAP:
    map = &fw_v4_stats_map;
    break;
  default:
    return;
  }

  pb = bpf_map_lookup_elem(map, &key);
  if (pb) {
    pb->bytes += xf->pm.py_bytes;
    pb->packets += 1;
    LL_DBG_PRINTK("[STAT] %d %llu %llu\n", key, pb->bytes, pb->packets);
    return;
  }

  pb_new.bytes =  xf->pm.py_bytes;;
  pb_new.packets = 1;

  bpf_map_update_elem(map, &key, &pb_new, BPF_ANY);

  return;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 633,
  "endLine": 647,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_ipv4_new_csum",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct iphdr *iph"
  ],
  "output": "staticvoid__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static void __always_inline dp_ipv4_new_csum (struct iphdr *iph)\n",
    "{\n",
    "    __u16 *iph16 = (__u16 *) iph;\n",
    "    __u32 csum;\n",
    "    int i;\n",
    "    iph->check = 0;\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (i = 0, csum = 0; i < sizeof (*iph) >> 1; i++)\n",
    "        csum += *iph16++;\n",
    "    iph->check = ~((csum & 0xffff) + (csum >> 16));\n",
    "}\n"
  ],
  "called_function_list": [
    "unroll"
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
static void __always_inline
dp_ipv4_new_csum(struct iphdr *iph)
{
  __u16 *iph16 = (__u16 *)iph;
  __u32 csum;
  int i;

  iph->check = 0;

#pragma clang loop unroll(full)
  for (i = 0, csum = 0; i < sizeof(*iph) >> 1; i++)
    csum += *iph16++;

  iph->check = ~((csum & 0xffff) + (csum >> 16));
}

#ifdef LL_TC_EBPF
#include <linux/pkt_cls.h>

#define DP_REDIRECT TC_ACT_REDIRECT
#define DP_DROP     TC_ACT_SHOT
#define DP_PASS     TC_ACT_OK

#define DP_LLB_MRK_INGP(md) (((struct __sk_buff *)md)->cb[0] = LLB_INGP_MARK)
#define DP_LLB_INGP(md) (((struct __sk_buff *)md)->cb[0] == LLB_INGP_MARK)
#define DP_NEED_MIRR(md) (((struct __sk_buff *)md)->cb[0] == LLB_MIRR_MARK)
#define DP_GET_MIRR(md) (((struct __sk_buff *)md)->cb[1])
#define DP_CTX_MIRR(md) (((struct __sk_buff *)md)->cb[0] == LLB_MIRR_MARK)
#define DP_IFI(md) (((struct __sk_buff *)md)->ifindex)
#define DP_IIFI(md) (((struct __sk_buff *)md)->ingress_ifindex)
#define DP_PDATA(md) (((struct __sk_buff *)md)->data)
#define DP_PDATA_END(md) (((struct __sk_buff *)md)->data_end)
#define DP_MDATA(md) (((struct __sk_buff *)md)->data_meta)

#ifdef HAVE_CLANG13
#define DP_NEW_FCXF(xf)                  \
  int val = 0;                           \
  xf = bpf_map_lookup_elem(&xfis, &val); \
  if (!xf) {                             \
    return DP_DROP;                      \
  }                                      \
  memset(xf, 0, sizeof(*xf));            \

#else

#define DP_NEW_FCXF(xf)                  \
  struct xfi xfr;                        \
  memset(&xfr, 0, sizeof(xfr));          \
  xf = &xfr;                             \

#endif


#define RETURN_TO_MP_OUT()                       \
do {                                             \
  xf->pm.phit |= LLB_DP_RES_HIT;                 \
  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);\
} while(0)

#define TCALL_CRC1() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CRC_PGM_ID1)
#define TCALL_CRC2() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CRC_PGM_ID2)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 695,
  "endLine": 711,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_csum_tcall",
  "developer_inline_comments": [
    {
      "start_line": 701,
      "end_line": 701,
      "text": " Init state-variables "
    }
  ],
  "updateMaps": [
    " xfis"
  ],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_update_elem"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_csum_tcall (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    int z = 0;\n",
    "    __u32 crc = 0xffffffff;\n",
    "    xf->km.skey[0] = 0;\n",
    "    *(__u16*) &xf->km.skey[2] = xf->pm.l4_off;\n",
    "    *(__u16*) &xf->km.skey[4] = xf->pm.l3_plen;\n",
    "    *(__u32*) &xf->km.skey[8] = crc;\n",
    "    bpf_map_update_elem (&xfis, &z, xf, BPF_ANY);\n",
    "    TCALL_CRC1 ();\n",
    "    return DP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "TCALL_CRC1"
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
static int __always_inline
dp_csum_tcall(void *ctx,  struct xfi *xf)
{
  int z = 0;
  __u32 crc = 0xffffffff;

   /* Init state-variables */
  xf->km.skey[0] = 0;
  *(__u16 *)&xf->km.skey[2] = xf->pm.l4_off;
  *(__u16 *)&xf->km.skey[4] = xf->pm.l3_plen;
  *(__u32 *)&xf->km.skey[8] = crc;

  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);

  TCALL_CRC1();
  return DP_PASS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 713,
  "endLine": 722,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_sunp_tcall",
  "developer_inline_comments": [],
  "updateMaps": [
    " xfis"
  ],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_update_elem",
    "bpf_tail_call"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "lwt_xmit",
    "cgroup_sock",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "perf_event",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_sunp_tcall (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    int z = 0;\n",
    "    bpf_map_update_elem (&xfis, &z, xf, BPF_ANY);\n",
    "    bpf_tail_call (ctx, &pgm_tbl, LLB_DP_SUNP_PGM_ID2);\n",
    "    return DP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_sunp_tcall(void *ctx,  struct xfi *xf)
{
  int z = 0;

  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);
  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_SUNP_PGM_ID2);

  return DP_PASS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 724,
  "endLine": 734,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pkt_is_l2mcbc",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xfi *xf",
    " void *md"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_pkt_is_l2mcbc (struct xfi *xf, void *md)\n",
    "{\n",
    "    struct  __sk_buff *b = md;\n",
    "    if (b->pkt_type == PACKET_MULTICAST || b->pkt_type == PACKET_BROADCAST) {\n",
    "        return 1;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_pkt_is_l2mcbc(struct xfi *xf, void *md)
{
  struct __sk_buff *b = md;  

  if (b->pkt_type == PACKET_MULTICAST ||
      b->pkt_type == PACKET_BROADCAST) {
    return 1;
  }
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 736,
  "endLine": 748,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_vlan_info",
  "developer_inline_comments": [
    {
      "start_line": 742,
      "end_line": 742,
      "text": "xf->l2m.dl_type = bpf_htons((__u16)(b->vlan_proto));"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xfi *xf",
    " void *md"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_vlan_info (struct xfi *xf, void *md)\n",
    "{\n",
    "    struct  __sk_buff *b = md;\n",
    "    if (b->vlan_present) {\n",
    "        xf->l2m.vlan[0] = bpf_htons ((__u16) (b->vlan_tci));\n",
    "        return 1;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_htons"
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
static int __always_inline
dp_vlan_info(struct xfi *xf, void *md)
{
  struct __sk_buff *b = md;

  if (b->vlan_present) {
    /*xf->l2m.dl_type = bpf_htons((__u16)(b->vlan_proto));*/
    xf->l2m.vlan[0] = bpf_htons((__u16)(b->vlan_tci));
    return 1;
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Grows headroom of packet associated to <[ skb ]>(IP: 0) and adjusts the offset of the MAC header accordingly , adding <[ len ]>(IP: 1) bytes of space. It automatically extends and reallocates memory as required. This helper can be used on a layer 3 <[ skb ]>(IP: 0) to push a MAC header for redirection into a layer 2 device. All values for <[ flags ]>(IP: 2) are reserved for future usage , and must be left at zero. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_change_head",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 750,
  "endLine": 754,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_add_l2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_change_head"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_add_l2 (void *md, int delta)\n",
    "{\n",
    "    return bpf_skb_change_head (md, delta, 0);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_add_l2(void *md, int delta)
{
  return bpf_skb_change_head(md, delta, 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Grow or shrink the room for data in the packet associated to <[ skb ]>(IP: 0) by <[ len_diff ]>(IP: 1) , and according to the selected mode. There are two supported modes at this time: \u00b7 BPF_ADJ_ROOM_MAC: Adjust room at the mac layer (room space is added or removed below the layer 2 header). \u00b7 BPF_ADJ_ROOM_NET: Adjust room at the network layer (room space is added or removed below the layer 3 header). The following <[ flags ]>(IP: 3) are supported at this time: \u00b7 BPF_F_ADJ_ROOM_FIXED_GSO: Do not adjust gso_size. Adjusting mss in this way is not allowed for datagrams. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 , BPF_F_ADJ_ROOM_ENCAP_L3_IPV6: Any new space is reserved to hold a tunnel header. Configure <[ skb ]>(IP: 0) offsets and other fields accordingly. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L4_GRE , BPF_F_ADJ_ROOM_ENCAP_L4_UDP: Use with ENCAP_L3 <[ flags ]>(IP: 3) to further specify the tunnel type. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L2(len): Use with ENCAP_L3/L4 <[ flags ]>(IP: 3) to further specify the tunnel type; len is the length of the inner MAC header. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_adjust_room",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  s32 ,Var: len_diff}",
            "{Type:  u32 ,Var: mode}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 756,
  "endLine": 761,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_remove_l2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_adjust_room"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_remove_l2 (void *md, int delta)\n",
    "{\n",
    "    return bpf_skb_adjust_room (md, -delta, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_remove_l2(void *md, int delta)
{
  return bpf_skb_adjust_room(md, -delta, BPF_ADJ_ROOM_MAC, 
                        BPF_F_ADJ_ROOM_FIXED_GSO);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Grow or shrink the room for data in the packet associated to <[ skb ]>(IP: 0) by <[ len_diff ]>(IP: 1) , and according to the selected mode. There are two supported modes at this time: \u00b7 BPF_ADJ_ROOM_MAC: Adjust room at the mac layer (room space is added or removed below the layer 2 header). \u00b7 BPF_ADJ_ROOM_NET: Adjust room at the network layer (room space is added or removed below the layer 3 header). The following <[ flags ]>(IP: 3) are supported at this time: \u00b7 BPF_F_ADJ_ROOM_FIXED_GSO: Do not adjust gso_size. Adjusting mss in this way is not allowed for datagrams. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 , BPF_F_ADJ_ROOM_ENCAP_L3_IPV6: Any new space is reserved to hold a tunnel header. Configure <[ skb ]>(IP: 0) offsets and other fields accordingly. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L4_GRE , BPF_F_ADJ_ROOM_ENCAP_L4_UDP: Use with ENCAP_L3 <[ flags ]>(IP: 3) to further specify the tunnel type. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L2(len): Use with ENCAP_L3/L4 <[ flags ]>(IP: 3) to further specify the tunnel type; len is the length of the inner MAC header. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_adjust_room",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  s32 ,Var: len_diff}",
            "{Type:  u32 ,Var: mode}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 763,
  "endLine": 768,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_buf_add_room",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta",
    " __u64 flags"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_adjust_room"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_buf_add_room (void *md, int delta, __u64 flags)\n",
    "{\n",
    "    return bpf_skb_adjust_room (md, delta, BPF_ADJ_ROOM_MAC, flags);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_buf_add_room(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, delta, BPF_ADJ_ROOM_MAC,
                            flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Grow or shrink the room for data in the packet associated to <[ skb ]>(IP: 0) by <[ len_diff ]>(IP: 1) , and according to the selected mode. There are two supported modes at this time: \u00b7 BPF_ADJ_ROOM_MAC: Adjust room at the mac layer (room space is added or removed below the layer 2 header). \u00b7 BPF_ADJ_ROOM_NET: Adjust room at the network layer (room space is added or removed below the layer 3 header). The following <[ flags ]>(IP: 3) are supported at this time: \u00b7 BPF_F_ADJ_ROOM_FIXED_GSO: Do not adjust gso_size. Adjusting mss in this way is not allowed for datagrams. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 , BPF_F_ADJ_ROOM_ENCAP_L3_IPV6: Any new space is reserved to hold a tunnel header. Configure <[ skb ]>(IP: 0) offsets and other fields accordingly. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L4_GRE , BPF_F_ADJ_ROOM_ENCAP_L4_UDP: Use with ENCAP_L3 <[ flags ]>(IP: 3) to further specify the tunnel type. \u00b7 BPF_F_ADJ_ROOM_ENCAP_L2(len): Use with ENCAP_L3/L4 <[ flags ]>(IP: 3) to further specify the tunnel type; len is the length of the inner MAC header. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_adjust_room",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  s32 ,Var: len_diff}",
            "{Type:  u32 ,Var: mode}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 770,
  "endLine": 775,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_buf_delete_room",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta",
    " __u64 flags"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_adjust_room"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_buf_delete_room (void *md, int delta, __u64 flags)\n",
    "{\n",
    "    return bpf_skb_adjust_room (md, -delta, BPF_ADJ_ROOM_MAC, flags);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_buf_delete_room(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, -delta, BPF_ADJ_ROOM_MAC, 
                            flags);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\".",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
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
  "startLine": 777,
  "endLine": 789,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_redirect_port",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " tbl"
  ],
  "input": [
    "void *tbl",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "TC_ACT_SHOT",
    "redirect",
    "bpf_redirect",
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_redirect_port (void *tbl, struct xfi *xf)\n",
    "{\n",
    "    int *oif;\n",
    "    int key = xf->pm.oport;\n",
    "    oif = bpf_map_lookup_elem (tbl, & key);\n",
    "    if (!oif) {\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[REDR] port %d OIF %d\\n\", key, *oif);\n",
    "    return bpf_redirect (*oif, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "LL_DBG_PRINTK"
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
static int __always_inline
dp_redirect_port(void *tbl, struct xfi *xf)
{
  int *oif;
  int key = xf->pm.oport;

  oif = bpf_map_lookup_elem(tbl, &key);
  if (!oif) {
    return TC_ACT_SHOT;
  }
  LL_DBG_PRINTK("[REDR] port %d OIF %d\n", key, *oif);
  return bpf_redirect(*oif, 0);
}

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
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\".",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 791,
  "endLine": 802,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_rewire_port",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " tbl"
  ],
  "input": [
    "void *tbl",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_redirect",
    "TC_ACT_SHOT"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_rewire_port (void *tbl, struct xfi *xf)\n",
    "{\n",
    "    int *oif;\n",
    "    int key = xf->pm.oport;\n",
    "    oif = bpf_map_lookup_elem (tbl, & key);\n",
    "    if (!oif) {\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    return bpf_redirect (*oif, BPF_F_INGRESS);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_rewire_port(void *tbl, struct xfi *xf)
{
  int *oif;
  int key = xf->pm.oport;

  oif = bpf_map_lookup_elem(tbl, &key);
  if (!oif) {
    return TC_ACT_SHOT;
  }
  return bpf_redirect(*oif, BPF_F_INGRESS);
}

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
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "TC_ACT_SHOT",
          "Return": 2,
          "Description": "instructs the kernel to drop the packet, meaning, upper layers of the networking stack will never see the skb on ingress and similarly the packet will never be submitted for transmission on egress. TC_ACT_SHOT and TC_ACT_STOLEN are both similar in nature with few differences: TC_ACT_SHOT will indicate to the kernel that the skb was released through kfree_skb() and return NET_XMIT_DROP to the callers for immediate feedback, whereas TC_ACT_STOLEN will release the skb through consume_skb() and pretend to upper layers that the transmission was successful through NET_XMIT_SUCCESS. The perf\u2019s drop monitor which records traces of kfree_skb() will therefore also not see any drop indications from TC_ACT_STOLEN since its semantics are such that the skb has been \u201cconsumed\u201d or queued but certainly not \"dropped\".",
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 804,
  "endLine": 815,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_record_it",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  tx_intf_map"
  ],
  "input": [
    "void *skb",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "redirect",
    "bpf_clone_redirect",
    "TC_ACT_SHOT"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_record_it (void *skb, struct xfi *xf)\n",
    "{\n",
    "    int *oif;\n",
    "    int key = LLB_PORT_NO;\n",
    "    oif = bpf_map_lookup_elem (& tx_intf_map, & key);\n",
    "    if (!oif) {\n",
    "        return TC_ACT_SHOT;\n",
    "    }\n",
    "    return bpf_clone_redirect (skb, *oif, 0);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_record_it(void *skb, struct xfi *xf)
{
  int *oif;
  int key = LLB_PORT_NO;

  oif = bpf_map_lookup_elem(&tx_intf_map, &key);
  if (!oif) {
    return TC_ACT_SHOT;
  }
  return bpf_clone_redirect(skb, *oif, 0); 
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Pop a VLAN header from the packet associated to skb. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_vlan_pop",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 817,
  "endLine": 833,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_remove_vlan_tag",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_vlan_pop"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_remove_vlan_tag (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct ethhdr *eth;\n",
    "    bpf_skb_vlan_pop (ctx);\n",
    "    eth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (eth + 1 > dend) {\n",
    "        return -1;\n",
    "    }\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 6);\n",
    "    memcpy (eth->h_source, xf->l2m.dl_src, 6);\n",
    "    eth->h_proto = xf->l2m.dl_type;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "dp_remove_l2",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_remove_vlan_tag(void *ctx, struct xfi *xf)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;

  bpf_skb_vlan_pop(ctx);
  eth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));
  if (eth + 1 > dend) {
    return -1;
  }
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);
  eth->h_proto = xf->l2m.dl_type;
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Push a <[ vlan_tci ]>(IP: 2) (VLAN tag control information) of protocol <[ vlan_proto ]>(IP: 1) to the packet associated to <[ skb ]>(IP: 0) , then update the checksum. Note that if <[ vlan_proto ]>(IP: 1) is different from ETH_P_8021Q and ETH_P_8021AD , it is considered to be ETH_P_8021Q. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_vlan_push",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  __be16 ,Var: vlan_proto}",
            "{Type:  u16 ,Var: vlan_tci}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 835,
  "endLine": 850,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_insert_vlan_tag",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be16 vlan"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_vlan_push"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_insert_vlan_tag (void *ctx, struct xfi *xf, __be16 vlan)\n",
    "{\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct ethhdr *eth;\n",
    "    bpf_skb_vlan_push (ctx, bpf_ntohs (xf->l2m.dl_type), bpf_ntohs (vlan));\n",
    "    eth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (eth + 1 > dend) {\n",
    "        return -1;\n",
    "    }\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 6);\n",
    "    memcpy (eth->h_source, xf->l2m.dl_src, 6);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_add_l2",
    "DP_PDATA",
    "bpf_htons",
    "DP_ADD_PTR",
    "bpf_ntohs",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_insert_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;

  bpf_skb_vlan_push(ctx, bpf_ntohs(xf->l2m.dl_type), bpf_ntohs(vlan));
  eth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));
  if (eth + 1 > dend) {
    return -1;
  }
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Pop a VLAN header from the packet associated to skb. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_vlan_pop",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 852,
  "endLine": 857,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_swap_vlan_tag",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be16 vlan"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_vlan_pop"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_swap_vlan_tag (void *ctx, struct xfi *xf, __be16 vlan)\n",
    "{\n",
    "    bpf_skb_vlan_pop (ctx);\n",
    "    return dp_insert_vlan_tag (ctx, xf, vlan);\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "dp_insert_vlan_tag",
    "memcpy"
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
static int __always_inline
dp_swap_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  bpf_skb_vlan_pop(ctx);
  return dp_insert_vlan_tag(ctx, xf, vlan);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 859,
  "endLine": 875,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_tcp_src_ip6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l4_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_tcp_src_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int tcp_csum_off = xf->pm.l4_off + offsetof (struct tcphdr, check);\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct ipv6hdr, saddr);\n",
    "    __be32 *old_sip = xf->l34m.saddr;\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_sip[0], xip[0], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_sip[1], xip[1], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_sip[2], xip[2], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_sip[3], xip[3], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_skb_store_bytes (md, ip_src_off, xip, sizeof (xf->l34m.saddr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.saddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_tcp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);
  __be32 *old_sip = xf->l34m.saddr;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[0], xip[0], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[1], xip[1], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[2], xip[2], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_sip[3], xip[3], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(xf->l34m.saddr), 0);

  DP_XADDR_CP(xf->l34m.saddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 877,
  "endLine": 892,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_tcp_src_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l4_csum_replace",
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_tcp_src_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int tcp_csum_off = xf->pm.l4_off + offsetof (struct tcphdr, check);\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct iphdr, saddr);\n",
    "    __be32 old_sip = xf->l34m.saddr4;\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_sip, xip, BPF_F_PSEUDO_HDR | sizeof (xip));\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_sip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_src_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.saddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_tcp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sip, xip, BPF_F_PSEUDO_HDR |sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);

  xf->l34m.saddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 894,
  "endLine": 910,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_tcp_dst_ip6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l4_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_tcp_dst_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int tcp_csum_off = xf->pm.l4_off + offsetof (struct tcphdr, check);\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct ipv6hdr, daddr);\n",
    "    __be32 *old_dip = xf->l34m.daddr;\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_dip[0], xip[0], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_dip[1], xip[1], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_dip[2], xip[2], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_dip[3], xip[3], BPF_F_PSEUDO_HDR | sizeof (*xip));\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, xip, sizeof (xf->l34m.saddr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.daddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_tcp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);
  __be32 *old_dip = xf->l34m.daddr;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[0], xip[0], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[1], xip[1], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[2], xip[2], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_l4_csum_replace(md, tcp_csum_off, old_dip[3], xip[3], BPF_F_PSEUDO_HDR |sizeof(*xip));
  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(xf->l34m.saddr), 0);

  DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 912,
  "endLine": 926,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_tcp_dst_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l4_csum_replace",
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_tcp_dst_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int tcp_csum_off = xf->pm.l4_off + offsetof (struct tcphdr, check);\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct iphdr, daddr);\n",
    "    __be32 old_dip = xf->l34m.daddr4;\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_dip, xip, BPF_F_PSEUDO_HDR | sizeof (xip));\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_dip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.daddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_tcp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dip, xip, BPF_F_PSEUDO_HDR | sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  xf->l34m.daddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 928,
  "endLine": 940,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_tcp_sport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l4_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_tcp_sport (void *md, struct xfi *xf, __be16 xport)\n",
    "{\n",
    "    int tcp_csum_off = xf->pm.l4_off + offsetof (struct tcphdr, check);\n",
    "    int tcp_sport_off = xf->pm.l4_off + offsetof (struct tcphdr, source);\n",
    "    __be32 old_sport = xf->l34m.source;\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_sport, xport, sizeof (xport));\n",
    "    bpf_skb_store_bytes (md, tcp_sport_off, &xport, sizeof (xport), 0);\n",
    "    xf->l34m.source = xport;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_tcp_sport(void *md, struct xfi *xf, __be16 xport)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int tcp_sport_off = xf->pm.l4_off + offsetof(struct tcphdr, source);
  __be32 old_sport = xf->l34m.source;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, tcp_sport_off, &xport, sizeof(xport), 0);
  xf->l34m.source = xport;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 942,
  "endLine": 954,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_tcp_dport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l4_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_tcp_dport (void *md, struct xfi *xf, __be16 xport)\n",
    "{\n",
    "    int tcp_csum_off = xf->pm.l4_off + offsetof (struct tcphdr, check);\n",
    "    int tcp_dport_off = xf->pm.l4_off + offsetof (struct tcphdr, dest);\n",
    "    __be32 old_dport = xf->l34m.dest;\n",
    "    bpf_l4_csum_replace (md, tcp_csum_off, old_dport, xport, sizeof (xport));\n",
    "    bpf_skb_store_bytes (md, tcp_dport_off, &xport, sizeof (xport), 0);\n",
    "    xf->l34m.dest = xport;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_tcp_dport(void *md, struct xfi *xf, __be16 xport)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int tcp_dport_off = xf->pm.l4_off + offsetof(struct tcphdr, dest);
  __be32 old_dport = xf->l34m.dest;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, tcp_dport_off, &xport, sizeof(xport), 0);
  xf->l34m.dest = xport;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 956,
  "endLine": 969,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_udp_src_ip6",
  "developer_inline_comments": [
    {
      "start_line": 963,
      "end_line": 963,
      "text": " UDP checksum = 0 is valid "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_udp_src_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int udp_csum_off = xf->pm.l4_off + offsetof (struct udphdr, check);\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct ipv6hdr, saddr);\n",
    "    __be16 csum = 0;\n",
    "    bpf_skb_store_bytes (md, udp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_skb_store_bytes (md, ip_src_off, xip, sizeof (xf->l34m.saddr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.saddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_udp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);
  __be16 csum = 0;

  /* UDP checksum = 0 is valid */
  bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(xf->l34m.saddr), 0);
  DP_XADDR_CP(xf->l34m.saddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 971,
  "endLine": 987,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_udp_src_ip",
  "developer_inline_comments": [
    {
      "start_line": 980,
      "end_line": 980,
      "text": " UDP checksum = 0 is valid "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_udp_src_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int udp_csum_off = xf->pm.l4_off + offsetof (struct udphdr, check);\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct iphdr, saddr);\n",
    "    __be16 csum = 0;\n",
    "    __be32 old_sip = xf->l34m.saddr4;\n",
    "    bpf_skb_store_bytes (md, udp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_sip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_src_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.saddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_udp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be16 csum = 0;
  __be32 old_sip = xf->l34m.saddr4;
  
  /* UDP checksum = 0 is valid */
  bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  xf->l34m.saddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 989,
  "endLine": 1002,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_udp_dst_ip6",
  "developer_inline_comments": [
    {
      "start_line": 996,
      "end_line": 996,
      "text": " UDP checksum = 0 is valid "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_udp_dst_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int udp_csum_off = xf->pm.l4_off + offsetof (struct udphdr, check);\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct ipv6hdr, daddr);\n",
    "    __be16 csum = 0;\n",
    "    bpf_skb_store_bytes (md, udp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, xip, sizeof (xf->l34m.daddr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.daddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_udp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);
  __be16 csum = 0;

  /* UDP checksum = 0 is valid */
  bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(xf->l34m.daddr), 0);
  DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1004,
  "endLine": 1020,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_udp_dst_ip",
  "developer_inline_comments": [
    {
      "start_line": 1013,
      "end_line": 1013,
      "text": " UDP checksum = 0 is valid "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_udp_dst_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int udp_csum_off = xf->pm.l4_off + offsetof (struct udphdr, check);\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct iphdr, daddr);\n",
    "    __be16 csum = 0;\n",
    "    __be32 old_dip = xf->l34m.daddr4;\n",
    "    bpf_skb_store_bytes (md, udp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_dip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.daddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_udp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be16 csum = 0;
  __be32 old_dip = xf->l34m.daddr4;
  
  /* UDP checksum = 0 is valid */
  bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
    bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  xf->l34m.daddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1022,
  "endLine": 1035,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_udp_sport",
  "developer_inline_comments": [
    {
      "start_line": 1029,
      "end_line": 1029,
      "text": " UDP checksum = 0 is valid "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_udp_sport (void *md, struct xfi *xf, __be16 xport)\n",
    "{\n",
    "    int udp_csum_off = xf->pm.l4_off + offsetof (struct udphdr, check);\n",
    "    int udp_sport_off = xf->pm.l4_off + offsetof (struct udphdr, source);\n",
    "    __be16 csum = 0;\n",
    "    bpf_skb_store_bytes (md, udp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_skb_store_bytes (md, udp_sport_off, &xport, sizeof (xport), 0);\n",
    "    xf->l34m.source = xport;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_udp_sport(void *md, struct xfi *xf, __be16 xport)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int udp_sport_off = xf->pm.l4_off + offsetof(struct udphdr, source);
  __be16 csum = 0;

  /* UDP checksum = 0 is valid */
  bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_skb_store_bytes(md, udp_sport_off, &xport, sizeof(xport), 0);
  xf->l34m.source = xport;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1037,
  "endLine": 1050,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_udp_dport",
  "developer_inline_comments": [
    {
      "start_line": 1044,
      "end_line": 1044,
      "text": " UDP checksum = 0 is valid "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_udp_dport (void *md, struct xfi *xf, __be16 xport)\n",
    "{\n",
    "    int udp_csum_off = xf->pm.l4_off + offsetof (struct udphdr, check);\n",
    "    int udp_dport_off = xf->pm.l4_off + offsetof (struct udphdr, dest);\n",
    "    __be16 csum = 0;\n",
    "    bpf_skb_store_bytes (md, udp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_skb_store_bytes (md, udp_dport_off, &xport, sizeof (xport), 0);\n",
    "    xf->l34m.dest = xport;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_udp_dport(void *md, struct xfi *xf, __be16 xport)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int udp_dport_off = xf->pm.l4_off + offsetof(struct udphdr, dest);
  __be16 csum = 0;

  /* UDP checksum = 0 is valid */
  bpf_skb_store_bytes(md, udp_csum_off, &csum, sizeof(csum), 0);
  bpf_skb_store_bytes(md, udp_dport_off, &xport, sizeof(xport), 0);
  xf->l34m.dest = xport;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1052,
  "endLine": 1061,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_icmp_src_ip6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_icmp_src_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct ipv6hdr, saddr);\n",
    "    bpf_skb_store_bytes (md, ip_src_off, xip, sizeof (struct in6_addr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.saddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_icmp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);
 
  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(struct in6_addr), 0);
  DP_XADDR_CP(xf->l34m.saddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1063,
  "endLine": 1075,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_icmp_src_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_icmp_src_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct iphdr, saddr);\n",
    "    __be32 old_sip = xf->l34m.saddr4;\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_sip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_src_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.saddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_icmp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;
 
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  xf->l34m.saddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1077,
  "endLine": 1086,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_icmp_dst_ip6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_icmp_dst_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct ipv6hdr, daddr);\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, xip, sizeof (struct in6_addr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.daddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_icmp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);

  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(struct in6_addr), 0);
  DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1088,
  "endLine": 1100,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_icmp_dst_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_icmp_dst_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct iphdr, daddr);\n",
    "    __be32 old_dip = xf->l34m.daddr4;\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_dip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.daddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_icmp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;
  
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  xf->l34m.daddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1102,
  "endLine": 1111,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_sctp_src_ip6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_sctp_src_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct ipv6hdr, saddr);\n",
    "    bpf_skb_store_bytes (md, ip_src_off, xip, sizeof (struct in6_addr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.saddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_sctp_src_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int ip_src_off = xf->pm.l3_off + offsetof(struct ipv6hdr, saddr);

  bpf_skb_store_bytes(md, ip_src_off, xip, sizeof(struct in6_addr), 0);
  DP_XADDR_CP(xf->l34m.saddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1113,
  "endLine": 1125,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_sctp_src_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_sctp_src_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int ip_src_off = xf->pm.l3_off + offsetof (struct iphdr, saddr);\n",
    "    __be32 old_sip = xf->l34m.saddr4;\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_sip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_src_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.saddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_sctp_src_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;
  
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  xf->l34m.saddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1127,
  "endLine": 1136,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_sctp_dst_ip6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 *xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_sctp_dst_ip6 (void *md, struct xfi *xf, __be32 *xip)\n",
    "{\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct ipv6hdr, daddr);\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, xip, sizeof (struct in6_addr), 0);\n",
    "    DP_XADDR_CP (xf->l34m.daddr, xip);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "offsetof"
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
static int __always_inline
dp_set_sctp_dst_ip6(void *md, struct xfi *xf, __be32 *xip)
{
  int ip_dst_off = xf->pm.l3_off + offsetof(struct ipv6hdr, daddr);
 
  bpf_skb_store_bytes(md, ip_dst_off, xip, sizeof(struct in6_addr), 0);
  DP_XADDR_CP(xf->l34m.daddr, xip);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 3 (e. g. IP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored in size. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and <[ size ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l3_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: size}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1138,
  "endLine": 1150,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_sctp_dst_ip",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 xip"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_l3_csum_replace",
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_sctp_dst_ip (void *md, struct xfi *xf, __be32 xip)\n",
    "{\n",
    "    int ip_csum_off = xf->pm.l3_off + offsetof (struct iphdr, check);\n",
    "    int ip_dst_off = xf->pm.l3_off + offsetof (struct iphdr, daddr);\n",
    "    __be32 old_dip = xf->l34m.daddr4;\n",
    "    bpf_l3_csum_replace (md, ip_csum_off, old_dip, xip, sizeof (xip));\n",
    "    bpf_skb_store_bytes (md, ip_dst_off, &xip, sizeof (xip), 0);\n",
    "    xf->l34m.daddr4 = xip;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_sctp_dst_ip(void *md, struct xfi *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;
  
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  xf->l34m.daddr4 = xip;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1152,
  "endLine": 1164,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_sctp_sport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_sctp_sport (void *md, struct xfi *xf, __be16 xport)\n",
    "{\n",
    "    uint32_t csum = 0;\n",
    "    int sctp_csum_off = xf->pm.l4_off + offsetof (struct sctphdr, checksum);\n",
    "    int sctp_sport_off = xf->pm.l4_off + offsetof (struct sctphdr, source);\n",
    "    bpf_skb_store_bytes (md, sctp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_skb_store_bytes (md, sctp_sport_off, &xport, sizeof (xport), 0);\n",
    "    xf->l34m.source = xport;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_sctp_sport(void *md, struct xfi *xf, __be16 xport)
{
  uint32_t csum = 0;
  int sctp_csum_off = xf->pm.l4_off + offsetof(struct sctphdr, checksum);
  int sctp_sport_off = xf->pm.l4_off + offsetof(struct sctphdr, source);

  bpf_skb_store_bytes(md, sctp_csum_off, &csum , sizeof(csum), 0);
  bpf_skb_store_bytes(md, sctp_sport_off, &xport, sizeof(xport), 0);
  xf->l34m.source = xport;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1166,
  "endLine": 1178,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_set_sctp_dport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_set_sctp_dport (void *md, struct xfi *xf, __be16 xport)\n",
    "{\n",
    "    uint32_t csum = 0;\n",
    "    int sctp_csum_off = xf->pm.l4_off + offsetof (struct sctphdr, checksum);\n",
    "    int sctp_dport_off = xf->pm.l4_off + offsetof (struct sctphdr, dest);\n",
    "    bpf_skb_store_bytes (md, sctp_csum_off, &csum, sizeof (csum), 0);\n",
    "    bpf_skb_store_bytes (md, sctp_dport_off, &xport, sizeof (xport), 0);\n",
    "    xf->l34m.dest = xport;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof"
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
static int __always_inline
dp_set_sctp_dport(void *md, struct xfi *xf, __be16 xport)
{
  uint32_t csum = 0;
  int sctp_csum_off = xf->pm.l4_off + offsetof(struct sctphdr, checksum); 
  int sctp_dport_off = xf->pm.l4_off + offsetof(struct sctphdr, dest);

  bpf_skb_store_bytes(md, sctp_csum_off, &csum , sizeof(csum), 0);
  bpf_skb_store_bytes(md, sctp_dport_off, &xport, sizeof(xport), 0);
  xf->l34m.dest = xport;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1180,
  "endLine": 1255,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_dnat",
  "developer_inline_comments": [
    {
      "start_line": 1193,
      "end_line": 1193,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1213,
      "end_line": 1213,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1233,
      "end_line": 1233,
      "text": " Hairpin nat to host "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_dnat (void *ctx, struct xfi *xf, __be32 xip, __be16 xport)\n",
    "{\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        struct tcphdr *tcp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (tcp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (xip == 0) {\n",
    "            xip = xf->l34m.saddr4;\n",
    "            dp_set_tcp_src_ip (ctx, xf, xf->l34m.daddr4);\n",
    "            dp_set_tcp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            if (xf->nm.nrip4) {\n",
    "                dp_set_tcp_src_ip (ctx, xf, xf->nm.nrip4);\n",
    "            }\n",
    "            dp_set_tcp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        dp_set_tcp_dport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_UDP) {\n",
    "        struct udphdr *udp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (udp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (xip == 0) {\n",
    "            xip = xf->l34m.saddr4;\n",
    "            dp_set_udp_src_ip (ctx, xf, xf->l34m.daddr4);\n",
    "            dp_set_udp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            if (xf->nm.nrip4) {\n",
    "                dp_set_udp_src_ip (ctx, xf, xf->nm.nrip4);\n",
    "            }\n",
    "            dp_set_udp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        dp_set_udp_dport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_SCTP) {\n",
    "        struct sctphdr *sctp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (sctp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (xip == 0) {\n",
    "            xip = xf->l34m.saddr4;\n",
    "            dp_set_sctp_src_ip (ctx, xf, xf->l34m.daddr4);\n",
    "            dp_set_sctp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            if (xf->nm.nrip4) {\n",
    "                dp_set_sctp_src_ip (ctx, xf, xf->nm.nrip4);\n",
    "            }\n",
    "            dp_set_sctp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        dp_set_sctp_dport (ctx, xf, xport);\n",
    "\n",
    "#ifdef HAVE_DP_SCTP_SUM\n",
    "        dp_csum_tcall (ctx, xf);\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ICMP) {\n",
    "        if (xf->nm.nrip4) {\n",
    "            dp_set_icmp_src_ip (ctx, xf, xf->nm.nrip4);\n",
    "        }\n",
    "        dp_set_icmp_dst_ip (ctx, xf, xip);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_sctp_dst_ip",
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_set_udp_src_ip",
    "DP_ADD_PTR",
    "dp_set_icmp_dst_ip",
    "dp_set_tcp_dport",
    "dp_set_sctp_src_ip",
    "dp_set_icmp_src_ip",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "dp_set_tcp_src_ip",
    "dp_csum_tcall",
    "dp_set_udp_dst_ip",
    "dp_set_sctp_dport",
    "dp_set_tcp_dst_ip",
    "dp_set_udp_dport"
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
static int __always_inline
dp_do_dnat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_tcp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_tcp_dst_ip(ctx, xf, xip);
    } else {
      if (xf->nm.nrip4) {
        dp_set_tcp_src_ip(ctx, xf, xf->nm.nrip4);
      }
      dp_set_tcp_dst_ip(ctx, xf, xip);
    }
    dp_set_tcp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_udp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_udp_dst_ip(ctx, xf, xip);
    } else {
      if (xf->nm.nrip4) {
        dp_set_udp_src_ip(ctx, xf, xf->nm.nrip4);
      }
      dp_set_udp_dst_ip(ctx, xf, xip);
    }
    dp_set_udp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_sctp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_sctp_dst_ip(ctx, xf, xip);
    } else {
      if (xf->nm.nrip4) {
        dp_set_sctp_src_ip(ctx, xf, xf->nm.nrip4);
      }
      dp_set_sctp_dst_ip(ctx, xf, xip);
    }
    dp_set_sctp_dport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    dp_csum_tcall(ctx, xf);
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    if (xf->nm.nrip4) {
      dp_set_icmp_src_ip(ctx, xf, xf->nm.nrip4);
    }
    dp_set_icmp_dst_ip(ctx, xf, xip);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1257,
  "endLine": 1332,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_dnat6",
  "developer_inline_comments": [
    {
      "start_line": 1270,
      "end_line": 1270,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1290,
      "end_line": 1290,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1310,
      "end_line": 1310,
      "text": " Hairpin nat to host "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 *xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_dnat6 (void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)\n",
    "{\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        struct tcphdr *tcp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (tcp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (DP_XADDR_ISZR (xip)) {\n",
    "            DP_XADDR_CP (xip, xf->l34m.saddr);\n",
    "            dp_set_tcp_src_ip6 (ctx, xf, xf->l34m.daddr);\n",
    "            dp_set_tcp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "                dp_set_tcp_src_ip6 (ctx, xf, xf->nm.nrip);\n",
    "            }\n",
    "            dp_set_tcp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        dp_set_tcp_dport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_UDP) {\n",
    "        struct udphdr *udp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (udp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (DP_XADDR_ISZR (xip)) {\n",
    "            DP_XADDR_CP (xip, xf->l34m.saddr);\n",
    "            dp_set_udp_src_ip6 (ctx, xf, xf->l34m.daddr);\n",
    "            dp_set_udp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "                dp_set_udp_src_ip6 (ctx, xf, xf->nm.nrip);\n",
    "            }\n",
    "            dp_set_udp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        dp_set_udp_dport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_SCTP) {\n",
    "        struct sctphdr *sctp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (sctp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (DP_XADDR_ISZR (xip)) {\n",
    "            DP_XADDR_CP (xip, xf->l34m.saddr);\n",
    "            dp_set_sctp_src_ip6 (ctx, xf, xf->l34m.daddr);\n",
    "            dp_set_sctp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "                dp_set_sctp_src_ip6 (ctx, xf, xf->nm.nrip);\n",
    "            }\n",
    "            dp_set_sctp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        dp_set_sctp_dport (ctx, xf, xport);\n",
    "\n",
    "#ifdef HAVE_DP_SCTP_SUM\n",
    "        dp_csum_tcall (ctx, xf);\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ICMP) {\n",
    "        if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "            dp_set_icmp_src_ip6 (ctx, xf, xf->nm.nrip);\n",
    "        }\n",
    "        dp_set_icmp_dst_ip6 (ctx, xf, xip);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_icmp_src_ip6",
    "DP_ADD_PTR",
    "dp_csum_tcall",
    "DP_XADDR_CP",
    "dp_set_udp_src_ip6",
    "DP_PDATA",
    "dp_set_tcp_dport",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "DP_XADDR_ISZR",
    "dp_set_udp_dport",
    "LLBS_PPLN_DROP",
    "dp_set_sctp_dst_ip6",
    "dp_set_sctp_src_ip6",
    "dp_set_icmp_dst_ip6",
    "dp_set_sctp_dport",
    "dp_set_tcp_src_ip6",
    "dp_set_udp_dst_ip6",
    "dp_set_tcp_dst_ip6"
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
static int __always_inline
dp_do_dnat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_tcp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_tcp_dst_ip6(ctx, xf, xip);
    } else {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_tcp_src_ip6(ctx, xf, xf->nm.nrip);
      }
      dp_set_tcp_dst_ip6(ctx, xf, xip);
    }
    dp_set_tcp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_udp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_udp_dst_ip6(ctx, xf, xip);
    } else {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_udp_src_ip6(ctx, xf, xf->nm.nrip);
      }
      dp_set_udp_dst_ip6(ctx, xf, xip);
    }
    dp_set_udp_dport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_sctp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_sctp_dst_ip6(ctx, xf, xip);
    } else {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_sctp_src_ip6(ctx, xf, xf->nm.nrip);
      }
      dp_set_sctp_dst_ip6(ctx, xf, xip);
    }
    dp_set_sctp_dport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    dp_csum_tcall(ctx, xf);
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    if (!DP_XADDR_ISZR(xf->nm.nrip)) {
      dp_set_icmp_src_ip6(ctx, xf, xf->nm.nrip);
    }
    dp_set_icmp_dst_ip6(ctx, xf, xip);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1334,
  "endLine": 1409,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_snat",
  "developer_inline_comments": [
    {
      "start_line": 1347,
      "end_line": 1347,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1367,
      "end_line": 1367,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1387,
      "end_line": 1387,
      "text": " Hairpin nat to host "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_snat (void *ctx, struct xfi *xf, __be32 xip, __be16 xport)\n",
    "{\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        struct tcphdr *tcp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (tcp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (xip == 0) {\n",
    "            xip = xf->l34m.saddr4;\n",
    "            dp_set_tcp_src_ip (ctx, xf, xf->l34m.daddr4);\n",
    "            dp_set_tcp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            dp_set_tcp_src_ip (ctx, xf, xip);\n",
    "            if (xf->nm.nrip4) {\n",
    "                dp_set_tcp_dst_ip (ctx, xf, xf->nm.nrip4);\n",
    "            }\n",
    "        }\n",
    "        dp_set_tcp_sport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_UDP) {\n",
    "        struct udphdr *udp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (udp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (xip == 0) {\n",
    "            xip = xf->l34m.saddr4;\n",
    "            dp_set_udp_src_ip (ctx, xf, xf->l34m.daddr4);\n",
    "            dp_set_udp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            dp_set_udp_src_ip (ctx, xf, xip);\n",
    "            if (xf->nm.nrip4) {\n",
    "                dp_set_udp_dst_ip (ctx, xf, xf->nm.nrip4);\n",
    "            }\n",
    "        }\n",
    "        dp_set_udp_sport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_SCTP) {\n",
    "        struct sctphdr *sctp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (sctp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (xip == 0) {\n",
    "            xip = xf->l34m.saddr4;\n",
    "            dp_set_sctp_src_ip (ctx, xf, xf->l34m.daddr4);\n",
    "            dp_set_sctp_dst_ip (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            dp_set_sctp_src_ip (ctx, xf, xip);\n",
    "            if (xf->nm.nrip4) {\n",
    "                dp_set_sctp_dst_ip (ctx, xf, xf->nm.nrip4);\n",
    "            }\n",
    "        }\n",
    "        dp_set_sctp_sport (ctx, xf, xport);\n",
    "\n",
    "#ifdef HAVE_DP_SCTP_SUM\n",
    "        dp_csum_tcall (ctx, xf);\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ICMP) {\n",
    "        dp_set_icmp_src_ip (ctx, xf, xip);\n",
    "        if (xf->nm.nrip4) {\n",
    "            dp_set_icmp_dst_ip (ctx, xf, xf->nm.nrip4);\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_sctp_dst_ip",
    "dp_set_udp_sport",
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_set_udp_src_ip",
    "DP_ADD_PTR",
    "dp_set_icmp_dst_ip",
    "dp_set_sctp_src_ip",
    "dp_set_sctp_sport",
    "DP_TC_PTR",
    "dp_set_icmp_src_ip",
    "DP_PDATA_END",
    "dp_set_tcp_src_ip",
    "dp_csum_tcall",
    "dp_set_tcp_sport",
    "dp_set_tcp_dst_ip",
    "dp_set_udp_dst_ip"
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
static int __always_inline
dp_do_snat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_tcp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_tcp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_tcp_src_ip(ctx, xf, xip);
      if (xf->nm.nrip4) {
        dp_set_tcp_dst_ip(ctx, xf, xf->nm.nrip4);
      }
    }
    dp_set_tcp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_udp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_udp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_udp_src_ip(ctx, xf, xip);
      if (xf->nm.nrip4) {
        dp_set_udp_dst_ip(ctx, xf, xf->nm.nrip4);
      }
    }
    dp_set_udp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (xip == 0) {
      /* Hairpin nat to host */
      xip = xf->l34m.saddr4;
      dp_set_sctp_src_ip(ctx, xf, xf->l34m.daddr4);
      dp_set_sctp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_sctp_src_ip(ctx, xf, xip);
      if (xf->nm.nrip4) {
        dp_set_sctp_dst_ip(ctx, xf, xf->nm.nrip4);
      }
    }
    dp_set_sctp_sport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    dp_csum_tcall(ctx, xf);
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    dp_set_icmp_src_ip(ctx, xf, xip);
    if (xf->nm.nrip4) {
      dp_set_icmp_dst_ip(ctx, xf, xf->nm.nrip4);
    }
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1411,
  "endLine": 1486,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_snat6",
  "developer_inline_comments": [
    {
      "start_line": 1424,
      "end_line": 1424,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1444,
      "end_line": 1444,
      "text": " Hairpin nat to host "
    },
    {
      "start_line": 1464,
      "end_line": 1464,
      "text": " Hairpin nat to host "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 *xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_snat6 (void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)\n",
    "{\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        struct tcphdr *tcp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (tcp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (DP_XADDR_ISZR (xip)) {\n",
    "            DP_XADDR_CP (xip, xf->l34m.saddr);\n",
    "            dp_set_tcp_src_ip6 (ctx, xf, xf->l34m.daddr);\n",
    "            dp_set_tcp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            dp_set_tcp_src_ip6 (ctx, xf, xip);\n",
    "            if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "                dp_set_tcp_dst_ip6 (ctx, xf, xf->nm.nrip);\n",
    "            }\n",
    "        }\n",
    "        dp_set_tcp_sport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_UDP) {\n",
    "        struct udphdr *udp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (udp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (DP_XADDR_ISZR (xip)) {\n",
    "            DP_XADDR_CP (xip, xf->l34m.saddr);\n",
    "            dp_set_udp_src_ip6 (ctx, xf, xf->l34m.daddr);\n",
    "            dp_set_udp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            dp_set_udp_src_ip6 (ctx, xf, xip);\n",
    "            if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "                dp_set_udp_dst_ip6 (ctx, xf, xf->nm.nrip);\n",
    "            }\n",
    "        }\n",
    "        dp_set_udp_sport (ctx, xf, xport);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_SCTP) {\n",
    "        struct sctphdr *sctp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "        if (sctp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        if (DP_XADDR_ISZR (xip)) {\n",
    "            DP_XADDR_CP (xip, xf->l34m.saddr);\n",
    "            dp_set_sctp_src_ip6 (ctx, xf, xf->l34m.daddr);\n",
    "            dp_set_sctp_dst_ip6 (ctx, xf, xip);\n",
    "        }\n",
    "        else {\n",
    "            dp_set_sctp_src_ip6 (ctx, xf, xip);\n",
    "            if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "                dp_set_sctp_dst_ip6 (ctx, xf, xf->nm.nrip);\n",
    "            }\n",
    "        }\n",
    "        dp_set_sctp_sport (ctx, xf, xport);\n",
    "\n",
    "#ifdef HAVE_DP_SCTP_SUM\n",
    "        dp_csum_tcall (ctx, xf);\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ICMP) {\n",
    "        dp_set_icmp_src_ip6 (ctx, xf, xip);\n",
    "        if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "            dp_set_icmp_dst_ip6 (ctx, xf, xf->nm.nrip);\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_icmp_src_ip6",
    "DP_ADD_PTR",
    "dp_set_sctp_sport",
    "dp_csum_tcall",
    "dp_set_tcp_sport",
    "dp_set_udp_src_ip6",
    "DP_XADDR_CP",
    "DP_PDATA",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "DP_XADDR_ISZR",
    "dp_set_udp_sport",
    "LLBS_PPLN_DROP",
    "dp_set_sctp_dst_ip6",
    "dp_set_sctp_src_ip6",
    "dp_set_icmp_dst_ip6",
    "dp_set_tcp_src_ip6",
    "dp_set_udp_dst_ip6",
    "dp_set_tcp_dst_ip6"
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
static int __always_inline
dp_do_snat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_tcp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_tcp_dst_ip6(ctx, xf, xip);
    } else {
      dp_set_tcp_src_ip6(ctx, xf, xip);
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_tcp_dst_ip6(ctx, xf, xf->nm.nrip);
      }
    }
    dp_set_tcp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_udp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_udp_dst_ip6(ctx, xf, xip);
    } else {
      dp_set_udp_src_ip6(ctx, xf, xip);
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_udp_dst_ip6(ctx, xf, xf->nm.nrip);
      }
    }
    dp_set_udp_sport(ctx, xf, xport);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
    struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);

    if (sctp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    if (DP_XADDR_ISZR(xip)) {
      /* Hairpin nat to host */
      DP_XADDR_CP(xip, xf->l34m.saddr);
      dp_set_sctp_src_ip6(ctx, xf, xf->l34m.daddr);
      dp_set_sctp_dst_ip6(ctx, xf, xip);
    } else {
      dp_set_sctp_src_ip6(ctx, xf, xip);
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        dp_set_sctp_dst_ip6(ctx, xf, xf->nm.nrip);
      }
    }
    dp_set_sctp_sport(ctx, xf, xport);
#ifdef HAVE_DP_SCTP_SUM
    dp_csum_tcall(ctx, xf);
#endif
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    dp_set_icmp_src_ip6(ctx, xf, xip);
    if (!DP_XADDR_ISZR(xf->nm.nrip)) {
      dp_set_icmp_dst_ip6(ctx, xf, xf->nm.nrip);
    }
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Change the protocol of the <[ skb ]>(IP: 0) to proto. Currently supported are transition from IPv4 to IPv6 , and from IPv6 to IPv4. The helper takes care of the groundwork for the transition , including resizing the socket buffer. The eBPF program is expected to fill the new headers , if any , via skb_store_bytes() and to recompute the checksums with bpf_l3_csum_replace() and bpf_l4_csum_replace(). The main case for this helper is to perform NAT64 operations out of an eBPF program. Internally , the GSO type is marked as dodgy so that headers are checked and segments are recalculated by the GSO/GRO engine. The size for GSO target is adapted as well. All values for <[ flags ]>(IP: 2) are reserved for future usage , and must be left at zero. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_change_proto",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  __be16 ,Var: proto}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    },
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "libbpf",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with bpf_l3_csum_replace() and bpf_l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with bpf_csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "bpf_csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1488,
  "endLine": 1582,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_dnat64",
  "developer_inline_comments": [
    {
      "start_line": 1542,
      "end_line": 1542,
      "text": " Outer IP header "
    },
    {
      "start_line": 1546,
      "end_line": 1546,
      "text": " FIXME - Copy inner"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_change_proto",
    "bpf_l4_csum_replace",
    "bpf_csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_do_dnat64 (void *md, struct xfi *xf)\n",
    "{\n",
    "    struct iphdr *iph;\n",
    "    struct ethhdr *eth;\n",
    "    struct tcphdr *tcp;\n",
    "    struct udphdr *udp;\n",
    "    struct vlanhdr *vlh;\n",
    "    __be32 sum;\n",
    "    void *dend;\n",
    "    if (xf->l34m.nw_proto != IPPROTO_TCP && xf->l34m.nw_proto != IPPROTO_UDP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    if (bpf_skb_change_proto (md, bpf_htons (ETH_P_IP), 0) < 0) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    xf->l2m.dl_type = bpf_htons (ETH_P_IP);\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 2 * 6);\n",
    "    if (xf->l2m.vlan[0] != 0) {\n",
    "        vlh = DP_ADD_PTR (eth, sizeof (* eth));\n",
    "        if (vlh + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        eth->h_proto = bpf_htons (0x8100);\n",
    "        vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;\n",
    "    }\n",
    "    else {\n",
    "        eth->h_proto = xf->l2m.dl_type;\n",
    "    }\n",
    "    iph = (void *) (eth + 1);\n",
    "    if (iph + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    xf->pm.l3_len = xf->pm.l3_plen + sizeof (*iph);\n",
    "    xf->pm.l3_off = DP_DIFF_PTR (iph, eth);\n",
    "    xf->pm.l4_off = DP_DIFF_PTR ((iph + 1), eth);\n",
    "    iph->version = 4;\n",
    "    iph->ihl = 5;\n",
    "    iph->tot_len = bpf_htons (xf->pm.l3_len);\n",
    "    iph->ttl = 64;\n",
    "    iph->protocol = xf->l34m.nw_proto;\n",
    "    iph->saddr = xf->nm.nrip4;\n",
    "    iph->daddr = xf->nm.nxip4;\n",
    "    dp_ipv4_new_csum ((void *) iph);\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        tcp = (void *) (iph + 1);\n",
    "        if (tcp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        sum = bpf_csum_diff (xf -> l34m.saddr, sizeof (xf -> l34m.saddr), & iph -> saddr, sizeof (iph -> saddr), 0);\n",
    "        sum = bpf_csum_diff (xf -> l34m.daddr, sizeof (xf -> l34m.daddr), & iph -> daddr, sizeof (iph -> daddr), sum);\n",
    "        bpf_l4_csum_replace (md, xf->pm.l4_off + offsetof (struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);\n",
    "        dp_set_tcp_dport (md, xf, xf->nm.nxport);\n",
    "    }\n",
    "    else {\n",
    "        udp = (void *) (iph + 1);\n",
    "        if (udp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        dp_set_udp_dport (md, xf, xf->nm.nxport);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_DIFF_PTR",
    "offsetof",
    "dp_ipv4_new_csum",
    "bpf_htons",
    "DP_ADD_PTR",
    "dp_set_tcp_dport",
    "dp_set_udp_dport",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_do_dnat64(void *md, struct xfi *xf)
{
  struct iphdr *iph;
  struct ethhdr *eth;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct vlanhdr *vlh;
  __be32 sum;
  void *dend;

  if (xf->l34m.nw_proto != IPPROTO_TCP &&
      xf->l34m.nw_proto != IPPROTO_UDP) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  if (bpf_skb_change_proto(md, bpf_htons(ETH_P_IP), 0) < 0) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  xf->l2m.dl_type = bpf_htons(ETH_P_IP);
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  if (xf->l2m.vlan[0] != 0) {
    vlh = DP_ADD_PTR(eth, sizeof(*eth));
    if (vlh + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }
    eth->h_proto = bpf_htons(0x8100);
    vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;
  } else {
    eth->h_proto = xf->l2m.dl_type;
  }

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  xf->pm.l3_len = xf->pm.l3_plen + sizeof(*iph);
  xf->pm.l3_off = DP_DIFF_PTR(iph, eth);
  xf->pm.l4_off = DP_DIFF_PTR((iph+1), eth);

  /* Outer IP header */
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = xf->l34m.nw_proto;
  iph->saddr    = xf->nm.nrip4;
  iph->daddr    = xf->nm.nxip4;

  dp_ipv4_new_csum((void *)iph);

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    tcp = (void *)(iph + 1);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    sum = bpf_csum_diff(xf->l34m.saddr, sizeof(xf->l34m.saddr),
                &iph->saddr, sizeof(iph->saddr), 0);
    sum = bpf_csum_diff(xf->l34m.daddr, sizeof(xf->l34m.daddr),
                &iph->daddr, sizeof(iph->daddr), sum);

    bpf_l4_csum_replace(md, xf->pm.l4_off + offsetof(struct tcphdr, check),
                        0, sum, BPF_F_PSEUDO_HDR);

    dp_set_tcp_dport(md, xf, xf->nm.nxport);

  } else {

    udp = (void *)(iph + 1);
    if (udp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    dp_set_udp_dport(md, xf, xf->nm.nxport);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Change the protocol of the <[ skb ]>(IP: 0) to proto. Currently supported are transition from IPv4 to IPv6 , and from IPv6 to IPv4. The helper takes care of the groundwork for the transition , including resizing the socket buffer. The eBPF program is expected to fill the new headers , if any , via skb_store_bytes() and to recompute the checksums with bpf_l3_csum_replace() and bpf_l4_csum_replace(). The main case for this helper is to perform NAT64 operations out of an eBPF program. Internally , the GSO type is marked as dodgy so that headers are checked and segments are recalculated by the GSO/GRO engine. The size for GSO target is adapted as well. All values for <[ flags ]>(IP: 2) are reserved for future usage , and must be left at zero. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_change_proto",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  __be16 ,Var: proto}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Recompute the layer 4 (e. g. TCP , UDP or ICMP) checksum for the packet associated <[ to ]>(IP: 3) skb. Computation is incremental , so the helper must know the former value of the header field that was modified (from) , the new value of this field (to) , and the number of bytes (2 or 4) for this field , stored on the lowest four bits of flags. Alternatively , it is possible <[ to ]>(IP: 3) store the difference between the previous and the new values of the header field in <[ to ]>(IP: 3) , by setting <[ from ]>(IP: 2) and the four lowest bits of <[ flags ]>(IP: 4) <[ to ]>(IP: 3) 0. For both methods , <[ offset ]>(IP: 1) indicates the location of the IP checksum within the packet. In addition <[ to ]>(IP: 3) the size of the field , <[ flags ]>(IP: 4) can be added (bitwise OR) actual flags. With BPF_F_MARK_MANGLED_0 , a null checksum is left untouched (unless BPF_F_MARK_ENFORCE is added as well) , and for updates resulting in a null checksum the value is set <[ to ]>(IP: 3) CSUM_MANGLED_0 instead. Flag BPF_F_PSEUDO_HDR indicates the checksum is <[ to ]>(IP: 3) be computed against a pseudo-header. This helper works in combination with bpf_csum_diff() , which does not update the checksum in-place , but offers more flexibility and can handle sizes larger than 2 or 4 for the checksum <[ to ]>(IP: 3) update. A call <[ to ]>(IP: 3) this helper is susceptible <[ to ]>(IP: 3) change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_l4_csum_replace",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  u64 ,Var: from}",
            "{Type:  u64 ,Var: to}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    },
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "libbpf",
          "Return Type": "s64",
          "Description": "Compute a checksum difference , <[ from ]>(IP: 0) the raw buffer pointed by <[ from ]>(IP: 0) , of length <[ from_size ]>(IP: 1) (that must be a multiple of 4) , towards the raw buffer pointed by <[ to ]>(IP: 2) , of size <[ to_size ]>(IP: 3) (same remark). An optional <[ seed ]>(IP: 4) can be added <[ to ]>(IP: 2) the value (this can be cascaded , the <[ seed ]>(IP: 4) may come <[ from ]>(IP: 0) a previous call <[ to ]>(IP: 2) the helper). This is flexible enough <[ to ]>(IP: 2) be used in several ways: \u00b7 With <[ from_size ]>(IP: 1) == 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when pushing new data. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) == 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) checksum , it can be used when removing data <[ from ]>(IP: 0) a packet. \u00b7 With <[ from_size ]>(IP: 1) > 0 , <[ to_size ]>(IP: 3) > 0 and <[ seed ]>(IP: 4) set <[ to ]>(IP: 2) 0 , it can be used <[ to ]>(IP: 2) compute a diff. Note that <[ from_size ]>(IP: 1) and <[ to_size ]>(IP: 3) do not need <[ to ]>(IP: 2) be equal. This helper can be used in combination with bpf_l3_csum_replace() and bpf_l4_csum_replace() , <[ to ]>(IP: 2) which one can feed in the difference computed with bpf_csum_diff(). ",
          "Return": " The checksum result, or a negative error code in case of failure.",
          "Function Name": "bpf_csum_diff",
          "Input Params": [
            "{Type: __be32 ,Var: *from}",
            "{Type:  u32 ,Var: from_size}",
            "{Type:  __be32 ,Var: *to}",
            "{Type:  u32 ,Var: to_size}",
            "{Type:  __wsum ,Var: seed}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "xdp",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1584,
  "endLine": 1677,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_snat46",
  "developer_inline_comments": [
    {
      "start_line": 1638,
      "end_line": 1638,
      "text": " Outer IP header "
    },
    {
      "start_line": 1641,
      "end_line": 1641,
      "text": " FIXME - Copy inner ??"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_change_proto",
    "bpf_l4_csum_replace",
    "bpf_csum_diff"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_do_snat46 (void *md, struct xfi *xf)\n",
    "{\n",
    "    struct ipv6hdr *ip6h;\n",
    "    struct ethhdr *eth;\n",
    "    struct tcphdr *tcp;\n",
    "    struct udphdr *udp;\n",
    "    struct vlanhdr *vlh;\n",
    "    __be32 sum;\n",
    "    void *dend;\n",
    "    if (xf->l34m.nw_proto != IPPROTO_TCP && xf->l34m.nw_proto != IPPROTO_UDP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    if (bpf_skb_change_proto (md, bpf_htons (ETH_P_IPV6), 0) < 0) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    xf->l2m.dl_type = bpf_htons (ETH_P_IPV6);\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 2 * 6);\n",
    "    if (xf->l2m.vlan[0] != 0) {\n",
    "        vlh = DP_ADD_PTR (eth, sizeof (* eth));\n",
    "        if (vlh + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        eth->h_proto = bpf_htons (0x8100);\n",
    "        vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;\n",
    "    }\n",
    "    else {\n",
    "        eth->h_proto = xf->l2m.dl_type;\n",
    "    }\n",
    "    ip6h = (void *) (eth + 1);\n",
    "    if (ip6h + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    xf->pm.l3_len = xf->pm.l3_plen + sizeof (*ip6h);\n",
    "    xf->pm.l3_off = DP_DIFF_PTR (ip6h, eth);\n",
    "    xf->pm.l4_off = DP_DIFF_PTR ((ip6h + 1), eth);\n",
    "    ip6h->version = 6;\n",
    "    ip6h->payload_len = bpf_htons (xf->pm.l3_plen);\n",
    "    ip6h->hop_limit = 64;\n",
    "    ip6h->flow_lbl[0] = 0;\n",
    "    ip6h->flow_lbl[1] = 0;\n",
    "    ip6h->flow_lbl[2] = 0;\n",
    "    ip6h->nexthdr = xf->l34m.nw_proto;\n",
    "    memcpy (&ip6h->saddr, xf->nm.nxip, 16);\n",
    "    memcpy (&ip6h->daddr, xf->nm.nrip, 16);\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        tcp = (void *) (ip6h + 1);\n",
    "        if (tcp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        sum = bpf_csum_diff (& xf -> l34m.saddr [0], 4, (void *) & ip6h -> saddr, sizeof (ip6h -> saddr), 0);\n",
    "        sum = bpf_csum_diff (& xf -> l34m.daddr [0], 4, (void *) & ip6h -> daddr, sizeof (ip6h -> daddr), sum);\n",
    "        bpf_l4_csum_replace (md, xf->pm.l4_off + offsetof (struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);\n",
    "        dp_set_tcp_sport (md, xf, xf->nm.nxport);\n",
    "    }\n",
    "    else {\n",
    "        udp = (void *) (ip6h + 1);\n",
    "        if (udp + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        dp_set_udp_sport (md, xf, xf->nm.nxport);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_udp_sport",
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_DIFF_PTR",
    "offsetof",
    "bpf_htons",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "dp_set_tcp_sport",
    "memcpy"
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
static int __always_inline
dp_do_snat46(void *md, struct xfi *xf)
{
  struct ipv6hdr *ip6h;
  struct ethhdr *eth;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct vlanhdr *vlh;
  __be32 sum;
  void *dend;

  if (xf->l34m.nw_proto != IPPROTO_TCP &&
      xf->l34m.nw_proto != IPPROTO_UDP) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  if (bpf_skb_change_proto(md, bpf_htons(ETH_P_IPV6), 0) < 0) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  xf->l2m.dl_type = bpf_htons(ETH_P_IPV6);
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  if (xf->l2m.vlan[0] != 0) {
    vlh = DP_ADD_PTR(eth, sizeof(*eth));
    if (vlh + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }
    eth->h_proto = bpf_htons(0x8100);
    vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;
  } else {
    eth->h_proto = xf->l2m.dl_type;
  }

  ip6h = (void *)(eth + 1);
  if (ip6h + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  xf->pm.l3_len = xf->pm.l3_plen + sizeof(*ip6h);
  xf->pm.l3_off = DP_DIFF_PTR(ip6h, eth);
  xf->pm.l4_off = DP_DIFF_PTR((ip6h+1), eth);

  /* Outer IP header */
  ip6h->version  = 6;
  ip6h->payload_len = bpf_htons(xf->pm.l3_plen);
  ip6h->hop_limit = 64; // FIXME - Copy inner ??
  ip6h->flow_lbl[0] = 0;
  ip6h->flow_lbl[1] = 0;
  ip6h->flow_lbl[2] = 0;
  ip6h->nexthdr = xf->l34m.nw_proto;
  memcpy(&ip6h->saddr, xf->nm.nxip, 16);
  memcpy(&ip6h->daddr, xf->nm.nrip, 16);

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    tcp = (void *)(ip6h + 1);
    if (tcp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    sum = bpf_csum_diff(&xf->l34m.saddr[0], 4,
                        (void *)&ip6h->saddr, sizeof(ip6h->saddr), 0);
    sum = bpf_csum_diff(&xf->l34m.daddr[0], 4,
                        (void *)&ip6h->daddr, sizeof(ip6h->daddr), sum);
    bpf_l4_csum_replace(md, xf->pm.l4_off + offsetof(struct tcphdr, check),
                      0, sum, BPF_F_PSEUDO_HDR);

    dp_set_tcp_sport(md, xf, xf->nm.nxport);

  } else {

    udp = (void *)(ip6h + 1);
    if (udp + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    dp_set_udp_sport(md, xf, xf->nm.nxport);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "u32",
          "Description": "Set the full <[ hash ]>(IP: 1) for <[ skb ]>(IP: 0) (set the field skb->hash) to value hash. ",
          "Return": " 0",
          "Function Name": "bpf_set_hash",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: hash}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act"
          ],
          "capabilities": [
            "update_pkt"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "void",
          "Description": "Invalidate the current skb->hash. It can be used after mangling on headers through direct packet access , in order to indicate that the hash is outdated and to trigger a recalculation the next time the kernel tries to access this hash or when the bpf_get_hash_recalc() helper is called. ",
          "Function Name": "bpf_set_hash_invalid",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    },
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "u32",
          "Description": "Retrieve the hash of the packet , skb->hash. If it is not set , in particular if the hash was cleared due to mangling , recompute this hash. Later accesses to the hash can be done directly with skb->hash. Calling bpf_set_hash_invalid() , changing a packet prototype with bpf_skb_change_proto() , or calling bpf_skb_store_bytes() with the BPF_F_INVALIDATE_HASH are actions susceptible to clear the hash and to trigger a new computation for the next call to bpf_get_hash_recalc(). ",
          "Return": " The 32-bit hash.",
          "Function Name": "bpf_get_hash_recalc",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "lwt_seg6local"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1679,
  "endLine": 1684,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_get_pkt_hash",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md"
  ],
  "output": "static__u32__always_inline",
  "helper": [
    "bpf_set_hash",
    "bpf_set_hash_invalid",
    "bpf_get_hash_recalc"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static __u32 __always_inline dp_get_pkt_hash (void *md)\n",
    "{\n",
    "    bpf_set_hash_invalid (md);\n",
    "    return bpf_get_hash_recalc (md);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static __u32 __always_inline
dp_get_pkt_hash(void *md)
{
  bpf_set_hash_invalid(md);
  return bpf_get_hash_recalc(md);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_skb",
      "read_skb": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "This helper was provided as an easy way <[ to ]>(IP: 2) load data from a packet. It can be used <[ to ]>(IP: 2) load <[ len ]>(IP: 3) bytes from <[ offset ]>(IP: 1) from the packet associated <[ to ]>(IP: 2) <[ skb ]>(IP: 0) , into the buffer pointed by to. Since Linux 4. 7 , usage of this helper has mostly been replaced by \"direct packet access\" , enabling packet data <[ to ]>(IP: 2) be manipulated with skb->data and skb->data_end pointing respectively <[ to ]>(IP: 2) the first byte of packet data and <[ to ]>(IP: 2) the byte after the last byte of packet data. However , it remains useful if one wishes <[ to ]>(IP: 2) read large quantities of data at once from a packet into the eBPF stack. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_load_bytes",
          "Input Params": [
            "{Type: const struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  void ,Var: *to}",
            "{Type:  u32 ,Var: len}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "sched_cls",
            "sched_act",
            "cgroup_skb",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sk_skb",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector"
          ],
          "capabilities": [
            "read_skb"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1686,
  "endLine": 1690,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pktbuf_read",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " __u32 off",
    " void *tobuf",
    " __u32 tolen"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_load_bytes"
  ],
  "compatibleHookpoints": [
    "socket_filter",
    "sched_act",
    "sk_reuseport",
    "lwt_seg6local",
    "lwt_in",
    "sk_skb",
    "lwt_xmit",
    "lwt_out",
    "sched_cls",
    "flow_dissector",
    "cgroup_skb"
  ],
  "source": [
    "static int __always_inline dp_pktbuf_read (void *md, __u32 off, void *tobuf, __u32 tolen)\n",
    "{\n",
    "    return bpf_skb_load_bytes (md, off, tobuf, tolen);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_pktbuf_read(void *md, __u32 off, void *tobuf, __u32 tolen)
{
  return bpf_skb_load_bytes(md, off, tobuf, tolen);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Store <[ len ]>(IP: 3) bytes <[ from ]>(IP: 2) address <[ from ]>(IP: 2) into the packet associated to <[ skb ]>(IP: 0) , at offset. <[ flags ]>(IP: 4) are a combination of BPF_F_RECOMPUTE_CSUM (automatically recompute the checksum for the packet after storing the bytes) and BPF_F_INVALIDATE_HASH (set skb->hash , skb->swhash and skb->l4hash to 0). A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_skb_store_bytes",
          "Input Params": [
            "{Type: struct sk_buff ,Var: *skb}",
            "{Type:  u32 ,Var: offset}",
            "{Type:  const void ,Var: *from}",
            "{Type:  u32 ,Var: len}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "sched_cls",
            "sched_act",
            "lwt_xmit",
            "sk_skb"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1692,
  "endLine": 1696,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pktbuf_write",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " __u32 off",
    " void *frmbuf",
    " __u32 frmlen",
    " __u64 flags"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_skb_store_bytes"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sk_skb",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_pktbuf_write (void *md, __u32 off, void *frmbuf, __u32 frmlen, __u64 flags)\n",
    "{\n",
    "    return bpf_skb_store_bytes (md, off, frmbuf, frmlen, flags);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_pktbuf_write(void *md, __u32 off, void *frmbuf, __u32 frmlen, __u64 flags)
{
  return bpf_skb_store_bytes(md, off, frmbuf, frmlen, flags);
}

#else /* XDP utilities */

#define DP_LLB_MRK_INGP(md)
#define DP_LLB_INGP(md) (0)
#define DP_NEED_MIRR(md) (0)
#define DP_GET_MIRR(md)  (0)
#define DP_REDIRECT XDP_REDIRECT
#define DP_DROP     XDP_DROP
#define DP_PASS     XDP_PASS

#define dp_sunp_tcall(x, y)
#define TCALL_CRC1()
#define TCALL_CRC2()
#define RETURN_TO_MP_OUT()

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1713,
  "endLine": 1730,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pkt_is_l2mcbc",
  "developer_inline_comments": [
    {
      "start_line": 1698,
      "end_line": 1698,
      "text": " XDP utilities "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xfi *xf",
    " void *md"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_pkt_is_l2mcbc (struct xfi *xf, void *md)\n",
    "{\n",
    "    if (xf->l2m.dl_dst[0] & 1) {\n",
    "        return 1;\n",
    "    }\n",
    "    if (xf->l2m.dl_dst[0] == 0xff && xf->l2m.dl_dst[1] == 0xff && xf->l2m.dl_dst[2] == 0xff && xf->l2m.dl_dst[3] == 0xff && xf->l2m.dl_dst[4] == 0xff && xf->l2m.dl_dst[5] == 0xff) {\n",
    "        return 1;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_pkt_is_l2mcbc(struct xfi *xf, void *md)
{
  if (xf->l2m.dl_dst[0] & 1) {
    return 1;
  }

  if (xf->l2m.dl_dst[0] == 0xff &&
      xf->l2m.dl_dst[1] == 0xff &&
      xf->l2m.dl_dst[2] == 0xff &&
      xf->l2m.dl_dst[3] == 0xff &&
      xf->l2m.dl_dst[4] == 0xff &&
      xf->l2m.dl_dst[5] == 0xff) {
    return 1;
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ],
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1732,
  "endLine": 1736,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_add_l2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline dp_add_l2 (void *md, int delta)\n",
    "{\n",
    "    return bpf_xdp_adjust_head (md, -delta);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_add_l2(void *md, int delta)
{
  return bpf_xdp_adjust_head(md, -delta);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ],
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1738,
  "endLine": 1742,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_remove_l2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline dp_remove_l2 (void *md, int delta)\n",
    "{\n",
    "    return bpf_xdp_adjust_head (md, delta);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_remove_l2(void *md, int delta)
{
  return bpf_xdp_adjust_head(md, delta);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ],
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1744,
  "endLine": 1748,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_buf_add_room",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta",
    " __u64 flags"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline dp_buf_add_room (void *md, int delta, __u64 flags)\n",
    "{\n",
    "    return bpf_xdp_adjust_head (md, -delta);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_buf_add_room(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, -delta);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "update_pkt",
      "update_pkt": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Adjust (move) xdp_md->data by <[ delta ]>(IP: 1) bytes. Note that it is possible to use a negative value for delta. This helper can be used to prepare the packet for pushing or popping headers. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_head",
          "Input Params": [
            "{Type: struct xdp_buff ,Var: *xdp_md}",
            "{Type:  int ,Var: delta}"
          ],
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 1750,
  "endLine": 1754,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_buf_delete_room",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " int delta",
    " __u64 flags"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_xdp_adjust_head"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline dp_buf_delete_room (void *md, int delta, __u64 flags)\n",
    "{\n",
    "    return bpf_xdp_adjust_head (md, delta);\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_buf_delete_room(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, delta);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1756,
  "endLine": 1760,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_redirect_port",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *tbl",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "redirect",
    "bpf_redirect_map",
    "bpf_redirect"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline dp_redirect_port (void *tbl, struct xfi *xf)\n",
    "{\n",
    "    return bpf_redirect_map (tbl, xf->pm.oport, 0);\n",
    "}\n"
  ],
  "called_function_list": [
    "LL_DBG_PRINTK"
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
static int __always_inline
dp_redirect_port(void *tbl, struct xfi *xf)
{
  return bpf_redirect_map(tbl, xf->pm.oport, 0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1762,
  "endLine": 1767,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_rewire_port",
  "developer_inline_comments": [
    {
      "start_line": 1765,
      "end_line": 1765,
      "text": " Not supported "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *tbl",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_rewire_port (void *tbl, struct xfi *xf)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_rewire_port(void *tbl, struct xfi *xf)
{
  /* Not supported */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1769,
  "endLine": 1774,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_record_it",
  "developer_inline_comments": [
    {
      "start_line": 1772,
      "end_line": 1772,
      "text": " Not supported "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_record_it (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_record_it(void *ctx, struct xfi *xf)
{
  /* Not supported */
  return 0;
}

#define DP_IFI(md) (((struct xdp_md *)md)->ingress_ifindex)
#define DP_IIFI(md) (((struct xdp_md *)md)->ingress_ifindex)
#define DP_PDATA(md) (((struct xdp_md *)md)->data)
#define DP_PDATA_END(md) (((struct xdp_md *)md)->data_end)
#define DP_MDATA(md) (((struct xdp_md *)md)->data_meta)

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1782,
  "endLine": 1801,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_remove_vlan_tag",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_remove_vlan_tag (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    void *start = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct ethhdr *eth;\n",
    "    struct vlanhdr *vlh;\n",
    "    if (start + (sizeof (*eth) + sizeof (*vlh)) > dend) {\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_ADD_PTR (DP_PDATA (ctx), (int) sizeof (struct vlanhdr));\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 6);\n",
    "    memcpy (eth->h_source, xf->l2m.dl_src, 6);\n",
    "    eth->h_proto = xf->l2m.dl_type;\n",
    "    if (dp_remove_l2 (ctx, (int) sizeof (struct vlanhdr))) {\n",
    "        return -1;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "dp_remove_l2",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_remove_vlan_tag(void *ctx, struct xfi *xf)
{
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;
  struct vlanhdr *vlh;

  if (start + (sizeof(*eth) + sizeof(*vlh)) > dend) {
    return -1;
  }
  eth = DP_ADD_PTR(DP_PDATA(ctx), (int)sizeof(struct vlanhdr));
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);
  eth->h_proto = xf->l2m.dl_type;
  if (dp_remove_l2(ctx, (int)sizeof(struct vlanhdr))) {
    return -1;
  }
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1803,
  "endLine": 1838,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_insert_vlan_tag",
  "developer_inline_comments": [
    {
      "start_line": 1817,
      "end_line": 1817,
      "text": " Revalidate for satisfy eBPF verifier "
    },
    {
      "start_line": 1825,
      "end_line": 1825,
      "text": " FIXME : "
    },
    {
      "start_line": 1835,
      "end_line": 1835,
      "text": " FIXME : "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be16 vlan"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_insert_vlan_tag (void *ctx, struct xfi *xf, __be16 vlan)\n",
    "{\n",
    "    struct ethhdr *neth;\n",
    "    struct vlanhdr *vlh;\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (dp_add_l2 (ctx, (int) sizeof (struct vlanhdr))) {\n",
    "        return -1;\n",
    "    }\n",
    "    neth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (DP_TC_PTR (neth) + sizeof (*neth) > dend) {\n",
    "        return -1;\n",
    "    }\n",
    "    memcpy (neth->h_dest, xf->l2m.dl_dst, 6);\n",
    "    memcpy (neth->h_source, xf->l2m.dl_src, 6);\n",
    "    neth->h_proto = bpf_htons (ETH_P_8021Q);\n",
    "    vlh = DP_ADD_PTR (DP_PDATA (ctx), sizeof (* neth));\n",
    "    if (DP_TC_PTR (vlh) + sizeof (*vlh) > dend) {\n",
    "        return -1;\n",
    "    }\n",
    "    vlh->h_vlan_TCI = vlan;\n",
    "    vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_add_l2",
    "DP_PDATA",
    "bpf_htons",
    "DP_ADD_PTR",
    "bpf_ntohs",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_insert_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  struct ethhdr *neth;
  struct vlanhdr *vlh;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (dp_add_l2(ctx, (int)sizeof(struct vlanhdr))) {
    return -1;
  }

  neth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));

  /* Revalidate for satisfy eBPF verifier */
  if (DP_TC_PTR(neth) + sizeof(*neth) > dend) {
    return -1;
  }

  memcpy(neth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(neth->h_source, xf->l2m.dl_src, 6);

  /* FIXME : */
  neth->h_proto = bpf_htons(ETH_P_8021Q);

  vlh = DP_ADD_PTR(DP_PDATA(ctx), sizeof(*neth));

  if (DP_TC_PTR(vlh) + sizeof(*vlh) > dend) {
    return -1;
  }

  vlh->h_vlan_TCI = vlan;
  /* FIXME : */
  vlh->h_vlan_encapsulated_proto = xf->l2m.dl_type;
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1840,
  "endLine": 1861,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_swap_vlan_tag",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be16 vlan"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_swap_vlan_tag (void *ctx, struct xfi *xf, __be16 vlan)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    struct vlanhdr *vlh;\n",
    "    void *start = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if ((start + sizeof (*eth)) > dend) {\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 6);\n",
    "    memcpy (eth->h_source, xf->l2m.dl_src, 6);\n",
    "    vlh = DP_ADD_PTR (DP_PDATA (ctx), sizeof (* eth));\n",
    "    if (DP_TC_PTR (vlh) + sizeof (*vlh) > dend) {\n",
    "        return -1;\n",
    "    }\n",
    "    vlh->h_vlan_TCI = vlan;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "dp_insert_vlan_tag",
    "memcpy"
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
static int __always_inline
dp_swap_vlan_tag(void *ctx, struct xfi *xf, __be16 vlan)
{
  struct ethhdr *eth;
  struct vlanhdr *vlh;
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if ((start +  sizeof(*eth)) > dend) {
    return -1;
  }
  eth = DP_TC_PTR(DP_PDATA(ctx));
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);

  vlh = DP_ADD_PTR(DP_PDATA(ctx), sizeof(*eth));
  if (DP_TC_PTR(vlh) + sizeof(*vlh) > dend) {
    return -1;
  }
  vlh->h_vlan_TCI = vlan;
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1863,
  "endLine": 1868,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_snat",
  "developer_inline_comments": [
    {
      "start_line": 1866,
      "end_line": 1866,
      "text": " FIXME - TBD "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_snat (void *ctx, struct xfi *xf, __be32 xip, __be16 xport)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_sctp_dst_ip",
    "dp_set_udp_sport",
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_set_udp_src_ip",
    "DP_ADD_PTR",
    "dp_set_icmp_dst_ip",
    "dp_set_sctp_src_ip",
    "dp_set_sctp_sport",
    "DP_TC_PTR",
    "dp_set_icmp_src_ip",
    "DP_PDATA_END",
    "dp_set_tcp_src_ip",
    "dp_csum_tcall",
    "dp_set_tcp_sport",
    "dp_set_tcp_dst_ip",
    "dp_set_udp_dst_ip"
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
static int __always_inline
dp_do_snat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1870,
  "endLine": 1875,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_snat6",
  "developer_inline_comments": [
    {
      "start_line": 1873,
      "end_line": 1873,
      "text": " FIXME - TBD "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 *xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_snat6 (void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_icmp_src_ip6",
    "DP_ADD_PTR",
    "dp_set_sctp_sport",
    "dp_csum_tcall",
    "dp_set_tcp_sport",
    "dp_set_udp_src_ip6",
    "DP_XADDR_CP",
    "DP_PDATA",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "DP_XADDR_ISZR",
    "dp_set_udp_sport",
    "LLBS_PPLN_DROP",
    "dp_set_sctp_dst_ip6",
    "dp_set_sctp_src_ip6",
    "dp_set_icmp_dst_ip6",
    "dp_set_tcp_src_ip6",
    "dp_set_udp_dst_ip6",
    "dp_set_tcp_dst_ip6"
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
static int __always_inline
dp_do_snat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1877,
  "endLine": 1882,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_dnat",
  "developer_inline_comments": [
    {
      "start_line": 1880,
      "end_line": 1880,
      "text": " FIXME - TBD "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_dnat (void *ctx, struct xfi *xf, __be32 xip, __be16 xport)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_sctp_dst_ip",
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_set_udp_src_ip",
    "DP_ADD_PTR",
    "dp_set_icmp_dst_ip",
    "dp_set_tcp_dport",
    "dp_set_sctp_src_ip",
    "dp_set_icmp_src_ip",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "dp_set_tcp_src_ip",
    "dp_csum_tcall",
    "dp_set_udp_dst_ip",
    "dp_set_sctp_dport",
    "dp_set_tcp_dst_ip",
    "dp_set_udp_dport"
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
static int __always_inline
dp_do_dnat(void *ctx, struct xfi *xf, __be32 xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1884,
  "endLine": 1889,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_dnat6",
  "developer_inline_comments": [
    {
      "start_line": 1887,
      "end_line": 1887,
      "text": " FIXME - TBD "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __be32 *xip",
    " __be16 xport"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_dnat6 (void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_icmp_src_ip6",
    "DP_ADD_PTR",
    "dp_csum_tcall",
    "DP_XADDR_CP",
    "dp_set_udp_src_ip6",
    "DP_PDATA",
    "dp_set_tcp_dport",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "DP_XADDR_ISZR",
    "dp_set_udp_dport",
    "LLBS_PPLN_DROP",
    "dp_set_sctp_dst_ip6",
    "dp_set_sctp_src_ip6",
    "dp_set_icmp_dst_ip6",
    "dp_set_sctp_dport",
    "dp_set_tcp_src_ip6",
    "dp_set_udp_dst_ip6",
    "dp_set_tcp_dst_ip6"
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
static int __always_inline
dp_do_dnat6(void *ctx, struct xfi *xf, __be32 *xip, __be16 xport)
{
  /* FIXME - TBD */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1891,
  "endLine": 1896,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_dnat64",
  "developer_inline_comments": [
    {
      "start_line": 1894,
      "end_line": 1894,
      "text": " FIXME - TBD "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_dnat64 (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_DIFF_PTR",
    "offsetof",
    "dp_ipv4_new_csum",
    "bpf_htons",
    "DP_ADD_PTR",
    "dp_set_tcp_dport",
    "dp_set_udp_dport",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_do_dnat64(void *ctx, struct xfi *xf)
{
  /* FIXME - TBD */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1898,
  "endLine": 1903,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_snat46",
  "developer_inline_comments": [
    {
      "start_line": 1901,
      "end_line": 1901,
      "text": " FIXME - TBD "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_snat46 (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_set_udp_sport",
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_DIFF_PTR",
    "offsetof",
    "bpf_htons",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "dp_set_tcp_sport",
    "memcpy"
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
static int __always_inline
dp_do_snat46(void *ctx, struct xfi *xf)
{
  /* FIXME - TBD */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1905,
  "endLine": 1910,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_get_pkt_hash",
  "developer_inline_comments": [
    {
      "start_line": 1908,
      "end_line": 1908,
      "text": " FIXME - TODO "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md"
  ],
  "output": "static__u32__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static __u32 __always_inline dp_get_pkt_hash (void *md)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static __u32 __always_inline
dp_get_pkt_hash(void *md)
{
  /* FIXME - TODO */
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1912,
  "endLine": 1917,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pktbuf_read",
  "developer_inline_comments": [
    {
      "start_line": 1915,
      "end_line": 1915,
      "text": " FIXME - TODO "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " __u32 off",
    " void *buf",
    " __u32 tolen"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_pktbuf_read (void *md, __u32 off, void *buf, __u32 tolen)\n",
    "{\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_pktbuf_read(void *md, __u32 off, void *buf, __u32 tolen)
{
  /* FIXME - TODO */
  return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1919,
  "endLine": 1924,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pktbuf_write",
  "developer_inline_comments": [
    {
      "start_line": 1922,
      "end_line": 1922,
      "text": " FIXME - TODO "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " __u32 off",
    " void *frmbuf",
    " __u32 frmlen",
    " __u64 flags"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_pktbuf_write (void *md, __u32 off, void *frmbuf, __u32 frmlen, __u64 flags)\n",
    "{\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_pktbuf_write(void *md, __u32 off, void *frmbuf, __u32 frmlen, __u64 flags)
{
  /* FIXME - TODO */
  return -1;
}

#endif  /* End of XDP utilities */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1928,
  "endLine": 1974,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_out_vlan",
  "developer_inline_comments": [
    {
      "start_line": 1926,
      "end_line": 1926,
      "text": " End of XDP utilities "
    },
    {
      "start_line": 1939,
      "end_line": 1939,
      "text": " Strip existing vlan. Nothing to do if there was no vlan tag "
    },
    {
      "start_line": 1956,
      "end_line": 1958,
      "text": " If existing vlan tag was present just replace vlan-id, else      * push a new vlan tag and set the vlan-id     "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_out_vlan (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    void *start = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct ethhdr *eth;\n",
    "    int vlan;\n",
    "    vlan = xf->pm.bd;\n",
    "    if (vlan == 0) {\n",
    "        if (xf->l2m.vlan[0] != 0) {\n",
    "            if (dp_remove_vlan_tag (ctx, xf) != 0) {\n",
    "                LLBS_PPLN_DROP (xf);\n",
    "                return -1;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            if (start + sizeof (*eth) > dend) {\n",
    "                LLBS_PPLN_DROP (xf);\n",
    "                return -1;\n",
    "            }\n",
    "            eth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "            memcpy (eth->h_dest, xf->l2m.dl_dst, 6);\n",
    "            memcpy (eth->h_source, xf->l2m.dl_src, 6);\n",
    "        }\n",
    "        return 0;\n",
    "    }\n",
    "    else {\n",
    "        eth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "        if (xf->l2m.vlan[0] != 0) {\n",
    "            if (dp_swap_vlan_tag (ctx, xf, vlan) != 0) {\n",
    "                LLBS_PPLN_DROP (xf);\n",
    "                return -1;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            if (dp_insert_vlan_tag (ctx, xf, vlan) != 0) {\n",
    "                LLBS_PPLN_DROP (xf);\n",
    "                return -1;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_remove_vlan_tag",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "dp_swap_vlan_tag",
    "dp_insert_vlan_tag",
    "memcpy"
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
static int __always_inline
dp_do_out_vlan(void *ctx, struct xfi *xf)
{
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;
  int vlan;

  vlan = xf->pm.bd;

  if (vlan == 0) {
    /* Strip existing vlan. Nothing to do if there was no vlan tag */
    if (xf->l2m.vlan[0] != 0) {
      if (dp_remove_vlan_tag(ctx, xf) != 0) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }
    } else {
      if (start + sizeof(*eth) > dend) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }
      eth = DP_TC_PTR(DP_PDATA(ctx));
      memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
      memcpy(eth->h_source, xf->l2m.dl_src, 6);
    }
    return 0;
  } else {
    /* If existing vlan tag was present just replace vlan-id, else 
     * push a new vlan tag and set the vlan-id
     */
    eth = DP_TC_PTR(DP_PDATA(ctx));
    if (xf->l2m.vlan[0] != 0) {
      if (dp_swap_vlan_tag(ctx, xf, vlan) != 0) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }
    } else {
      if (dp_insert_vlan_tag(ctx, xf, vlan) != 0) {
        LLBS_PPLN_DROP(xf);
        return -1;
      }
    }
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1976,
  "endLine": 1986,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pop_outer_l2_metadata",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_pop_outer_l2_metadata (void *md, struct xfi *xf)\n",
    "{\n",
    "    memcpy (&xf->l2m.dl_type, &xf->il2m.dl_type, sizeof (xf->l2m) - sizeof (xf->l2m.vlan));\n",
    "    memcpy (xf->pm.lkup_dmac, xf->il2m.dl_dst, 6);\n",
    "    xf->il2m.valid = 0;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy"
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
static int __always_inline
dp_pop_outer_l2_metadata(void *md, struct xfi *xf)
{
  memcpy(&xf->l2m.dl_type, &xf->il2m.dl_type, 
         sizeof(xf->l2m) - sizeof(xf->l2m.vlan));

  memcpy(xf->pm.lkup_dmac, xf->il2m.dl_dst, 6);
  xf->il2m.valid = 0;

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1988,
  "endLine": 2008,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_pop_outer_metadata",
  "developer_inline_comments": [
    {
      "start_line": 1991,
      "end_line": 1991,
      "text": " Reset pipeline metadata "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " int l2tun"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_pop_outer_metadata (void *md, struct xfi *xf, int l2tun)\n",
    "{\n",
    "    memcpy (&xf->l34m, &xf->il34m, sizeof (xf->l34m));\n",
    "    xf->pm.tcp_flags = xf->pm.itcp_flags;\n",
    "    xf->pm.l4fin = xf->pm.il4fin;\n",
    "    xf->pm.l3_off = xf->pm.il3_off;\n",
    "    xf->pm.l3_len = xf->pm.il3_len;\n",
    "    xf->pm.l3_plen = xf->pm.il3_plen;\n",
    "    xf->pm.l4_off = xf->pm.il4_off;\n",
    "    xf->il34m.valid = 0;\n",
    "    xf->tm.tun_decap = 1;\n",
    "    if (l2tun) {\n",
    "        return dp_pop_outer_l2_metadata (md, xf);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_pop_outer_l2_metadata",
    "memcpy"
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
static int __always_inline
dp_pop_outer_metadata(void *md, struct xfi *xf, int l2tun)
{
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));

  xf->pm.tcp_flags = xf->pm.itcp_flags;
  xf->pm.l4fin = xf->pm.il4fin;
  xf->pm.l3_off = xf->pm.il3_off;
  xf->pm.l3_len = xf->pm.il3_len;
  xf->pm.l3_plen = xf->pm.il3_plen;
  xf->pm.l4_off = xf->pm.il4_off;
  xf->il34m.valid = 0;
  xf->tm.tun_decap = 1;

  if (l2tun) {
    return dp_pop_outer_l2_metadata(md, xf);  
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2010,
  "endLine": 2052,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_strip_ipip",
  "developer_inline_comments": [
    {
      "start_line": 2031,
      "end_line": 2031,
      "text": " Recreate eth header "
    },
    {
      "start_line": 2035,
      "end_line": 2037,
      "text": " We do not care about vlan's now   * After routing it will be set as per outgoing BD   "
    },
    {
      "start_line": 2042,
      "end_line": 2042,
      "text": " Reset pipeline metadata "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_strip_ipip (void *md, struct xfi *xf)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    void *dend;\n",
    "    int olen = sizeof (struct iphdr);\n",
    "    if (dp_buf_delete_room (md, olen, BPF_F_ADJ_ROOM_FIXED_GSO) < 0) {\n",
    "        LL_DBG_PRINTK (\"Failed gtph remove\\n\");\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 2 * 6);\n",
    "    eth->h_proto = xf->l2m.dl_type;\n",
    "    xf->l2m.vlan[0] = 0;\n",
    "    xf->l2m.vlan[1] = 0;\n",
    "\n",
    "#if 0\n",
    "    memcpy (&xf->l34m, &xf->il34m, sizeof (xf->l34m));\n",
    "    memcpy (xf->pm.lkup_dmac, eth->h_dest, 6);\n",
    "    xf->il34m.valid = 0;\n",
    "    xf->il2m.valid = 0;\n",
    "    xf->tm.tun_decap = 1;\n",
    "\n",
    "#endif\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "LL_DBG_PRINTK",
    "dp_buf_delete_room",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_do_strip_ipip(void *md, struct xfi *xf)
{
  struct ethhdr *eth;
  void *dend;
  int olen = sizeof(struct iphdr);

  if (dp_buf_delete_room(md, olen, BPF_F_ADJ_ROOM_FIXED_GSO)  < 0) {
    LL_DBG_PRINTK("Failed gtph remove\n");
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Recreate eth header */
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  eth->h_proto = xf->l2m.dl_type;

  /* We do not care about vlan's now
   * After routing it will be set as per outgoing BD
   */
  xf->l2m.vlan[0] = 0;
  xf->l2m.vlan[1] = 0;

#if 0
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));
  memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);

  xf->il34m.valid = 0;
  xf->il2m.valid = 0;
  xf->tm.tun_decap = 1;
#endif

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2054,
  "endLine": 2128,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_ins_ipip",
  "developer_inline_comments": [
    {
      "start_line": 2073,
      "end_line": 2073,
      "text": " add room between mac and network header "
    },
    {
      "start_line": 2093,
      "end_line": 2093,
      "text": " Outer IP header "
    },
    {
      "start_line": 2097,
      "end_line": 2097,
      "text": " FIXME - Copy inner"
    },
    {
      "start_line": 2110,
      "end_line": 2114,
      "text": "    * Reset pipeline metadata    * If it is called from deparser, there is no need   * to do the following (set skip_md = 1)   "
    },
    {
      "start_line": 2117,
      "end_line": 2117,
      "text": " Outer L2 - MAC addr are invalid as of now "
    },
    {
      "start_line": 2120,
      "end_line": 2120,
      "text": " Outer L3 "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 rip",
    " __be32 sip",
    " __be32 tid",
    " int skip_md"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_ins_ipip (void *md, struct xfi *xf, __be32 rip, __be32 sip, __be32 tid, int skip_md)\n",
    "{\n",
    "    void *dend;\n",
    "    struct ethhdr *eth;\n",
    "    struct iphdr *iph;\n",
    "    int olen;\n",
    "    __u64 flags;\n",
    "    olen = sizeof (*iph);\n",
    "    flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;\n",
    "    if (dp_buf_add_room (md, olen, flags)) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    iph = (void *) (eth + 1);\n",
    "    if (iph + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    iph->version = 4;\n",
    "    iph->ihl = 5;\n",
    "    iph->tot_len = bpf_htons (xf->pm.l3_len + olen);\n",
    "    iph->ttl = 64;\n",
    "    iph->protocol = IPPROTO_IPIP;\n",
    "    iph->saddr = sip;\n",
    "    iph->daddr = rip;\n",
    "    dp_ipv4_new_csum ((void *) iph);\n",
    "    xf->tm.tun_encap = 1;\n",
    "    if (skip_md) {\n",
    "        return 0;\n",
    "    }\n",
    "    memcpy (&xf->il34m, &xf->l34m, sizeof (xf->l34m));\n",
    "    xf->pm.lkup_dmac[0] = 0xff;\n",
    "    xf->l34m.saddr4 = sip;\n",
    "    xf->l34m.daddr4 = rip;\n",
    "    xf->l34m.source = 0;\n",
    "    xf->l34m.dest = 0;\n",
    "    xf->pm.l4_off = xf->pm.l3_off + sizeof (*iph);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_ipv4_new_csum",
    "bpf_htons",
    "DP_TC_PTR",
    "dp_buf_add_room",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_do_ins_ipip(void *md,
               struct xfi *xf,
               __be32 rip,
               __be32 sip,
               __be32 tid,
               int skip_md) 
{
  void *dend;
  struct ethhdr *eth;
  struct iphdr *iph;
  int olen;
  __u64 flags;

  olen  = sizeof(*iph);

  flags = BPF_F_ADJ_ROOM_FIXED_GSO |
          BPF_F_ADJ_ROOM_ENCAP_L3_IPV4; 

  /* add room between mac and network header */
  if (dp_buf_add_room(md, olen, flags)) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Outer IP header */ 
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len +  olen);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = IPPROTO_IPIP;
  iph->saddr    = sip;
  iph->daddr    = rip;

  dp_ipv4_new_csum((void *)iph);

  xf->tm.tun_encap = 1;

  if (skip_md) {
    return 0;
  }

  /* 
   * Reset pipeline metadata 
   * If it is called from deparser, there is no need
   * to do the following (set skip_md = 1)
   */
  memcpy(&xf->il34m, &xf->l34m, sizeof(xf->l34m));

  /* Outer L2 - MAC addr are invalid as of now */
  xf->pm.lkup_dmac[0] = 0xff;

  /* Outer L3 */
  xf->l34m.saddr4 = sip;
  xf->l34m.daddr4 = rip;
  xf->l34m.source = 0;
  xf->l34m.dest = 0;
  xf->pm.l4_off = xf->pm.l3_off + sizeof(*iph);
  
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2130,
  "endLine": 2175,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_strip_vxlan",
  "developer_inline_comments": [
    {
      "start_line": 2163,
      "end_line": 2163,
      "text": " Reset pipeline metadata "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " int olen"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_strip_vxlan (void *md, struct xfi *xf, int olen)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    struct vlanhdr *vlh;\n",
    "    void *dend;\n",
    "    if (dp_buf_delete_room (md, olen, BPF_F_ADJ_ROOM_FIXED_GSO) < 0) {\n",
    "        LL_DBG_PRINTK (\"Failed MAC remove\\n\");\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    memcpy (eth->h_dest, xf->il2m.dl_dst, 2 * 6);\n",
    "    if (xf->il2m.vlan[0] != 0) {\n",
    "        vlh = DP_ADD_PTR (eth, sizeof (* eth));\n",
    "        if (vlh + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        vlh->h_vlan_encapsulated_proto = xf->il2m.dl_type;\n",
    "    }\n",
    "    else {\n",
    "        eth->h_proto = xf->il2m.dl_type;\n",
    "    }\n",
    "\n",
    "#if 0\n",
    "    memcpy (&xf->l34m, &xf->il34m, sizeof (xf->l34m));\n",
    "    memcpy (&xf->l2m, &xf->il2m, sizeof (xf->l2m));\n",
    "    memcpy (xf->pm.lkup_dmac, eth->h_dest, 6);\n",
    "    xf->il34m.valid = 0;\n",
    "    xf->il2m.valid = 0;\n",
    "    xf->tm.tun_decap = 1;\n",
    "\n",
    "#endif\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_ADD_PTR",
    "LL_DBG_PRINTK",
    "dp_buf_delete_room",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_do_strip_vxlan(void *md, struct xfi *xf, int olen)
{
  struct ethhdr *eth;
  struct vlanhdr *vlh;
  void *dend;

  if (dp_buf_delete_room(md, olen, BPF_F_ADJ_ROOM_FIXED_GSO)  < 0) {
    LL_DBG_PRINTK("Failed MAC remove\n");
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }
  memcpy(eth->h_dest, xf->il2m.dl_dst, 2*6);
  if (xf->il2m.vlan[0] != 0) {
    vlh = DP_ADD_PTR(eth, sizeof(*eth));
    if (vlh + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }
    vlh->h_vlan_encapsulated_proto = xf->il2m.dl_type;
  } else {
    eth->h_proto = xf->il2m.dl_type;
  }

#if 0
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));
  memcpy(&xf->l2m, &xf->il2m, sizeof(xf->l2m));

  memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);

  xf->il34m.valid = 0;
  xf->il2m.valid = 0;
  xf->tm.tun_decap = 1;
#endif

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2177,
  "endLine": 2330,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_ins_vxlan",
  "developer_inline_comments": [
    {
      "start_line": 2194,
      "end_line": 2194,
      "text": " We do not pass vlan header inside vxlan "
    },
    {
      "start_line": 2211,
      "end_line": 2211,
      "text": " add room between mac and network header "
    },
    {
      "start_line": 2226,
      "end_line": 2232,
      "text": "    * FIXME - Inner ethernet    * No need to copy but if we dont    * inner eth header is sometimes not set   * properly especially when incoming packet   * was vlan tagged   "
    },
    {
      "start_line": 2245,
      "end_line": 2245,
      "text": " Outer IP header "
    },
    {
      "start_line": 2249,
      "end_line": 2249,
      "text": " FIXME - Copy inner"
    },
    {
      "start_line": 2262,
      "end_line": 2262,
      "text": " Outer UDP header "
    },
    {
      "start_line": 2268,
      "end_line": 2268,
      "text": " VxLAN header "
    },
    {
      "start_line": 2275,
      "end_line": 2277,
      "text": " Control agent should pass tunnel-id something like this -   * bpf_htonl(((__le32)(tid) << 8) & 0xffffff00);   "
    },
    {
      "start_line": 2281,
      "end_line": 2283,
      "text": " Inner eth header -   * XXX If we do not copy, inner eth is zero'd out   "
    },
    {
      "start_line": 2293,
      "end_line": 2293,
      "text": " Tunnel metadata "
    },
    {
      "start_line": 2301,
      "end_line": 2301,
      "text": " Reset flags essential for L2 header rewrite "
    },
    {
      "start_line": 2309,
      "end_line": 2313,
      "text": "    * Reset pipeline metadata    * If it is called from deparser, there is no need   * to do the following (set skip_md = 1)   "
    },
    {
      "start_line": 2318,
      "end_line": 2318,
      "text": " Outer L2 - MAC addr are invalid as of now "
    },
    {
      "start_line": 2321,
      "end_line": 2321,
      "text": " Outer L3 "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 rip",
    " __be32 sip",
    " __be32 tid",
    " int skip_md"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_ins_vxlan (void *md, struct xfi *xf, __be32 rip, __be32 sip, __be32 tid, int skip_md)\n",
    "{\n",
    "    void *dend;\n",
    "    struct ethhdr *eth;\n",
    "    struct ethhdr *ieth;\n",
    "    struct iphdr *iph;\n",
    "    struct udphdr *udp;\n",
    "    struct vxlanhdr *vx;\n",
    "    int olen, l2_len;\n",
    "    __u64 flags;\n",
    "    if (xf->l2m.vlan[0] != 0) {\n",
    "        if (dp_remove_vlan_tag (md, xf) < 0) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "    }\n",
    "    olen = sizeof (*iph) + sizeof (*udp) + sizeof (*vx);\n",
    "    l2_len = sizeof (*eth);\n",
    "    flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP | BPF_F_ADJ_ROOM_ENCAP_L2 (l2_len);\n",
    "    olen += l2_len;\n",
    "    if (dp_buf_add_room (md, olen, flags)) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "\n",
    "#if 0\n",
    "    if (xf->l2m.vlan[0]) {\n",
    "        memcpy (eth->h_dest, xf->il2m.dl_dst, 2 * 6);\n",
    "        eth->h_proto = xf->il2m.dl_type;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    iph = (void *) (eth + 1);\n",
    "    if (iph + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    iph->version = 4;\n",
    "    iph->ihl = 5;\n",
    "    iph->tot_len = bpf_htons (xf->pm.l3_len + olen);\n",
    "    iph->ttl = 64;\n",
    "    iph->protocol = IPPROTO_UDP;\n",
    "    iph->saddr = sip;\n",
    "    iph->daddr = rip;\n",
    "    dp_ipv4_new_csum ((void *) iph);\n",
    "    udp = (void *) (iph + 1);\n",
    "    if (udp + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    udp->source = xf->l34m.source + VXLAN_OUDP_SPORT;\n",
    "    udp->dest = bpf_htons (VXLAN_OUDP_DPORT);\n",
    "    udp->check = 0;\n",
    "    udp->len = bpf_htons (xf->pm.l3_len + olen - sizeof (*iph));\n",
    "    vx = (void *) (udp + 1);\n",
    "    if (vx + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    vx->vx_vni = tid;\n",
    "    vx->vx_flags = VXLAN_VI_FLAG_ON;\n",
    "    ieth = (void *) (vx + 1);\n",
    "    if (ieth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    memcpy (ieth->h_dest, xf->il2m.dl_dst, 2 * 6);\n",
    "    ieth->h_proto = xf->il2m.dl_type;\n",
    "    xf->tm.tun_type = LLB_TUN_VXLAN;\n",
    "    xf->tm.tunnel_id = bpf_ntohl (tid);\n",
    "    xf->pm.tun_off = sizeof (*eth) + sizeof (*iph) + sizeof (*udp);\n",
    "    xf->tm.tun_encap = 1;\n",
    "    xf->l2m.vlan[0] = 0;\n",
    "    xf->l2m.dl_type = bpf_htons (ETH_P_IP);\n",
    "    if (skip_md) {\n",
    "        return 0;\n",
    "    }\n",
    "    memcpy (&xf->il34m, &xf->l34m, sizeof (xf->l34m));\n",
    "    memcpy (&xf->il2m, &xf->l2m, sizeof (xf->l2m));\n",
    "    xf->il2m.vlan[0] = 0;\n",
    "    xf->pm.lkup_dmac[0] = 0xff;\n",
    "    xf->l34m.saddr4 = sip;\n",
    "    xf->l34m.daddr4 = rip;\n",
    "    xf->l34m.source = udp->source;\n",
    "    xf->l34m.dest = udp->dest;\n",
    "    xf->pm.l3_off = sizeof (*eth);\n",
    "    xf->pm.l4_off = sizeof (*eth) + sizeof (*iph);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_ipv4_new_csum",
    "dp_remove_vlan_tag",
    "bpf_htons",
    "bpf_ntohl",
    "DP_TC_PTR",
    "dp_buf_add_room",
    "DP_PDATA_END",
    "BPF_F_ADJ_ROOM_ENCAP_L2",
    "memcpy"
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
static int __always_inline
dp_do_ins_vxlan(void *md,
                struct xfi *xf,
                __be32 rip,
                __be32 sip,
                __be32 tid,
                int skip_md) 
{
  void *dend;
  struct ethhdr *eth;
  struct ethhdr *ieth;
  struct iphdr *iph;
  struct udphdr *udp;
  struct vxlanhdr *vx;
  int olen, l2_len;
  __u64 flags;

  /* We do not pass vlan header inside vxlan */
  if (xf->l2m.vlan[0] != 0) {
    if (dp_remove_vlan_tag(md, xf) < 0) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }
  }

  olen   = sizeof(*iph)  + sizeof(*udp) + sizeof(*vx); 
  l2_len = sizeof(*eth);

    flags = BPF_F_ADJ_ROOM_FIXED_GSO |
          BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
          BPF_F_ADJ_ROOM_ENCAP_L4_UDP |
          BPF_F_ADJ_ROOM_ENCAP_L2(l2_len);
    olen += l2_len;

    /* add room between mac and network header */
    if (dp_buf_add_room(md, olen, flags)) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

#if 0
  /* 
   * FIXME - Inner ethernet 
   * No need to copy but if we dont 
   * inner eth header is sometimes not set
   * properly especially when incoming packet
   * was vlan tagged
   */
  if (xf->l2m.vlan[0]) {
    memcpy(eth->h_dest, xf->il2m.dl_dst, 2*6);
    eth->h_proto = xf->il2m.dl_type;
  }
#endif

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Outer IP header */ 
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len +  olen);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = IPPROTO_UDP;
  iph->saddr    = sip;
  iph->daddr    = rip;

  dp_ipv4_new_csum((void *)iph);

  udp = (void *)(iph + 1);
  if (udp + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Outer UDP header */
  udp->source = xf->l34m.source + VXLAN_OUDP_SPORT;
  udp->dest   = bpf_htons(VXLAN_OUDP_DPORT);
  udp->check  = 0;
  udp->len    = bpf_htons(xf->pm.l3_len +  olen - sizeof(*iph));

  /* VxLAN header */
  vx = (void *)(udp + 1);
  if (vx + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Control agent should pass tunnel-id something like this -
   * bpf_htonl(((__le32)(tid) << 8) & 0xffffff00);
   */
  vx->vx_vni   = tid;
  vx->vx_flags = VXLAN_VI_FLAG_ON;

  /* Inner eth header -
   * XXX If we do not copy, inner eth is zero'd out
   */
  ieth = (void *)(vx + 1);
  if (ieth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  memcpy(ieth->h_dest, xf->il2m.dl_dst, 2*6);
  ieth->h_proto = xf->il2m.dl_type;

  /* Tunnel metadata */
  xf->tm.tun_type  = LLB_TUN_VXLAN;
  xf->tm.tunnel_id = bpf_ntohl(tid);
  xf->pm.tun_off   = sizeof(*eth) + 
                    sizeof(*iph) + 
                    sizeof(*udp);
  xf->tm.tun_encap = 1;

  /* Reset flags essential for L2 header rewrite */
  xf->l2m.vlan[0] = 0;
  xf->l2m.dl_type = bpf_htons(ETH_P_IP);

  if (skip_md) {
    return 0;
  }

  /* 
   * Reset pipeline metadata 
   * If it is called from deparser, there is no need
   * to do the following (set skip_md = 1)
   */
  memcpy(&xf->il34m, &xf->l34m, sizeof(xf->l34m));
  memcpy(&xf->il2m, &xf->l2m, sizeof(xf->l2m));
  xf->il2m.vlan[0] = 0;

  /* Outer L2 - MAC addr are invalid as of now */
  xf->pm.lkup_dmac[0] = 0xff;

  /* Outer L3 */
  xf->l34m.saddr4 = sip;
  xf->l34m.daddr4 = rip;
  xf->l34m.source = udp->source;
  xf->l34m.dest = udp->dest;
  xf->pm.l3_off = sizeof(*eth);
  xf->pm.l4_off = sizeof(*eth) + sizeof(*iph);
  
    return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2332,
  "endLine": 2378,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_strip_gtp",
  "developer_inline_comments": [
    {
      "start_line": 2357,
      "end_line": 2357,
      "text": " Recreate eth header "
    },
    {
      "start_line": 2361,
      "end_line": 2363,
      "text": " We do not care about vlan's now   * After routing it will be set as per outgoing BD   "
    },
    {
      "start_line": 2368,
      "end_line": 2368,
      "text": " Reset pipeline metadata "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " int olen"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_strip_gtp (void *md, struct xfi *xf, int olen)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    void *dend;\n",
    "    if (olen < sizeof (*eth)) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    if (dp_buf_delete_room (md, olen - sizeof (*eth), BPF_F_ADJ_ROOM_FIXED_GSO) < 0) {\n",
    "        LL_DBG_PRINTK (\"Failed gtph remove\\n\");\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 2 * 6);\n",
    "    eth->h_proto = xf->l2m.dl_type;\n",
    "    xf->l2m.vlan[0] = 0;\n",
    "    xf->l2m.vlan[1] = 0;\n",
    "\n",
    "#if 0\n",
    "    memcpy (&xf->l34m, &xf->il34m, sizeof (xf->l34m));\n",
    "    memcpy (xf->pm.lkup_dmac, eth->h_dest, 6);\n",
    "    xf->il34m.valid = 0;\n",
    "    xf->il2m.valid = 0;\n",
    "    xf->tm.tun_decap = 1;\n",
    "\n",
    "#endif\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "LL_DBG_PRINTK",
    "dp_buf_delete_room",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_do_strip_gtp(void *md, struct xfi *xf, int olen)
{
  struct ethhdr *eth;
  void *dend;

  if (olen < sizeof(*eth)) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  if (dp_buf_delete_room(md, olen - sizeof(*eth), BPF_F_ADJ_ROOM_FIXED_GSO)  < 0) {
    LL_DBG_PRINTK("Failed gtph remove\n");
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Recreate eth header */
  memcpy(eth->h_dest, xf->l2m.dl_dst, 2*6);
  eth->h_proto = xf->l2m.dl_type;

  /* We do not care about vlan's now
   * After routing it will be set as per outgoing BD
   */
  xf->l2m.vlan[0] = 0;
  xf->l2m.vlan[1] = 0;

#if 0
  /* Reset pipeline metadata */
  memcpy(&xf->l34m, &xf->il34m, sizeof(xf->l34m));
  memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);

  xf->il34m.valid = 0;
  xf->il2m.valid = 0;
  xf->tm.tun_decap = 1;
#endif

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2380,
  "endLine": 2528,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_do_ins_gtp",
  "developer_inline_comments": [
    {
      "start_line": 2415,
      "end_line": 2415,
      "text": " add room between mac and network header "
    },
    {
      "start_line": 2435,
      "end_line": 2435,
      "text": " Outer IP header "
    },
    {
      "start_line": 2439,
      "end_line": 2439,
      "text": " FIXME - Copy inner"
    },
    {
      "start_line": 2452,
      "end_line": 2452,
      "text": " Outer UDP header "
    },
    {
      "start_line": 2458,
      "end_line": 2458,
      "text": " GTP header "
    },
    {
      "start_line": 2473,
      "end_line": 2473,
      "text": " GTP extension header "
    },
    {
      "start_line": 2497,
      "end_line": 2497,
      "text": " Tunnel metadata "
    },
    {
      "start_line": 2509,
      "end_line": 2513,
      "text": "    * Reset pipeline metadata    * If it is called from deparser, there is no need   * to do the following (set skip_md = 1)   "
    },
    {
      "start_line": 2517,
      "end_line": 2517,
      "text": " Outer L2 - MAC addr are invalid as of now "
    },
    {
      "start_line": 2520,
      "end_line": 2520,
      "text": " Outer L3 "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " __be32 rip",
    " __be32 sip",
    " __be32 tid",
    " __u8 qfi",
    " int skip_md"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_do_ins_gtp (void *md, struct xfi *xf, __be32 rip, __be32 sip, __be32 tid, __u8 qfi, int skip_md)\n",
    "{\n",
    "    void *dend;\n",
    "    struct gtp_v1_hdr *gh;\n",
    "    struct gtp_v1_ehdr *geh;\n",
    "    struct gtp_dl_pdu_sess_hdr *gedh;\n",
    "    struct ethhdr *eth;\n",
    "    struct iphdr *iph;\n",
    "    struct udphdr *udp;\n",
    "    int olen;\n",
    "    __u64 flags;\n",
    "    int ghlen;\n",
    "    __u8 espn;\n",
    "    if (qfi) {\n",
    "        ghlen = sizeof (*gh) + sizeof (*geh) + sizeof (*gedh);\n",
    "        espn = GTP_EXT_FM;\n",
    "    }\n",
    "    else {\n",
    "        ghlen = sizeof (*gh);\n",
    "        espn = 0;\n",
    "    }\n",
    "    olen = sizeof (*iph) + sizeof (*udp) + ghlen;\n",
    "    flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;\n",
    "    if (dp_buf_add_room (md, olen, flags)) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    eth = DP_TC_PTR (DP_PDATA (md));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    if (eth + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    iph = (void *) (eth + 1);\n",
    "    if (iph + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    iph->version = 4;\n",
    "    iph->ihl = 5;\n",
    "    iph->tot_len = bpf_htons (xf->pm.l3_len + olen);\n",
    "    iph->ttl = 64;\n",
    "    iph->protocol = IPPROTO_UDP;\n",
    "    iph->saddr = sip;\n",
    "    iph->daddr = rip;\n",
    "    dp_ipv4_new_csum ((void *) iph);\n",
    "    udp = (void *) (iph + 1);\n",
    "    if (udp + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    udp->source = bpf_htons (GTPU_UDP_SPORT);\n",
    "    udp->dest = bpf_htons (GTPU_UDP_DPORT);\n",
    "    udp->check = 0;\n",
    "    udp->len = bpf_htons (xf->pm.l3_len + olen - sizeof (*iph));\n",
    "    gh = (void *) (udp + 1);\n",
    "    if (gh + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    gh->ver = GTP_VER_1;\n",
    "    gh->pt = 1;\n",
    "    gh->espn = espn;\n",
    "    gh->teid = tid;\n",
    "    gh->mt = GTP_MT_TPDU;\n",
    "    gh->mlen = bpf_ntohs (xf->pm.l3_len + ghlen);\n",
    "    if (qfi) {\n",
    "        geh = (void *) (gh + 1);\n",
    "        if (geh + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        geh->seq = 0;\n",
    "        geh->npdu = 0;\n",
    "        geh->next_hdr = GTP_NH_PDU_SESS;\n",
    "        gedh = (void *) (geh + 1);\n",
    "        if (gedh + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            return -1;\n",
    "        }\n",
    "        gedh->cmn.len = 1;\n",
    "        gedh->cmn.pdu_type = GTP_PDU_SESS_DL;\n",
    "        gedh->qfi = qfi;\n",
    "        gedh->ppp = 0;\n",
    "        gedh->rqi = 0;\n",
    "        gedh->next_hdr = 0;\n",
    "    }\n",
    "    xf->tm.tun_type = LLB_TUN_GTP;\n",
    "    xf->tm.tunnel_id = bpf_ntohl (tid);\n",
    "    xf->pm.tun_off = sizeof (*eth) + sizeof (*iph) + sizeof (*udp);\n",
    "    xf->tm.tun_encap = 1;\n",
    "    if (skip_md) {\n",
    "        return 0;\n",
    "    }\n",
    "    memcpy (&xf->il34m, &xf->l34m, sizeof (xf->l34m));\n",
    "    xf->il2m.vlan[0] = 0;\n",
    "    xf->pm.lkup_dmac[0] = 0xff;\n",
    "    xf->l34m.saddr4 = sip;\n",
    "    xf->l34m.daddr4 = rip;\n",
    "    xf->l34m.source = udp->source;\n",
    "    xf->l34m.dest = udp->dest;\n",
    "    xf->pm.l4_off = xf->pm.l3_off + sizeof (*iph);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "dp_ipv4_new_csum",
    "bpf_htons",
    "bpf_ntohl",
    "DP_TC_PTR",
    "bpf_ntohs",
    "dp_buf_add_room",
    "DP_PDATA_END",
    "memcpy"
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
static int __always_inline
dp_do_ins_gtp(void *md,
              struct xfi *xf,
              __be32 rip,
              __be32 sip,
              __be32 tid,
              __u8 qfi,
              int skip_md) 
{
  void *dend;
  struct gtp_v1_hdr *gh;
  struct gtp_v1_ehdr *geh;
  struct gtp_dl_pdu_sess_hdr *gedh;
  struct ethhdr *eth;
  struct iphdr *iph;
  struct udphdr *udp;
  int olen;
  __u64 flags;
  int ghlen;
  __u8 espn;

  if (qfi) {
    ghlen = sizeof(*gh) + sizeof(*geh) + sizeof(*gedh);
    espn = GTP_EXT_FM;
  } else {
    ghlen = sizeof(*gh);
    espn = 0;
  }

  olen   = sizeof(*iph)  + sizeof(*udp) + ghlen;

  flags = BPF_F_ADJ_ROOM_FIXED_GSO |
          BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
          BPF_F_ADJ_ROOM_ENCAP_L4_UDP;

  /* add room between mac and network header */
  if (dp_buf_add_room(md, olen, flags)) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  eth = DP_TC_PTR(DP_PDATA(md));
  dend = DP_TC_PTR(DP_PDATA_END(md));

  if (eth + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  iph = (void *)(eth + 1);
  if (iph + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Outer IP header */ 
  iph->version  = 4;
  iph->ihl      = 5;
  iph->tot_len  = bpf_htons(xf->pm.l3_len +  olen);
  iph->ttl      = 64; // FIXME - Copy inner
  iph->protocol = IPPROTO_UDP;
  iph->saddr    = sip;
  iph->daddr    = rip;

  dp_ipv4_new_csum((void *)iph);

  udp = (void *)(iph + 1);
  if (udp + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* Outer UDP header */
  udp->source = bpf_htons(GTPU_UDP_SPORT);
  udp->dest   = bpf_htons(GTPU_UDP_DPORT);
  udp->check  = 0;
  udp->len    = bpf_htons(xf->pm.l3_len +  olen - sizeof(*iph));

  /* GTP header */
  gh = (void *)(udp + 1);
  if (gh + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  gh->ver = GTP_VER_1;
  gh->pt = 1;
  gh->espn = espn;
  gh->teid = tid;
  gh->mt = GTP_MT_TPDU;
  gh->mlen = bpf_ntohs(xf->pm.l3_len + ghlen);
  
  if (qfi) {
    /* GTP extension header */
    geh = (void *)(gh + 1);
    if (geh + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    geh->seq = 0;
    geh->npdu = 0;
    geh->next_hdr = GTP_NH_PDU_SESS;

    gedh = (void *)(geh + 1);
    if (gedh + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      return -1;
    }

    gedh->cmn.len = 1;
    gedh->cmn.pdu_type = GTP_PDU_SESS_DL;
    gedh->qfi = qfi;
    gedh->ppp = 0;
    gedh->rqi = 0;
    gedh->next_hdr = 0;
  }
  /* Tunnel metadata */
  xf->tm.tun_type  = LLB_TUN_GTP;
  xf->tm.tunnel_id = bpf_ntohl(tid);
  xf->pm.tun_off   = sizeof(*eth) + 
                    sizeof(*iph) + 
                    sizeof(*udp);
  xf->tm.tun_encap = 1;

  if (skip_md) {
    return 0;
  }

  /* 
   * Reset pipeline metadata 
   * If it is called from deparser, there is no need
   * to do the following (set skip_md = 1)
   */
  memcpy(&xf->il34m, &xf->l34m, sizeof(xf->l34m));
  xf->il2m.vlan[0] = 0;

  /* Outer L2 - MAC addr are invalid as of now */
  xf->pm.lkup_dmac[0] = 0xff;

  /* Outer L3 */
  xf->l34m.saddr4 = sip;
  xf->l34m.daddr4 = rip;
  xf->l34m.source = udp->source;
  xf->l34m.dest = udp->dest;
  xf->pm.l4_off = xf->pm.l3_off + sizeof(*iph);
  
  return 0;
}


/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 2531,
  "endLine": 2559,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "xdp2tc_has_xmd",
  "developer_inline_comments": [
    {
      "start_line": 2538,
      "end_line": 2538,
      "text": " Check XDP gave us some data_meta "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline xdp2tc_has_xmd (void *md, struct xfi *xf)\n",
    "{\n",
    "    void *data = DP_TC_PTR (DP_PDATA (md));\n",
    "    void *data_meta = DP_TC_PTR (DP_MDATA (md));\n",
    "    struct ll_xmdi *meta = data_meta;\n",
    "    if (meta + 1 <= data) {\n",
    "        if (meta->pi.skip != 0) {\n",
    "            xf->pm.tc = 0;\n",
    "            LLBS_PPLN_PASS (xf);\n",
    "            return 1;\n",
    "        }\n",
    "        if (meta->pi.iport) {\n",
    "            xf->pm.oport = meta->pi.iport;\n",
    "            LLBS_PPLN_REWIRE (xf);\n",
    "        }\n",
    "        else {\n",
    "            xf->pm.oport = meta->pi.oport;\n",
    "            LLBS_PPLN_RDR (xf);\n",
    "        }\n",
    "        xf->pm.tc = 0;\n",
    "        meta->pi.skip = 1;\n",
    "        return 1;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "LLBS_PPLN_RDR",
    "LLBS_PPLN_PASS",
    "LLBS_PPLN_REWIRE",
    "DP_MDATA",
    "DP_TC_PTR"
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
static int __always_inline
xdp2tc_has_xmd(void *md, struct xfi *xf)
{
  void *data      = DP_TC_PTR(DP_PDATA(md));
  void *data_meta = DP_TC_PTR(DP_MDATA(md));
  struct ll_xmdi *meta = data_meta;

  /* Check XDP gave us some data_meta */
  if (meta + 1 <= data) {
    if (meta->pi.skip != 0) {
      xf->pm.tc = 0;
      LLBS_PPLN_PASS(xf);
      return 1;
    }

    if (meta->pi.iport) {
      xf->pm.oport = meta->pi.iport;
      LLBS_PPLN_REWIRE(xf);
    } else {
      xf->pm.oport = meta->pi.oport;
      LLBS_PPLN_RDR(xf);
    }
    xf->pm.tc = 0;
    meta->pi.skip = 1;
    return 1;
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 2561,
  "endLine": 2581,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_cdefs.h",
  "funcName": "dp_tail_call",
  "developer_inline_comments": [
    {
      "start_line": 2571,
      "end_line": 2571,
      "text": " fa state can be reused "
    },
    {
      "start_line": 2575,
      "end_line": 2575,
      "text": " xfi state can be reused "
    }
  ],
  "updateMaps": [
    " fcas",
    " xfis"
  ],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa",
    " __u32 idx"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_tail_call",
    "bpf_map_update_elem",
    "tail_call"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "lwt_xmit",
    "cgroup_sock",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "perf_event",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_tail_call (void *ctx, struct xfi *xf, void *fa, __u32 idx)\n",
    "{\n",
    "    int z = 0;\n",
    "    if (xf->nm.ct_sts != 0) {\n",
    "        return DP_PASS;\n",
    "    }\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    bpf_map_update_elem (&fcas, &z, fa, BPF_ANY);\n",
    "\n",
    "#endif\n",
    "    bpf_map_update_elem (&xfis, &z, xf, BPF_ANY);\n",
    "    bpf_tail_call (ctx, &pgm_tbl, idx);\n",
    "    return DP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
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
static int __always_inline
dp_tail_call(void *ctx,  struct xfi *xf, void *fa, __u32 idx)
{
  int z = 0;

  if (xf->nm.ct_sts != 0) {
    return DP_PASS;
  }

#ifdef HAVE_DP_FC
  /* fa state can be reused */ 
  bpf_map_update_elem(&fcas, &z, fa, BPF_ANY);
#endif

  /* xfi state can be reused */ 
  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);

  bpf_tail_call(ctx, &pgm_tbl, idx);

  return DP_PASS;
}

#endif
