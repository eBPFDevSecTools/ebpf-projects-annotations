/*
 *  llb_kern_entry.c: LoxiLB Kernel eBPF entry points
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/common_pdi.h"
#include "../common/llb_dpapi.h"

#include "llb_kern_cdefs.h"
#include "llb_kern_sum.c"
#include "llb_kern_compose.c"
#include "llb_kern_policer.c"
#include "llb_kern_sessfwd.c"
#include "llb_kern_fw.c"
#include "llb_kern_ct.c"
#include "llb_kern_natlbfwd.c"
#include "llb_kern_l3fwd.c"
#include "llb_kern_l2fwd.c"
#include "llb_kern_devif.c"
#include "llb_kern_fcfwd.c"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "libbpf",
          "Return Type": "u32",
          "Description": "Get the SMP (symmetric multiprocessing) processor id. Note that all programs run with preemption disabled , which means that the SMP processor id is stable during all the execution of the program. ",
          "Return": " The SMP id of the processor running the program.",
          "Function Name": "bpf_get_smp_processor_id",
          "Input Params": [
            "{Type: voi ,Var: void}"
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
  "startLine": 31,
  "endLine": 59,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "dp_ing_pkt_main",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_entry.c: LoxiLB Kernel eBPF entry points *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 46,
      "end_line": 46,
      "text": " Handle parser results "
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
    "bpf_get_smp_processor_id"
  ],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "lwt_xmit",
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
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_ing_pkt_main (void *md, struct xfi *xf)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[PRSR] START cpu %d \\n\", bpf_get_smp_processor_id ());\n",
    "    LL_DBG_PRINTK (\"[PRSR] fi  %d\\n\", sizeof (*xf));\n",
    "    LL_DBG_PRINTK (\"[PRSR] fm  %d\\n\", sizeof (xf->fm));\n",
    "    LL_DBG_PRINTK (\"[PRSR] l2m %d\\n\", sizeof (xf->l2m));\n",
    "    LL_DBG_PRINTK (\"[PRSR] l34m %d\\n\", sizeof (xf->l34m));\n",
    "    LL_DBG_PRINTK (\"[PRSR] tm  %d\\n\", sizeof (xf->tm));\n",
    "    LL_DBG_PRINTK (\"[PRSR] qm  %d\\n\", sizeof (xf->qm));\n",
    "    if (xf->pm.phit & LLB_DP_FC_HIT) {\n",
    "        dp_parse_d0 (md, xf, 0);\n",
    "    }\n",
    "    if (xf->pm.pipe_act & LLB_PIPE_REWIRE) {\n",
    "        return dp_rewire_packet (md, xf);\n",
    "    }\n",
    "    else if (xf->pm.pipe_act & LLB_PIPE_RDR) {\n",
    "        return dp_redir_packet (md, xf);\n",
    "    }\n",
    "    if (xf->pm.pipe_act & LLB_PIPE_PASS || xf->pm.pipe_act & LLB_PIPE_TRAP) {\n",
    "        return DP_PASS;\n",
    "    }\n",
    "    return dp_ing_slow_main (md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_rewire_packet",
    "dp_ing_slow_main",
    "dp_parse_d0",
    "LL_DBG_PRINTK",
    "dp_redir_packet"
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
dp_ing_pkt_main(void *md, struct xfi *xf)
{
  LL_DBG_PRINTK("[PRSR] START cpu %d \n", bpf_get_smp_processor_id());
  LL_DBG_PRINTK("[PRSR] fi  %d\n", sizeof(*xf));
  LL_DBG_PRINTK("[PRSR] fm  %d\n", sizeof(xf->fm));
  LL_DBG_PRINTK("[PRSR] l2m %d\n", sizeof(xf->l2m));
  LL_DBG_PRINTK("[PRSR] l34m %d\n", sizeof(xf->l34m));
  LL_DBG_PRINTK("[PRSR] tm  %d\n", sizeof(xf->tm));
  LL_DBG_PRINTK("[PRSR] qm  %d\n", sizeof(xf->qm));

  if (xf->pm.phit & LLB_DP_FC_HIT) {
    dp_parse_d0(md, xf, 0);
  }

  /* Handle parser results */
  if (xf->pm.pipe_act & LLB_PIPE_REWIRE) {
    return dp_rewire_packet(md, xf);
  } else if (xf->pm.pipe_act & LLB_PIPE_RDR) {
    return dp_redir_packet(md, xf);
  }

  if (xf->pm.pipe_act & LLB_PIPE_PASS ||
      xf->pm.pipe_act & LLB_PIPE_TRAP) {
    return DP_PASS;
  }

  return dp_ing_slow_main(md, xf);
}

#ifndef LL_TC_EBPF
SEC("xdp_packet_hook")
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
    }
  ],
  "helperCallParams": {},
  "startLine": 63,
  "endLine": 79,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "xdp_packet_func",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  xfis"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
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
    "int xdp_packet_func (struct xdp_md *ctx)\n",
    "{\n",
    "    int z = 0;\n",
    "    struct xfi *xf;\n",
    "    LL_FC_PRINTK (\"[PRSR] xdp start\\n\");\n",
    "    xf = bpf_map_lookup_elem (& xfis, & z);\n",
    "    if (!xf) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    memset (xf, 0, sizeof *xf);\n",
    "    dp_parse_d0 (ctx, xf, 0);\n",
    "    return DP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_parse_d0",
    "memset",
    "LL_FC_PRINTK"
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
int  xdp_packet_func(struct xdp_md *ctx)
{
  int z = 0;
  struct xfi *xf;

  LL_FC_PRINTK("[PRSR] xdp start\n");

  xf = bpf_map_lookup_elem(&xfis, &z);
  if (!xf) {
    return DP_DROP;
  }
  memset(xf, 0, sizeof *xf);

  dp_parse_d0(ctx, xf, 0);

  return DP_PASS;
}

SEC("xdp_pass")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 82,
  "endLine": 85,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "xdp_pass_func",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
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
    "int xdp_pass_func (struct xdp_md *ctx)\n",
    "{\n",
    "    return dp_ing_pass_main (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_ing_pass_main"
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
int xdp_pass_func(struct xdp_md *ctx)
{
  return dp_ing_pass_main(ctx);
}

#else

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
    }
  ],
  "helperCallParams": {},
  "startLine": 89,
  "endLine": 107,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_packet_func__",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  xfis"
  ],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem"
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
    "static int __always_inline tc_packet_func__ (struct  __sk_buff *md)\n",
    "{\n",
    "    int val = 0;\n",
    "    struct xfi *xf;\n",
    "    xf = bpf_map_lookup_elem (& xfis, & val);\n",
    "    if (!xf) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    if (xf->pm.phit & LLB_DP_FC_HIT) {\n",
    "        memset (xf, 0, sizeof (*xf));\n",
    "        xf->pm.phit |= LLB_DP_FC_HIT;\n",
    "    }\n",
    "    xf->pm.tc = 1;\n",
    "    return dp_ing_pkt_main (md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "memset",
    "dp_ing_pkt_main"
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
tc_packet_func__(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  if (xf->pm.phit & LLB_DP_FC_HIT) {
    memset(xf, 0, sizeof(*xf));
    xf->pm.phit |= LLB_DP_FC_HIT;
  }
  xf->pm.tc = 1;

  return dp_ing_pkt_main(md, xf);
}

SEC("tc_packet_hook0")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 110,
  "endLine": 129,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_packet_func_fast",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "int",
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
    "int tc_packet_func_fast (struct  __sk_buff *md)\n",
    "{\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    struct xfi *xf;\n",
    "    DP_NEW_FCXF (xf);\n",
    "\n",
    "#ifdef HAVE_DP_EGR_HOOK\n",
    "    if (DP_LLB_INGP (md)) {\n",
    "        return DP_PASS;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    dp_parse_d0 (md, xf, 0);\n",
    "    return dp_ing_fc_main (md, xf);\n",
    "\n",
    "#else\n",
    "    return tc_packet_func__ (md);\n",
    "\n",
    "#endif\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_ing_fc_main",
    "dp_parse_d0",
    "DP_LLB_INGP",
    "DP_NEW_FCXF",
    "tc_packet_func__"
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
int tc_packet_func_fast(struct __sk_buff *md)
{
#ifdef HAVE_DP_FC
  struct xfi *xf;

  DP_NEW_FCXF(xf);

#ifdef HAVE_DP_EGR_HOOK
  if (DP_LLB_INGP(md)) {
    return DP_PASS;
  }
#endif

  dp_parse_d0(md, xf, 0);

  return dp_ing_fc_main(md, xf);
#else
  return tc_packet_func__(md);
#endif
}

SEC("tc_packet_hook1")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 132,
  "endLine": 135,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_packet_func",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "int",
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
    "int tc_packet_func (struct  __sk_buff *md)\n",
    "{\n",
    "    return tc_packet_func__ (md);\n",
    "}\n"
  ],
  "called_function_list": [
    "tc_packet_func__"
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
int tc_packet_func(struct __sk_buff *md)
{
  return tc_packet_func__(md);
}

SEC("tc_packet_hook2")
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
    }
  ],
  "helperCallParams": {},
  "startLine": 138,
  "endLine": 149,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_packet_func_slow",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  xfis"
  ],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
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
    "int tc_packet_func_slow (struct  __sk_buff *md)\n",
    "{\n",
    "    int val = 0;\n",
    "    struct xfi *xf;\n",
    "    xf = bpf_map_lookup_elem (& xfis, & val);\n",
    "    if (!xf) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    return dp_ing_ct_main (md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_ing_ct_main"
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
int tc_packet_func_slow(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_ing_ct_main(md, xf);
}

SEC("tc_packet_hook3")
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
    }
  ],
  "helperCallParams": {},
  "startLine": 152,
  "endLine": 163,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_packet_func_fw",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  xfis"
  ],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
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
    "int tc_packet_func_fw (struct  __sk_buff *md)\n",
    "{\n",
    "    int val = 0;\n",
    "    struct xfi *xf;\n",
    "    xf = bpf_map_lookup_elem (& xfis, & val);\n",
    "    if (!xf) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    return dp_do_fw_main (md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_fw_main"
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
int tc_packet_func_fw(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_do_fw_main(md, xf);
}

SEC("tc_packet_hook4")
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
    }
  ],
  "helperCallParams": {},
  "startLine": 166,
  "endLine": 177,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_csum_func1",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  xfis"
  ],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
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
    "int tc_csum_func1 (struct  __sk_buff *md)\n",
    "{\n",
    "    int val = 0;\n",
    "    struct xfi *xf;\n",
    "    xf = bpf_map_lookup_elem (& xfis, & val);\n",
    "    if (!xf) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    return dp_sctp_csum (md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_sctp_csum"
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
int tc_csum_func1(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_sctp_csum(md, xf);
}

SEC("tc_packet_hook5")
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
    }
  ],
  "helperCallParams": {},
  "startLine": 180,
  "endLine": 191,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_csum_func2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  xfis"
  ],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
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
    "int tc_csum_func2 (struct  __sk_buff *md)\n",
    "{\n",
    "    int val = 0;\n",
    "    struct xfi *xf;\n",
    "    xf = bpf_map_lookup_elem (& xfis, & val);\n",
    "    if (!xf) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    return dp_sctp_csum (md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_sctp_csum"
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
int tc_csum_func2(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_sctp_csum(md, xf);
}

SEC("tc_packet_hook6")
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
    }
  ],
  "helperCallParams": {},
  "startLine": 194,
  "endLine": 205,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_entry.c",
  "funcName": "tc_slow_unp_func",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  xfis"
  ],
  "input": [
    "struct  __sk_buff *md"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem"
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
    "int tc_slow_unp_func (struct  __sk_buff *md)\n",
    "{\n",
    "    int val = 0;\n",
    "    struct xfi *xf;\n",
    "    xf = bpf_map_lookup_elem (& xfis, & val);\n",
    "    if (!xf) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    return dp_unparse_packet_always_slow (md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_unparse_packet_always_slow"
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
int tc_slow_unp_func(struct __sk_buff *md)
{
  int val = 0;
  struct xfi *xf;

  xf = bpf_map_lookup_elem(&xfis, &val);
  if (!xf) {
    return DP_DROP;
  }

  return dp_unparse_packet_always_slow(md, xf);
}

#endif
