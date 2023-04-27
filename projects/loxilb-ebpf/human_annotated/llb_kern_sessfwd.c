/*
 *  llb_kern_sess.c: LoxiLB kernel eBPF Subscriber Session Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 15,
  "endLine": 22,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_sessfwd.c",
  "funcName": "dp_pipe_set_rm_gtp_tun",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_sess.c: LoxiLB kernel eBPF Subscriber Session Implementation *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
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
    "static int __always_inline dp_pipe_set_rm_gtp_tun (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[SESS] rm-gtp \\n\");\n",
    "    dp_pop_outer_metadata (ctx, xf, 0);\n",
    "    xf->tm.tun_type = LLB_TUN_GTP;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_pop_outer_metadata",
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
dp_pipe_set_rm_gtp_tun(void *ctx, struct xfi *xf)
{
  LL_DBG_PRINTK("[SESS] rm-gtp \n");
  dp_pop_outer_metadata(ctx, xf, 0);
  xf->tm.tun_type = LLB_TUN_GTP;
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 31,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_sessfwd.c",
  "funcName": "dp_pipe_set_rm_ipip_tun",
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
    "static int __always_inline dp_pipe_set_rm_ipip_tun (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[SESS] rm-ipip \\n\");\n",
    "    dp_pop_outer_metadata (ctx, xf, 0);\n",
    "    xf->tm.tun_type = LLB_TUN_IPIP;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_pop_outer_metadata",
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
dp_pipe_set_rm_ipip_tun(void *ctx, struct xfi *xf)
{
  LL_DBG_PRINTK("[SESS] rm-ipip \n");
  dp_pop_outer_metadata(ctx, xf, 0);
  xf->tm.tun_type = LLB_TUN_IPIP;
  return 0;
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
    }
  ],
  "helperCallParams": {},
  "startLine": 33,
  "endLine": 96,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_sessfwd.c",
  "funcName": "dp_do_sess4_lkup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  sess_v4_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf"
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
    "static int __always_inline dp_do_sess4_lkup (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct dp_sess4_key key;\n",
    "    struct dp_sess_tact *act;\n",
    "    key.r = 0;\n",
    "    if (xf->tm.tunnel_id && xf->tm.tun_type != LLB_TUN_IPIP) {\n",
    "        key.daddr = xf->il34m.daddr4;\n",
    "        key.saddr = xf->il34m.saddr4;\n",
    "        key.teid = bpf_ntohl (xf->tm.tunnel_id);\n",
    "    }\n",
    "    else {\n",
    "        if (xf->pm.nf == LLB_NAT_SRC) {\n",
    "            key.saddr = xf->nm.nxip4;\n",
    "            key.daddr = xf->l34m.daddr4;\n",
    "        }\n",
    "        else if (xf->pm.nf == LLB_NAT_DST) {\n",
    "            key.daddr = xf->nm.nxip4;\n",
    "            key.saddr = xf->l34m.saddr4;\n",
    "        }\n",
    "        else {\n",
    "            key.daddr = xf->l34m.daddr4;\n",
    "            key.saddr = xf->l34m.saddr4;\n",
    "        }\n",
    "        key.teid = 0;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[SESS4] -- Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[SESS4] daddr %x\\n\", key.daddr);\n",
    "    LL_DBG_PRINTK (\"[SESS4] saddr %x\\n\", key.saddr);\n",
    "    LL_DBG_PRINTK (\"[SESS4] teid 0x%x\\n\", key.teid);\n",
    "    xf->pm.table_id = LL_DP_SESS4_MAP;\n",
    "    act = bpf_map_lookup_elem (& sess_v4_map, & key);\n",
    "    if (!act) {\n",
    "        LL_DBG_PRINTK (\"[SESS4] miss\");\n",
    "        return 0;\n",
    "    }\n",
    "    xf->pm.phit |= LLB_DP_SESS_HIT;\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_SESS4_STATS_MAP, act->ca.cidx);\n",
    "    if (act->ca.act_type == DP_SET_DROP) {\n",
    "        goto drop;\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_RM_GTP) {\n",
    "        dp_pipe_set_rm_gtp_tun (ctx, xf);\n",
    "        xf->qm.qfi = act->qfi;\n",
    "        xf->pm.phit |= LLB_DP_TMAC_HIT;\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_RM_IPIP) {\n",
    "        dp_pipe_set_rm_ipip_tun (ctx, xf);\n",
    "        xf->pm.phit |= LLB_DP_TMAC_HIT;\n",
    "    }\n",
    "    else {\n",
    "        xf->tm.new_tunnel_id = act->teid;\n",
    "        xf->tm.tun_type = LLB_TUN_GTP;\n",
    "        xf->qm.qfi = act->qfi;\n",
    "        xf->tm.tun_rip = act->rip;\n",
    "        xf->tm.tun_sip = act->sip;\n",
    "    }\n",
    "    return 0;\n",
    "drop :\n",
    "    LLBS_PPLN_DROP (xf);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "dp_do_map_stats",
    "LL_DBG_PRINTK",
    "dp_pipe_set_rm_ipip_tun",
    "bpf_ntohl",
    "dp_pipe_set_rm_gtp_tun"
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
dp_do_sess4_lkup(void *ctx, struct xfi *xf)
{
  struct dp_sess4_key key;
  struct dp_sess_tact *act;

  key.r = 0;
  if (xf->tm.tunnel_id && xf->tm.tun_type != LLB_TUN_IPIP) {
    key.daddr = xf->il34m.daddr4;
    key.saddr = xf->il34m.saddr4;
    key.teid = bpf_ntohl(xf->tm.tunnel_id);
  } else {
    if (xf->pm.nf == LLB_NAT_SRC) {
      key.saddr = xf->nm.nxip4;
      key.daddr = xf->l34m.daddr4;
    } else if (xf->pm.nf == LLB_NAT_DST) {
      key.daddr = xf->nm.nxip4;
      key.saddr = xf->l34m.saddr4;
    } else {
      key.daddr = xf->l34m.daddr4;
      key.saddr = xf->l34m.saddr4;
    }
    key.teid = 0;
  }

  LL_DBG_PRINTK("[SESS4] -- Lookup\n");
  LL_DBG_PRINTK("[SESS4] daddr %x\n", key.daddr);
  LL_DBG_PRINTK("[SESS4] saddr %x\n", key.saddr);
  LL_DBG_PRINTK("[SESS4] teid 0x%x\n", key.teid);

  xf->pm.table_id = LL_DP_SESS4_MAP;

  act = bpf_map_lookup_elem(&sess_v4_map, &key);
  if (!act) {
    LL_DBG_PRINTK("[SESS4] miss");
    return 0;
  }

  xf->pm.phit |= LLB_DP_SESS_HIT;
  dp_do_map_stats(ctx, xf, LL_DP_SESS4_STATS_MAP, act->ca.cidx);

  if (act->ca.act_type == DP_SET_DROP) {
    goto drop;
  } else if (act->ca.act_type == DP_SET_RM_GTP) {
    dp_pipe_set_rm_gtp_tun(ctx, xf);
    xf->qm.qfi = act->qfi;
    xf->pm.phit |= LLB_DP_TMAC_HIT;
  } else if (act->ca.act_type == DP_SET_RM_IPIP) {
    dp_pipe_set_rm_ipip_tun(ctx, xf);
    xf->pm.phit |= LLB_DP_TMAC_HIT;
  } else {
    xf->tm.new_tunnel_id = act->teid;
    xf->tm.tun_type = LLB_TUN_GTP;
    xf->qm.qfi = act->qfi;
    xf->tm.tun_rip = act->rip;
    xf->tm.tun_sip = act->sip;
  }

  return 0;

drop:
  LLBS_PPLN_DROP(xf);
  return 0;
}
