/*
 *  llb_kern_l2fwd.c: LoxiLB kernel eBPF L2 forwarder Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
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
  "startLine": 7,
  "endLine": 50,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_do_smac_lkup",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_l2fwd.c: LoxiLB kernel eBPF L2 forwarder Implementation *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 31,
      "end_line": 31,
      "text": " Default action "
    },
    {
      "start_line": 43,
      "end_line": 43,
      "text": " Nothing to do "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  smac_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fc"
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
    "static int __always_inline dp_do_smac_lkup (void *ctx, struct xfi *xf, void *fc)\n",
    "{\n",
    "    struct dp_smac_key key;\n",
    "    struct dp_smac_tact *sma;\n",
    "    if (xf->l2m.vlan[0] == 0) {\n",
    "        return 0;\n",
    "    }\n",
    "    memcpy (key.smac, xf->l2m.dl_src, 6);\n",
    "    key.bd = xf->pm.bd;\n",
    "    LL_DBG_PRINTK (\"[SMAC] -- Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[SMAC] %x:%x:%x\\n\", key.smac[0], key.smac[1], key.smac[2]);\n",
    "    LL_DBG_PRINTK (\"[SMAC] %x:%x:%x\\n\", key.smac[3], key.smac[4], key.smac[5]);\n",
    "    LL_DBG_PRINTK (\"[SMAC] BD%d\\n\", key.bd);\n",
    "    xf->pm.table_id = LL_DP_SMAC_MAP;\n",
    "    sma = bpf_map_lookup_elem (& smac_map, & key);\n",
    "    if (!sma) {\n",
    "        LLBS_PPLN_PASS (xf);\n",
    "        return 0;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[SMAC] action %d\\n\", sma->ca.act_type);\n",
    "    if (sma->ca.act_type == DP_SET_DROP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    else if (sma->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAP (xf);\n",
    "    }\n",
    "    else if (sma->ca.act_type == DP_SET_NOP) {\n",
    "        return 0;\n",
    "    }\n",
    "    else {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "LLBS_PPLN_PASS",
    "LL_DBG_PRINTK",
    "LLBS_PPLN_TRAP",
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
dp_do_smac_lkup(void *ctx, struct xfi *xf, void *fc)
{
  struct dp_smac_key key;
  struct dp_smac_tact *sma;

  if (xf->l2m.vlan[0] == 0) {
    return 0;
  }

  memcpy(key.smac, xf->l2m.dl_src, 6);
  key.bd = xf->pm.bd;

  LL_DBG_PRINTK("[SMAC] -- Lookup\n");
  LL_DBG_PRINTK("[SMAC] %x:%x:%x\n",
                 key.smac[0], key.smac[1], key.smac[2]);
  LL_DBG_PRINTK("[SMAC] %x:%x:%x\n",
                 key.smac[3], key.smac[4], key.smac[5]);
  LL_DBG_PRINTK("[SMAC] BD%d\n", key.bd);

  xf->pm.table_id = LL_DP_SMAC_MAP;

  sma = bpf_map_lookup_elem(&smac_map, &key);
  if (!sma) {
    /* Default action */
    LLBS_PPLN_PASS(xf);
    return 0;
  }

  LL_DBG_PRINTK("[SMAC] action %d\n", sma->ca.act_type);

  if (sma->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROP(xf);
  } else if (sma->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAP(xf);
  } else if (sma->ca.act_type == DP_SET_NOP) {
    /* Nothing to do */
    return 0;
  } else {
    LLBS_PPLN_DROP(xf);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 52,
  "endLine": 65,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_pipe_set_l22_tun_nh",
  "developer_inline_comments": [
    {
      "start_line": 57,
      "end_line": 60,
      "text": "   * We do not set out_bd here. After NH lookup match is   * found and packet tunnel insertion is done, BD is set accordingly   "
    },
    {
      "start_line": 61,
      "end_line": 61,
      "text": "xf->pm.bd = rnh->bd;"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_rt_nh_act *rnh"
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
    "static int __always_inline dp_pipe_set_l22_tun_nh (void *ctx, struct xfi *xf, struct dp_rt_nh_act *rnh)\n",
    "{\n",
    "    xf->pm.nh_num = rnh->nh_num;\n",
    "    xf->tm.new_tunnel_id = rnh->tid;\n",
    "    LL_DBG_PRINTK (\"[TMAC] new-vx nh %u\\n\", xf->pm.nh_num);\n",
    "    return 0;\n",
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
dp_pipe_set_l22_tun_nh(void *ctx, struct xfi *xf, struct dp_rt_nh_act *rnh)
{
  xf->pm.nh_num = rnh->nh_num;

  /*
   * We do not set out_bd here. After NH lookup match is
   * found and packet tunnel insertion is done, BD is set accordingly
   */
  /*xf->pm.bd = rnh->bd;*/
  xf->tm.new_tunnel_id = rnh->tid;
  LL_DBG_PRINTK("[TMAC] new-vx nh %u\n", xf->pm.nh_num);
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 67,
  "endLine": 75,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_pipe_set_rm_vx_tun",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_rt_nh_act *rnh"
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
    "static int __always_inline dp_pipe_set_rm_vx_tun (void *ctx, struct xfi *xf, struct dp_rt_nh_act *rnh)\n",
    "{\n",
    "    xf->pm.phit &= ~LLB_DP_TMAC_HIT;\n",
    "    xf->pm.bd = rnh->bd;\n",
    "    LL_DBG_PRINTK (\"[TMAC] rm-vx newbd %d \\n\", xf->pm.bd);\n",
    "    return dp_pop_outer_metadata (ctx, xf, 1);\n",
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
dp_pipe_set_rm_vx_tun(void *ctx, struct xfi *xf, struct dp_rt_nh_act *rnh)
{
  xf->pm.phit &= ~LLB_DP_TMAC_HIT;
  xf->pm.bd = rnh->bd;

  LL_DBG_PRINTK("[TMAC] rm-vx newbd %d \n", xf->pm.bd);
  return dp_pop_outer_metadata(ctx, xf, 1);
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
  "startLine": 77,
  "endLine": 140,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "__dp_do_tmac_lkup",
  "developer_inline_comments": [
    {
      "start_line": 108,
      "end_line": 108,
      "text": " No L3 lookup "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  tmac_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " int tun_lkup",
    " void *fa_"
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
    "static int __always_inline __dp_do_tmac_lkup (void *ctx, struct xfi *xf, int tun_lkup, void *fa_)\n",
    "{\n",
    "    struct dp_tmac_key key;\n",
    "    struct dp_tmac_tact *tma;\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "    struct dp_fc_tacts *fa = fa_;\n",
    "\n",
    "#endif\n",
    "    memcpy (key.mac, xf->l2m.dl_dst, 6);\n",
    "    key.pad = 0;\n",
    "    if (tun_lkup) {\n",
    "        key.tunnel_id = xf->tm.tunnel_id;\n",
    "        key.tun_type = xf->tm.tun_type;\n",
    "    }\n",
    "    else {\n",
    "        key.tunnel_id = 0;\n",
    "        key.tun_type = 0;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[TMAC] -- Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[TMAC] %x:%x:%x\\n\", key.mac[0], key.mac[1], key.mac[2]);\n",
    "    LL_DBG_PRINTK (\"[TMAC] %x:%x:%x\\n\", key.mac[3], key.mac[4], key.mac[5]);\n",
    "    LL_DBG_PRINTK (\"[TMAC] %x:%x\\n\", key.tunnel_id, key.tun_type);\n",
    "    xf->pm.table_id = LL_DP_TMAC_MAP;\n",
    "    tma = bpf_map_lookup_elem (& tmac_map, & key);\n",
    "    if (!tma) {\n",
    "        return 0;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[TMAC] action %d %d\\n\", tma->ca.act_type, tma->ca.cidx);\n",
    "    if (tma->ca.cidx != 0) {\n",
    "        dp_do_map_stats (ctx, xf, LL_DP_TMAC_STATS_MAP, tma->ca.cidx);\n",
    "    }\n",
    "    if (tma->ca.act_type == DP_SET_DROP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    else if (tma->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAP (xf);\n",
    "    }\n",
    "    else if (tma->ca.act_type == DP_SET_RT_TUN_NH) {\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "        struct dp_fc_tact *ta = &fa->fcta[DP_SET_RT_TUN_NH];\n",
    "        ta->ca.act_type = DP_SET_RT_TUN_NH;\n",
    "        memcpy (&ta->nh_act, &tma->rt_nh, sizeof (tma->rt_nh));\n",
    "\n",
    "#endif\n",
    "        return dp_pipe_set_l22_tun_nh (ctx, xf, &tma->rt_nh);\n",
    "    }\n",
    "    else if (tma->ca.act_type == DP_SET_L3_EN) {\n",
    "        xf->pm.phit |= LLB_DP_TMAC_HIT;\n",
    "    }\n",
    "    else if (tma->ca.act_type == DP_SET_RM_VXLAN) {\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "        struct dp_fc_tact *ta = &fa->fcta[DP_SET_RM_VXLAN];\n",
    "        ta->ca.act_type = DP_SET_RM_VXLAN;\n",
    "        memcpy (&ta->nh_act, &tma->rt_nh, sizeof (tma->rt_nh));\n",
    "\n",
    "#endif\n",
    "        return dp_pipe_set_rm_vx_tun (ctx, xf, &tma->rt_nh);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "dp_pipe_set_l22_tun_nh",
    "dp_do_map_stats",
    "LL_DBG_PRINTK",
    "LLBS_PPLN_TRAP",
    "dp_pipe_set_rm_vx_tun",
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
__dp_do_tmac_lkup(void *ctx, struct xfi *xf,
                  int tun_lkup, void *fa_)
{
  struct dp_tmac_key key;
  struct dp_tmac_tact *tma;
#ifdef HAVE_DP_EXTFC
  struct dp_fc_tacts *fa = fa_;
#endif

  memcpy(key.mac, xf->l2m.dl_dst, 6);
  key.pad  = 0;
  if (tun_lkup) {
    key.tunnel_id = xf->tm.tunnel_id;
    key.tun_type = xf->tm.tun_type;
  } else {
    key.tunnel_id = 0;
    key.tun_type  = 0;
  }

  LL_DBG_PRINTK("[TMAC] -- Lookup\n");
  LL_DBG_PRINTK("[TMAC] %x:%x:%x\n",
                 key.mac[0], key.mac[1], key.mac[2]);
  LL_DBG_PRINTK("[TMAC] %x:%x:%x\n",
                 key.mac[3], key.mac[4], key.mac[5]);
  LL_DBG_PRINTK("[TMAC] %x:%x\n", key.tunnel_id, key.tun_type);

  xf->pm.table_id = LL_DP_TMAC_MAP;

  tma = bpf_map_lookup_elem(&tmac_map, &key);
  if (!tma) {
    /* No L3 lookup */
    return 0;
  }

  LL_DBG_PRINTK("[TMAC] action %d %d\n", tma->ca.act_type, tma->ca.cidx);
  if (tma->ca.cidx != 0) {
    dp_do_map_stats(ctx, xf, LL_DP_TMAC_STATS_MAP, tma->ca.cidx);
  }

  if (tma->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROP(xf);
  } else if (tma->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAP(xf);
  } else if (tma->ca.act_type == DP_SET_RT_TUN_NH) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_RT_TUN_NH];
    ta->ca.act_type = DP_SET_RT_TUN_NH;
    memcpy(&ta->nh_act,  &tma->rt_nh, sizeof(tma->rt_nh));
#endif
    return dp_pipe_set_l22_tun_nh(ctx, xf, &tma->rt_nh);
  } else if (tma->ca.act_type == DP_SET_L3_EN) {
    xf->pm.phit |= LLB_DP_TMAC_HIT;
  } else if (tma->ca.act_type == DP_SET_RM_VXLAN) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_RM_VXLAN];
    ta->ca.act_type = DP_SET_RM_VXLAN;
    memcpy(&ta->nh_act,  &tma->rt_nh, sizeof(tma->rt_nh));
#endif
    return dp_pipe_set_rm_vx_tun(ctx, xf, &tma->rt_nh);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 142,
  "endLine": 146,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_do_tmac_lkup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa"
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
    "static int __always_inline dp_do_tmac_lkup (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    return __dp_do_tmac_lkup (ctx, xf, 0, fa);\n",
    "}\n"
  ],
  "called_function_list": [
    "__dp_do_tmac_lkup"
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
dp_do_tmac_lkup(void *ctx, struct xfi *xf, void *fa)
{
  return __dp_do_tmac_lkup(ctx, xf, 0, fa);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 148,
  "endLine": 155,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_do_tun_lkup",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa"
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
    "static int __always_inline dp_do_tun_lkup (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    if (xf->tm.tunnel_id != 0) {\n",
    "        return __dp_do_tmac_lkup (ctx, xf, 1, fa);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "__dp_do_tmac_lkup"
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
dp_do_tun_lkup(void *ctx, struct xfi *xf, void *fa)
{
  if (xf->tm.tunnel_id != 0) {
    return __dp_do_tmac_lkup(ctx, xf, 1, fa);
  }
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 157,
  "endLine": 166,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_set_egr_vlan",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __u16 vlan",
    " __u16 oport"
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
    "static int __always_inline dp_set_egr_vlan (void *ctx, struct xfi *xf, __u16 vlan, __u16 oport)\n",
    "{\n",
    "    LLBS_PPLN_RDR (xf);\n",
    "    xf->pm.oport = oport;\n",
    "    xf->pm.bd = vlan;\n",
    "    LL_DBG_PRINTK (\"[SETVLAN] OP %u V %u\\n\", oport, vlan);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_RDR",
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
dp_set_egr_vlan(void *ctx, struct xfi *xf,
                __u16 vlan, __u16 oport)
{
  LLBS_PPLN_RDR(xf);
  xf->pm.oport = oport;
  xf->pm.bd = vlan;
  LL_DBG_PRINTK("[SETVLAN] OP %u V %u\n", oport, vlan);
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
  "startLine": 168,
  "endLine": 226,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_do_dmac_lkup",
  "developer_inline_comments": [
    {
      "start_line": 190,
      "end_line": 190,
      "text": " No DMAC lookup "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  dmac_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa_"
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
    "static int __always_inline dp_do_dmac_lkup (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    struct dp_dmac_key key;\n",
    "    struct dp_dmac_tact *dma;\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    struct dp_fc_tacts *fa = fa_;\n",
    "\n",
    "#endif\n",
    "    memcpy (key.dmac, xf->pm.lkup_dmac, 6);\n",
    "    key.bd = xf->pm.bd;\n",
    "    xf->pm.table_id = LL_DP_DMAC_MAP;\n",
    "    LL_DBG_PRINTK (\"[DMAC] -- Lookup \\n\");\n",
    "    LL_DBG_PRINTK (\"[DMAC] %x:%x:%x\\n\", key.dmac[0], key.dmac[1], key.dmac[2]);\n",
    "    LL_DBG_PRINTK (\"[DMAC] %x:%x:%x\\n\", key.dmac[3], key.dmac[4], key.dmac[5]);\n",
    "    LL_DBG_PRINTK (\"[DMAC] BD %d\\n\", key.bd);\n",
    "    dma = bpf_map_lookup_elem (& dmac_map, & key);\n",
    "    if (!dma) {\n",
    "        LL_DBG_PRINTK (\"[DMAC] not found\\n\");\n",
    "        LLBS_PPLN_PASS (xf);\n",
    "        return 0;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[DMAC] action %d pipe %d\\n\", dma->ca.act_type, xf->pm.pipe_act);\n",
    "    if (dma->ca.act_type == DP_SET_DROP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    else if (dma->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAP (xf);\n",
    "    }\n",
    "    else if (dma->ca.act_type == DP_SET_RDR_PORT) {\n",
    "        struct dp_rdr_act *ra = &dma->port_act;\n",
    "        LLBS_PPLN_RDR (xf);\n",
    "        xf->pm.oport = ra->oport;\n",
    "        LL_DBG_PRINTK (\"[DMAC] oport %lu\\n\", xf->pm.oport);\n",
    "        return 0;\n",
    "    }\n",
    "    else if (dma->ca.act_type == DP_SET_ADD_L2VLAN || dma->ca.act_type == DP_SET_RM_L2VLAN) {\n",
    "        struct dp_l2vlan_act *va = &dma->vlan_act;\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "        struct dp_fc_tact *ta = &fa->fcta[dma->ca.act_type == DP_SET_ADD_L2VLAN ? DP_SET_ADD_L2VLAN : DP_SET_RM_L2VLAN];\n",
    "        ta->ca.act_type = dma->ca.act_type;\n",
    "        memcpy (&ta->l2ov, va, sizeof (*va));\n",
    "\n",
    "#endif\n",
    "        return dp_set_egr_vlan (ctx, xf, dma->ca.act_type == DP_SET_RM_L2VLAN ? 0 : va->vlan, va->oport);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "LLBS_PPLN_RDR",
    "LLBS_PPLN_PASS",
    "LL_DBG_PRINTK",
    "dp_set_egr_vlan",
    "LLBS_PPLN_TRAP",
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
dp_do_dmac_lkup(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_dmac_key key;
  struct dp_dmac_tact *dma;
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  memcpy(key.dmac, xf->pm.lkup_dmac, 6);
  key.bd = xf->pm.bd;
  xf->pm.table_id = LL_DP_DMAC_MAP;

  LL_DBG_PRINTK("[DMAC] -- Lookup \n");
  LL_DBG_PRINTK("[DMAC] %x:%x:%x\n",
                 key.dmac[0], key.dmac[1], key.dmac[2]);
  LL_DBG_PRINTK("[DMAC] %x:%x:%x\n", 
                 key.dmac[3], key.dmac[4], key.dmac[5]);
  LL_DBG_PRINTK("[DMAC] BD %d\n", key.bd);

  dma = bpf_map_lookup_elem(&dmac_map, &key);
  if (!dma) {
    /* No DMAC lookup */
    LL_DBG_PRINTK("[DMAC] not found\n");
    LLBS_PPLN_PASS(xf);
    return 0;
  }

  LL_DBG_PRINTK("[DMAC] action %d pipe %d\n",
                 dma->ca.act_type, xf->pm.pipe_act);

  if (dma->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROP(xf);
  } else if (dma->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAP(xf);
  } else if (dma->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ra = &dma->port_act;

    LLBS_PPLN_RDR(xf);
    xf->pm.oport = ra->oport;
    LL_DBG_PRINTK("[DMAC] oport %lu\n", xf->pm.oport);
    return 0;
  } else if (dma->ca.act_type == DP_SET_ADD_L2VLAN || 
             dma->ca.act_type == DP_SET_RM_L2VLAN) {
    struct dp_l2vlan_act *va = &dma->vlan_act;
#ifdef HAVE_DP_FC
    struct dp_fc_tact *ta = &fa->fcta[
                          dma->ca.act_type == DP_SET_ADD_L2VLAN ?
                          DP_SET_ADD_L2VLAN : DP_SET_RM_L2VLAN];
    ta->ca.act_type = dma->ca.act_type;
    memcpy(&ta->l2ov,  va, sizeof(*va));
#endif
    return dp_set_egr_vlan(ctx, xf, 
                    dma->ca.act_type == DP_SET_RM_L2VLAN ?
                    0 : va->vlan, va->oport);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 228,
  "endLine": 238,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_do_rt_l2_nh",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_rt_l2nh_act *nl2"
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
    "static int __always_inline dp_do_rt_l2_nh (void *ctx, struct xfi *xf, struct dp_rt_l2nh_act *nl2)\n",
    "{\n",
    "    memcpy (xf->l2m.dl_dst, nl2->dmac, 6);\n",
    "    memcpy (xf->l2m.dl_src, nl2->smac, 6);\n",
    "    memcpy (xf->pm.lkup_dmac, nl2->dmac, 6);\n",
    "    xf->pm.bd = nl2->bd;\n",
    "    return nl2->rnh_num;\n",
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
dp_do_rt_l2_nh(void *ctx, struct xfi *xf,
               struct dp_rt_l2nh_act *nl2)
{
  memcpy(xf->l2m.dl_dst, nl2->dmac, 6);
  memcpy(xf->l2m.dl_src, nl2->smac, 6);
  memcpy(xf->pm.lkup_dmac, nl2->dmac, 6);
  xf->pm.bd = nl2->bd;
 
  return nl2->rnh_num;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 240,
  "endLine": 263,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_do_rt_tun_nh",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " __u32 tun_type",
    " struct dp_rt_tunnh_act *ntun"
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
    "static int __always_inline dp_do_rt_tun_nh (void *ctx, struct xfi *xf, __u32 tun_type, struct dp_rt_tunnh_act *ntun)\n",
    "{\n",
    "    struct dp_rt_l2nh_act *nl2;\n",
    "    xf->tm.tun_rip = ntun->l3t.rip;\n",
    "    xf->tm.tun_sip = ntun->l3t.sip;\n",
    "    xf->tm.new_tunnel_id = ntun->l3t.tid;\n",
    "    xf->tm.tun_type = tun_type;\n",
    "    if (tun_type == LLB_TUN_VXLAN) {\n",
    "        memcpy (&xf->il2m, &xf->l2m, sizeof (xf->l2m));\n",
    "        xf->il2m.vlan[0] = 0;\n",
    "    }\n",
    "    nl2 = &ntun->l2nh;\n",
    "    memcpy (xf->l2m.dl_dst, nl2->dmac, 6);\n",
    "    memcpy (xf->l2m.dl_src, nl2->smac, 6);\n",
    "    memcpy (xf->pm.lkup_dmac, nl2->dmac, 6);\n",
    "    xf->pm.bd = nl2->bd;\n",
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
dp_do_rt_tun_nh(void *ctx, struct xfi *xf, __u32 tun_type,
                struct dp_rt_tunnh_act *ntun)
{
  struct dp_rt_l2nh_act *nl2;

  xf->tm.tun_rip = ntun->l3t.rip;
  xf->tm.tun_sip = ntun->l3t.sip;
  xf->tm.new_tunnel_id = ntun->l3t.tid;
  xf->tm.tun_type = tun_type;

  if (tun_type == LLB_TUN_VXLAN) {
    memcpy(&xf->il2m, &xf->l2m, sizeof(xf->l2m));
    xf->il2m.vlan[0] = 0;
  }

  nl2 = &ntun->l2nh;
  memcpy(xf->l2m.dl_dst, nl2->dmac, 6);
  memcpy(xf->l2m.dl_src, nl2->smac, 6);
  memcpy(xf->pm.lkup_dmac, nl2->dmac, 6);
  xf->pm.bd = nl2->bd;
 
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
  "startLine": 265,
  "endLine": 326,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_do_nh_lkup",
  "developer_inline_comments": [
    {
      "start_line": 282,
      "end_line": 282,
      "text": " No NH - Drop "
    },
    {
      "start_line": 301,
      "end_line": 301,
      "text": " Check if need to do recursive next-hop lookup "
    },
    {
      "start_line": 306,
      "end_line": 306,
      "text": " No NH - Trap "
    },
    {
      "start_line": 307,
      "end_line": 307,
      "text": " LLBS_PPLN_DROP(xf); "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  nh_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa_"
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
    "static int __always_inline dp_do_nh_lkup (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    struct dp_nh_key key;\n",
    "    struct dp_nh_tact *nha;\n",
    "    int rnh = 0;\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    struct dp_fc_tacts *fa = fa_;\n",
    "\n",
    "#endif\n",
    "    key.nh_num = (__u32) xf->pm.nh_num;\n",
    "    LL_DBG_PRINTK (\"[NHFW] -- Lookup ID %d\\n\", key.nh_num);\n",
    "    xf->pm.table_id = LL_DP_NH_MAP;\n",
    "    nha = bpf_map_lookup_elem (& nh_map, & key);\n",
    "    if (!nha) {\n",
    "        LLBS_PPLN_TRAP (xf)\n",
    "        return 0;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[NHFW] action %d pipe %x\\n\", nha->ca.act_type, xf->pm.pipe_act);\n",
    "    if (nha->ca.act_type == DP_SET_DROP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    else if (nha->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAP (xf);\n",
    "    }\n",
    "    else if (nha->ca.act_type == DP_SET_NEIGH_L2) {\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "        struct dp_fc_tact *ta = &fa->fcta[DP_SET_NEIGH_L2];\n",
    "        ta->ca.act_type = nha->ca.act_type;\n",
    "        memcpy (&ta->nl2, &nha->rt_l2nh, sizeof (nha->rt_l2nh));\n",
    "\n",
    "#endif\n",
    "        rnh = dp_do_rt_l2_nh (ctx, xf, & nha -> rt_l2nh);\n",
    "        if (rnh != 0) {\n",
    "            key.nh_num = (__u32) rnh;\n",
    "            nha = bpf_map_lookup_elem (& nh_map, & key);\n",
    "            if (!nha) {\n",
    "                LLBS_PPLN_TRAP (xf)\n",
    "                return 0;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (nha->ca.act_type == DP_SET_NEIGH_VXLAN) {\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "        struct dp_fc_tact *ta = &fa->fcta[DP_SET_NEIGH_VXLAN];\n",
    "        ta->ca.act_type = nha->ca.act_type;\n",
    "        memcpy (&ta->ntun, &nha->rt_tnh, sizeof (nha->rt_tnh));\n",
    "\n",
    "#endif\n",
    "        return dp_do_rt_tun_nh (ctx, xf, LLB_TUN_VXLAN, &nha->rt_tnh);\n",
    "    }\n",
    "    else if (nha->ca.act_type == DP_SET_NEIGH_IPIP) {\n",
    "        return dp_do_rt_tun_nh (ctx, xf, LLB_TUN_IPIP, &nha->rt_tnh);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_rt_l2_nh",
    "LLBS_PPLN_DROP",
    "LL_DBG_PRINTK",
    "dp_do_rt_tun_nh",
    "LLBS_PPLN_TRAP",
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
dp_do_nh_lkup(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_nh_key key;
  struct dp_nh_tact *nha;
  int rnh = 0;
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  key.nh_num = (__u32)xf->pm.nh_num;

  LL_DBG_PRINTK("[NHFW] -- Lookup ID %d\n", key.nh_num);
  xf->pm.table_id = LL_DP_NH_MAP;

  nha = bpf_map_lookup_elem(&nh_map, &key);
  if (!nha) {
    /* No NH - Drop */
    LLBS_PPLN_TRAP(xf)
    return 0;
  }

  LL_DBG_PRINTK("[NHFW] action %d pipe %x\n",
                nha->ca.act_type, xf->pm.pipe_act);

  if (nha->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROP(xf);
  } else if (nha->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAP(xf);
  } else if (nha->ca.act_type == DP_SET_NEIGH_L2) {
#ifdef HAVE_DP_FC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_NEIGH_L2];
    ta->ca.act_type = nha->ca.act_type;
    memcpy(&ta->nl2,  &nha->rt_l2nh, sizeof(nha->rt_l2nh));
#endif
    rnh = dp_do_rt_l2_nh(ctx, xf, &nha->rt_l2nh);
    /* Check if need to do recursive next-hop lookup */
    if (rnh != 0) {
      key.nh_num = (__u32)rnh;
      nha = bpf_map_lookup_elem(&nh_map, &key);
      if (!nha) {
        /* No NH - Trap */
        // LLBS_PPLN_DROP(xf); //
        LLBS_PPLN_TRAP(xf)
        return 0;
      }
    }
  } 

  if (nha->ca.act_type == DP_SET_NEIGH_VXLAN) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_NEIGH_VXLAN];
    ta->ca.act_type = nha->ca.act_type;
    memcpy(&ta->ntun,  &nha->rt_tnh, sizeof(nha->rt_tnh));
#endif
    return dp_do_rt_tun_nh(ctx, xf, LLB_TUN_VXLAN, &nha->rt_tnh);
  } else if (nha->ca.act_type == DP_SET_NEIGH_IPIP) {
    return dp_do_rt_tun_nh(ctx, xf, LLB_TUN_IPIP, &nha->rt_tnh);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 328,
  "endLine": 344,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_eg_l2",
  "developer_inline_comments": [
    {
      "start_line": 331,
      "end_line": 331,
      "text": " Any processing based on results from L3 "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa"
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
    "static int __always_inline dp_eg_l2 (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    if (xf->pm.pipe_act & LLB_PIPE_RDR_MASK) {\n",
    "        return 0;\n",
    "    }\n",
    "    if (xf->pm.nh_num != 0) {\n",
    "        dp_do_nh_lkup (ctx, xf, fa);\n",
    "    }\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_TX_BD_STATS_MAP, xf->pm.bd);\n",
    "    dp_do_dmac_lkup (ctx, xf, fa);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_nh_lkup",
    "dp_do_map_stats",
    "dp_do_dmac_lkup"
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
dp_eg_l2(void *ctx,  struct xfi *xf, void *fa)
{
  /* Any processing based on results from L3 */
  if (xf->pm.pipe_act & LLB_PIPE_RDR_MASK) {
    return 0;
  }   
      
  if (xf->pm.nh_num != 0) {
    dp_do_nh_lkup(ctx, xf, fa);
  }

  dp_do_map_stats(ctx, xf, LL_DP_TX_BD_STATS_MAP, xf->pm.bd);

  dp_do_dmac_lkup(ctx, xf, fa);
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 346,
  "endLine": 351,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_ing_fwd",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa"
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
    "static int __always_inline dp_ing_fwd (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    dp_ing_l3 (ctx, xf, fa);\n",
    "    return dp_eg_l2 (ctx, xf, fa);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_eg_l2",
    "dp_ing_l3"
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
dp_ing_fwd(void *ctx,  struct xfi *xf, void *fa)
{
  dp_ing_l3(ctx, xf, fa);
  return dp_eg_l2(ctx, xf, fa);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 353,
  "endLine": 367,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_ing_l2_top",
  "developer_inline_comments": [
    {
      "start_line": 361,
      "end_line": 361,
      "text": " FIXME Also need to check if L2 tunnel "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa"
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
    "static int __always_inline dp_ing_l2_top (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    dp_do_smac_lkup (ctx, xf, fa);\n",
    "    dp_do_tmac_lkup (ctx, xf, fa);\n",
    "    dp_do_tun_lkup (ctx, xf, fa);\n",
    "    if (xf->tm.tun_decap) {\n",
    "        dp_do_smac_lkup (ctx, xf, fa);\n",
    "        dp_do_tmac_lkup (ctx, xf, fa);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_smac_lkup",
    "dp_do_tmac_lkup",
    "dp_do_tun_lkup"
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
dp_ing_l2_top(void *ctx,  struct xfi *xf, void *fa)
{
  dp_do_smac_lkup(ctx, xf, fa);
  dp_do_tmac_lkup(ctx, xf, fa);
  dp_do_tun_lkup(ctx, xf, fa);

  if (xf->tm.tun_decap) {
    /* FIXME Also need to check if L2 tunnel */
    dp_do_smac_lkup(ctx, xf, fa);
    dp_do_tmac_lkup(ctx, xf, fa);
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 369,
  "endLine": 375,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l2fwd.c",
  "funcName": "dp_ing_l2",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa"
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
    "static int __always_inline dp_ing_l2 (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[ING L2]\");\n",
    "    dp_ing_l2_top (ctx, xf, fa);\n",
    "    return dp_ing_fwd (ctx, xf, fa);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_ing_l2_top",
    "dp_ing_fwd",
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
dp_ing_l2(void *ctx,  struct xfi *xf, void *fa)
{
  LL_DBG_PRINTK("[ING L2]");
  dp_ing_l2_top(ctx, xf, fa);
  return dp_ing_fwd(ctx, xf, fa);
}
