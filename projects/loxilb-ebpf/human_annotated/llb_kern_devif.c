/*
 *  llb_kernel_devif.c: LoxiLB kernel eBPF dev in/out pipeline
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
  "endLine": 61,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_do_if_lkup",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kernel_devif.c: LoxiLB kernel eBPF dev in/out pipeline *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 37,
      "end_line": 37,
      "text": "LLBS_PPLN_DROP(xf);"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  intf_map",
    "  tx_intf_map"
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
    "static int __always_inline dp_do_if_lkup (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct intf_key key;\n",
    "    struct dp_intf_tact *l2a;\n",
    "    key.ifindex = DP_IFI (ctx);\n",
    "    key.ing_vid = xf->l2m.vlan[0];\n",
    "    key.pad = 0;\n",
    "\n",
    "#ifdef HAVE_DP_EGR_HOOK\n",
    "    if (DP_IIFI (ctx) == 0) {\n",
    "        __u32 ikey = LLB_PORT_NO;\n",
    "        __u32 *oif = NULL;\n",
    "        oif = bpf_map_lookup_elem (& tx_intf_map, & ikey);\n",
    "        if (!oif) {\n",
    "            return DP_PASS;\n",
    "        }\n",
    "        key.ifindex = *(__u32*) oif;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    LL_DBG_PRINTK (\"[INTF] -- Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[INTF] ifidx %d vid %d\\n\", key.ifindex, bpf_ntohs (key.ing_vid));\n",
    "    xf->pm.table_id = LL_DP_SMAC_MAP;\n",
    "    l2a = bpf_map_lookup_elem (& intf_map, & key);\n",
    "    if (!l2a) {\n",
    "        LL_DBG_PRINTK (\"[INTF] not found\");\n",
    "        LLBS_PPLN_PASS (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[INTF] L2 action %d\\n\", l2a->ca.act_type);\n",
    "    if (l2a->ca.act_type == DP_SET_DROP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    else if (l2a->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAP (xf);\n",
    "    }\n",
    "    else if (l2a->ca.act_type == DP_SET_IFI) {\n",
    "        xf->pm.iport = l2a->set_ifi.xdp_ifidx;\n",
    "        xf->pm.zone = l2a->set_ifi.zone;\n",
    "        xf->pm.bd = l2a->set_ifi.bd;\n",
    "        xf->pm.mirr = l2a->set_ifi.mirr;\n",
    "        xf->pm.pprop = l2a->set_ifi.pprop;\n",
    "        xf->qm.ipolid = l2a->set_ifi.polid;\n",
    "    }\n",
    "    else {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_IFI",
    "LLBS_PPLN_PASS",
    "LL_DBG_PRINTK",
    "bpf_ntohs",
    "LLBS_PPLN_TRAP",
    "DP_IIFI"
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
dp_do_if_lkup(void *ctx, struct xfi *xf)
{
  struct intf_key key;
  struct dp_intf_tact *l2a;

  key.ifindex = DP_IFI(ctx);
  key.ing_vid = xf->l2m.vlan[0];
  key.pad =  0;

#ifdef HAVE_DP_EGR_HOOK
  if (DP_IIFI(ctx) == 0) {
    __u32 ikey = LLB_PORT_NO;
    __u32 *oif = NULL;
    oif = bpf_map_lookup_elem(&tx_intf_map, &ikey);
    if (!oif) {
      return DP_PASS;
    }
    key.ifindex = *(__u32 *)oif;
  }
#endif

  LL_DBG_PRINTK("[INTF] -- Lookup\n");
  LL_DBG_PRINTK("[INTF] ifidx %d vid %d\n",
                key.ifindex, bpf_ntohs(key.ing_vid));
  
  xf->pm.table_id = LL_DP_SMAC_MAP;

  l2a = bpf_map_lookup_elem(&intf_map, &key);
  if (!l2a) {
    //LLBS_PPLN_DROP(xf);
    LL_DBG_PRINTK("[INTF] not found");
    LLBS_PPLN_PASS(xf);
    return -1;
  }

  LL_DBG_PRINTK("[INTF] L2 action %d\n", l2a->ca.act_type);

  if (l2a->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROP(xf);
  } else if (l2a->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAP(xf);
  } else if (l2a->ca.act_type == DP_SET_IFI) {
    xf->pm.iport = l2a->set_ifi.xdp_ifidx;
    xf->pm.zone  = l2a->set_ifi.zone;
    xf->pm.bd    = l2a->set_ifi.bd;
    xf->pm.mirr  = l2a->set_ifi.mirr;
    xf->pm.pprop = l2a->set_ifi.pprop;
    xf->qm.ipolid = l2a->set_ifi.polid;
  } else {
    LLBS_PPLN_DROP(xf);
  }

  return 0;
}

#ifdef LL_TC_EBPF
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
  "startLine": 64,
  "endLine": 82,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_do_mark_mirr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  tx_intf_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "redirect",
    "bpf_clone_redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_do_mark_mirr (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct  __sk_buff *skb = DP_TC_PTR (ctx);\n",
    "    int *oif;\n",
    "    int key;\n",
    "    key = LLB_PORT_NO;\n",
    "    oif = bpf_map_lookup_elem (& tx_intf_map, & key);\n",
    "    if (!oif) {\n",
    "        return -1;\n",
    "    }\n",
    "    skb->cb[0] = LLB_MIRR_MARK;\n",
    "    skb->cb[1] = xf->pm.mirr;\n",
    "    LL_DBG_PRINTK (\"[REDR] Mirr port %d OIF %d\\n\", key, *oif);\n",
    "    return bpf_clone_redirect (skb, *oif, BPF_F_INGRESS);\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_TC_PTR",
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
dp_do_mark_mirr(void *ctx, struct xfi *xf)
{
  struct __sk_buff *skb = DP_TC_PTR(ctx);
  int *oif;
  int key;

  key = LLB_PORT_NO;
  oif = bpf_map_lookup_elem(&tx_intf_map, &key);
  if (!oif) {
    return -1;
  }

  skb->cb[0] = LLB_MIRR_MARK;
  skb->cb[1] = xf->pm.mirr; 

  LL_DBG_PRINTK("[REDR] Mirr port %d OIF %d\n", key, *oif);
  return bpf_clone_redirect(skb, *oif, BPF_F_INGRESS);
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
  "startLine": 84,
  "endLine": 112,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_do_mirr_lkup",
  "developer_inline_comments": [
    {
      "start_line": 108,
      "end_line": 108,
      "text": " VXLAN to be done "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  mirr_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint",
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
    "static int dp_do_mirr_lkup (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct dp_mirr_tact *ma;\n",
    "    __u32 mkey = xf->pm.mirr;\n",
    "    LL_DBG_PRINTK (\"[MIRR] -- Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[MIRR] -- Key %u\\n\", mkey);\n",
    "    ma = bpf_map_lookup_elem (& mirr_map, & mkey);\n",
    "    if (!ma) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[MIRR] Action %d\\n\", ma->ca.act_type);\n",
    "    if (ma->ca.act_type == DP_SET_ADD_L2VLAN || ma->ca.act_type == DP_SET_RM_L2VLAN) {\n",
    "        struct dp_l2vlan_act *va = &ma->vlan_act;\n",
    "        return dp_set_egr_vlan (ctx, xf, ma->ca.act_type == DP_SET_RM_L2VLAN ? 0 : va->vlan, va->oport);\n",
    "    }\n",
    "    LLBS_PPLN_DROP (xf);\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "dp_set_egr_vlan",
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
static int
dp_do_mirr_lkup(void *ctx, struct xfi *xf)
{
  struct dp_mirr_tact *ma;
  __u32 mkey = xf->pm.mirr;

  LL_DBG_PRINTK("[MIRR] -- Lookup\n");
  LL_DBG_PRINTK("[MIRR] -- Key %u\n", mkey);

  ma = bpf_map_lookup_elem(&mirr_map, &mkey);
  if (!ma) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  LL_DBG_PRINTK("[MIRR] Action %d\n", ma->ca.act_type);

  if (ma->ca.act_type == DP_SET_ADD_L2VLAN ||
      ma->ca.act_type == DP_SET_RM_L2VLAN) {
    struct dp_l2vlan_act *va = &ma->vlan_act;
    return dp_set_egr_vlan(ctx, xf,
                    ma->ca.act_type == DP_SET_RM_L2VLAN ?
                    0 : va->vlan, va->oport);
  }
  /* VXLAN to be done */

  LLBS_PPLN_DROP(xf);
  return -1;
}

#else

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 116,
  "endLine": 120,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_do_mark_mirr",
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
    "static int __always_inline dp_do_mark_mirr (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_TC_PTR",
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
dp_do_mark_mirr(void *ctx, struct xfi *xf)
{
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 122,
  "endLine": 127,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_do_mirr_lkup",
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
    "static int __always_inline dp_do_mirr_lkup (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "dp_set_egr_vlan",
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
dp_do_mirr_lkup(void *ctx, struct xfi *xf)
{
  return 0;

}
#endif

#ifdef LLB_TRAP_PERF_RING
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
  "startLine": 131,
  "endLine": 158,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_trap_packet",
  "developer_inline_comments": [
    {
      "start_line": 138,
      "end_line": 138,
      "text": " Metadata will be in the perf event before the packet data. "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  pkts"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_perf_event_output"
  ],
  "compatibleHookpoints": [
    "socket_filter",
    "sock_ops",
    "xdp",
    "sched_act",
    "lwt_seg6local",
    "raw_tracepoint",
    "lwt_in",
    "sk_skb",
    "lwt_xmit",
    "raw_tracepoint_writable",
    "kprobe",
    "perf_event",
    "lwt_out",
    "sched_cls",
    "cgroup_skb",
    "tracepoint"
  ],
  "source": [
    "static int __always_inline dp_trap_packet (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct ll_dp_pmdi *pmd;\n",
    "    int z = 0;\n",
    "    __u64 flags = BPF_F_CURRENT_CPU;\n",
    "    pmd = bpf_map_lookup_elem (& pkts, & z);\n",
    "    if (!pmd)\n",
    "        return 0;\n",
    "    LL_DBG_PRINTK (\"[TRAP] START--\\n\");\n",
    "    pmd->ifindex = ctx->ingress_ifindex;\n",
    "    pmd->xdp_inport = xf->pm.iport;\n",
    "    pmd->xdp_oport = xf->pm.oport;\n",
    "    pmd->pm.table_id = xf->table_id;\n",
    "    pmd->rcode = xf->pm.rcode;\n",
    "    pmd->pkt_len = xf->pm.py_bytes;\n",
    "    flags |= (__u64) pmd->pkt_len << 32;\n",
    "    if (bpf_perf_event_output (ctx, &pkt_ring, flags, pmd, sizeof (*pmd))) {\n",
    "        LL_DBG_PRINTK (\"[TRAP] FAIL--\\n\");\n",
    "    }\n",
    "    return DP_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_add_l2",
    "DP_PDATA",
    "bpf_htons",
    "DP_ADD_PTR",
    "LL_DBG_PRINTK",
    "DP_TC_PTR",
    "dp_redirect_port",
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
dp_trap_packet(void *ctx,  struct xfi *xf)
{
  struct ll_dp_pmdi *pmd;
  int z = 0;
  __u64 flags = BPF_F_CURRENT_CPU;

  /* Metadata will be in the perf event before the packet data. */
  pmd = bpf_map_lookup_elem(&pkts, &z);
  if (!pmd) return 0;

  LL_DBG_PRINTK("[TRAP] START--\n");

  pmd->ifindex = ctx->ingress_ifindex;
  pmd->xdp_inport = xf->pm.iport;
  pmd->xdp_oport = xf->pm.oport;
  pmd->pm.table_id = xf->table_id;
  pmd->rcode = xf->pm.rcode;
  pmd->pkt_len = xf->pm.py_bytes;

  flags |= (__u64)pmd->pkt_len << 32;
  
  if (bpf_perf_event_output(ctx, &pkt_ring, flags,
                            pmd, sizeof(*pmd))) {
    LL_DBG_PRINTK("[TRAP] FAIL--\n");
  }
  return DP_DROP;
}
#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 160,
  "endLine": 226,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_trap_packet",
  "developer_inline_comments": [
    {
      "start_line": 171,
      "end_line": 173,
      "text": " FIXME - There is a problem right now if we send decapped   * packet up the stack. So, this is a safety check for now   "
    },
    {
      "start_line": 174,
      "end_line": 174,
      "text": "if (xf->tm.tun_decap)"
    },
    {
      "start_line": 175,
      "end_line": 175,
      "text": "  return DP_DROP;"
    },
    {
      "start_line": 182,
      "end_line": 182,
      "text": " If tunnel was present, outer metadata is popped "
    },
    {
      "start_line": 187,
      "end_line": 190,
      "text": " This can fail to push headroom for tunnelled packets.     * It might be better to pass it rather than drop it in case     * of failure     "
    },
    {
      "start_line": 203,
      "end_line": 203,
      "text": " Add LLB shim "
    },
    {
      "start_line": 215,
      "end_line": 215,
      "text": " FIXME "
    },
    {
      "start_line": 224,
      "end_line": 224,
      "text": " TODO - Apply stats "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa_"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_trap_packet (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    struct ethhdr *neth;\n",
    "    struct ethhdr *oeth;\n",
    "    uint16_t ntype;\n",
    "    struct llb_ethhdr *llb;\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    LL_DBG_PRINTK (\"[TRAP] START--\\n\");\n",
    "    oeth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    if (oeth + 1 > dend) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    memcpy (xf->l2m.dl_dst, oeth->h_dest, 6 * 2);\n",
    "    ntype = oeth->h_proto;\n",
    "    if (dp_add_l2 (ctx, (int) sizeof (*llb))) {\n",
    "        return DP_PASS;\n",
    "    }\n",
    "    neth = DP_TC_PTR (DP_PDATA (ctx));\n",
    "    dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (neth + 1 > dend) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    memcpy (neth->h_dest, xf->l2m.dl_dst, 6 * 2);\n",
    "    neth->h_proto = bpf_htons (ETH_TYPE_LLB);\n",
    "    llb = DP_ADD_PTR (neth, sizeof (* neth));\n",
    "    if (llb + 1 > dend) {\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    llb->iport = bpf_htons (xf->pm.iport);\n",
    "    llb->oport = bpf_htons (xf->pm.oport);\n",
    "    llb->rcode = xf->pm.rcode;\n",
    "    if (xf->tm.tun_decap) {\n",
    "        llb->rcode |= LLB_PIPE_RC_TUN_DECAP;\n",
    "    }\n",
    "    llb->mmap = xf->pm.table_id;\n",
    "    llb->ntype = ntype;\n",
    "    xf->pm.oport = LLB_PORT_NO;\n",
    "    if (dp_redirect_port (&tx_intf_map, xf) != DP_REDIRECT) {\n",
    "        LL_DBG_PRINTK (\"[TRAP] FAIL--\\n\");\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    return DP_REDIRECT;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_add_l2",
    "DP_PDATA",
    "bpf_htons",
    "DP_ADD_PTR",
    "LL_DBG_PRINTK",
    "DP_TC_PTR",
    "dp_redirect_port",
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
dp_trap_packet(void *ctx,  struct xfi *xf, void *fa_)
{
  struct ethhdr *neth;
  struct ethhdr *oeth;
  uint16_t ntype;
  struct llb_ethhdr *llb;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  LL_DBG_PRINTK("[TRAP] START--\n");

  /* FIXME - There is a problem right now if we send decapped
   * packet up the stack. So, this is a safety check for now
   */
  //if (xf->tm.tun_decap)
  //  return DP_DROP;

  oeth = DP_TC_PTR(DP_PDATA(ctx));
  if (oeth + 1 > dend) {
    return DP_DROP;
  }

  /* If tunnel was present, outer metadata is popped */
  memcpy(xf->l2m.dl_dst, oeth->h_dest, 6*2);
  ntype = oeth->h_proto;

  if (dp_add_l2(ctx, (int)sizeof(*llb))) {
    /* This can fail to push headroom for tunnelled packets.
     * It might be better to pass it rather than drop it in case
     * of failure
     */
    return DP_PASS;
  }

  neth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));
  if (neth + 1 > dend) {
    return DP_DROP;
  }

  memcpy(neth->h_dest, xf->l2m.dl_dst, 6*2);
  neth->h_proto = bpf_htons(ETH_TYPE_LLB); 
  
  /* Add LLB shim */
  llb = DP_ADD_PTR(neth, sizeof(*neth));
  if (llb + 1 > dend) {
    return DP_DROP;
  }

  llb->iport = bpf_htons(xf->pm.iport);
  llb->oport = bpf_htons(xf->pm.oport);
  llb->rcode = xf->pm.rcode;
  if (xf->tm.tun_decap) {
    llb->rcode |= LLB_PIPE_RC_TUN_DECAP;
  }
  llb->mmap = xf->pm.table_id; /* FIXME */
  llb->ntype = ntype;

  xf->pm.oport = LLB_PORT_NO;
  if (dp_redirect_port(&tx_intf_map, xf) != DP_REDIRECT) {
    LL_DBG_PRINTK("[TRAP] FAIL--\n");
    return DP_DROP;
  }

  /* TODO - Apply stats */
  return DP_REDIRECT;
}
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 229,
  "endLine": 244,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_redir_packet",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "redirect"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_redir_packet (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[REDI] --\\n\");\n",
    "    if (dp_redirect_port (&tx_intf_map, xf) != DP_REDIRECT) {\n",
    "        LL_DBG_PRINTK (\"[REDI] FAIL--\\n\");\n",
    "        return DP_DROP;\n",
    "    }\n",
    "\n",
    "#ifdef LLB_DP_IF_STATS\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_TX_INTF_STATS_MAP, xf->pm.oport);\n",
    "\n",
    "#endif\n",
    "    return DP_REDIRECT;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_redirect_port",
    "dp_do_map_stats",
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
dp_redir_packet(void *ctx,  struct xfi *xf)
{
  LL_DBG_PRINTK("[REDI] --\n");

  if (dp_redirect_port(&tx_intf_map, xf) != DP_REDIRECT) {
    LL_DBG_PRINTK("[REDI] FAIL--\n");
    return DP_DROP;
  }

#ifdef LLB_DP_IF_STATS
  dp_do_map_stats(ctx, xf, LL_DP_TX_INTF_STATS_MAP, xf->pm.oport);
#endif

  return DP_REDIRECT;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 246,
  "endLine": 257,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_rewire_packet",
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
    "static int __always_inline dp_rewire_packet (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[REWR] --\\n\");\n",
    "    if (dp_rewire_port (&tx_intf_map, xf) != DP_REDIRECT) {\n",
    "        LL_DBG_PRINTK (\"[REWR] FAIL--\\n\");\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    return DP_REDIRECT;\n",
    "}\n"
  ],
  "called_function_list": [
    "LL_DBG_PRINTK",
    "dp_rewire_port"
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
dp_rewire_packet(void *ctx,  struct xfi *xf)
{
  LL_DBG_PRINTK("[REWR] --\n");

  if (dp_rewire_port(&tx_intf_map, xf) != DP_REDIRECT) {
    LL_DBG_PRINTK("[REWR] FAIL--\n");
    return DP_DROP;
  }

  return DP_REDIRECT;
}

//#ifdef HAVE_DP_FUNCS
//static int
//#else
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 262,
  "endLine": 311,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_pipe_check_res",
  "developer_inline_comments": [
    {
      "start_line": 259,
      "end_line": 259,
      "text": "#ifdef HAVE_DP_FUNCS"
    },
    {
      "start_line": 260,
      "end_line": 260,
      "text": "static int"
    },
    {
      "start_line": 261,
      "end_line": 261,
      "text": "#else"
    },
    {
      "start_line": 263,
      "end_line": 263,
      "text": "#endif"
    },
    {
      "start_line": 310,
      "end_line": 310,
      "text": " FIXME "
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
    "static int __always_inline dp_pipe_check_res (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[PIPE] act 0x%x\\n\", xf->pm.pipe_act);\n",
    "\n",
    "#ifdef HAVE_DP_EGR_HOOK\n",
    "    DP_LLB_MRK_INGP (ctx);\n",
    "\n",
    "#endif\n",
    "    if (xf->pm.pipe_act) {\n",
    "        if (xf->pm.pipe_act & LLB_PIPE_DROP) {\n",
    "            return DP_DROP;\n",
    "        }\n",
    "        if (dp_unparse_packet_always (ctx, xf) != 0) {\n",
    "            return DP_DROP;\n",
    "        }\n",
    "\n",
    "#ifndef HAVE_LLB_DISAGGR\n",
    "\n",
    "#ifdef HAVE_OOB_CH\n",
    "        if (xf->pm.pipe_act & LLB_PIPE_TRAP) {\n",
    "            return dp_trap_packet (ctx, xf, fa);\n",
    "        }\n",
    "        if (xf->pm.pipe_act & LLB_PIPE_PASS) {\n",
    "            return DP_PASS;\n",
    "        }\n",
    "\n",
    "#else\n",
    "        if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) {\n",
    "            return DP_PASS;\n",
    "        }\n",
    "\n",
    "#endif\n",
    "\n",
    "#else\n",
    "        if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) {\n",
    "            return dp_trap_packet (ctx, xf, fa);\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        if (xf->pm.pipe_act & LLB_PIPE_RDR_MASK) {\n",
    "            if (dp_unparse_packet (ctx, xf) != 0) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "            return dp_redir_packet (ctx, xf);\n",
    "        }\n",
    "    }\n",
    "    return DP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_unparse_packet",
    "dp_trap_packet",
    "LL_DBG_PRINTK",
    "DP_LLB_MRK_INGP",
    "dp_unparse_packet_always",
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
//#endif
dp_pipe_check_res(void *ctx, struct xfi *xf, void *fa)
{
  LL_DBG_PRINTK("[PIPE] act 0x%x\n", xf->pm.pipe_act);

#ifdef HAVE_DP_EGR_HOOK
  DP_LLB_MRK_INGP(ctx);
#endif

  if (xf->pm.pipe_act) {

    if (xf->pm.pipe_act & LLB_PIPE_DROP) {
      return DP_DROP;
    } 

    if (dp_unparse_packet_always(ctx, xf) != 0) {
        return DP_DROP;
    }

#ifndef HAVE_LLB_DISAGGR
#ifdef HAVE_OOB_CH
    if (xf->pm.pipe_act & LLB_PIPE_TRAP) { 
      return dp_trap_packet(ctx, xf, fa);
    } 

    if (xf->pm.pipe_act & LLB_PIPE_PASS) {
      return DP_PASS;
    }
#else
    if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) {
      return DP_PASS;
    }
#endif
#else
    if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) { 
      return dp_trap_packet(ctx, xf, fa);
    } 
#endif

    if (xf->pm.pipe_act & LLB_PIPE_RDR_MASK) {
      if (dp_unparse_packet(ctx, xf) != 0) {
        return DP_DROP;
      }
      return dp_redir_packet(ctx, xf);
    }

  } 
  return DP_PASS; /* FIXME */
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 313,
  "endLine": 331,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_ing",
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
    "static int __always_inline dp_ing (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    dp_do_if_lkup (ctx, xf);\n",
    "\n",
    "#ifdef LLB_DP_IF_STATS\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_INTF_STATS_MAP, xf->pm.iport);\n",
    "\n",
    "#endif\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_BD_STATS_MAP, xf->pm.bd);\n",
    "    if (xf->pm.mirr != 0) {\n",
    "        dp_do_mark_mirr (ctx, xf);\n",
    "    }\n",
    "    if (xf->qm.ipolid != 0) {\n",
    "        do_dp_policer (ctx, xf, 0);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_if_lkup",
    "dp_do_map_stats",
    "dp_do_mark_mirr",
    "do_dp_policer"
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
dp_ing(void *ctx,  struct xfi *xf)
{
  dp_do_if_lkup(ctx, xf);
#ifdef LLB_DP_IF_STATS
  dp_do_map_stats(ctx, xf, LL_DP_INTF_STATS_MAP, xf->pm.iport);
#endif
  dp_do_map_stats(ctx, xf, LL_DP_BD_STATS_MAP, xf->pm.bd);

  if (xf->pm.mirr != 0) {
    dp_do_mark_mirr(ctx, xf);
  }

  if (xf->qm.ipolid != 0) {
    do_dp_policer(ctx, xf, 0);
  }

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
  "startLine": 333,
  "endLine": 359,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_insert_fcv4",
  "developer_inline_comments": [],
  "updateMaps": [
    " fc_v4_map"
  ],
  "readMaps": [
    " fc_v4_map",
    "  tx_intf_map",
    "  xfck"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_fc_tacts *acts"
  ],
  "output": "staticint__always_inline",
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
    "static int __always_inline dp_insert_fcv4 (void *ctx, struct xfi *xf, struct dp_fc_tacts *acts)\n",
    "{\n",
    "    struct dp_fcv4_key *key;\n",
    "    int z = 0;\n",
    "    int *oif;\n",
    "    int pkey = xf->pm.oport;\n",
    "    oif = bpf_map_lookup_elem (& tx_intf_map, & pkey);\n",
    "    if (oif) {\n",
    "        acts->ca.oaux = *oif;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[FCH4] INS--\\n\");\n",
    "    key = bpf_map_lookup_elem (& xfck, & z);\n",
    "    if (key == NULL) {\n",
    "        return -1;\n",
    "    }\n",
    "    if (bpf_map_lookup_elem (&fc_v4_map, key) != NULL) {\n",
    "        return 1;\n",
    "    }\n",
    "    bpf_map_update_elem (&fc_v4_map, key, acts, BPF_ANY);\n",
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
dp_insert_fcv4(void *ctx, struct xfi *xf, struct dp_fc_tacts *acts)
{
  struct dp_fcv4_key *key;
  int z = 0;
  int *oif;
  int pkey = xf->pm.oport;
  
  oif = bpf_map_lookup_elem(&tx_intf_map, &pkey);
  if (oif) {
    acts->ca.oaux = *oif;
  } 

  LL_DBG_PRINTK("[FCH4] INS--\n");

  key = bpf_map_lookup_elem(&xfck, &z);
  if (key == NULL) {
    return -1;
  }

  if (bpf_map_lookup_elem(&fc_v4_map, key) != NULL) {
    return 1;
  }
  
  bpf_map_update_elem(&fc_v4_map, key, acts, BPF_ANY);
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
  "startLine": 361,
  "endLine": 420,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_ing_slow_main",
  "developer_inline_comments": [
    {
      "start_line": 371,
      "end_line": 371,
      "text": " No nonsense no loop "
    },
    {
      "start_line": 381,
      "end_line": 381,
      "text": " memset is too costly "
    },
    {
      "start_line": 382,
      "end_line": 382,
      "text": "memset(fa->fcta, 0, sizeof(fa->fcta));"
    },
    {
      "start_line": 387,
      "end_line": 390,
      "text": " If there are any packets marked for mirroring, we do   * it here and immediately get it out of way without   * doing any further processing   "
    },
    {
      "start_line": 398,
      "end_line": 400,
      "text": " If there are pipeline errors at this stage,   * we again skip any further processing   "
    },
    {
      "start_line": 408,
      "end_line": 408,
      "text": " fast-cache is used only when certain conditions are met "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  fcas"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_ktime_get_ns",
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
    "static int __always_inline dp_ing_slow_main (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct dp_fc_tacts *fa = NULL;\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    int z = 0;\n",
    "    fa = bpf_map_lookup_elem (& fcas, & z);\n",
    "    if (!fa)\n",
    "        return 0;\n",
    "    fa->ca.ftrap = 0;\n",
    "    fa->ca.cidx = 0;\n",
    "    fa->zone = 0;\n",
    "    fa->its = bpf_ktime_get_ns ();\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "    for (z = 0; z < LLB_FCV4_MAP_ACTS; z++) {\n",
    "        fa->fcta[z].ca.act_type = 0;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    LL_DBG_PRINTK (\"[INGR] START--\\n\");\n",
    "    if (xf->pm.mirr != 0) {\n",
    "        dp_do_mirr_lkup (ctx, xf);\n",
    "        goto out;\n",
    "    }\n",
    "    dp_ing (ctx, xf);\n",
    "    if (xf->pm.pipe_act || xf->pm.tc == 0) {\n",
    "        goto out;\n",
    "    }\n",
    "    dp_ing_l2 (ctx, xf, fa);\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    if (LL_PIPE_FC_CAP (xf)) {\n",
    "        fa->zone = xf->pm.zone;\n",
    "        dp_insert_fcv4 (ctx, xf, fa);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "out :\n",
    "    xf->pm.phit |= LLB_DP_RES_HIT;\n",
    "    bpf_tail_call (ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);\n",
    "    return DP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_ing_l2",
    "LL_DBG_PRINTK",
    "dp_do_mirr_lkup",
    "LL_PIPE_FC_CAP",
    "dp_insert_fcv4",
    "dp_ing",
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
static int __always_inline
dp_ing_slow_main(void *ctx,  struct xfi *xf)
{
  struct dp_fc_tacts *fa = NULL;
#ifdef HAVE_DP_FC
  int z = 0;

  fa = bpf_map_lookup_elem(&fcas, &z);
  if (!fa) return 0;

  /* No nonsense no loop */
  fa->ca.ftrap = 0;
  fa->ca.cidx = 0;
  fa->zone = 0;
  fa->its = bpf_ktime_get_ns();
#pragma clang loop unroll(full)
  for (z = 0; z < LLB_FCV4_MAP_ACTS; z++) {
    fa->fcta[z].ca.act_type = 0;
  }

  /* memset is too costly */
  /*memset(fa->fcta, 0, sizeof(fa->fcta));*/
#endif

  LL_DBG_PRINTK("[INGR] START--\n");

  /* If there are any packets marked for mirroring, we do
   * it here and immediately get it out of way without
   * doing any further processing
   */
  if (xf->pm.mirr != 0) {
    dp_do_mirr_lkup(ctx, xf);
    goto out;
  }

  dp_ing(ctx, xf);

  /* If there are pipeline errors at this stage,
   * we again skip any further processing
   */
  if (xf->pm.pipe_act || xf->pm.tc == 0) {
    goto out;
  }

  dp_ing_l2(ctx, xf, fa);

#ifdef HAVE_DP_FC
  /* fast-cache is used only when certain conditions are met */
  if (LL_PIPE_FC_CAP(xf)) {
    fa->zone = xf->pm.zone;
    dp_insert_fcv4(ctx, xf, fa);
  }
#endif

out:
  xf->pm.phit |= LLB_DP_RES_HIT;

  bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID);
  return DP_PASS;
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
  "startLine": 422,
  "endLine": 475,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_ing_ct_main",
  "developer_inline_comments": [
    {
      "start_line": 437,
      "end_line": 440,
      "text": " If ACL is hit, and packet arrives here    * it only means that we need CT processing.   * In such a case, we skip nat lookup   "
    },
    {
      "start_line": 463,
      "end_line": 469,
      "text": " CT pipeline is hit after acl lookup fails    * So, after CT processing we continue the rest   * of the stack. We could potentially make    * another tail-call to where ACL lookup failed   * and start over. But simplicity wins against   * complexity for now    "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  fcas"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
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
    "static int __always_inline dp_ing_ct_main (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    int val = 0;\n",
    "    struct dp_fc_tacts *fa = NULL;\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    fa = bpf_map_lookup_elem (& fcas, & val);\n",
    "    if (!fa)\n",
    "        return DP_DROP;\n",
    "\n",
    "#endif\n",
    "    if (xf->pm.phit & LLB_DP_RES_HIT) {\n",
    "        goto res_end;\n",
    "    }\n",
    "    if ((xf->pm.phit & LLB_DP_ACL_HIT) == 0) {\n",
    "        if (xf->pm.fw_lid < LLB_FW4_MAP_ENTRIES) {\n",
    "            bpf_tail_call (ctx, &pgm_tbl, LLB_DP_FW_PGM_ID);\n",
    "        }\n",
    "        if (xf->pm.dp_rec) {\n",
    "            dp_record_it (ctx, xf);\n",
    "        }\n",
    "        dp_do_nat (ctx, xf);\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[CTRK] start\\n\");\n",
    "    val = dp_ct_in (ctx, xf);\n",
    "    if (val < 0) {\n",
    "        return DP_PASS;\n",
    "    }\n",
    "    xf->nm.ct_sts = LLB_PIPE_CT_INP;\n",
    "    dp_l3_fwd (ctx, xf, fa);\n",
    "    dp_eg_l2 (ctx, xf, fa);\n",
    "res_end :\n",
    "    return dp_pipe_check_res (ctx, xf, fa);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_record_it",
    "dp_eg_l2",
    "dp_l3_fwd",
    "LL_DBG_PRINTK",
    "dp_pipe_check_res",
    "dp_ct_in",
    "dp_do_nat"
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
dp_ing_ct_main(void *ctx,  struct xfi *xf)
{
  int val = 0;
  struct dp_fc_tacts *fa = NULL;

#ifdef HAVE_DP_FC
  fa = bpf_map_lookup_elem(&fcas, &val);
  if (!fa) return DP_DROP;
#endif

  if (xf->pm.phit & LLB_DP_RES_HIT) {
    goto res_end;
  }

  /* If ACL is hit, and packet arrives here 
   * it only means that we need CT processing.
   * In such a case, we skip nat lookup
   */
  if ((xf->pm.phit & LLB_DP_ACL_HIT) == 0) {

    if (xf->pm.fw_lid < LLB_FW4_MAP_ENTRIES) {
      bpf_tail_call(ctx, &pgm_tbl, LLB_DP_FW_PGM_ID);
    }

    if (xf->pm.dp_rec) {
      dp_record_it(ctx, xf);
    }

    dp_do_nat(ctx, xf);
  }

  LL_DBG_PRINTK("[CTRK] start\n");

  val = dp_ct_in(ctx, xf);
  if (val < 0) {
    return DP_PASS;
  }

  xf->nm.ct_sts = LLB_PIPE_CT_INP;

  /* CT pipeline is hit after acl lookup fails 
   * So, after CT processing we continue the rest
   * of the stack. We could potentially make 
   * another tail-call to where ACL lookup failed
   * and start over. But simplicity wins against
   * complexity for now 
   */
  dp_l3_fwd(ctx, xf, fa);
  dp_eg_l2(ctx, xf, fa);

res_end:
  return dp_pipe_check_res(ctx, xf, fa);
}
 
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 477,
  "endLine": 483,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_devif.c",
  "funcName": "dp_ing_pass_main",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx"
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
    "static int __always_inline dp_ing_pass_main (void *ctx)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[INGR] PASS--\\n\");\n",
    "    return DP_PASS;\n",
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
dp_ing_pass_main(void *ctx)
{
  LL_DBG_PRINTK("[INGR] PASS--\n");

  return DP_PASS;
}
