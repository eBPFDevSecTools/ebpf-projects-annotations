/*
 *  llb_kern_l3fwd.c: LoxiLB Kernel eBPF L3 forwarder Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 7,
  "endLine": 19,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_rt4_fwdops",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_l3fwd.c: LoxiLB Kernel eBPF L3 forwarder Implementation *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
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
    "static int __always_inline dp_do_rt4_fwdops (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct iphdr *iph = DP_TC_PTR (DP_PDATA (ctx) +xf->pm.l3_off);\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (iph + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    ip_decrease_ttl (iph);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "ip_decrease_ttl",
    "DP_TC_PTR",
    "DP_PDATA_END"
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
dp_do_rt4_fwdops(void *ctx, struct xfi *xf)
{
  struct iphdr *iph = DP_TC_PTR(DP_PDATA(ctx) + xf->pm.l3_off);
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (iph + 1 > dend)  {
    LLBS_PPLN_DROP(xf);
    return -1;
  }
  ip_decrease_ttl(iph);
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 21,
  "endLine": 33,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_rt6_fwdops",
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
    "static int __always_inline dp_do_rt6_fwdops (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct ipv6hdr *ip6h = DP_TC_PTR (DP_PDATA (ctx) +xf->pm.l3_off);\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    if (ip6h + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    ip6h->hop_limit--;\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_TC_PTR",
    "DP_PDATA",
    "DP_PDATA_END"
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
dp_do_rt6_fwdops(void *ctx, struct xfi *xf)
{
  struct ipv6hdr *ip6h = DP_TC_PTR(DP_PDATA(ctx) + xf->pm.l3_off);
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));

  if (ip6h + 1 > dend)  {
    LLBS_PPLN_DROP(xf);
    return -1;
  }
  ip6h->hop_limit--;
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 35,
  "endLine": 44,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_rt_fwdops",
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
    "static int __always_inline dp_do_rt_fwdops (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    if (xf->l2m.dl_type == ETH_P_IP) {\n",
    "        return dp_do_rt4_fwdops (ctx, xf);\n",
    "    }\n",
    "    else if (xf->l2m.dl_type == ETH_P_IPV6) {\n",
    "        return dp_do_rt6_fwdops (ctx, xf);\n",
    "    }\n",
    "    return DP_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_rt4_fwdops",
    "dp_do_rt6_fwdops"
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
dp_do_rt_fwdops(void *ctx, struct xfi *xf)
{
  if (xf->l2m.dl_type == ETH_P_IP) {
    return dp_do_rt4_fwdops(ctx, xf);
  } else if (xf->l2m.dl_type == ETH_P_IPV6) {
    return dp_do_rt6_fwdops(ctx, xf);
  }
  return DP_DROP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 67,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_pipe_set_l32_tun_nh",
  "developer_inline_comments": [
    {
      "start_line": 52,
      "end_line": 55,
      "text": "   * We do not set out_bd here. After NH lookup match is   * found and packet tunnel insertion is done, BD is set accordingly   "
    },
    {
      "start_line": 56,
      "end_line": 56,
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
    "static int __always_inline dp_pipe_set_l32_tun_nh (void *ctx, struct xfi *xf, struct dp_rt_nh_act *rnh)\n",
    "{\n",
    "    struct dp_rt_l2nh_act *nl2;\n",
    "    xf->pm.nh_num = rnh->nh_num;\n",
    "    xf->tm.new_tunnel_id = rnh->tid;\n",
    "    nl2 = &rnh->l2nh;\n",
    "    memcpy (xf->l2m.dl_dst, nl2->dmac, 6);\n",
    "    memcpy (xf->l2m.dl_src, nl2->smac, 6);\n",
    "    memcpy (xf->pm.lkup_dmac, nl2->dmac, 6);\n",
    "    xf->pm.bd = nl2->bd;\n",
    "    LL_DBG_PRINTK (\"[RTFW] new-vx nh %u\\n\", xf->pm.nh_num);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LL_DBG_PRINTK",
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
dp_pipe_set_l32_tun_nh(void *ctx, struct xfi *xf,
                       struct dp_rt_nh_act *rnh)
{
  struct dp_rt_l2nh_act *nl2;
  xf->pm.nh_num = rnh->nh_num;
  /*
   * We do not set out_bd here. After NH lookup match is
   * found and packet tunnel insertion is done, BD is set accordingly
   */
  /*xf->pm.bd = rnh->bd;*/
  xf->tm.new_tunnel_id = rnh->tid;

  nl2 = &rnh->l2nh;
  memcpy(xf->l2m.dl_dst, nl2->dmac, 6);
  memcpy(xf->l2m.dl_src, nl2->smac, 6);
  memcpy(xf->pm.lkup_dmac, nl2->dmac, 6);
  xf->pm.bd = nl2->bd;

  LL_DBG_PRINTK("[RTFW] new-vx nh %u\n", xf->pm.nh_num);
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 69,
  "endLine": 97,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_rtv4_get_ipkey",
  "developer_inline_comments": [
    {
      "start_line": 87,
      "end_line": 89,
      "text": " In case of GTP, there is no interface created in OS          * which has a specific route through it. So, this hack !!         "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xfi *xf"
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
    "static __u32 __always_inline dp_rtv4_get_ipkey (struct xfi *xf)\n",
    "{\n",
    "    __u32 ipkey;\n",
    "    if (xf->pm.nf & LLB_NAT_DST) {\n",
    "        ipkey = xf->nm.nxip4 ? : xf->l34m.saddr4;\n",
    "    }\n",
    "    else {\n",
    "        if (xf->pm.nf & LLB_NAT_SRC) {\n",
    "            if (xf->nm.nrip4) {\n",
    "                ipkey = xf->nm.nrip4;\n",
    "            }\n",
    "            else if (xf->nm.nxip4 == 0) {\n",
    "                ipkey = xf->l34m.saddr4;\n",
    "            }\n",
    "            else {\n",
    "                ipkey = xf->l34m.daddr4;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            if (xf->tm.new_tunnel_id && xf->tm.tun_type == LLB_TUN_GTP) {\n",
    "                ipkey = xf->tm.tun_rip;\n",
    "            }\n",
    "            else {\n",
    "                ipkey = xf->l34m.daddr4;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return ipkey;\n",
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
dp_rtv4_get_ipkey(struct xfi *xf)
{
  __u32 ipkey;

  if (xf->pm.nf & LLB_NAT_DST) {
    ipkey = xf->nm.nxip4?:xf->l34m.saddr4;
  } else {
    if (xf->pm.nf & LLB_NAT_SRC) {
      if (xf->nm.nrip4) {
        ipkey = xf->nm.nrip4;
      } else if (xf->nm.nxip4 == 0) {
        ipkey = xf->l34m.saddr4;
      } else {
        ipkey = xf->l34m.daddr4;
      }
    } else {
      if (xf->tm.new_tunnel_id && xf->tm.tun_type == LLB_TUN_GTP) {
        /* In case of GTP, there is no interface created in OS 
         * which has a specific route through it. So, this hack !!
         */
        ipkey = xf->tm.tun_rip;
      } else {
        ipkey = xf->l34m.daddr4;
      }
    }
  }
  return ipkey;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 99,
  "endLine": 129,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_rtops",
  "developer_inline_comments": [
    {
      "start_line": 117,
      "end_line": 124,
      "text": "else if (act->ca.act_type == DP_SET_L3RT_TUN_NH) {#ifdef HAVE_DP_EXTFC    struct dp_fc_tact *ta = &fa->fcta[DP_SET_L3RT_TUN_NH];    ta->ca.act_type = DP_SET_L3RT_TUN_NH;    memcpy(&ta->nh_act,  &act->rt_nh, sizeof(act->rt_nh));#endif    return dp_pipe_set_l32_tun_nh(ctx, xf, &act->rt_nh);  } "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa_",
    " struct dp_rt_tact *act"
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
    "static int __always_inline dp_do_rtops (void *ctx, struct xfi *xf, void *fa_, struct dp_rt_tact *act)\n",
    "{\n",
    "    LL_DBG_PRINTK (\"[RTFW] action %d pipe %x\\n\", act->ca.act_type, xf->pm.pipe_act);\n",
    "    if (act->ca.act_type == DP_SET_DROP) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAP (xf);\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_RDR_PORT) {\n",
    "        struct dp_rdr_act *ra = &act->port_act;\n",
    "        LLBS_PPLN_RDR (xf);\n",
    "        xf->pm.oport = ra->oport;\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_RT_NHNUM) {\n",
    "        struct dp_rt_nh_act *rnh = &act->rt_nh;\n",
    "        xf->pm.nh_num = rnh->nh_num;\n",
    "        return dp_do_rt_fwdops (ctx, xf);\n",
    "    }\n",
    "    else {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "LLBS_PPLN_RDR",
    "dp_do_rt_fwdops",
    "LL_DBG_PRINTK",
    "LLBS_PPLN_TRAP"
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
dp_do_rtops(void *ctx, struct xfi *xf, void *fa_, struct dp_rt_tact *act)
{
  LL_DBG_PRINTK("[RTFW] action %d pipe %x\n",
                act->ca.act_type, xf->pm.pipe_act);

  if (act->ca.act_type == DP_SET_DROP) {
    LLBS_PPLN_DROP(xf);
  } else if (act->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAP(xf);
  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ra = &act->port_act;
    LLBS_PPLN_RDR(xf);
    xf->pm.oport = ra->oport;
  } else if (act->ca.act_type == DP_SET_RT_NHNUM) {
    struct dp_rt_nh_act *rnh = &act->rt_nh;
    xf->pm.nh_num = rnh->nh_num;
    return dp_do_rt_fwdops(ctx, xf);
  } /*else if (act->ca.act_type == DP_SET_L3RT_TUN_NH) {
#ifdef HAVE_DP_EXTFC
    struct dp_fc_tact *ta = &fa->fcta[DP_SET_L3RT_TUN_NH];
    ta->ca.act_type = DP_SET_L3RT_TUN_NH;
    memcpy(&ta->nh_act,  &act->rt_nh, sizeof(act->rt_nh));
#endif
    return dp_pipe_set_l32_tun_nh(ctx, xf, &act->rt_nh);
  } */ else {
    LLBS_PPLN_DROP(xf);
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
    }
  ],
  "helperCallParams": {},
  "startLine": 131,
  "endLine": 179,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_rtv6",
  "developer_inline_comments": [
    {
      "start_line": 137,
      "end_line": 137,
      "text": " 128-bit prefix "
    },
    {
      "start_line": 169,
      "end_line": 169,
      "text": " Default action - Nothing to do "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  rt_v6_map"
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
    "static int __always_inline dp_do_rtv6 (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    struct dp_rtv6_key *key = (void *) xf->km.skey;\n",
    "    struct dp_rt_tact *act;\n",
    "    key->l.prefixlen = 128;\n",
    "    if (xf->pm.nf & LLB_NAT_DST) {\n",
    "        if (DP_XADDR_ISZR (xf->nm.nxip)) {\n",
    "            DP_XADDR_CP (key->addr, xf->l34m.saddr);\n",
    "        }\n",
    "        else {\n",
    "            DP_XADDR_CP (key->addr, xf->nm.nxip);\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        if (xf->pm.nf & LLB_NAT_SRC) {\n",
    "            if (!DP_XADDR_ISZR(xf->nm.nrip)) {\n",
    "                DP_XADDR_CP (key->addr, xf->nm.nrip);\n",
    "            }\n",
    "            else if (DP_XADDR_ISZR (xf->nm.nxip)) {\n",
    "                DP_XADDR_CP (key->addr, xf->l34m.saddr);\n",
    "            }\n",
    "            else {\n",
    "                DP_XADDR_CP (key->addr, xf->l34m.daddr);\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            DP_XADDR_CP (key->addr, xf->l34m.daddr);\n",
    "        }\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[RT6FW] --Lookup\");\n",
    "    LL_DBG_PRINTK (\"[RT6FW] --addr0 %x\", key->addr[0]);\n",
    "    LL_DBG_PRINTK (\"[RT6FW] --addr1 %x\", key->addr[1]);\n",
    "    LL_DBG_PRINTK (\"[RT6FW] --addr2 %x\", key->addr[2]);\n",
    "    LL_DBG_PRINTK (\"[RT6FW] --addr3 %x\", key->addr[3]);\n",
    "    xf->pm.table_id = LL_DP_RTV6_MAP;\n",
    "    act = bpf_map_lookup_elem (& rt_v6_map, key);\n",
    "    if (!act) {\n",
    "        xf->pm.nf &= ~LLB_NAT_SRC;\n",
    "        LL_DBG_PRINTK (\"RT Not found\");\n",
    "        return 0;\n",
    "    }\n",
    "    xf->pm.phit |= LLB_XDP_RT_HIT;\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_RTV6_STATS_MAP, act->ca.cidx);\n",
    "    return dp_do_rtops (ctx, xf, fa_, act);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_rtops",
    "dp_do_map_stats",
    "LL_DBG_PRINTK",
    "DP_XADDR_CP",
    "DP_XADDR_ISZR"
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
dp_do_rtv6(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_rtv6_key *key = (void *)xf->km.skey;
  struct dp_rt_tact *act;

  key->l.prefixlen = 128; /* 128-bit prefix */

  if (xf->pm.nf & LLB_NAT_DST) {
    if (DP_XADDR_ISZR(xf->nm.nxip)) {
      DP_XADDR_CP(key->addr, xf->l34m.saddr);
    } else {
      DP_XADDR_CP(key->addr, xf->nm.nxip);
    }
  } else {
    if (xf->pm.nf & LLB_NAT_SRC) {
      if (!DP_XADDR_ISZR(xf->nm.nrip)) {
        DP_XADDR_CP(key->addr, xf->nm.nrip);
      } else if (DP_XADDR_ISZR(xf->nm.nxip)) {
        DP_XADDR_CP(key->addr, xf->l34m.saddr);
      } else {
        DP_XADDR_CP(key->addr, xf->l34m.daddr);
      }
    } else {
        DP_XADDR_CP(key->addr, xf->l34m.daddr);
    }
  }

  LL_DBG_PRINTK("[RT6FW] --Lookup");
  LL_DBG_PRINTK("[RT6FW] --addr0 %x", key->addr[0]);
  LL_DBG_PRINTK("[RT6FW] --addr1 %x", key->addr[1]);
  LL_DBG_PRINTK("[RT6FW] --addr2 %x", key->addr[2]);
  LL_DBG_PRINTK("[RT6FW] --addr3 %x", key->addr[3]);

  xf->pm.table_id = LL_DP_RTV6_MAP;

  act = bpf_map_lookup_elem(&rt_v6_map, key);
  if (!act) {
    /* Default action - Nothing to do */
    xf->pm.nf &= ~LLB_NAT_SRC;
    LL_DBG_PRINTK("RT Not found");
    return 0;
  }

  xf->pm.phit |= LLB_XDP_RT_HIT;
  dp_do_map_stats(ctx, xf, LL_DP_RTV6_STATS_MAP, act->ca.cidx);

  return dp_do_rtops(ctx, xf, fa_, act);
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
  "startLine": 181,
  "endLine": 211,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_rtv4",
  "developer_inline_comments": [
    {
      "start_line": 184,
      "end_line": 184,
      "text": "struct dp_rtv4_key key = { 0 };"
    },
    {
      "start_line": 188,
      "end_line": 188,
      "text": " 16-bit zone + 32-bit prefix "
    },
    {
      "start_line": 202,
      "end_line": 202,
      "text": " Default action - Nothing to do "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  rt_v4_map"
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
    "static int __always_inline dp_do_rtv4 (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    struct dp_rtv4_key *key = (void *) xf->km.skey;\n",
    "    struct dp_rt_tact *act;\n",
    "    key->l.prefixlen = 48;\n",
    "    key->v4k[0] = xf->pm.zone >> 8 & 0xff;\n",
    "    key->v4k[1] = xf->pm.zone & 0xff;\n",
    "    *(__u32*) &key->v4k[2] = dp_rtv4_get_ipkey (xf);\n",
    "    LL_DBG_PRINTK (\"[RTFW] --Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[RTFW] Zone %d 0x%x\\n\", xf->pm.zone, *(__u32*) &key->v4k[2]);\n",
    "    xf->pm.table_id = LL_DP_RTV4_MAP;\n",
    "    act = bpf_map_lookup_elem (& rt_v4_map, key);\n",
    "    if (!act) {\n",
    "        xf->pm.nf &= ~LLB_NAT_SRC;\n",
    "        return 0;\n",
    "    }\n",
    "    xf->pm.phit |= LLB_XDP_RT_HIT;\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_RTV4_STATS_MAP, act->ca.cidx);\n",
    "    return dp_do_rtops (ctx, xf, fa_, act);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_rtops",
    "dp_do_map_stats",
    "LL_DBG_PRINTK",
    "dp_rtv4_get_ipkey"
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
dp_do_rtv4(void *ctx, struct xfi *xf, void *fa_)
{
  //struct dp_rtv4_key key = { 0 };
  struct dp_rtv4_key *key = (void *)xf->km.skey;
  struct dp_rt_tact *act;

  key->l.prefixlen = 48; /* 16-bit zone + 32-bit prefix */
  key->v4k[0] = xf->pm.zone >> 8 & 0xff;
  key->v4k[1] = xf->pm.zone & 0xff;

  *(__u32 *)&key->v4k[2] = dp_rtv4_get_ipkey(xf);
  
  LL_DBG_PRINTK("[RTFW] --Lookup\n");
  LL_DBG_PRINTK("[RTFW] Zone %d 0x%x\n",
                 xf->pm.zone, *(__u32 *)&key->v4k[2]);

  xf->pm.table_id = LL_DP_RTV4_MAP;

  act = bpf_map_lookup_elem(&rt_v4_map, key);
  if (!act) {
    /* Default action - Nothing to do */
    xf->pm.nf &= ~LLB_NAT_SRC;
    return 0;
  }

  xf->pm.phit |= LLB_XDP_RT_HIT;
  dp_do_map_stats(ctx, xf, LL_DP_RTV4_STATS_MAP, act->ca.cidx);

  return dp_do_rtops(ctx, xf, fa_, act);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 213,
  "endLine": 226,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_pipe_set_nat",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_nat_act *na",
    " int do_snat"
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
    "static int __always_inline dp_pipe_set_nat (void *ctx, struct xfi *xf, struct dp_nat_act *na, int do_snat)\n",
    "{\n",
    "    xf->pm.nf = do_snat ? LLB_NAT_SRC : LLB_NAT_DST;\n",
    "    DP_XADDR_CP (xf->nm.nxip, na->xip);\n",
    "    DP_XADDR_CP (xf->nm.nrip, na->rip);\n",
    "    xf->nm.nxport = na->xport;\n",
    "    xf->nm.nv6 = na->nv6 ? 1 : 0;\n",
    "    xf->nm.dsr = na->dsr;\n",
    "    LL_DBG_PRINTK (\"[ACL4] NAT ACT %x\\n\", xf->pm.nf);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
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
dp_pipe_set_nat(void *ctx, struct xfi *xf, 
                struct dp_nat_act *na, int do_snat)
{
  xf->pm.nf = do_snat ? LLB_NAT_SRC : LLB_NAT_DST;
  DP_XADDR_CP(xf->nm.nxip, na->xip);
  DP_XADDR_CP(xf->nm.nrip, na->rip);
  xf->nm.nxport = na->xport;
  xf->nm.nv6 = na->nv6 ? 1 : 0;
  xf->nm.dsr = na->dsr;
  LL_DBG_PRINTK("[ACL4] NAT ACT %x\n", xf->pm.nf);

  return 0;
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
  "startLine": 228,
  "endLine": 336,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_ctops",
  "developer_inline_comments": [
    {
      "start_line": 299,
      "end_line": 299,
      "text": "LLBS_PPLN_TRAP(xf);"
    },
    {
      "start_line": 305,
      "end_line": 305,
      "text": " Same for DP_SET_DROP "
    },
    {
      "start_line": 324,
      "end_line": 327,
      "text": " Note that this might result in consistency problems    * between packet and byte counts at times but this should be    * better than holding bpf-spinlock    "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa_",
    " struct dp_ct_tact *act"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_ktime_get_ns",
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
    "static int __always_inline dp_do_ctops (void *ctx, struct xfi *xf, void *fa_, struct dp_ct_tact *act)\n",
    "{\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    struct dp_fc_tacts *fa = fa_;\n",
    "\n",
    "#endif\n",
    "    if (!act) {\n",
    "        LL_DBG_PRINTK (\"[ACL] miss\");\n",
    "        goto ct_trk;\n",
    "    }\n",
    "    xf->pm.phit |= LLB_DP_ACL_HIT;\n",
    "    act->lts = bpf_ktime_get_ns ();\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "    fa->ca.cidx = act->ca.cidx;\n",
    "    fa->ca.fwrid = act->ca.fwrid;\n",
    "\n",
    "#endif\n",
    "    if (act->ca.act_type == DP_SET_DO_CT) {\n",
    "        goto ct_trk;\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_NOP) {\n",
    "        struct dp_rdr_act *ar = &act->port_act;\n",
    "        if (xf->pm.l4fin) {\n",
    "            ar->fr = 1;\n",
    "        }\n",
    "        if (ar->fr == 1) {\n",
    "            goto ct_trk;\n",
    "        }\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_RDR_PORT) {\n",
    "        struct dp_rdr_act *ar = &act->port_act;\n",
    "        if (xf->pm.l4fin) {\n",
    "            ar->fr = 1;\n",
    "        }\n",
    "        if (ar->fr == 1) {\n",
    "            goto ct_trk;\n",
    "        }\n",
    "        LLBS_PPLN_RDR_PRIO (xf);\n",
    "        xf->pm.oport = ar->oport;\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_SNAT || act->ca.act_type == DP_SET_DNAT) {\n",
    "        struct dp_nat_act *na;\n",
    "\n",
    "#ifdef HAVE_DP_FC\n",
    "        struct dp_fc_tact *ta = &fa->fcta[act->ca.act_type == DP_SET_SNAT ? DP_SET_SNAT : DP_SET_DNAT];\n",
    "        ta->ca.act_type = act->ca.act_type;\n",
    "        memcpy (&ta->nat_act, &act->nat_act, sizeof (act->nat_act));\n",
    "\n",
    "#endif\n",
    "        na = &act->nat_act;\n",
    "        if (xf->pm.l4fin) {\n",
    "            na->fr = 1;\n",
    "        }\n",
    "        dp_pipe_set_nat (ctx, xf, na, act->ca.act_type == DP_SET_SNAT ? 1 : 0);\n",
    "        dp_do_map_stats (ctx, xf, LL_DP_NAT_STATS_MAP, na->rid);\n",
    "        if (na->fr == 1 || na->doct) {\n",
    "            goto ct_trk;\n",
    "        }\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAPC (xf, LLB_PIPE_RC_ACL_MISS);\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_SESS_FWD_ACT) {\n",
    "        struct dp_sess_act *pa = &act->pdr_sess_act;\n",
    "        xf->pm.sess_id = pa->sess_id;\n",
    "    }\n",
    "    else {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "\n",
    "#ifdef HAVE_DP_EXTCT\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        dp_run_ctact_helper (xf, act);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if (act->ca.fwrid != 0) {\n",
    "        if (act->ca.record) {\n",
    "            dp_record_it (ctx, xf);\n",
    "            xf->pm.dp_rec = act->ca.record;\n",
    "        }\n",
    "        dp_do_map_stats (ctx, xf, LL_DP_FW4_STATS_MAP, act->ca.fwrid);\n",
    "    }\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_CT_STATS_MAP, act->ca.cidx);\n",
    "\n",
    "#if 0\n",
    "    lock_xadd (&act->ctd.pb.bytes, xf->pm.l3_len);\n",
    "    lock_xadd (&act->ctd.pb.packets, 1);\n",
    "\n",
    "#endif\n",
    "    return 0;\n",
    "ct_trk :\n",
    "    return dp_tail_call (ctx, xf, fa_, LLB_DP_CT_PGM_ID);\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "LLBS_PPLN_TRAPC",
    "dp_record_it",
    "lock_xadd",
    "dp_do_map_stats",
    "LL_DBG_PRINTK",
    "dp_pipe_set_nat",
    "LLBS_PPLN_RDR_PRIO",
    "dp_tail_call",
    "dp_run_ctact_helper",
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
dp_do_ctops(void *ctx, struct xfi *xf, void *fa_, 
             struct dp_ct_tact *act)
{
#ifdef HAVE_DP_FC
  struct dp_fc_tacts *fa = fa_;
#endif

  if (!act) {
    LL_DBG_PRINTK("[ACL] miss");
    goto ct_trk;
  }

  xf->pm.phit |= LLB_DP_ACL_HIT;
  act->lts = bpf_ktime_get_ns();

#ifdef HAVE_DP_FC
  fa->ca.cidx = act->ca.cidx;
  fa->ca.fwrid = act->ca.fwrid;
#endif

  if (act->ca.act_type == DP_SET_DO_CT) {
    goto ct_trk;
  } else if (act->ca.act_type == DP_SET_NOP) {
    struct dp_rdr_act *ar = &act->port_act;
    if (xf->pm.l4fin) {
      ar->fr = 1;
    }

    if (ar->fr == 1) {
      goto ct_trk;
    }

  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ar = &act->port_act;

    if (xf->pm.l4fin) {
      ar->fr = 1;
    }

    if (ar->fr == 1) {
      goto ct_trk;
    }

    LLBS_PPLN_RDR_PRIO(xf);
    xf->pm.oport = ar->oport;
  } else if (act->ca.act_type == DP_SET_SNAT || 
             act->ca.act_type == DP_SET_DNAT) {
    struct dp_nat_act *na;
#ifdef HAVE_DP_FC
    struct dp_fc_tact *ta = &fa->fcta[
                                  act->ca.act_type == DP_SET_SNAT ?
                                  DP_SET_SNAT : DP_SET_DNAT];
    ta->ca.act_type = act->ca.act_type;
    memcpy(&ta->nat_act,  &act->nat_act, sizeof(act->nat_act));
#endif

    na = &act->nat_act;

    if (xf->pm.l4fin) {
      na->fr = 1;
    }

    dp_pipe_set_nat(ctx, xf, na, act->ca.act_type == DP_SET_SNAT ? 1: 0);
    dp_do_map_stats(ctx, xf, LL_DP_NAT_STATS_MAP, na->rid);

    if (na->fr == 1 || na->doct) {
      goto ct_trk;
    }

  } else if (act->ca.act_type == DP_SET_TOCP) {
    /*LLBS_PPLN_TRAP(xf);*/
    LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_ACL_MISS);
  } else if (act->ca.act_type == DP_SET_SESS_FWD_ACT) {
    struct dp_sess_act *pa = &act->pdr_sess_act; 
    xf->pm.sess_id = pa->sess_id;
  } else {
    /* Same for DP_SET_DROP */
    LLBS_PPLN_DROP(xf);
  }

#ifdef HAVE_DP_EXTCT
  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    dp_run_ctact_helper(xf, act);
  }
#endif

  if (act->ca.fwrid != 0) {
    if (act->ca.record) {
      dp_record_it(ctx, xf);
      xf->pm.dp_rec = act->ca.record;
    }
    dp_do_map_stats(ctx, xf, LL_DP_FW4_STATS_MAP, act->ca.fwrid);
  }
  dp_do_map_stats(ctx, xf, LL_DP_CT_STATS_MAP, act->ca.cidx);
#if 0
  /* Note that this might result in consistency problems 
   * between packet and byte counts at times but this should be 
   * better than holding bpf-spinlock 
   */
  lock_xadd(&act->ctd.pb.bytes, xf->pm.l3_len);
  lock_xadd(&act->ctd.pb.packets, 1);
#endif

  return 0;

ct_trk:
  return dp_tail_call(ctx, xf, fa_, LLB_DP_CT_PGM_ID);
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
  "startLine": 338,
  "endLine": 360,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_ing_ct",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  ct_map"
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
    "static int __always_inline dp_do_ing_ct (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    struct dp_ct_key key;\n",
    "    struct dp_ct_tact *act;\n",
    "    CT_KEY_GEN (&key, xf);\n",
    "    LL_DBG_PRINTK (\"[ACL] -- Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[ACL] daddr %x\\n\", key.daddr[0]);\n",
    "    LL_DBG_PRINTK (\"[ACL] saddr %d\\n\", key.saddr[0]);\n",
    "    LL_DBG_PRINTK (\"[ACL] sport %d\\n\", key.sport);\n",
    "    LL_DBG_PRINTK (\"[ACL] dport %d\\n\", key.dport);\n",
    "    LL_DBG_PRINTK (\"[ACL] l4proto %d\\n\", key.l4proto);\n",
    "    xf->pm.table_id = LL_DP_CT_MAP;\n",
    "    act = bpf_map_lookup_elem (& ct_map, & key);\n",
    "    if (!act) {\n",
    "        LL_DBG_PRINTK (\"[ACL] miss\");\n",
    "    }\n",
    "    return dp_do_ctops (ctx, xf, fa_, act);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_ctops",
    "LL_DBG_PRINTK",
    "CT_KEY_GEN"
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
dp_do_ing_ct(void *ctx, struct xfi *xf, void *fa_)
{
  struct dp_ct_key key;
  struct dp_ct_tact *act;

  CT_KEY_GEN(&key, xf);

  LL_DBG_PRINTK("[ACL] -- Lookup\n");
  LL_DBG_PRINTK("[ACL] daddr %x\n", key.daddr[0]);
  LL_DBG_PRINTK("[ACL] saddr %d\n", key.saddr[0]);
  LL_DBG_PRINTK("[ACL] sport %d\n", key.sport);
  LL_DBG_PRINTK("[ACL] dport %d\n", key.dport);
  LL_DBG_PRINTK("[ACL] l4proto %d\n", key.l4proto);

  xf->pm.table_id = LL_DP_CT_MAP;
  act = bpf_map_lookup_elem(&ct_map, &key);
  if (!act) {
    LL_DBG_PRINTK("[ACL] miss");
  }

  return dp_do_ctops(ctx, xf, fa_, act);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 362,
  "endLine": 379,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_ipv4_fwd",
  "developer_inline_comments": [
    {
      "start_line": 365,
      "end_line": 365,
      "text": " Check tunnel initiation "
    },
    {
      "start_line": 372,
      "end_line": 374,
      "text": " If some pipeline block already set a redirect before this,     * we honor this and dont do further l3 processing      "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa_"
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
    "static void __always_inline dp_do_ipv4_fwd (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    if (xf->tm.tunnel_id == 0 || xf->tm.tun_type != LLB_TUN_GTP) {\n",
    "        dp_do_sess4_lkup (ctx, xf);\n",
    "    }\n",
    "    if (xf->pm.phit & LLB_DP_TMAC_HIT) {\n",
    "        if ((xf->pm.pipe_act & LLB_PIPE_RDR_MASK) == 0) {\n",
    "            dp_do_rtv4 (ctx, xf, fa_);\n",
    "        }\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_sess4_lkup",
    "dp_do_rtv4"
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
dp_do_ipv4_fwd(void *ctx,  struct xfi *xf, void *fa_)
{
  /* Check tunnel initiation */
  if (xf->tm.tunnel_id == 0 ||  xf->tm.tun_type != LLB_TUN_GTP) {
    dp_do_sess4_lkup(ctx, xf);
  }

  if (xf->pm.phit & LLB_DP_TMAC_HIT) {

    /* If some pipeline block already set a redirect before this,
     * we honor this and dont do further l3 processing 
     */
    if ((xf->pm.pipe_act & LLB_PIPE_RDR_MASK) == 0) {
      dp_do_rtv4(ctx, xf, fa_);
    }
  }
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 381,
  "endLine": 393,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_do_ipv6_fwd",
  "developer_inline_comments": [
    {
      "start_line": 386,
      "end_line": 388,
      "text": " If some pipeline block already set a redirect before this,     * we honor this and dont do further l3 processing     "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " void *fa_"
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
    "static void __always_inline dp_do_ipv6_fwd (void *ctx, struct xfi *xf, void *fa_)\n",
    "{\n",
    "    if (xf->pm.phit & LLB_DP_TMAC_HIT) {\n",
    "        if ((xf->pm.pipe_act & LLB_PIPE_RDR_MASK) == 0) {\n",
    "            dp_do_rtv6 (ctx, xf, fa_);\n",
    "        }\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_rtv6"
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
dp_do_ipv6_fwd(void *ctx,  struct xfi *xf, void *fa_)
{
  if (xf->pm.phit & LLB_DP_TMAC_HIT) {

    /* If some pipeline block already set a redirect before this,
     * we honor this and dont do further l3 processing
     */
    if ((xf->pm.pipe_act & LLB_PIPE_RDR_MASK) == 0) {
      dp_do_rtv6(ctx, xf, fa_);
    }
  }
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 395,
  "endLine": 414,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_l3_fwd",
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
    "static int __always_inline dp_l3_fwd (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    if (xf->l2m.dl_type == bpf_htons (ETH_P_IP)) {\n",
    "        if (xf->pm.nf && xf->nm.nv6 != 0) {\n",
    "            xf->nm.xlate_proto = 1;\n",
    "            dp_do_ipv6_fwd (ctx, xf, fa);\n",
    "        }\n",
    "        else {\n",
    "            dp_do_ipv4_fwd (ctx, xf, fa);\n",
    "        }\n",
    "    }\n",
    "    else if (xf->l2m.dl_type == bpf_htons (ETH_P_IPV6)) {\n",
    "        if (xf->pm.nf && xf->nm.nv6 == 0) {\n",
    "            xf->nm.xlate_proto = 1;\n",
    "            dp_do_ipv4_fwd (ctx, xf, fa);\n",
    "        }\n",
    "        else {\n",
    "            dp_do_ipv6_fwd (ctx, xf, fa);\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_ipv6_fwd",
    "bpf_htons",
    "dp_do_ipv4_fwd"
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
dp_l3_fwd(void *ctx,  struct xfi *xf, void *fa)
{
  if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    if (xf->pm.nf && xf->nm.nv6 != 0) {
      xf->nm.xlate_proto = 1;
      dp_do_ipv6_fwd(ctx, xf, fa);
    } else {
      dp_do_ipv4_fwd(ctx, xf, fa);
    }
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    if (xf->pm.nf && xf->nm.nv6 == 0) {
      xf->nm.xlate_proto = 1;
      dp_do_ipv4_fwd(ctx, xf, fa);
    } else {
      dp_do_ipv6_fwd(ctx, xf, fa);
    }
  }
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 416,
  "endLine": 431,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_l3fwd.c",
  "funcName": "dp_ing_l3",
  "developer_inline_comments": [
    {
      "start_line": 420,
      "end_line": 420,
      "text": " Check termination "
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
    "static int __always_inline dp_ing_l3 (void *ctx, struct xfi *xf, void *fa)\n",
    "{\n",
    "    if (xf->l2m.dl_type == bpf_htons (ETH_P_IP)) {\n",
    "        if (xf->tm.tunnel_id && (xf->tm.tun_type == LLB_TUN_GTP || xf->tm.tun_type == LLB_TUN_IPIP)) {\n",
    "            dp_do_sess4_lkup (ctx, xf);\n",
    "        }\n",
    "    }\n",
    "    dp_do_ing_ct (ctx, xf, fa);\n",
    "    dp_l3_fwd (ctx, xf, fa);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_sess4_lkup",
    "bpf_htons",
    "dp_l3_fwd",
    "dp_do_ing_ct"
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
dp_ing_l3(void *ctx,  struct xfi *xf, void *fa)
{
  if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    /* Check termination */
    if (xf->tm.tunnel_id &&
        (xf->tm.tun_type == LLB_TUN_GTP || xf->tm.tun_type == LLB_TUN_IPIP)) {
      dp_do_sess4_lkup(ctx, xf);
    }
  }

  dp_do_ing_ct(ctx, xf, fa);
  dp_l3_fwd(ctx, xf, fa);

  return 0;
}
