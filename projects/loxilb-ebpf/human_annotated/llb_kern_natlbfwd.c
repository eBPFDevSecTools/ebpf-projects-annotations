/*
 *  llb_kern_nat.c: LoxiLB Kernel eBPF Stateful NAT/LB Processing
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
  "endLine": 53,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_natlbfwd.c",
  "funcName": "dp_sel_nat_ep",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_nat.c: LoxiLB Kernel eBPF Stateful NAT/LB Processing *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 38,
      "end_line": 38,
      "text": " Fall back if hash selection gives us a deadend "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct dp_nat_tacts *act"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_spin_lock",
    "bpf_spin_unlock"
  ],
  "compatibleHookpoints": [
    "socket_filter",
    "sock_ops",
    "xdp",
    "sched_act",
    "sk_reuseport",
    "lwt_seg6local",
    "lwt_in",
    "sk_skb",
    "cgroup_skb",
    "lwt_xmit",
    "cgroup_sock",
    "lwt_out",
    "sched_cls",
    "flow_dissector",
    "sk_msg",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int __always_inline dp_sel_nat_ep (void *ctx, struct dp_nat_tacts *act)\n",
    "{\n",
    "    int sel = -1;\n",
    "    uint8_t n = 0;\n",
    "    uint16_t i = 0;\n",
    "    struct mf_xfrm_inf *nxfrm_act;\n",
    "    if (act->sel_type == NAT_LB_SEL_RR) {\n",
    "        bpf_spin_lock (&act->lock);\n",
    "        i = act->sel_hint;\n",
    "        while (n < LLB_MAX_NXFRMS) {\n",
    "            if (i >= 0 && i < LLB_MAX_NXFRMS) {\n",
    "                nxfrm_act = &act->nxfrms[i];\n",
    "                if (nxfrm_act < act + 1) {\n",
    "                    if (nxfrm_act->inactive == 0) {\n",
    "                        act->sel_hint = (i + 1) % act->nxfrm;\n",
    "                        sel = i;\n",
    "                        break;\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "            i++;\n",
    "            i = i % act->nxfrm;\n",
    "            n++;\n",
    "        }\n",
    "        bpf_spin_unlock (&act->lock);\n",
    "    }\n",
    "    else if (act->sel_type == NAT_LB_SEL_HASH) {\n",
    "        sel = dp_get_pkt_hash (ctx) % act->nxfrm;\n",
    "        if (sel >= 0 && sel < LLB_MAX_NXFRMS) {\n",
    "            if (act->nxfrms[sel].inactive) {\n",
    "                for (i = 0; i < LLB_MAX_NXFRMS; i++) {\n",
    "                    if (act->nxfrms[i].inactive == 0) {\n",
    "                        sel = i;\n",
    "                        break;\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"lb-sel %d\", sel);\n",
    "    return sel;\n",
    "}\n"
  ],
  "called_function_list": [
    "LL_DBG_PRINTK",
    "dp_get_pkt_hash"
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
dp_sel_nat_ep(void *ctx, struct dp_nat_tacts *act)
{
  int sel = -1;
  uint8_t n = 0;
  uint16_t i = 0;
  struct mf_xfrm_inf *nxfrm_act;

  if (act->sel_type == NAT_LB_SEL_RR) {
    bpf_spin_lock(&act->lock);
    i = act->sel_hint; 

    while (n < LLB_MAX_NXFRMS) {
      if (i >= 0 && i < LLB_MAX_NXFRMS) {
        nxfrm_act = &act->nxfrms[i];
        if (nxfrm_act < act + 1) {
          if (nxfrm_act->inactive == 0) { 
            act->sel_hint = (i + 1) % act->nxfrm;
            sel = i;
            break;
          }
        }
      }
      i++;
      i = i % act->nxfrm;
      n++;
    }
    bpf_spin_unlock(&act->lock);
  } else if (act->sel_type == NAT_LB_SEL_HASH) {
    sel = dp_get_pkt_hash(ctx) % act->nxfrm;
    if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
      /* Fall back if hash selection gives us a deadend */
      if (act->nxfrms[sel].inactive) {
        for (i = 0; i < LLB_MAX_NXFRMS; i++) {
          if (act->nxfrms[i].inactive == 0) {
            sel = i;
            break;
          }
        }
      }
    }
  }

  LL_DBG_PRINTK("lb-sel %d", sel);

  return sel;
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
  "startLine": 55,
  "endLine": 126,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_natlbfwd.c",
  "funcName": "dp_do_nat",
  "developer_inline_comments": [
    {
      "start_line": 83,
      "end_line": 83,
      "text": " Default action - Nothing to do "
    },
    {
      "start_line": 98,
      "end_line": 100,
      "text": " FIXME - Do not select inactive end-points      * Need multi-passes for selection     "
    },
    {
      "start_line": 113,
      "end_line": 113,
      "text": " Special case related to host-dnat "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  nat_map"
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
    "static int __always_inline dp_do_nat (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct dp_nat_key key;\n",
    "    struct mf_xfrm_inf *nxfrm_act;\n",
    "    struct dp_nat_tacts *act;\n",
    "    __u32 sel;\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    DP_XADDR_CP (key.daddr, xf->l34m.daddr);\n",
    "    if (xf->l34m.nw_proto != IPPROTO_ICMP) {\n",
    "        key.dport = xf->l34m.dest;\n",
    "    }\n",
    "    else {\n",
    "        key.dport = 0;\n",
    "    }\n",
    "    key.zone = xf->pm.zone;\n",
    "    key.l4proto = xf->l34m.nw_proto;\n",
    "    key.mark = (__u16) (xf->pm.dp_mark & 0xffff);\n",
    "    if (xf->l2m.dl_type == bpf_ntohs (ETH_P_IPV6)) {\n",
    "        key.v6 = 1;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[NAT] --Lookup\\n\");\n",
    "    xf->pm.table_id = LL_DP_NAT_MAP;\n",
    "    act = bpf_map_lookup_elem (& nat_map, & key);\n",
    "    if (!act) {\n",
    "        xf->pm.nf &= ~LLB_NAT_SRC;\n",
    "        return 0;\n",
    "    }\n",
    "    LL_DBG_PRINTK (\"[NAT] action %d pipe %x\\n\", act->ca.act_type, xf->pm.pipe_act);\n",
    "    if (act->ca.act_type == DP_SET_SNAT || act->ca.act_type == DP_SET_DNAT) {\n",
    "        sel = dp_sel_nat_ep (ctx, act);\n",
    "        xf->nm.dsr = act->ca.oaux ? 1 : 0;\n",
    "        xf->pm.nf = act->ca.act_type == DP_SET_SNAT ? LLB_NAT_SRC : LLB_NAT_DST;\n",
    "        if (sel >= 0 && sel < LLB_MAX_NXFRMS) {\n",
    "            nxfrm_act = &act->nxfrms[sel];\n",
    "            if (nxfrm_act < act + 1) {\n",
    "                DP_XADDR_CP (xf->nm.nxip, nxfrm_act->nat_xip);\n",
    "                DP_XADDR_CP (xf->nm.nrip, nxfrm_act->nat_rip);\n",
    "                xf->nm.nxport = nxfrm_act->nat_xport;\n",
    "                xf->nm.nv6 = nxfrm_act->nv6 ? 1 : 0;\n",
    "                xf->nm.sel_aid = sel;\n",
    "                xf->nm.ito = act->ito;\n",
    "                xf->pm.rule_id = act->ca.cidx;\n",
    "                LL_DBG_PRINTK (\"[NAT] ACT %x\\n\", xf->pm.nf);\n",
    "                if (xf->l34m.saddr4 == xf->nm.nxip4 && xf->pm.nf == LLB_NAT_DST) {\n",
    "                    xf->nm.nxip4 = 0;\n",
    "                }\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            xf->pm.nf = 0;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    return 1;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "memset",
    "LL_DBG_PRINTK",
    "bpf_ntohs",
    "dp_sel_nat_ep",
    "DP_XADDR_CP"
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
dp_do_nat(void *ctx, struct xfi *xf)
{
  struct dp_nat_key key;
  struct mf_xfrm_inf *nxfrm_act;
  struct dp_nat_tacts *act;
  __u32 sel;

  memset(&key, 0, sizeof(key));
  DP_XADDR_CP(key.daddr, xf->l34m.daddr);
  if (xf->l34m.nw_proto != IPPROTO_ICMP) {
    key.dport = xf->l34m.dest;
  } else {
    key.dport = 0;
  }
  key.zone = xf->pm.zone;
  key.l4proto = xf->l34m.nw_proto;
  key.mark = (__u16)(xf->pm.dp_mark & 0xffff);
  if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
    key.v6 = 1;
  }

  LL_DBG_PRINTK("[NAT] --Lookup\n");

  xf->pm.table_id = LL_DP_NAT_MAP;

  act = bpf_map_lookup_elem(&nat_map, &key);
  if (!act) {
    /* Default action - Nothing to do */
    xf->pm.nf &= ~LLB_NAT_SRC;
    return 0;
  }

  LL_DBG_PRINTK("[NAT] action %d pipe %x\n",
                 act->ca.act_type, xf->pm.pipe_act);

  if (act->ca.act_type == DP_SET_SNAT || 
      act->ca.act_type == DP_SET_DNAT) {
    sel = dp_sel_nat_ep(ctx, act);

    xf->nm.dsr = act->ca.oaux ? 1: 0;
    xf->pm.nf = act->ca.act_type == DP_SET_SNAT ? LLB_NAT_SRC : LLB_NAT_DST;

    /* FIXME - Do not select inactive end-points 
     * Need multi-passes for selection
     */
    if (sel >= 0 && sel < LLB_MAX_NXFRMS) {
      nxfrm_act = &act->nxfrms[sel];

      if (nxfrm_act < act + 1) {
        DP_XADDR_CP(xf->nm.nxip, nxfrm_act->nat_xip);
        DP_XADDR_CP(xf->nm.nrip, nxfrm_act->nat_rip);
        xf->nm.nxport = nxfrm_act->nat_xport;
        xf->nm.nv6 = nxfrm_act->nv6 ? 1: 0;
        xf->nm.sel_aid = sel;
        xf->nm.ito = act->ito;
        xf->pm.rule_id =  act->ca.cidx;
        LL_DBG_PRINTK("[NAT] ACT %x\n", xf->pm.nf);
        /* Special case related to host-dnat */
        if (xf->l34m.saddr4 == xf->nm.nxip4 && xf->pm.nf == LLB_NAT_DST) {
          xf->nm.nxip4 = 0;
        }
      }
    } else {
      xf->pm.nf = 0;
    }
  } else { 
    LLBS_PPLN_DROP(xf);
  }

  return 1;
}
