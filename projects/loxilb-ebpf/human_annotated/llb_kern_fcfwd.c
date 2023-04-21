/*
 *  llb_kern_fc.c: LoxiLB kernel cache based forwarding
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
  "startLine": 8,
  "endLine": 37,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_fcfwd.c",
  "funcName": "dp_do_fcv4_ct_helper",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_fc.c: LoxiLB kernel cache based forwarding *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 22,
      "end_line": 24,
      "text": " We dont do much strict tracking after EST state.   * But need to maintain certain ct info   "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  ct_map"
  ],
  "input": [
    "struct xfi *xf"
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
    "static int __always_inline dp_do_fcv4_ct_helper (struct xfi *xf)\n",
    "{\n",
    "    struct dp_ct_key key;\n",
    "    struct dp_ct_tact *act;\n",
    "    CT_KEY_GEN (&key, xf);\n",
    "    act = bpf_map_lookup_elem (& ct_map, & key);\n",
    "    if (!act) {\n",
    "        LL_DBG_PRINTK (\"[FCH4] miss\");\n",
    "        return -1;\n",
    "    }\n",
    "    switch (act->ca.act_type) {\n",
    "    case DP_SET_NOP :\n",
    "    case DP_SET_SNAT :\n",
    "    case DP_SET_DNAT :\n",
    "        act->ctd.pi.t.tcp_cts[CT_DIR_IN].pseq = xf->l34m.seq;\n",
    "        act->ctd.pi.t.tcp_cts[CT_DIR_IN].pack = xf->l34m.ack;\n",
    "        break;\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
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
dp_do_fcv4_ct_helper(struct xfi *xf) 
{
  struct dp_ct_key key;
  struct dp_ct_tact *act;

  CT_KEY_GEN(&key, xf);

  act = bpf_map_lookup_elem(&ct_map, &key);
  if (!act) {
    LL_DBG_PRINTK("[FCH4] miss");
    return -1;
  }

  /* We dont do much strict tracking after EST state.
   * But need to maintain certain ct info
   */
  switch (act->ca.act_type) {
  case DP_SET_NOP:
  case DP_SET_SNAT:
  case DP_SET_DNAT:
    act->ctd.pi.t.tcp_cts[CT_DIR_IN].pseq = xf->l34m.seq;
    act->ctd.pi.t.tcp_cts[CT_DIR_IN].pack = xf->l34m.ack;
    break;
  default:
    break;
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 39,
  "endLine": 67,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_fcfwd.c",
  "funcName": "dp_mk_fcv4_key",
  "developer_inline_comments": [
    {
      "start_line": 47,
      "end_line": 47,
      "text": "key->bd = xf->pm.bd;"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xfi *xf",
    " struct dp_fcv4_key *key"
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
    "static int __always_inline dp_mk_fcv4_key (struct xfi *xf, struct dp_fcv4_key *key)\n",
    "{\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "    memcpy (key->smac, xf->l2m.dl_src, 6);\n",
    "    memcpy (key->dmac, xf->l2m.dl_dst, 6);\n",
    "    memcpy (key->in_smac, xf->il2m.dl_src, 6);\n",
    "    memcpy (key->in_dmac, xf->il2m.dl_dst, 6);\n",
    "\n",
    "#endif\n",
    "    key->daddr = xf->l34m.daddr4;\n",
    "    key->saddr = xf->l34m.saddr4;\n",
    "    key->sport = xf->l34m.source;\n",
    "    key->dport = xf->l34m.dest;\n",
    "    key->l4proto = xf->l34m.nw_proto;\n",
    "    key->pad = 0;\n",
    "    key->in_port = 0;\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "    key->in_daddr = xf->il34m.daddr4;\n",
    "    key->in_saddr = xf->il34m.saddr4;\n",
    "    key->in_sport = xf->il34m.source;\n",
    "    key->in_dport = xf->il34m.dest;\n",
    "    key->in_l4proto = xf->il34m.nw_proto;\n",
    "\n",
    "#endif\n",
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
static int  __always_inline
dp_mk_fcv4_key(struct xfi *xf, struct dp_fcv4_key *key)
{
#ifdef HAVE_DP_EXTFC
  memcpy(key->smac, xf->l2m.dl_src, 6);
  memcpy(key->dmac, xf->l2m.dl_dst, 6);
  memcpy(key->in_smac, xf->il2m.dl_src, 6);
  memcpy(key->in_dmac, xf->il2m.dl_dst, 6);
  //key->bd = xf->pm.bd;
#endif

  key->daddr      = xf->l34m.daddr4;
  key->saddr      = xf->l34m.saddr4;
  key->sport      = xf->l34m.source;
  key->dport      = xf->l34m.dest;
  key->l4proto    = xf->l34m.nw_proto;
  key->pad        = 0;
  key->in_port    = 0;

#ifdef HAVE_DP_EXTFC
  key->in_daddr   = xf->il34m.daddr4;
  key->in_saddr   = xf->il34m.saddr4;
  key->in_sport   = xf->il34m.source;
  key->in_dport   = xf->il34m.dest;
  key->in_l4proto = xf->il34m.nw_proto;
#endif

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
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Delete entry with <[ key ]>(IP: 1) from map. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_delete_elem",
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 69,
  "endLine": 216,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_fcfwd.c",
  "funcName": "dp_do_fcv4_lkup",
  "developer_inline_comments": [
    {
      "start_line": 96,
      "end_line": 99,
      "text": " xfck - fcache key table is maintained so that      * there is no need to make fcv4 key again in     * tail-call sections     "
    },
    {
      "start_line": 104,
      "end_line": 104,
      "text": " Check timeout "
    },
    {
      "start_line": 191,
      "end_line": 191,
      "text": " Catch any conditions which need us to go to cp/ct "
    },
    {
      "start_line": 209,
      "end_line": 209,
      "text": " Field overloaded as oif "
    }
  ],
  "updateMaps": [
    " fc_v4_map",
    " xfck"
  ],
  "readMaps": [
    "  fc_v4_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_ktime_get_ns",
    "bpf_map_update_elem",
    "bpf_map_delete_elem"
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
    "static int __always_inline dp_do_fcv4_lkup (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct dp_fcv4_key key;\n",
    "    struct dp_fc_tacts *acts;\n",
    "    struct dp_fc_tact *ta;\n",
    "    int ret = 1;\n",
    "    int z = 0;\n",
    "    dp_mk_fcv4_key (xf, &key);\n",
    "    LL_FC_PRINTK (\"[FCH4] -- Lookup\\n\");\n",
    "    LL_FC_PRINTK (\"[FCH4] key-sz %d\\n\", sizeof (key));\n",
    "    LL_FC_PRINTK (\"[FCH4] daddr %x\\n\", key.daddr);\n",
    "    LL_FC_PRINTK (\"[FCH4] saddr %x\\n\", key.saddr);\n",
    "    LL_FC_PRINTK (\"[FCH4] sport %x\\n\", key.sport);\n",
    "    LL_FC_PRINTK (\"[FCH4] dport %x\\n\", key.dport);\n",
    "    LL_FC_PRINTK (\"[FCH4] l4proto %x\\n\", key.l4proto);\n",
    "    LL_FC_PRINTK (\"[FCH4] idaddr %x\\n\", key.in_daddr);\n",
    "    LL_FC_PRINTK (\"[FCH4] isaddr %x\\n\", key.in_saddr);\n",
    "    LL_FC_PRINTK (\"[FCH4] isport %x\\n\", key.in_sport);\n",
    "    LL_FC_PRINTK (\"[FCH4] idport %x\\n\", key.in_dport);\n",
    "    LL_FC_PRINTK (\"[FCH4] il4proto %x\\n\", key.in_l4proto);\n",
    "    xf->pm.table_id = LL_DP_FCV4_MAP;\n",
    "    acts = bpf_map_lookup_elem (& fc_v4_map, & key);\n",
    "    if (!acts) {\n",
    "        bpf_map_update_elem (&xfck, &z, &key, BPF_ANY);\n",
    "        return 0;\n",
    "    }\n",
    "    if (bpf_ktime_get_ns () - acts->its > FC_V4_DPTO) {\n",
    "        LL_FC_PRINTK (\"[FCH4] hto\");\n",
    "        bpf_map_update_elem (&xfck, &z, &key, BPF_ANY);\n",
    "        bpf_map_delete_elem (&fc_v4_map, &key);\n",
    "        return 0;\n",
    "    }\n",
    "    LL_FC_PRINTK (\"[FCH4] key found act-sz %d\\n\", sizeof (struct dp_fc_tacts));\n",
    "    if (acts->ca.ftrap)\n",
    "        return 0;\n",
    "    xf->pm.phit |= LLB_DP_FC_HIT;\n",
    "    xf->pm.zone = acts->zone;\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "    if (acts->fcta[DP_SET_RM_VXLAN].ca.act_type == DP_SET_RM_VXLAN) {\n",
    "        LL_FC_PRINTK (\"[FCH4] strip-vxlan-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_RM_VXLAN];\n",
    "        dp_pipe_set_rm_vx_tun (ctx, xf, &ta->nh_act);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if (acts->fcta[DP_SET_SNAT].ca.act_type == DP_SET_SNAT) {\n",
    "        LL_FC_PRINTK (\"[FCH4] snat-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_SNAT];\n",
    "        if (ta->nat_act.fr == 1 || ta->nat_act.doct) {\n",
    "            return 0;\n",
    "        }\n",
    "        dp_pipe_set_nat (ctx, xf, &ta->nat_act, 1);\n",
    "        dp_do_map_stats (ctx, xf, LL_DP_NAT_STATS_MAP, ta->nat_act.rid);\n",
    "    }\n",
    "    else if (acts->fcta[DP_SET_DNAT].ca.act_type == DP_SET_DNAT) {\n",
    "        LL_FC_PRINTK (\"[FCH4] dnat-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_DNAT];\n",
    "        if (ta->nat_act.fr == 1 || ta->nat_act.doct) {\n",
    "            return 0;\n",
    "        }\n",
    "        dp_pipe_set_nat (ctx, xf, &ta->nat_act, 0);\n",
    "        dp_do_map_stats (ctx, xf, LL_DP_NAT_STATS_MAP, ta->nat_act.rid);\n",
    "    }\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "    if (acts->fcta[DP_SET_RT_TUN_NH].ca.act_type == DP_SET_RT_TUN_NH) {\n",
    "        ta = &acts->fcta[DP_SET_RT_TUN_NH];\n",
    "        LL_FC_PRINTK (\"[FCH4] tun-nh found\\n\");\n",
    "        dp_pipe_set_l22_tun_nh (ctx, xf, &ta->nh_act);\n",
    "    }\n",
    "    else if (acts->fcta[DP_SET_L3RT_TUN_NH].ca.act_type == DP_SET_L3RT_TUN_NH) {\n",
    "        LL_FC_PRINTK (\"[FCH4] l3-rt-tnh-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_L3RT_TUN_NH];\n",
    "        dp_pipe_set_l32_tun_nh (ctx, xf, &ta->nh_act);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if (acts->fcta[DP_SET_NEIGH_L2].ca.act_type == DP_SET_NEIGH_L2) {\n",
    "        LL_FC_PRINTK (\"[FCH4] l2-rt-nh-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_NEIGH_L2];\n",
    "        dp_do_rt_l2_nh (ctx, xf, &ta->nl2);\n",
    "    }\n",
    "\n",
    "#ifdef HAVE_DP_EXTFC\n",
    "    if (acts->fcta[DP_SET_NEIGH_VXLAN].ca.act_type == DP_SET_NEIGH_VXLAN) {\n",
    "        LL_FC_PRINTK (\"[FCH4] rt-l2-nh-vxlan-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_NEIGH_VXLAN];\n",
    "        dp_do_rt_tun_nh (ctx, xf, LLB_TUN_VXLAN, &ta->ntun);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if (acts->fcta[DP_SET_ADD_L2VLAN].ca.act_type == DP_SET_ADD_L2VLAN) {\n",
    "        LL_FC_PRINTK (\"[FCH4] new-l2-vlan-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_ADD_L2VLAN];\n",
    "        dp_set_egr_vlan (ctx, xf, ta->l2ov.vlan, ta->l2ov.oport);\n",
    "    }\n",
    "    else if (acts->fcta[DP_SET_RM_L2VLAN].ca.act_type == DP_SET_RM_L2VLAN) {\n",
    "        LL_FC_PRINTK (\"[FCH4] strip-l2-vlan-act\\n\");\n",
    "        ta = &acts->fcta[DP_SET_RM_L2VLAN];\n",
    "        dp_set_egr_vlan (ctx, xf, 0, ta->l2ov.oport);\n",
    "    }\n",
    "    else {\n",
    "        goto del_out;\n",
    "    }\n",
    "    if (xf->pm.l4fin) {\n",
    "        acts->ca.ftrap = 1;\n",
    "        goto del_out;\n",
    "    }\n",
    "    DP_RUN_CT_HELPER (xf);\n",
    "    if (acts->ca.fwrid != 0) {\n",
    "        dp_do_map_stats (ctx, xf, LL_DP_FW4_STATS_MAP, acts->ca.fwrid);\n",
    "    }\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_CT_STATS_MAP, acts->ca.cidx);\n",
    "    LL_FC_PRINTK (\"[FCH4] oport %d\\n\", xf->pm.oport);\n",
    "    dp_unparse_packet_always (ctx, xf);\n",
    "    dp_unparse_packet (ctx, xf);\n",
    "    xf->pm.oport = acts->ca.oaux;\n",
    "    return ret;\n",
    "del_out :\n",
    "    bpf_map_delete_elem (&fc_v4_map, &key);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_rt_l2_nh",
    "dp_mk_fcv4_key",
    "dp_pipe_set_l22_tun_nh",
    "dp_pipe_set_l32_tun_nh",
    "dp_unparse_packet",
    "dp_do_map_stats",
    "LL_FC_PRINTK",
    "dp_pipe_set_nat",
    "dp_do_rt_tun_nh",
    "dp_set_egr_vlan",
    "dp_unparse_packet_always",
    "dp_pipe_set_rm_vx_tun",
    "DP_RUN_CT_HELPER"
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
dp_do_fcv4_lkup(void *ctx, struct xfi *xf)
{
  struct dp_fcv4_key key;
  struct dp_fc_tacts *acts;
  struct dp_fc_tact *ta;
  int ret = 1;
  int z = 0;

  dp_mk_fcv4_key(xf, &key);

  LL_FC_PRINTK("[FCH4] -- Lookup\n");
  LL_FC_PRINTK("[FCH4] key-sz %d\n", sizeof(key));
  LL_FC_PRINTK("[FCH4] daddr %x\n", key.daddr);
  LL_FC_PRINTK("[FCH4] saddr %x\n", key.saddr);
  LL_FC_PRINTK("[FCH4] sport %x\n", key.sport);
  LL_FC_PRINTK("[FCH4] dport %x\n", key.dport);
  LL_FC_PRINTK("[FCH4] l4proto %x\n", key.l4proto);
  LL_FC_PRINTK("[FCH4] idaddr %x\n", key.in_daddr);
  LL_FC_PRINTK("[FCH4] isaddr %x\n", key.in_saddr);
  LL_FC_PRINTK("[FCH4] isport %x\n", key.in_sport);
  LL_FC_PRINTK("[FCH4] idport %x\n", key.in_dport);
  LL_FC_PRINTK("[FCH4] il4proto %x\n", key.in_l4proto);

  xf->pm.table_id = LL_DP_FCV4_MAP;
  acts = bpf_map_lookup_elem(&fc_v4_map, &key);
  if (!acts) {
    /* xfck - fcache key table is maintained so that 
     * there is no need to make fcv4 key again in
     * tail-call sections
     */
    bpf_map_update_elem(&xfck, &z, &key, BPF_ANY);
    return 0; 
  }

  /* Check timeout */ 
  if (bpf_ktime_get_ns() - acts->its > FC_V4_DPTO) {
    LL_FC_PRINTK("[FCH4] hto");
    bpf_map_update_elem(&xfck, &z, &key, BPF_ANY);
    bpf_map_delete_elem(&fc_v4_map, &key);
    return 0; 
  }

  LL_FC_PRINTK("[FCH4] key found act-sz %d\n", sizeof(struct dp_fc_tacts));

  if (acts->ca.ftrap)
    return 0; 

  xf->pm.phit |= LLB_DP_FC_HIT;

  xf->pm.zone = acts->zone;


#ifdef HAVE_DP_EXTFC
  if (acts->fcta[DP_SET_RM_VXLAN].ca.act_type == DP_SET_RM_VXLAN) {
    LL_FC_PRINTK("[FCH4] strip-vxlan-act\n");
    ta = &acts->fcta[DP_SET_RM_VXLAN];
    dp_pipe_set_rm_vx_tun(ctx, xf, &ta->nh_act);
  }
#endif

  if (acts->fcta[DP_SET_SNAT].ca.act_type == DP_SET_SNAT) {
    LL_FC_PRINTK("[FCH4] snat-act\n");
    ta = &acts->fcta[DP_SET_SNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      return 0;
    }

    dp_pipe_set_nat(ctx, xf, &ta->nat_act, 1);
    dp_do_map_stats(ctx, xf, LL_DP_NAT_STATS_MAP, ta->nat_act.rid);
  } else if (acts->fcta[DP_SET_DNAT].ca.act_type == DP_SET_DNAT) {
    LL_FC_PRINTK("[FCH4] dnat-act\n");
    ta = &acts->fcta[DP_SET_DNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      return 0;
    }

    dp_pipe_set_nat(ctx, xf, &ta->nat_act, 0);
    dp_do_map_stats(ctx, xf, LL_DP_NAT_STATS_MAP, ta->nat_act.rid);
  }


#ifdef HAVE_DP_EXTFC
  if (acts->fcta[DP_SET_RT_TUN_NH].ca.act_type == DP_SET_RT_TUN_NH) {
    ta = &acts->fcta[DP_SET_RT_TUN_NH];
    LL_FC_PRINTK("[FCH4] tun-nh found\n");
    dp_pipe_set_l22_tun_nh(ctx, xf, &ta->nh_act);
  } else if (acts->fcta[DP_SET_L3RT_TUN_NH].ca.act_type == DP_SET_L3RT_TUN_NH) {
    LL_FC_PRINTK("[FCH4] l3-rt-tnh-act\n");
    ta = &acts->fcta[DP_SET_L3RT_TUN_NH];
    dp_pipe_set_l32_tun_nh(ctx, xf, &ta->nh_act);
  }
#endif

  if (acts->fcta[DP_SET_NEIGH_L2].ca.act_type == DP_SET_NEIGH_L2) {
    LL_FC_PRINTK("[FCH4] l2-rt-nh-act\n");
    ta = &acts->fcta[DP_SET_NEIGH_L2];
    dp_do_rt_l2_nh(ctx, xf, &ta->nl2);
  }

#ifdef HAVE_DP_EXTFC
  if (acts->fcta[DP_SET_NEIGH_VXLAN].ca.act_type == DP_SET_NEIGH_VXLAN) {
    LL_FC_PRINTK("[FCH4] rt-l2-nh-vxlan-act\n");
    ta = &acts->fcta[DP_SET_NEIGH_VXLAN];
    dp_do_rt_tun_nh(ctx, xf, LLB_TUN_VXLAN, &ta->ntun);
  }
#endif

  if (acts->fcta[DP_SET_ADD_L2VLAN].ca.act_type == DP_SET_ADD_L2VLAN) {
    LL_FC_PRINTK("[FCH4] new-l2-vlan-act\n");
    ta = &acts->fcta[DP_SET_ADD_L2VLAN];
    dp_set_egr_vlan(ctx, xf, ta->l2ov.vlan, ta->l2ov.oport);
  } else if (acts->fcta[DP_SET_RM_L2VLAN].ca.act_type == DP_SET_RM_L2VLAN) {
    LL_FC_PRINTK("[FCH4] strip-l2-vlan-act\n");
    ta = &acts->fcta[DP_SET_RM_L2VLAN];
    dp_set_egr_vlan(ctx, xf, 0, ta->l2ov.oport);
  } else {
    goto del_out;
  }

  /* Catch any conditions which need us to go to cp/ct */
  if (xf->pm.l4fin) {
    acts->ca.ftrap = 1;
    goto del_out;
  }

  DP_RUN_CT_HELPER(xf);

  if (acts->ca.fwrid != 0) {
    dp_do_map_stats(ctx, xf, LL_DP_FW4_STATS_MAP, acts->ca.fwrid);
  }

  dp_do_map_stats(ctx, xf, LL_DP_CT_STATS_MAP, acts->ca.cidx);

  LL_FC_PRINTK("[FCH4] oport %d\n",  xf->pm.oport);
  dp_unparse_packet_always(ctx, xf);
  dp_unparse_packet(ctx, xf);

  xf->pm.oport = acts->ca.oaux; /* Field overloaded as oif */

  return ret;

del_out:
  bpf_map_delete_elem(&fc_v4_map, &key);
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
  "startLine": 218,
  "endLine": 240,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_fcfwd.c",
  "funcName": "dp_ing_fc_main",
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
    "bpf_tail_call",
    "bpf_redirect",
    "bpf_map_update_elem"
  ],
  "compatibleHookpoints": [
    "lwt_xmit",
    "sched_cls",
    "xdp",
    "sched_act"
  ],
  "source": [
    "static int __always_inline dp_ing_fc_main (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    int z = 0;\n",
    "    __u32 idx = LLB_DP_PKT_SLOW_PGM_ID;\n",
    "    LL_FC_PRINTK (\"[FCHM] Main--\\n\");\n",
    "    if (xf->pm.pipe_act == 0 && xf->l2m.dl_type == bpf_ntohs (ETH_P_IP)) {\n",
    "        if (dp_do_fcv4_lkup (ctx, xf) == 1) {\n",
    "            if (xf->pm.pipe_act == LLB_PIPE_RDR) {\n",
    "                int oif = xf->pm.oport;\n",
    "\n",
    "#ifdef HAVE_DP_EGR_HOOK\n",
    "                DP_LLB_MRK_INGP (ctx);\n",
    "\n",
    "#endif\n",
    "                return bpf_redirect (oif, 0);\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    bpf_map_update_elem (&xfis, &z, xf, BPF_ANY);\n",
    "    bpf_tail_call (ctx, &pgm_tbl, idx);\n",
    "    return DP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "dp_do_fcv4_lkup",
    "LL_FC_PRINTK",
    "DP_LLB_MRK_INGP"
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
dp_ing_fc_main(void *ctx, struct xfi *xf)
{
  int z = 0;
  __u32 idx = LLB_DP_PKT_SLOW_PGM_ID;
  LL_FC_PRINTK("[FCHM] Main--\n");
  if (xf->pm.pipe_act == 0 &&
      xf->l2m.dl_type == bpf_ntohs(ETH_P_IP)) {
    if (dp_do_fcv4_lkup(ctx, xf) == 1) {
      if (xf->pm.pipe_act == LLB_PIPE_RDR) {
        int oif = xf->pm.oport;
#ifdef HAVE_DP_EGR_HOOK
        DP_LLB_MRK_INGP(ctx);
#endif
        return bpf_redirect(oif, 0);         
      }
    }
  }

  bpf_map_update_elem(&xfis, &z, xf, BPF_ANY);
  bpf_tail_call(ctx, &pgm_tbl, idx);
  return DP_PASS;
}
