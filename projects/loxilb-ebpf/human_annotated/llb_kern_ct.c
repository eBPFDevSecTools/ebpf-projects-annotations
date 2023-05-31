/*
 *  llb_kern_ct.c: Loxilb kernel eBPF ConnTracking Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#ifdef HAVE_LEGACY_BPF_MAPS

struct bpf_map_def SEC("maps") ct_ctr = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_ct_ctrtact),
  .max_entries = 1 
};

#else

struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_ctrtact);
  __uint(max_entries, 1);
} ct_ctr SEC(".maps");

#endif

#define CT_KEY_GEN(k, xf)                    \
do {                                         \
  (k)->daddr[0] = xf->l34m.daddr[0];         \
  (k)->daddr[1] = xf->l34m.daddr[1];         \
  (k)->daddr[2] = xf->l34m.daddr[2];         \
  (k)->daddr[3] = xf->l34m.daddr[3];         \
  (k)->saddr[0] = xf->l34m.saddr[0];         \
  (k)->saddr[1] = xf->l34m.saddr[1];         \
  (k)->saddr[2] = xf->l34m.saddr[2];         \
  (k)->saddr[3] = xf->l34m.saddr[3];         \
  (k)->sport = xf->l34m.source;              \
  (k)->dport = xf->l34m.dest;                \
  (k)->l4proto = xf->l34m.nw_proto;          \
  (k)->zone = xf->pm.zone;                   \
  (k)->v6 = xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) ? 1: 0; \
}while(0)

#define dp_run_ctact_helper(x, a) \
do {                              \
  switch ((a)->ca.act_type) {     \
  case DP_SET_NOP:                \
  case DP_SET_SNAT:               \
  case DP_SET_DNAT:               \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pseq = (x)->l34m.seq;   \
    (a)->ctd.pi.t.tcp_cts[CT_DIR_IN].pack = (x)->l34m.ack;   \
    break;                        \
  default:                        \
    break;                        \
  }                               \
} while(0)

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
  "startLine": 59,
  "endLine": 78,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_run_ct_helper",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_ct.c: Loxilb kernel eBPF ConnTracking Implementation *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 73,
      "end_line": 75,
      "text": " We dont do much strict tracking after EST state.   * But need to maintain minimal ctinfo   "
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
    "static int __always_inline dp_run_ct_helper (struct xfi *xf)\n",
    "{\n",
    "    struct dp_ct_key key;\n",
    "    struct dp_ct_tact *act;\n",
    "    CT_KEY_GEN (&key, xf);\n",
    "    act = bpf_map_lookup_elem (& ct_map, & key);\n",
    "    if (!act) {\n",
    "        LL_DBG_PRINTK (\"[FCH4] miss\");\n",
    "        return -1;\n",
    "    }\n",
    "    dp_run_ctact_helper (xf, act);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_run_ctact_helper",
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
dp_run_ct_helper(struct xfi *xf)
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
   * But need to maintain minimal ctinfo
   */
  dp_run_ctact_helper(xf, act);
  return 0;
}

#ifdef HAVE_DP_EXTCT
#define DP_RUN_CT_HELPER(x)                \
do {                                       \
  if ((x)->l34m.nw_proto == IPPROTO_TCP) { \
    dp_run_ct_helper(x);                   \
  }                                        \
} while(0)
#else
#define DP_RUN_CT_HELPER(x)
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
    }
  ],
  "helperCallParams": {},
  "startLine": 91,
  "endLine": 116,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_get_newctr",
  "developer_inline_comments": [
    {
      "start_line": 104,
      "end_line": 106,
      "text": " FIXME - We can potentially do a percpu array and do away   *         with the locking here   "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  ct_ctr"
  ],
  "input": [
    "void"
  ],
  "output": "static__u32__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
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
    "static __u32 __always_inline dp_ct_get_newctr (void)\n",
    "{\n",
    "    __u32 k = 0;\n",
    "    __u32 v = 0;\n",
    "    struct dp_ct_ctrtact *ctr;\n",
    "    ctr = bpf_map_lookup_elem (& ct_ctr, & k);\n",
    "    if (ctr == NULL) {\n",
    "        return 0;\n",
    "    }\n",
    "    bpf_spin_lock (&ctr->lock);\n",
    "    v = ctr->counter;\n",
    "    ctr->counter += 2;\n",
    "    if (ctr->counter >= ctr->entries) {\n",
    "        ctr->counter = ctr->start;\n",
    "    }\n",
    "    bpf_spin_unlock (&ctr->lock);\n",
    "    return v;\n",
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
dp_ct_get_newctr(void)
{
  __u32 k = 0;
  __u32 v = 0;
  struct dp_ct_ctrtact *ctr;

  ctr = bpf_map_lookup_elem(&ct_ctr, &k);

  if (ctr == NULL) {
    return 0;
  }

  /* FIXME - We can potentially do a percpu array and do away
   *         with the locking here
   */ 
  bpf_spin_lock(&ctr->lock);
  v = ctr->counter;
  ctr->counter += 2;
  if (ctr->counter >= ctr->entries) {
    ctr->counter = ctr->start;
  }
  bpf_spin_unlock(&ctr->lock);

  return v;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 118,
  "endLine": 223,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_proto_xfk_init",
  "developer_inline_comments": [
    {
      "start_line": 143,
      "end_line": 143,
      "text": " Apply NAT xfrm if needed "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct dp_ct_key *key",
    " nxfrm_inf_t *xi",
    " struct dp_ct_key *xkey",
    " nxfrm_inf_t *xxi"
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
    "static int __always_inline dp_ct_proto_xfk_init (struct dp_ct_key *key, nxfrm_inf_t *xi, struct dp_ct_key *xkey, nxfrm_inf_t *xxi)\n",
    "{\n",
    "    DP_XADDR_CP (xkey->daddr, key->saddr);\n",
    "    DP_XADDR_CP (xkey->saddr, key->daddr);\n",
    "    xkey->sport = key->dport;\n",
    "    xkey->dport = key->sport;\n",
    "    xkey->l4proto = key->l4proto;\n",
    "    xkey->zone = key->zone;\n",
    "    xkey->v6 = key->v6;\n",
    "    if (xi->dsr) {\n",
    "        if (xi->nat_flags & LLB_NAT_DST) {\n",
    "            xxi->nat_flags = LLB_NAT_SRC;\n",
    "            DP_XADDR_CP (xxi->nat_xip, key->daddr);\n",
    "            xxi->nat_xport = key->dport;\n",
    "            xxi->nv6 = xi->nv6;\n",
    "        }\n",
    "        xxi->dsr = xi->dsr;\n",
    "        return 0;\n",
    "    }\n",
    "    if (xi->nat_flags & LLB_NAT_DST) {\n",
    "        xkey->v6 = (__u8) (xi->nv6);\n",
    "        DP_XADDR_CP (xkey->saddr, xi->nat_xip);\n",
    "        if (!DP_XADDR_ISZR(xi->nat_rip)) {\n",
    "            DP_XADDR_CP (xkey->daddr, xi->nat_rip);\n",
    "            DP_XADDR_CP (xxi->nat_rip, key->saddr);\n",
    "        }\n",
    "        if (key->l4proto != IPPROTO_ICMP) {\n",
    "            if (xi->nat_xport)\n",
    "                xkey->sport = xi->nat_xport;\n",
    "            else\n",
    "                xi->nat_xport = key->dport;\n",
    "        }\n",
    "        xxi->nat_flags = LLB_NAT_SRC;\n",
    "        xxi->nv6 = key->v6;\n",
    "        DP_XADDR_CP (xxi->nat_xip, key->daddr);\n",
    "        if (key->l4proto != IPPROTO_ICMP)\n",
    "            xxi->nat_xport = key->dport;\n",
    "    }\n",
    "    if (xi->nat_flags & LLB_NAT_SRC) {\n",
    "        xkey->v6 = xi->nv6;\n",
    "        DP_XADDR_CP (xkey->daddr, xi->nat_xip);\n",
    "        if (!DP_XADDR_ISZR(xi->nat_rip)) {\n",
    "            DP_XADDR_CP (xkey->saddr, xi->nat_rip);\n",
    "            DP_XADDR_CP (xxi->nat_rip, key->daddr);\n",
    "        }\n",
    "        if (key->l4proto != IPPROTO_ICMP) {\n",
    "            if (xi->nat_xport)\n",
    "                xkey->dport = xi->nat_xport;\n",
    "            else\n",
    "                xi->nat_xport = key->sport;\n",
    "        }\n",
    "        xxi->nat_flags = LLB_NAT_DST;\n",
    "        xxi->nv6 = key->v6;\n",
    "        DP_XADDR_CP (xxi->nat_xip, key->saddr);\n",
    "        if (key->l4proto != IPPROTO_ICMP)\n",
    "            xxi->nat_xport = key->sport;\n",
    "    }\n",
    "    if (xi->nat_flags & LLB_NAT_HDST) {\n",
    "        DP_XADDR_CP (xkey->saddr, key->saddr);\n",
    "        DP_XADDR_CP (xkey->daddr, key->daddr);\n",
    "        if (key->l4proto != IPPROTO_ICMP) {\n",
    "            if (xi->nat_xport)\n",
    "                xkey->sport = xi->nat_xport;\n",
    "            else\n",
    "                xi->nat_xport = key->dport;\n",
    "        }\n",
    "        xxi->nat_flags = LLB_NAT_HSRC;\n",
    "        xxi->nv6 = key->v6;\n",
    "        DP_XADDR_SETZR (xxi->nat_xip);\n",
    "        DP_XADDR_SETZR (xi->nat_xip);\n",
    "        if (key->l4proto != IPPROTO_ICMP)\n",
    "            xxi->nat_xport = key->dport;\n",
    "    }\n",
    "    if (xi->nat_flags & LLB_NAT_HSRC) {\n",
    "        DP_XADDR_CP (xkey->saddr, key->saddr);\n",
    "        DP_XADDR_CP (xkey->daddr, key->daddr);\n",
    "        if (key->l4proto != IPPROTO_ICMP) {\n",
    "            if (xi->nat_xport)\n",
    "                xkey->dport = xi->nat_xport;\n",
    "            else\n",
    "                xi->nat_xport = key->sport;\n",
    "        }\n",
    "        xxi->nat_flags = LLB_NAT_HDST;\n",
    "        xxi->nv6 = key->v6;\n",
    "        DP_XADDR_SETZR (xxi->nat_xip);\n",
    "        DP_XADDR_SETZR (xi->nat_xip);\n",
    "        if (key->l4proto != IPPROTO_ICMP)\n",
    "            xxi->nat_xport = key->sport;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_XADDR_CP",
    "DP_XADDR_SETZR",
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
dp_ct_proto_xfk_init(struct dp_ct_key *key,
                     nxfrm_inf_t *xi,
                     struct dp_ct_key *xkey,
                     nxfrm_inf_t *xxi)
{
  DP_XADDR_CP(xkey->daddr, key->saddr);
  DP_XADDR_CP(xkey->saddr, key->daddr);
  xkey->sport = key->dport; 
  xkey->dport = key->sport;
  xkey->l4proto = key->l4proto;
  xkey->zone = key->zone;
  xkey->v6 = key->v6;

  if (xi->dsr) {
    if (xi->nat_flags & LLB_NAT_DST) {
      xxi->nat_flags = LLB_NAT_SRC;
      DP_XADDR_CP(xxi->nat_xip, key->daddr);
      xxi->nat_xport = key->dport;
      xxi->nv6 = xi->nv6;
    }
    xxi->dsr = xi->dsr;
    return 0;
  }

  /* Apply NAT xfrm if needed */
  if (xi->nat_flags & LLB_NAT_DST) {
    xkey->v6 = (__u8)(xi->nv6);
    DP_XADDR_CP(xkey->saddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->daddr, xi->nat_rip);
      DP_XADDR_CP(xxi->nat_rip, key->saddr);
    }
    if (key->l4proto != IPPROTO_ICMP) {
        if (xi->nat_xport)
          xkey->sport = xi->nat_xport;
        else
          xi->nat_xport = key->dport;
    }

    xxi->nat_flags = LLB_NAT_SRC;
    xxi->nv6 = key->v6;
    DP_XADDR_CP(xxi->nat_xip, key->daddr);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->dport;
  }
  if (xi->nat_flags & LLB_NAT_SRC) {
    xkey->v6 = xi->nv6;
    DP_XADDR_CP(xkey->daddr, xi->nat_xip);
    if (!DP_XADDR_ISZR(xi->nat_rip)) {
      DP_XADDR_CP(xkey->saddr, xi->nat_rip);
      DP_XADDR_CP(xxi->nat_rip, key->daddr);
    }
    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
      else
        xi->nat_xport = key->sport;
    }

    xxi->nat_flags = LLB_NAT_DST;
    xxi->nv6 = key->v6;
    DP_XADDR_CP(xxi->nat_xip, key->saddr);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->sport;
  }
  if (xi->nat_flags & LLB_NAT_HDST) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->sport = xi->nat_xport;
      else
        xi->nat_xport = key->dport;
    }

    xxi->nat_flags = LLB_NAT_HSRC;
    xxi->nv6 = key->v6;
    DP_XADDR_SETZR(xxi->nat_xip);
    DP_XADDR_SETZR(xi->nat_xip);
    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->dport;
  }
  if (xi->nat_flags & LLB_NAT_HSRC) {
    DP_XADDR_CP(xkey->saddr, key->saddr);
    DP_XADDR_CP(xkey->daddr, key->daddr);

    if (key->l4proto != IPPROTO_ICMP) {
      if (xi->nat_xport)
        xkey->dport = xi->nat_xport;
      else
        xi->nat_xport = key->sport;
    }

    xxi->nat_flags = LLB_NAT_HDST;
    xxi->nv6 = key->v6;
    DP_XADDR_SETZR(xxi->nat_xip);
    DP_XADDR_SETZR(xi->nat_xip);

    if (key->l4proto != IPPROTO_ICMP)
      xxi->nat_xport = key->sport;
  }

  return 0;  
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 225,
  "endLine": 260,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct3_sm",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct dp_ct_dat *tdat",
    " struct dp_ct_dat *xtdat",
    " ct_dir_t dir"
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
    "static int __always_inline dp_ct3_sm (struct dp_ct_dat *tdat, struct dp_ct_dat *xtdat, ct_dir_t dir)\n",
    "{\n",
    "    ct_state_t new_state = tdat->pi.l3i.state;\n",
    "    switch (tdat->pi.l3i.state) {\n",
    "    case CT_STATE_NONE :\n",
    "        if (dir == CT_DIR_IN) {\n",
    "            new_state = CT_STATE_REQ;\n",
    "        }\n",
    "        else {\n",
    "            return -1;\n",
    "        }\n",
    "        break;\n",
    "    case CT_STATE_REQ :\n",
    "        if (dir == CT_DIR_OUT) {\n",
    "            new_state = CT_STATE_REP;\n",
    "        }\n",
    "        break;\n",
    "    case CT_STATE_REP :\n",
    "        if (dir == CT_DIR_IN) {\n",
    "            new_state = CT_STATE_EST;\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "    tdat->pi.l3i.state = new_state;\n",
    "    if (new_state == CT_STATE_EST) {\n",
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
dp_ct3_sm(struct dp_ct_dat *tdat,
          struct dp_ct_dat *xtdat,
          ct_dir_t dir)
{
  ct_state_t new_state = tdat->pi.l3i.state;
  switch (tdat->pi.l3i.state) {
  case CT_STATE_NONE:
    if (dir == CT_DIR_IN)  {
      new_state = CT_STATE_REQ;
    } else {
      return -1;
    }
    break;
  case CT_STATE_REQ:
    if (dir == CT_DIR_OUT)  {
      new_state = CT_STATE_REP;
    }
    break;
  case CT_STATE_REP:
    if (dir == CT_DIR_IN)  {
      new_state = CT_STATE_EST;
    } 
    break;
  default:
    break;
  }

  tdat->pi.l3i.state = new_state;

  if (new_state == CT_STATE_EST) {
    return 1;
  }

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 262,
  "endLine": 495,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_tcp_sm",
  "developer_inline_comments": [
    {
      "start_line": 318,
      "end_line": 320,
      "text": " If DP starts after TCP was established     * we need to somehow handle this particular case     "
    },
    {
      "start_line": 344,
      "end_line": 344,
      "text": " SYN sent with ack 0 "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_ct_tact *atdat",
    " struct dp_ct_tact *axtdat",
    " ct_dir_t dir"
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
    "static int __always_inline dp_ct_tcp_sm (void *ctx, struct xfi *xf, struct dp_ct_tact *atdat, struct dp_ct_tact *axtdat, ct_dir_t dir)\n",
    "{\n",
    "    struct dp_ct_dat *tdat = &atdat->ctd;\n",
    "    struct dp_ct_dat *xtdat = &axtdat->ctd;\n",
    "    ct_tcp_pinf_t *ts = &tdat->pi.t;\n",
    "    ct_tcp_pinf_t *rts = &xtdat->pi.t;\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct tcphdr *t = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "    uint8_t tcp_flags = xf->pm.tcp_flags;\n",
    "    ct_tcp_pinfd_t *td = &ts->tcp_cts[dir];\n",
    "    ct_tcp_pinfd_t *rtd;\n",
    "    uint32_t seq;\n",
    "    uint32_t ack;\n",
    "    uint32_t nstate = 0;\n",
    "    if (t + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    seq = bpf_ntohl (t -> seq);\n",
    "    ack = bpf_ntohl (t -> ack_seq);\n",
    "    bpf_spin_lock (&atdat->lock);\n",
    "    if (dir == CT_DIR_IN) {\n",
    "        tdat->pi.t.tcp_cts[0].pseq = t->seq;\n",
    "        tdat->pi.t.tcp_cts[0].pack = t->ack_seq;\n",
    "        tdat->pb.bytes += xf->pm.l3_len;\n",
    "        tdat->pb.packets += 1;\n",
    "    }\n",
    "    else {\n",
    "        xtdat->pi.t.tcp_cts[0].pseq = t->seq;\n",
    "        xtdat->pi.t.tcp_cts[0].pack = t->ack_seq;\n",
    "        xtdat->pb.bytes += xf->pm.l3_len;\n",
    "        xtdat->pb.packets += 1;\n",
    "    }\n",
    "    rtd = &ts->tcp_cts[dir == CT_DIR_IN ? CT_DIR_OUT : CT_DIR_IN];\n",
    "    if (tcp_flags & LLB_TCP_RST) {\n",
    "        nstate = CT_TCP_CW;\n",
    "        goto end;\n",
    "    }\n",
    "    switch (ts->state) {\n",
    "    case CT_TCP_CLOSED :\n",
    "        if (xf->nm.dsr) {\n",
    "            nstate = CT_TCP_EST;\n",
    "            goto end;\n",
    "        }\n",
    "        if (tcp_flags & LLB_TCP_ACK) {\n",
    "            td->seq = seq;\n",
    "            if (td->init_acks) {\n",
    "                if (ack > rtd->seq + 2) {\n",
    "                    nstate = CT_TCP_ERR;\n",
    "                    goto end;\n",
    "                }\n",
    "            }\n",
    "            td->init_acks++;\n",
    "            if (td->init_acks >= CT_TCP_INIT_ACK_THRESHOLD && rtd->init_acks >= CT_TCP_INIT_ACK_THRESHOLD) {\n",
    "                nstate = CT_TCP_EST;\n",
    "                break;\n",
    "            }\n",
    "            nstate = CT_TCP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        if ((tcp_flags & LLB_TCP_SYN) != LLB_TCP_SYN) {\n",
    "            nstate = CT_TCP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        if (ack != 0 && dir != CT_DIR_IN) {\n",
    "            nstate = CT_TCP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        td->seq = seq;\n",
    "        nstate = CT_TCP_SS;\n",
    "        break;\n",
    "    case CT_TCP_SS :\n",
    "        if (dir != CT_DIR_OUT) {\n",
    "            if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {\n",
    "                td->seq = seq;\n",
    "                nstate = CT_TCP_SS;\n",
    "            }\n",
    "            else {\n",
    "                nstate = CT_TCP_ERR;\n",
    "            }\n",
    "            goto end;\n",
    "        }\n",
    "        if ((tcp_flags & (LLB_TCP_SYN | LLB_TCP_ACK)) != (LLB_TCP_SYN | LLB_TCP_ACK)) {\n",
    "            nstate = CT_TCP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        if (ack != rtd->seq + 1) {\n",
    "            nstate = CT_TCP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        td->seq = seq;\n",
    "        nstate = CT_TCP_SA;\n",
    "        break;\n",
    "    case CT_TCP_SA :\n",
    "        if (dir != CT_DIR_IN) {\n",
    "            if ((tcp_flags & (LLB_TCP_SYN | LLB_TCP_ACK)) != (LLB_TCP_SYN | LLB_TCP_ACK)) {\n",
    "                nstate = CT_TCP_ERR;\n",
    "                goto end;\n",
    "            }\n",
    "            if (ack != rtd->seq + 1) {\n",
    "                nstate = CT_TCP_ERR;\n",
    "                goto end;\n",
    "            }\n",
    "            nstate = CT_TCP_SA;\n",
    "            goto end;\n",
    "        }\n",
    "        if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {\n",
    "            td->seq = seq;\n",
    "            nstate = CT_TCP_SS;\n",
    "            goto end;\n",
    "        }\n",
    "        if ((tcp_flags & LLB_TCP_ACK) != LLB_TCP_ACK) {\n",
    "            nstate = CT_TCP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        if (ack != rtd->seq + 1) {\n",
    "            nstate = CT_TCP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        td->seq = seq;\n",
    "        nstate = CT_TCP_EST;\n",
    "        break;\n",
    "    case CT_TCP_EST :\n",
    "        if (tcp_flags & LLB_TCP_FIN) {\n",
    "            ts->fndir = dir;\n",
    "            nstate = CT_TCP_FINI;\n",
    "            td->seq = seq;\n",
    "        }\n",
    "        else {\n",
    "            nstate = CT_TCP_EST;\n",
    "        }\n",
    "        break;\n",
    "    case CT_TCP_FINI :\n",
    "        if (ts->fndir != dir) {\n",
    "            if ((tcp_flags & (LLB_TCP_FIN | LLB_TCP_ACK)) == (LLB_TCP_FIN | LLB_TCP_ACK)) {\n",
    "                if (ack != rtd->seq + 1) {\n",
    "                    nstate = CT_TCP_ERR;\n",
    "                    goto end;\n",
    "                }\n",
    "                nstate = CT_TCP_FINI3;\n",
    "                td->seq = seq;\n",
    "            }\n",
    "            else if (tcp_flags & LLB_TCP_ACK) {\n",
    "                if (ack != rtd->seq + 1) {\n",
    "                    nstate = CT_TCP_ERR;\n",
    "                    goto end;\n",
    "                }\n",
    "                nstate = CT_TCP_FINI2;\n",
    "                td->seq = seq;\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    case CT_TCP_FINI2 :\n",
    "        if (ts->fndir != dir) {\n",
    "            if (tcp_flags & LLB_TCP_FIN) {\n",
    "                nstate = CT_TCP_FINI3;\n",
    "                td->seq = seq;\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    case CT_TCP_FINI3 :\n",
    "        if (ts->fndir == dir) {\n",
    "            if (tcp_flags & LLB_TCP_ACK) {\n",
    "                if (ack != rtd->seq + 1) {\n",
    "                    nstate = CT_TCP_ERR;\n",
    "                    goto end;\n",
    "                }\n",
    "                nstate = CT_TCP_CW;\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "end :\n",
    "    ts->state = nstate;\n",
    "    rts->state = nstate;\n",
    "    if (nstate != CT_TCP_ERR && dir == CT_DIR_OUT) {\n",
    "        xtdat->pi.t.tcp_cts[0].seq = seq;\n",
    "    }\n",
    "    bpf_spin_unlock (&atdat->lock);\n",
    "    if (nstate == CT_TCP_EST) {\n",
    "        return CT_SMR_EST;\n",
    "    }\n",
    "    else if (nstate & CT_TCP_CW) {\n",
    "        return CT_SMR_CTD;\n",
    "    }\n",
    "    else if (nstate & CT_TCP_ERR) {\n",
    "        return CT_SMR_ERR;\n",
    "    }\n",
    "    else if (nstate & CT_TCP_FIN_MASK) {\n",
    "        return CT_SMR_FIN;\n",
    "    }\n",
    "    return CT_SMR_INPROG;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_ADD_PTR",
    "bpf_ntohl",
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
dp_ct_tcp_sm(void *ctx, struct xfi *xf, 
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_tcp_pinf_t *ts = &tdat->pi.t;
  ct_tcp_pinf_t *rts = &xtdat->pi.t;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct tcphdr *t = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint8_t tcp_flags = xf->pm.tcp_flags;
  ct_tcp_pinfd_t *td = &ts->tcp_cts[dir];
  ct_tcp_pinfd_t *rtd;
  uint32_t seq;
  uint32_t ack;
  uint32_t nstate = 0;

  if (t + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  seq = bpf_ntohl(t->seq);
  ack = bpf_ntohl(t->ack_seq);

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pi.t.tcp_cts[0].pseq = t->seq;
    tdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pi.t.tcp_cts[0].pseq = t->seq;
    xtdat->pi.t.tcp_cts[0].pack = t->ack_seq;
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  rtd = &ts->tcp_cts[dir == CT_DIR_IN ? CT_DIR_OUT:CT_DIR_IN];

  if (tcp_flags & LLB_TCP_RST) {
    nstate = CT_TCP_CW;
    goto end;
  }

  switch (ts->state) {
  case CT_TCP_CLOSED:

    if (xf->nm.dsr) {
      nstate = CT_TCP_EST;
      goto end;
    }

    /* If DP starts after TCP was established
     * we need to somehow handle this particular case
     */
    if (tcp_flags & LLB_TCP_ACK)  {
      td->seq = seq;
      if (td->init_acks) {
        if (ack  > rtd->seq + 2) {
          nstate = CT_TCP_ERR;
          goto end;
        }
      }
      td->init_acks++;
      if (td->init_acks >= CT_TCP_INIT_ACK_THRESHOLD &&
          rtd->init_acks >= CT_TCP_INIT_ACK_THRESHOLD) {
        nstate = CT_TCP_EST;
        break;
      }
      nstate = CT_TCP_ERR;
      goto end;
    }
    
    if ((tcp_flags & LLB_TCP_SYN) != LLB_TCP_SYN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    /* SYN sent with ack 0 */
    if (ack != 0 && dir != CT_DIR_IN) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SS;
    break;
  case CT_TCP_SS:
    if (dir != CT_DIR_OUT) {
      if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {
        td->seq = seq;
        nstate = CT_TCP_SS;
      } else {
        nstate = CT_TCP_ERR;
      }
      goto end;
    }
  
    if ((tcp_flags & (LLB_TCP_SYN|LLB_TCP_ACK)) !=
         (LLB_TCP_SYN|LLB_TCP_ACK)) {
      nstate = CT_TCP_ERR;
      goto end;
    }
  
    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_SA;
    break;

  case CT_TCP_SA:
    if (dir != CT_DIR_IN) {
      if ((tcp_flags & (LLB_TCP_SYN|LLB_TCP_ACK)) !=
         (LLB_TCP_SYN|LLB_TCP_ACK)) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      if (ack  != rtd->seq + 1) {
        nstate = CT_TCP_ERR;
        goto end;
      }

      nstate = CT_TCP_SA;
      goto end;
    } 

    if ((tcp_flags & LLB_TCP_SYN) == LLB_TCP_SYN) {
      td->seq = seq;
      nstate = CT_TCP_SS;
      goto end;
    }
  
    if ((tcp_flags & LLB_TCP_ACK) != LLB_TCP_ACK) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    if (ack  != rtd->seq + 1) {
      nstate = CT_TCP_ERR;
      goto end;
    }

    td->seq = seq;
    nstate = CT_TCP_EST;
    break;

  case CT_TCP_EST:
    if (tcp_flags & LLB_TCP_FIN) {
      ts->fndir = dir;
      nstate = CT_TCP_FINI;
      td->seq = seq;
    } else {
      nstate = CT_TCP_EST;
    }
    break;

  case CT_TCP_FINI:
    if (ts->fndir != dir) {
      if ((tcp_flags & (LLB_TCP_FIN|LLB_TCP_ACK)) == 
          (LLB_TCP_FIN|LLB_TCP_ACK)) {
        if (ack  != rtd->seq + 1) {
          nstate = CT_TCP_ERR;
          goto end;
        }

        nstate = CT_TCP_FINI3;
        td->seq = seq;
      } else if (tcp_flags & LLB_TCP_ACK) {
        if (ack  != rtd->seq + 1) {
          nstate = CT_TCP_ERR;
          goto end;
        }
        nstate = CT_TCP_FINI2;
        td->seq = seq;
      }
    }
    break;

  case CT_TCP_FINI2:
    if (ts->fndir != dir) {
      if (tcp_flags & LLB_TCP_FIN) {
        nstate = CT_TCP_FINI3;
        td->seq = seq;
      }
    }
    break;

  case CT_TCP_FINI3:
    if (ts->fndir == dir) {
      if (tcp_flags & LLB_TCP_ACK) {

        if (ack != rtd->seq + 1) {
          nstate = CT_TCP_ERR;
          goto end;
        }
        nstate = CT_TCP_CW;
      }
    }
    break;

  default:
    break;
  }

end:
  ts->state = nstate;
  rts->state = nstate;

  if (nstate != CT_TCP_ERR && dir == CT_DIR_OUT) {
    xtdat->pi.t.tcp_cts[0].seq = seq;
  }

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_TCP_EST) {
    return CT_SMR_EST;
  } else if (nstate & CT_TCP_CW) {
    return CT_SMR_CTD;
  } else if (nstate & CT_TCP_ERR) {
    return CT_SMR_ERR;
  } else if (nstate & CT_TCP_FIN_MASK) {
    return CT_SMR_FIN;
  }

  return CT_SMR_INPROG;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 497,
  "endLine": 559,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_udp_sm",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_ct_tact *atdat",
    " struct dp_ct_tact *axtdat",
    " ct_dir_t dir"
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
    "static int __always_inline dp_ct_udp_sm (void *ctx, struct xfi *xf, struct dp_ct_tact *atdat, struct dp_ct_tact *axtdat, ct_dir_t dir)\n",
    "{\n",
    "    struct dp_ct_dat *tdat = &atdat->ctd;\n",
    "    struct dp_ct_dat *xtdat = &axtdat->ctd;\n",
    "    ct_udp_pinf_t *us = &tdat->pi.u;\n",
    "    ct_udp_pinf_t *xus = &xtdat->pi.u;\n",
    "    uint32_t nstate = us->state;\n",
    "    bpf_spin_lock (&atdat->lock);\n",
    "    if (dir == CT_DIR_IN) {\n",
    "        tdat->pb.bytes += xf->pm.l3_len;\n",
    "        tdat->pb.packets += 1;\n",
    "        us->pkts_seen++;\n",
    "    }\n",
    "    else {\n",
    "        xtdat->pb.bytes += xf->pm.l3_len;\n",
    "        xtdat->pb.packets += 1;\n",
    "        us->rpkts_seen++;\n",
    "    }\n",
    "    switch (us->state) {\n",
    "    case CT_UDP_CNI :\n",
    "        if (xf->nm.dsr) {\n",
    "            nstate = CT_UDP_EST;\n",
    "            break;\n",
    "        }\n",
    "        if (us->pkts_seen && us->rpkts_seen) {\n",
    "            nstate = CT_UDP_EST;\n",
    "        }\n",
    "        else if (us->pkts_seen > CT_UDP_CONN_THRESHOLD) {\n",
    "            nstate = CT_UDP_UEST;\n",
    "        }\n",
    "        break;\n",
    "    case CT_UDP_UEST :\n",
    "        if (us->rpkts_seen)\n",
    "            nstate = CT_UDP_EST;\n",
    "        break;\n",
    "    case CT_UDP_EST :\n",
    "        break;\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "    us->state = nstate;\n",
    "    xus->state = nstate;\n",
    "    bpf_spin_unlock (&atdat->lock);\n",
    "    if (nstate == CT_UDP_UEST)\n",
    "        return CT_SMR_UEST;\n",
    "    else if (nstate == CT_UDP_EST)\n",
    "        return CT_SMR_EST;\n",
    "    return CT_SMR_INPROG;\n",
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
dp_ct_udp_sm(void *ctx, struct xfi *xf,
             struct dp_ct_tact *atdat,
             struct dp_ct_tact *axtdat,
             ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_udp_pinf_t *us = &tdat->pi.u;
  ct_udp_pinf_t *xus = &xtdat->pi.u;
  uint32_t nstate = us->state;

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
    us->pkts_seen++;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
    us->rpkts_seen++;
  }

  switch (us->state) {
  case CT_UDP_CNI:

    if (xf->nm.dsr) {
      nstate = CT_UDP_EST;
      break;
    }

    if (us->pkts_seen && us->rpkts_seen) {
      nstate = CT_UDP_EST;
    } else if (us->pkts_seen > CT_UDP_CONN_THRESHOLD) {
      nstate = CT_UDP_UEST;
    }

    break;
  case CT_UDP_UEST:
    if (us->rpkts_seen)
      nstate = CT_UDP_EST;
    break;
  case CT_UDP_EST:
    break;
  default:
    break;
  }


  us->state = nstate;
  xus->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_UDP_UEST)
    return CT_SMR_UEST;
  else if (nstate == CT_UDP_EST)
    return CT_SMR_EST;


  return CT_SMR_INPROG;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 561,
  "endLine": 656,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_icmp6_sm",
  "developer_inline_comments": [
    {
      "start_line": 581,
      "end_line": 584,
      "text": " We fetch the sequence number even if icmp may not be   * echo type because we can't call another fn holding   * spinlock   "
    },
    {
      "start_line": 608,
      "end_line": 608,
      "text": " Further state-machine processing "
    },
    {
      "start_line": 641,
      "end_line": 641,
      "text": " Connection is tracked now "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_ct_tact *atdat",
    " struct dp_ct_tact *axtdat",
    " ct_dir_t dir"
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
    "static int __always_inline dp_ct_icmp6_sm (void *ctx, struct xfi *xf, struct dp_ct_tact *atdat, struct dp_ct_tact *axtdat, ct_dir_t dir)\n",
    "{\n",
    "    struct dp_ct_dat *tdat = &atdat->ctd;\n",
    "    struct dp_ct_dat *xtdat = &axtdat->ctd;\n",
    "    ct_icmp_pinf_t *is = &tdat->pi.i;\n",
    "    ct_icmp_pinf_t *xis = &xtdat->pi.i;\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct icmp6hdr *i = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "    uint32_t nstate;\n",
    "    uint16_t seq;\n",
    "    if (i + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    seq = bpf_ntohs (i -> icmp6_dataun.u_echo.sequence);\n",
    "    bpf_spin_lock (&atdat->lock);\n",
    "    if (dir == CT_DIR_IN) {\n",
    "        tdat->pb.bytes += xf->pm.l3_len;\n",
    "        tdat->pb.packets += 1;\n",
    "    }\n",
    "    else {\n",
    "        xtdat->pb.bytes += xf->pm.l3_len;\n",
    "        xtdat->pb.packets += 1;\n",
    "    }\n",
    "    nstate = is->state;\n",
    "    switch (i->icmp6_type) {\n",
    "    case ICMPV6_DEST_UNREACH :\n",
    "        is->state |= CT_ICMP_DUNR;\n",
    "        goto end;\n",
    "    case ICMPV6_TIME_EXCEED :\n",
    "        is->state |= CT_ICMP_TTL;\n",
    "        goto end;\n",
    "    case ICMPV6_ECHO_REPLY :\n",
    "    case ICMPV6_ECHO_REQUEST :\n",
    "        break;\n",
    "    default :\n",
    "        is->state |= CT_ICMP_UNK;\n",
    "        goto end;\n",
    "    }\n",
    "    switch (is->state) {\n",
    "    case CT_ICMP_CLOSED :\n",
    "        if (xf->nm.dsr) {\n",
    "            nstate = CT_ICMP_REPS;\n",
    "            goto end;\n",
    "        }\n",
    "        if (i->icmp6_type != ICMPV6_ECHO_REQUEST) {\n",
    "            is->errs = 1;\n",
    "            goto end;\n",
    "        }\n",
    "        nstate = CT_ICMP_REQS;\n",
    "        is->lseq = seq;\n",
    "        break;\n",
    "    case CT_ICMP_REQS :\n",
    "        if (i->icmp6_type == ICMPV6_ECHO_REQUEST) {\n",
    "            is->lseq = seq;\n",
    "        }\n",
    "        else if (i->icmp6_type == ICMPV6_ECHO_REPLY) {\n",
    "            if (is->lseq != seq) {\n",
    "                is->errs = 1;\n",
    "                goto end;\n",
    "            }\n",
    "            nstate = CT_ICMP_REPS;\n",
    "            is->lseq = seq;\n",
    "        }\n",
    "        break;\n",
    "    case CT_ICMP_REPS :\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "end :\n",
    "    is->state = nstate;\n",
    "    xis->state = nstate;\n",
    "    bpf_spin_unlock (&atdat->lock);\n",
    "    if (nstate == CT_ICMP_REPS)\n",
    "        return CT_SMR_EST;\n",
    "    return CT_SMR_INPROG;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "bpf_ntohs",
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
dp_ct_icmp6_sm(void *ctx, struct xfi *xf,
               struct dp_ct_tact *atdat,
               struct dp_ct_tact *axtdat,
               ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct icmp6hdr *i = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint32_t nstate;
  uint16_t seq;

  if (i + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = bpf_ntohs(i->icmp6_dataun.u_echo.sequence);

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->icmp6_type) {
  case ICMPV6_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMPV6_TIME_EXCEED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMPV6_ECHO_REPLY:
  case ICMPV6_ECHO_REQUEST:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  }

  switch (is->state) {
  case CT_ICMP_CLOSED:
    if (xf->nm.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }
    if (i->icmp6_type != ICMPV6_ECHO_REQUEST) {
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->icmp6_type == ICMPV6_ECHO_REQUEST) {
      is->lseq = seq;
    } else if (i->icmp6_type == ICMPV6_ECHO_REPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 658,
  "endLine": 757,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_icmp_sm",
  "developer_inline_comments": [
    {
      "start_line": 678,
      "end_line": 681,
      "text": " We fetch the sequence number even if icmp may not be   * echo type because we can't call another fn holding   * spinlock   "
    },
    {
      "start_line": 708,
      "end_line": 708,
      "text": " Further state-machine processing "
    },
    {
      "start_line": 742,
      "end_line": 742,
      "text": " Connection is tracked now "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_ct_tact *atdat",
    " struct dp_ct_tact *axtdat",
    " ct_dir_t dir"
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
    "static int __always_inline dp_ct_icmp_sm (void *ctx, struct xfi *xf, struct dp_ct_tact *atdat, struct dp_ct_tact *axtdat, ct_dir_t dir)\n",
    "{\n",
    "    struct dp_ct_dat *tdat = &atdat->ctd;\n",
    "    struct dp_ct_dat *xtdat = &axtdat->ctd;\n",
    "    ct_icmp_pinf_t *is = &tdat->pi.i;\n",
    "    ct_icmp_pinf_t *xis = &xtdat->pi.i;\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct icmphdr *i = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "    uint32_t nstate;\n",
    "    uint16_t seq;\n",
    "    if (i + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    seq = bpf_ntohs (i -> un.echo.sequence);\n",
    "    bpf_spin_lock (&atdat->lock);\n",
    "    if (dir == CT_DIR_IN) {\n",
    "        tdat->pb.bytes += xf->pm.l3_len;\n",
    "        tdat->pb.packets += 1;\n",
    "    }\n",
    "    else {\n",
    "        xtdat->pb.bytes += xf->pm.l3_len;\n",
    "        xtdat->pb.packets += 1;\n",
    "    }\n",
    "    nstate = is->state;\n",
    "    switch (i->type) {\n",
    "    case ICMP_DEST_UNREACH :\n",
    "        is->state |= CT_ICMP_DUNR;\n",
    "        goto end;\n",
    "    case ICMP_TIME_EXCEEDED :\n",
    "        is->state |= CT_ICMP_TTL;\n",
    "        goto end;\n",
    "    case ICMP_REDIRECT :\n",
    "        is->state |= CT_ICMP_RDR;\n",
    "        goto end;\n",
    "    case ICMP_ECHOREPLY :\n",
    "    case ICMP_ECHO :\n",
    "        break;\n",
    "    default :\n",
    "        is->state |= CT_ICMP_UNK;\n",
    "        goto end;\n",
    "    }\n",
    "    switch (is->state) {\n",
    "    case CT_ICMP_CLOSED :\n",
    "        if (xf->nm.dsr) {\n",
    "            nstate = CT_ICMP_REPS;\n",
    "            goto end;\n",
    "        }\n",
    "        if (i->type != ICMP_ECHO) {\n",
    "            is->errs = 1;\n",
    "            goto end;\n",
    "        }\n",
    "        nstate = CT_ICMP_REQS;\n",
    "        is->lseq = seq;\n",
    "        break;\n",
    "    case CT_ICMP_REQS :\n",
    "        if (i->type == ICMP_ECHO) {\n",
    "            is->lseq = seq;\n",
    "        }\n",
    "        else if (i->type == ICMP_ECHOREPLY) {\n",
    "            if (is->lseq != seq) {\n",
    "                is->errs = 1;\n",
    "                goto end;\n",
    "            }\n",
    "            nstate = CT_ICMP_REPS;\n",
    "            is->lseq = seq;\n",
    "        }\n",
    "        break;\n",
    "    case CT_ICMP_REPS :\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "end :\n",
    "    is->state = nstate;\n",
    "    xis->state = nstate;\n",
    "    bpf_spin_unlock (&atdat->lock);\n",
    "    if (nstate == CT_ICMP_REPS)\n",
    "        return CT_SMR_EST;\n",
    "    return CT_SMR_INPROG;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "bpf_ntohs",
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
dp_ct_icmp_sm(void *ctx, struct xfi *xf, 
              struct dp_ct_tact *atdat,
              struct dp_ct_tact *axtdat,
              ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_icmp_pinf_t *is = &tdat->pi.i;
  ct_icmp_pinf_t *xis = &xtdat->pi.i;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct icmphdr *i = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  uint32_t nstate;
  uint16_t seq;

  if (i + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  /* We fetch the sequence number even if icmp may not be
   * echo type because we can't call another fn holding
   * spinlock
   */
  seq = bpf_ntohs(i->un.echo.sequence);

  bpf_spin_lock(&atdat->lock);

  if (dir == CT_DIR_IN) {
    tdat->pb.bytes += xf->pm.l3_len;
    tdat->pb.packets += 1;
  } else {
    xtdat->pb.bytes += xf->pm.l3_len;
    xtdat->pb.packets += 1;
  }

  nstate = is->state;

  switch (i->type) {
  case ICMP_DEST_UNREACH:
    is->state |= CT_ICMP_DUNR;
    goto end;
  case ICMP_TIME_EXCEEDED:
    is->state |= CT_ICMP_TTL;
    goto end;
  case ICMP_REDIRECT:
    is->state |= CT_ICMP_RDR;
    goto end;
  case ICMP_ECHOREPLY:
  case ICMP_ECHO:
    /* Further state-machine processing */
    break;
  default:
    is->state |= CT_ICMP_UNK;
    goto end;
  } 

  switch (is->state) { 
  case CT_ICMP_CLOSED: 
    if (xf->nm.dsr) {
      nstate = CT_ICMP_REPS;
      goto end;
    }

    if (i->type != ICMP_ECHO) { 
      is->errs = 1;
      goto end;
    }
    nstate = CT_ICMP_REQS;
    is->lseq = seq;
    break;
  case CT_ICMP_REQS:
    if (i->type == ICMP_ECHO) {
      is->lseq = seq;
    } else if (i->type == ICMP_ECHOREPLY) {
      if (is->lseq != seq) {
        is->errs = 1;
        goto end;
      }
      nstate = CT_ICMP_REPS;
      is->lseq = seq;
    }
    break;
  case CT_ICMP_REPS:
    /* Connection is tracked now */
  default:
    break;
  }

end:
  is->state = nstate;
  xis->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_ICMP_REPS)
    return CT_SMR_EST;

  return CT_SMR_INPROG;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 759,
  "endLine": 998,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_sctp_sm",
  "developer_inline_comments": [
    {
      "start_line": 838,
      "end_line": 838,
      "text": "bpf_printk(\"IP 0x%x\", bpf_ntohl(*ip));"
    },
    {
      "start_line": 840,
      "end_line": 840,
      "text": " Checksum to be taken care of later stage "
    },
    {
      "start_line": 894,
      "end_line": 894,
      "text": "bpf_printk(\"ina ip 0x%x\", bpf_ntohl(*ip));"
    },
    {
      "start_line": 896,
      "end_line": 896,
      "text": " Checksum to be taken care of later stage "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_ct_tact *atdat",
    " struct dp_ct_tact *axtdat",
    " ct_dir_t dir"
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
    "static int __always_inline dp_ct_sctp_sm (void *ctx, struct xfi *xf, struct dp_ct_tact *atdat, struct dp_ct_tact *axtdat, ct_dir_t dir)\n",
    "{\n",
    "    struct dp_ct_dat *tdat = &atdat->ctd;\n",
    "    struct dp_ct_dat *xtdat = &axtdat->ctd;\n",
    "    ct_sctp_pinf_t *ss = &tdat->pi.s;\n",
    "    ct_sctp_pinf_t *xss = &xtdat->pi.s;\n",
    "    uint32_t nstate = 0;\n",
    "    uint16_t sz = 0;\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "    struct sctphdr *s = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "    struct sctp_dch *c;\n",
    "    struct sctp_init_ch *ic;\n",
    "    struct sctp_cookie *ck;\n",
    "    struct sctp_param *pm;\n",
    "    int i = 0;\n",
    "    if (s + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    c = DP_TC_PTR (DP_ADD_PTR (s, sizeof (* s)));\n",
    "    if (c + 1 > dend) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "        return -1;\n",
    "    }\n",
    "    nstate = ss->state;\n",
    "    bpf_spin_lock (&atdat->lock);\n",
    "    switch (c->type) {\n",
    "    case SCTP_ERROR :\n",
    "        nstate = CT_SCTP_ERR;\n",
    "        goto end;\n",
    "    case SCTP_SHUT :\n",
    "        nstate = CT_SCTP_SHUT;\n",
    "        goto end;\n",
    "    case SCTP_ABORT :\n",
    "        nstate = CT_SCTP_ABRT;\n",
    "        goto end;\n",
    "    }\n",
    "    switch (ss->state) {\n",
    "    case CT_SCTP_CLOSED :\n",
    "        if (xf->nm.dsr) {\n",
    "            nstate = CT_SCTP_EST;\n",
    "            goto end;\n",
    "        }\n",
    "        if (c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        ic = DP_TC_PTR (DP_ADD_PTR (c, sizeof (* c)));\n",
    "        if (ic + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            goto end;\n",
    "        }\n",
    "        ss->itag = ic->tag;\n",
    "        nstate = CT_SCTP_INIT;\n",
    "        pm = DP_TC_PTR (DP_ADD_PTR (ic, sizeof (* ic)));\n",
    "        if (pm + 1 > dend) {\n",
    "            break;\n",
    "        }\n",
    "        for (i = 0; i < SCTP_MAX_BIND_ADDRS; i++) {\n",
    "            if (pm->type == bpf_htons (SCTP_IPV4_ADDR_PARAM)) {\n",
    "                __be32 *ip = DP_TC_PTR (DP_ADD_PTR (pm, sizeof (*pm)));\n",
    "                if (ip + 1 > dend) {\n",
    "                    break;\n",
    "                }\n",
    "                if (atdat->nat_act.rip[0] != 0 && !atdat->nat_act.nv6) {\n",
    "                    *ip = atdat->nat_act.rip[0];\n",
    "                }\n",
    "            }\n",
    "            sz = bpf_ntohs (pm -> len);\n",
    "            if (sz >= 32) {\n",
    "                break;\n",
    "            }\n",
    "            pm = DP_TC_PTR (DP_ADD_PTR (pm, sz));\n",
    "            if (pm + 1 > dend) {\n",
    "                break;\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    case CT_SCTP_INIT :\n",
    "        if ((c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) && (c->type != SCTP_INIT_CHUNK_ACK && dir != CT_DIR_OUT)) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        ic = DP_TC_PTR (DP_ADD_PTR (c, sizeof (* c)));\n",
    "        if (ic + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            goto end;\n",
    "        }\n",
    "        if (c->type == SCTP_INIT_CHUNK) {\n",
    "            ss->itag = ic->tag;\n",
    "            ss->otag = 0;\n",
    "            nstate = CT_SCTP_INIT;\n",
    "        }\n",
    "        else {\n",
    "            if (s->vtag != ss->itag) {\n",
    "                nstate = CT_SCTP_ERR;\n",
    "                goto end;\n",
    "            }\n",
    "            ss->otag = ic->tag;\n",
    "            nstate = CT_SCTP_INITA;\n",
    "        }\n",
    "        pm = DP_TC_PTR (DP_ADD_PTR (ic, sizeof (* ic)));\n",
    "        if (pm + 1 > dend) {\n",
    "            break;\n",
    "        }\n",
    "        for (i = 0; i < SCTP_MAX_BIND_ADDRS; i++) {\n",
    "            if (pm->type == bpf_htons (SCTP_IPV4_ADDR_PARAM)) {\n",
    "                __be32 *ip = DP_TC_PTR (DP_ADD_PTR (pm, sizeof (*pm)));\n",
    "                if (ip + 1 > dend) {\n",
    "                    break;\n",
    "                }\n",
    "                if (axtdat->nat_act.xip[0] != 0 && !axtdat->nat_act.nv6) {\n",
    "                    *ip = axtdat->nat_act.xip[0];\n",
    "                }\n",
    "            }\n",
    "            sz = bpf_ntohs (pm -> len);\n",
    "            if (sz >= 32) {\n",
    "                break;\n",
    "            }\n",
    "            pm = DP_TC_PTR (DP_ADD_PTR (pm, sz));\n",
    "            if (pm + 1 > dend) {\n",
    "                break;\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    case CT_SCTP_INITA :\n",
    "        if ((c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) && (c->type != SCTP_COOKIE_ECHO && dir != CT_DIR_IN)) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        if (c->type == SCTP_INIT_CHUNK) {\n",
    "            ic = DP_TC_PTR (DP_ADD_PTR (c, sizeof (* c)));\n",
    "            if (ic + 1 > dend) {\n",
    "                LLBS_PPLN_DROP (xf);\n",
    "                goto end;\n",
    "            }\n",
    "            ss->itag = ic->tag;\n",
    "            ss->otag = 0;\n",
    "            nstate = CT_SCTP_INIT;\n",
    "            goto end;\n",
    "        }\n",
    "        ck = DP_TC_PTR (DP_ADD_PTR (c, sizeof (* c)));\n",
    "        if (ck + 1 > dend) {\n",
    "            LLBS_PPLN_DROP (xf);\n",
    "            goto end;\n",
    "        }\n",
    "        if (ss->otag != s->vtag) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        ss->cookie = ck->cookie;\n",
    "        nstate = CT_SCTP_COOKIE;\n",
    "        break;\n",
    "    case CT_SCTP_COOKIE :\n",
    "        if (c->type != SCTP_COOKIE_ACK && dir != CT_DIR_OUT) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        if (ss->itag != s->vtag) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        nstate = CT_SCTP_COOKIEA;\n",
    "        break;\n",
    "    case CT_SCTP_COOKIEA :\n",
    "        nstate = CT_SCTP_EST;\n",
    "        break;\n",
    "    case CT_SCTP_ABRT :\n",
    "        nstate = CT_SCTP_ABRT;\n",
    "        break;\n",
    "    case CT_SCTP_SHUT :\n",
    "        if (c->type != SCTP_SHUT_ACK && dir != CT_DIR_OUT) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        nstate = CT_SCTP_SHUTA;\n",
    "        break;\n",
    "    case CT_SCTP_SHUTA :\n",
    "        if (c->type != SCTP_SHUT_COMPLETE && dir != CT_DIR_IN) {\n",
    "            nstate = CT_SCTP_ERR;\n",
    "            goto end;\n",
    "        }\n",
    "        nstate = CT_SCTP_SHUTC;\n",
    "        break;\n",
    "    default :\n",
    "        break;\n",
    "    }\n",
    "end :\n",
    "    ss->state = nstate;\n",
    "    xss->state = nstate;\n",
    "    bpf_spin_unlock (&atdat->lock);\n",
    "    if (nstate == CT_SCTP_COOKIEA) {\n",
    "        return CT_SMR_EST;\n",
    "    }\n",
    "    else if (nstate & CT_SCTP_SHUTC) {\n",
    "        return CT_SMR_CTD;\n",
    "    }\n",
    "    else if (nstate & CT_SCTP_ERR) {\n",
    "        return CT_SMR_ERR;\n",
    "    }\n",
    "    else if (nstate & CT_SCTP_FIN_MASK) {\n",
    "        return CT_SMR_FIN;\n",
    "    }\n",
    "    return CT_SMR_INPROG;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "DP_PDATA",
    "DP_ADD_PTR",
    "bpf_htons",
    "DP_TC_PTR",
    "bpf_ntohs",
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
dp_ct_sctp_sm(void *ctx, struct xfi *xf, 
              struct dp_ct_tact *atdat,
              struct dp_ct_tact *axtdat,
              ct_dir_t dir)
{
  struct dp_ct_dat *tdat = &atdat->ctd;
  struct dp_ct_dat *xtdat = &axtdat->ctd;
  ct_sctp_pinf_t *ss = &tdat->pi.s;
  ct_sctp_pinf_t *xss = &xtdat->pi.s;
  uint32_t nstate = 0;
  uint16_t sz = 0;
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct sctphdr *s = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
  struct sctp_dch *c;
  struct sctp_init_ch *ic;
  struct sctp_cookie *ck;
  struct sctp_param  *pm;
  int i = 0;

  if (s + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  c = DP_TC_PTR(DP_ADD_PTR(s, sizeof(*s)));
  
  if (c + 1 > dend) {
    LLBS_PPLN_DROP(xf);
    return -1;
  }

  nstate = ss->state;
  bpf_spin_lock(&atdat->lock);

  switch (c->type) {
  case SCTP_ERROR:
    nstate = CT_SCTP_ERR;
    goto end;
  case SCTP_SHUT:
    nstate = CT_SCTP_SHUT;
    goto end;
  case SCTP_ABORT:
    nstate = CT_SCTP_ABRT;
    goto end;
  }

  switch (ss->state) {
  case CT_SCTP_CLOSED:
    if (xf->nm.dsr) {
      nstate = CT_SCTP_EST;
      goto end;
    }

    if (c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ic + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      goto end;
    }

    ss->itag = ic->tag;
    nstate = CT_SCTP_INIT;

    pm = DP_TC_PTR(DP_ADD_PTR(ic, sizeof(*ic)));
    if (pm + 1 > dend) {
      break;
    } 

    for (i = 0; i < SCTP_MAX_BIND_ADDRS; i++) {
      if (pm->type == bpf_htons(SCTP_IPV4_ADDR_PARAM)) {
        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }
        //bpf_printk("IP 0x%x", bpf_ntohl(*ip));
        if (atdat->nat_act.rip[0] != 0 && !atdat->nat_act.nv6) {
          /* Checksum to be taken care of later stage */
          *ip = atdat->nat_act.rip[0];
        }
      }

      sz = bpf_ntohs(pm->len);
      if (sz >= 32) {
        break;
      }
      pm = DP_TC_PTR(DP_ADD_PTR(pm, sz));
      if (pm + 1 > dend) {
        break;
      }
    }
    break;
  case CT_SCTP_INIT:

    if ((c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) &&
        (c->type != SCTP_INIT_CHUNK_ACK && dir != CT_DIR_OUT)) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ic + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      goto end;
    }

    if (c->type == SCTP_INIT_CHUNK) {
      ss->itag = ic->tag;
      ss->otag = 0;
      nstate = CT_SCTP_INIT;
    } else {
      if (s->vtag != ss->itag) {
        nstate = CT_SCTP_ERR;
        goto end;
      }

      ss->otag = ic->tag;
      nstate = CT_SCTP_INITA;
    }

    pm = DP_TC_PTR(DP_ADD_PTR(ic, sizeof(*ic)));
    if (pm + 1 > dend) {
      break;
    }

    for (i = 0; i < SCTP_MAX_BIND_ADDRS; i++) {
      if (pm->type == bpf_htons(SCTP_IPV4_ADDR_PARAM)) {
        __be32 *ip = DP_TC_PTR(DP_ADD_PTR(pm, sizeof(*pm)));
        if (ip + 1 > dend) {
          break;
        }
        //bpf_printk("ina ip 0x%x", bpf_ntohl(*ip));
        if (axtdat->nat_act.xip[0] != 0 && !axtdat->nat_act.nv6) {
          /* Checksum to be taken care of later stage */
          *ip = axtdat->nat_act.xip[0];
        }
      }
      sz = bpf_ntohs(pm->len);
      if (sz >= 32) {
        break;
      }
      pm = DP_TC_PTR(DP_ADD_PTR(pm, sz));
      if (pm + 1 > dend) {
        break;
      }
    }
    break;
  case CT_SCTP_INITA:

    if ((c->type != SCTP_INIT_CHUNK && dir != CT_DIR_IN) &&
        (c->type != SCTP_COOKIE_ECHO && dir != CT_DIR_IN)) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if (c->type == SCTP_INIT_CHUNK) {
      ic = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
      if (ic + 1 > dend) {
        LLBS_PPLN_DROP(xf);
        goto end;
      }

      ss->itag = ic->tag;
      ss->otag = 0;
      nstate = CT_SCTP_INIT;
      goto end;
    }

    ck = DP_TC_PTR(DP_ADD_PTR(c, sizeof(*c)));
    if (ck + 1 > dend) {
      LLBS_PPLN_DROP(xf);
      goto end;
    }

    if (ss->otag != s->vtag) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    ss->cookie = ck->cookie;
    nstate = CT_SCTP_COOKIE;
    break;
  case CT_SCTP_COOKIE:
    if (c->type != SCTP_COOKIE_ACK && dir != CT_DIR_OUT) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    if (ss->itag != s->vtag) {
      nstate = CT_SCTP_ERR;
      goto end;
    }

    nstate = CT_SCTP_COOKIEA;
    break;
  case CT_SCTP_COOKIEA:
    nstate = CT_SCTP_EST;
    break;
  case CT_SCTP_ABRT:
    nstate = CT_SCTP_ABRT;
    break;
  case CT_SCTP_SHUT:
    if (c->type != SCTP_SHUT_ACK && dir != CT_DIR_OUT) {
      nstate = CT_SCTP_ERR;
      goto end;
    }
    nstate = CT_SCTP_SHUTA;
    break;
  case CT_SCTP_SHUTA:
    if (c->type != SCTP_SHUT_COMPLETE && dir != CT_DIR_IN) {
      nstate = CT_SCTP_ERR;
      goto end;
    }
    nstate = CT_SCTP_SHUTC;
    break;
  default:
    break;
  }
end:
  ss->state = nstate;
  xss->state = nstate;

  bpf_spin_unlock(&atdat->lock);

  if (nstate == CT_SCTP_COOKIEA) {
    return CT_SMR_EST;
  } else if (nstate & CT_SCTP_SHUTC) {
    return CT_SMR_CTD;
  } else if (nstate & CT_SCTP_ERR) {
    return CT_SMR_ERR;
  } else if (nstate & CT_SCTP_FIN_MASK) {
    return CT_SMR_FIN;
  }

  return CT_SMR_INPROG;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 1000,
  "endLine": 1037,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_sm",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " struct dp_ct_tact *atdat",
    " struct dp_ct_tact *axtdat",
    " ct_dir_t dir"
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
    "static int __always_inline dp_ct_sm (void *ctx, struct xfi *xf, struct dp_ct_tact *atdat, struct dp_ct_tact *axtdat, ct_dir_t dir)\n",
    "{\n",
    "    int sm_ret = 0;\n",
    "    if (xf->pm.l4_off == 0) {\n",
    "        atdat->ctd.pi.frag = 1;\n",
    "        return CT_SMR_UNT;\n",
    "    }\n",
    "    atdat->ctd.pi.frag = 0;\n",
    "    switch (xf->l34m.nw_proto) {\n",
    "    case IPPROTO_TCP :\n",
    "        sm_ret = dp_ct_tcp_sm (ctx, xf, atdat, axtdat, dir);\n",
    "        break;\n",
    "    case IPPROTO_UDP :\n",
    "        sm_ret = dp_ct_udp_sm (ctx, xf, atdat, axtdat, dir);\n",
    "        break;\n",
    "    case IPPROTO_ICMP :\n",
    "        sm_ret = dp_ct_icmp_sm (ctx, xf, atdat, axtdat, dir);\n",
    "        break;\n",
    "    case IPPROTO_SCTP :\n",
    "        sm_ret = dp_ct_sctp_sm (ctx, xf, atdat, axtdat, dir);\n",
    "        break;\n",
    "    case IPPROTO_ICMPV6 :\n",
    "        sm_ret = dp_ct_icmp6_sm (ctx, xf, atdat, axtdat, dir);\n",
    "        break;\n",
    "    default :\n",
    "        sm_ret = CT_SMR_UNT;\n",
    "        break;\n",
    "    }\n",
    "    return sm_ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_ct_udp_sm",
    "dp_ct_tcp_sm",
    "dp_ct_icmp6_sm",
    "dp_ct_sctp_sm",
    "dp_ct_icmp_sm"
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
dp_ct_sm(void *ctx, struct xfi *xf,
         struct dp_ct_tact *atdat,
         struct dp_ct_tact *axtdat,
         ct_dir_t dir)
{
  int sm_ret = 0;

  if (xf->pm.l4_off == 0) {
    atdat->ctd.pi.frag = 1;
    return CT_SMR_UNT;
  }

  atdat->ctd.pi.frag = 0;

  switch (xf->l34m.nw_proto) {
  case IPPROTO_TCP:
    sm_ret = dp_ct_tcp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_UDP:
    sm_ret = dp_ct_udp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_ICMP:
    sm_ret = dp_ct_icmp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_SCTP:
    sm_ret = dp_ct_sctp_sm(ctx, xf, atdat, axtdat, dir);
    break;
  case IPPROTO_ICMPV6:
    sm_ret = dp_ct_icmp6_sm(ctx, xf, atdat, axtdat, dir);
    break;
  default:
    sm_ret = CT_SMR_UNT;
    break;
  }

  return sm_ret;
}

struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         int);
        __type(value,       struct dp_ct_tact);
        __uint(max_entries, 2);
} xctk SEC(".maps");

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
  "startLine": 1046,
  "endLine": 1212,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_ct.c",
  "funcName": "dp_ct_in",
  "developer_inline_comments": [
    {
      "start_line": 1074,
      "end_line": 1074,
      "text": " CT Key "
    },
    {
      "start_line": 1144,
      "end_line": 1144,
      "text": " FIXME This is duplicated data "
    }
  ],
  "updateMaps": [
    " ct_map"
  ],
  "readMaps": [
    "  ct_map",
    "  xctk"
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
    "static int __always_inline dp_ct_in (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    struct dp_ct_key key;\n",
    "    struct dp_ct_key xkey;\n",
    "    struct dp_ct_tact *adat;\n",
    "    struct dp_ct_tact *axdat;\n",
    "    struct dp_ct_tact *atdat;\n",
    "    struct dp_ct_tact *axtdat;\n",
    "    nxfrm_inf_t *xi;\n",
    "    nxfrm_inf_t *xxi;\n",
    "    ct_dir_t cdir = CT_DIR_IN;\n",
    "    int smr = CT_SMR_ERR;\n",
    "    int k;\n",
    "    k = 0;\n",
    "    adat = bpf_map_lookup_elem (& xctk, & k);\n",
    "    k = 1;\n",
    "    axdat = bpf_map_lookup_elem (& xctk, & k);\n",
    "    if (adat == NULL || axdat == NULL) {\n",
    "        return smr;\n",
    "    }\n",
    "    xi = &adat->ctd.xi;\n",
    "    xxi = &axdat->ctd.xi;\n",
    "    DP_XADDR_CP (key.daddr, xf->l34m.daddr);\n",
    "    DP_XADDR_CP (key.saddr, xf->l34m.saddr);\n",
    "    key.sport = xf->l34m.source;\n",
    "    key.dport = xf->l34m.dest;\n",
    "    key.l4proto = xf->l34m.nw_proto;\n",
    "    key.zone = xf->pm.zone;\n",
    "    key.v6 = xf->l2m.dl_type == bpf_ntohs (ETH_P_IPV6) ? 1 : 0;\n",
    "    if (key.l4proto != IPPROTO_TCP && key.l4proto != IPPROTO_UDP && key.l4proto != IPPROTO_ICMP && key.l4proto != IPPROTO_SCTP && key.l4proto != IPPROTO_ICMPV6) {\n",
    "        return 0;\n",
    "    }\n",
    "    xi->nat_flags = xf->pm.nf;\n",
    "    DP_XADDR_CP (xi->nat_xip, xf->nm.nxip);\n",
    "    DP_XADDR_CP (xi->nat_rip, xf->nm.nrip);\n",
    "    xi->nat_xport = xf->nm.nxport;\n",
    "    xi->nv6 = xf->nm.nv6;\n",
    "    xi->dsr = xf->nm.dsr;\n",
    "    xxi->nat_flags = 0;\n",
    "    xxi->nat_xport = 0;\n",
    "    DP_XADDR_SETZR (xxi->nat_xip);\n",
    "    DP_XADDR_SETZR (xxi->nat_rip);\n",
    "    if (xf->pm.nf & (LLB_NAT_DST | LLB_NAT_SRC)) {\n",
    "        if (DP_XADDR_ISZR (xi->nat_xip)) {\n",
    "            if (xf->pm.nf == LLB_NAT_DST) {\n",
    "                xi->nat_flags = LLB_NAT_HDST;\n",
    "            }\n",
    "            else if (xf->pm.nf == LLB_NAT_SRC) {\n",
    "                xi->nat_flags = LLB_NAT_HSRC;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    dp_ct_proto_xfk_init (&key, xi, &xkey, xxi);\n",
    "    atdat = bpf_map_lookup_elem (& ct_map, & key);\n",
    "    axtdat = bpf_map_lookup_elem (& ct_map, & xkey);\n",
    "    if (atdat == NULL || axtdat == NULL) {\n",
    "        LL_DBG_PRINTK (\"[CTRK] new-ct4\");\n",
    "        adat->ca.ftrap = 0;\n",
    "        adat->ca.oaux = 0;\n",
    "        adat->ca.cidx = dp_ct_get_newctr ();\n",
    "        adat->ca.fwrid = xf->pm.fw_rid;\n",
    "        adat->ca.record = xf->pm.dp_rec;\n",
    "        memset (&adat->ctd.pi, 0, sizeof (ct_pinf_t));\n",
    "        if (xi->nat_flags) {\n",
    "            adat->ca.act_type = xi->nat_flags & (LLB_NAT_DST | LLB_NAT_HDST) ? DP_SET_DNAT : DP_SET_SNAT;\n",
    "            DP_XADDR_CP (adat->nat_act.xip, xi->nat_xip);\n",
    "            DP_XADDR_CP (adat->nat_act.rip, xi->nat_rip);\n",
    "            adat->nat_act.xport = xi->nat_xport;\n",
    "            adat->nat_act.doct = 1;\n",
    "            adat->nat_act.rid = xf->pm.rule_id;\n",
    "            adat->nat_act.aid = xf->nm.sel_aid;\n",
    "            adat->nat_act.nv6 = xf->nm.nv6 ? 1 : 0;\n",
    "            adat->nat_act.dsr = xf->nm.dsr;\n",
    "            adat->ito = xf->nm.ito;\n",
    "        }\n",
    "        else {\n",
    "            adat->ito = 0;\n",
    "            adat->ca.act_type = DP_SET_DO_CT;\n",
    "        }\n",
    "        adat->ctd.dir = cdir;\n",
    "        adat->ctd.rid = xf->pm.rule_id;\n",
    "        adat->ctd.aid = xf->nm.sel_aid;\n",
    "        adat->ctd.smr = CT_SMR_INIT;\n",
    "        axdat->ca.ftrap = 0;\n",
    "        axdat->ca.oaux = 0;\n",
    "        axdat->ca.cidx = adat->ca.cidx + 1;\n",
    "        axdat->ca.fwrid = xf->pm.fw_rid;\n",
    "        axdat->ca.record = xf->pm.dp_rec;\n",
    "        memset (&axdat->ctd.pi, 0, sizeof (ct_pinf_t));\n",
    "        if (xxi->nat_flags) {\n",
    "            axdat->ca.act_type = xxi->nat_flags & (LLB_NAT_DST | LLB_NAT_HDST) ? DP_SET_DNAT : DP_SET_SNAT;\n",
    "            DP_XADDR_CP (axdat->nat_act.xip, xxi->nat_xip);\n",
    "            DP_XADDR_CP (axdat->nat_act.rip, xxi->nat_rip);\n",
    "            axdat->nat_act.xport = xxi->nat_xport;\n",
    "            axdat->nat_act.doct = 1;\n",
    "            axdat->nat_act.rid = xf->pm.rule_id;\n",
    "            axdat->nat_act.aid = xf->nm.sel_aid;\n",
    "            axdat->nat_act.nv6 = key.v6 ? 1 : 0;\n",
    "            axdat->nat_act.dsr = xf->nm.dsr;\n",
    "            axdat->ito = xf->nm.ito;\n",
    "        }\n",
    "        else {\n",
    "            axdat->ito = 0;\n",
    "            axdat->ca.act_type = DP_SET_DO_CT;\n",
    "        }\n",
    "        axdat->lts = adat->lts;\n",
    "        axdat->ctd.dir = CT_DIR_OUT;\n",
    "        axdat->ctd.smr = CT_SMR_INIT;\n",
    "        axdat->ctd.rid = adat->ctd.rid;\n",
    "        axdat->ctd.aid = adat->ctd.aid;\n",
    "        bpf_map_update_elem (&ct_map, &xkey, axdat, BPF_ANY);\n",
    "        bpf_map_update_elem (&ct_map, &key, adat, BPF_ANY);\n",
    "        atdat = bpf_map_lookup_elem (& ct_map, & key);\n",
    "        axtdat = bpf_map_lookup_elem (& ct_map, & xkey);\n",
    "    }\n",
    "    if (atdat != NULL && axtdat != NULL) {\n",
    "        atdat->lts = bpf_ktime_get_ns ();\n",
    "        axtdat->lts = atdat->lts;\n",
    "        if (atdat->ctd.dir == CT_DIR_IN) {\n",
    "            LL_DBG_PRINTK (\"[CTRK] in-dir\");\n",
    "            smr = dp_ct_sm (ctx, xf, atdat, axtdat, CT_DIR_IN);\n",
    "        }\n",
    "        else {\n",
    "            LL_DBG_PRINTK (\"[CTRK] out-dir\");\n",
    "            smr = dp_ct_sm (ctx, xf, axtdat, atdat, CT_DIR_OUT);\n",
    "        }\n",
    "        LL_DBG_PRINTK (\"[CTRK] smr %d\", smr);\n",
    "        if (smr == CT_SMR_EST) {\n",
    "            if (xi->nat_flags) {\n",
    "                atdat->nat_act.doct = 0;\n",
    "                axtdat->nat_act.doct = 0;\n",
    "            }\n",
    "            else {\n",
    "                atdat->ca.act_type = DP_SET_NOP;\n",
    "                axtdat->ca.act_type = DP_SET_NOP;\n",
    "            }\n",
    "        }\n",
    "        else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {\n",
    "            bpf_map_delete_elem (&ct_map, &xkey);\n",
    "            bpf_map_delete_elem (&ct_map, &key);\n",
    "        }\n",
    "    }\n",
    "    return smr;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_ct_get_newctr",
    "memset",
    "LL_DBG_PRINTK",
    "bpf_ntohs",
    "DP_XADDR_SETZR",
    "dp_ct_proto_xfk_init",
    "DP_XADDR_CP",
    "dp_ct_sm",
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
dp_ct_in(void *ctx, struct xfi *xf)
{
  struct dp_ct_key key;
  struct dp_ct_key xkey;
  struct dp_ct_tact *adat;
  struct dp_ct_tact *axdat;
  struct dp_ct_tact *atdat;
  struct dp_ct_tact *axtdat;
  nxfrm_inf_t *xi;
  nxfrm_inf_t *xxi;
  ct_dir_t cdir = CT_DIR_IN;
  int smr = CT_SMR_ERR;
  int k;

  k = 0;
  adat = bpf_map_lookup_elem(&xctk, &k);

  k = 1;
  axdat = bpf_map_lookup_elem(&xctk, &k);

  if (adat == NULL || axdat == NULL) {
    return smr;
  }

  xi = &adat->ctd.xi;
  xxi = &axdat->ctd.xi;
 
  /* CT Key */
  DP_XADDR_CP(key.daddr, xf->l34m.daddr);
  DP_XADDR_CP(key.saddr, xf->l34m.saddr);
  key.sport = xf->l34m.source;
  key.dport = xf->l34m.dest;
  key.l4proto = xf->l34m.nw_proto;
  key.zone = xf->pm.zone;
  key.v6 = xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) ? 1: 0;

  if (key.l4proto != IPPROTO_TCP &&
      key.l4proto != IPPROTO_UDP &&
      key.l4proto != IPPROTO_ICMP &&
      key.l4proto != IPPROTO_SCTP &&
      key.l4proto != IPPROTO_ICMPV6) {
    return 0;
  }

  xi->nat_flags = xf->pm.nf;
  DP_XADDR_CP(xi->nat_xip, xf->nm.nxip);
  DP_XADDR_CP(xi->nat_rip, xf->nm.nrip);
  xi->nat_xport = xf->nm.nxport;
  xi->nv6 = xf->nm.nv6;
  xi->dsr = xf->nm.dsr;

  xxi->nat_flags = 0;
  xxi->nat_xport = 0;
  DP_XADDR_SETZR(xxi->nat_xip);
  DP_XADDR_SETZR(xxi->nat_rip);

  if (xf->pm.nf & (LLB_NAT_DST|LLB_NAT_SRC)) {
    if (DP_XADDR_ISZR(xi->nat_xip)) {
      if (xf->pm.nf == LLB_NAT_DST) {
        xi->nat_flags = LLB_NAT_HDST;
      } else if (xf->pm.nf == LLB_NAT_SRC){
        xi->nat_flags = LLB_NAT_HSRC;
      }
    }
  }

  dp_ct_proto_xfk_init(&key, xi, &xkey, xxi);

  atdat = bpf_map_lookup_elem(&ct_map, &key);
  axtdat = bpf_map_lookup_elem(&ct_map, &xkey);
  if (atdat == NULL || axtdat == NULL) {

    LL_DBG_PRINTK("[CTRK] new-ct4");
    adat->ca.ftrap = 0;
    adat->ca.oaux = 0;
    adat->ca.cidx = dp_ct_get_newctr();
    adat->ca.fwrid = xf->pm.fw_rid;
    adat->ca.record = xf->pm.dp_rec;
    memset(&adat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xi->nat_flags) {
      adat->ca.act_type = xi->nat_flags & (LLB_NAT_DST|LLB_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      DP_XADDR_CP(adat->nat_act.xip,  xi->nat_xip);
      DP_XADDR_CP(adat->nat_act.rip, xi->nat_rip);
      adat->nat_act.xport = xi->nat_xport;
      adat->nat_act.doct = 1;
      adat->nat_act.rid = xf->pm.rule_id;
      adat->nat_act.aid = xf->nm.sel_aid;
      adat->nat_act.nv6 = xf->nm.nv6 ? 1:0;
      adat->nat_act.dsr = xf->nm.dsr;
      adat->ito = xf->nm.ito;
    } else {
      adat->ito = 0;
      adat->ca.act_type = DP_SET_DO_CT;
    }
    adat->ctd.dir = cdir;

    /* FIXME This is duplicated data */
    adat->ctd.rid = xf->pm.rule_id;
    adat->ctd.aid = xf->nm.sel_aid;
    adat->ctd.smr = CT_SMR_INIT;

    axdat->ca.ftrap = 0;
    axdat->ca.oaux = 0;
    axdat->ca.cidx = adat->ca.cidx + 1;
    axdat->ca.fwrid = xf->pm.fw_rid;
    axdat->ca.record = xf->pm.dp_rec;
    memset(&axdat->ctd.pi, 0, sizeof(ct_pinf_t));
    if (xxi->nat_flags) { 
      axdat->ca.act_type = xxi->nat_flags & (LLB_NAT_DST|LLB_NAT_HDST) ?
                             DP_SET_DNAT: DP_SET_SNAT;
      DP_XADDR_CP(axdat->nat_act.xip, xxi->nat_xip);
      DP_XADDR_CP(axdat->nat_act.rip, xxi->nat_rip);
      axdat->nat_act.xport = xxi->nat_xport;
      axdat->nat_act.doct = 1;
      axdat->nat_act.rid = xf->pm.rule_id;
      axdat->nat_act.aid = xf->nm.sel_aid;
      axdat->nat_act.nv6 = key.v6 ? 1:0;
      axdat->nat_act.dsr = xf->nm.dsr;
      axdat->ito = xf->nm.ito;
    } else {
      axdat->ito = 0;
      axdat->ca.act_type = DP_SET_DO_CT;
    }
    axdat->lts = adat->lts;
    axdat->ctd.dir = CT_DIR_OUT;
    axdat->ctd.smr = CT_SMR_INIT;
    axdat->ctd.rid = adat->ctd.rid;
    axdat->ctd.aid = adat->ctd.aid;

    bpf_map_update_elem(&ct_map, &xkey, axdat, BPF_ANY);
    bpf_map_update_elem(&ct_map, &key, adat, BPF_ANY);

    atdat = bpf_map_lookup_elem(&ct_map, &key);
    axtdat = bpf_map_lookup_elem(&ct_map, &xkey);
  }

  if (atdat != NULL && axtdat != NULL) {
    atdat->lts = bpf_ktime_get_ns();
    axtdat->lts = atdat->lts;
    if (atdat->ctd.dir == CT_DIR_IN) {
      LL_DBG_PRINTK("[CTRK] in-dir");
      smr = dp_ct_sm(ctx, xf, atdat, axtdat, CT_DIR_IN);
    } else {
      LL_DBG_PRINTK("[CTRK] out-dir");
      smr = dp_ct_sm(ctx, xf, axtdat, atdat, CT_DIR_OUT);
    }

    LL_DBG_PRINTK("[CTRK] smr %d", smr);

    if (smr == CT_SMR_EST) {
      if (xi->nat_flags) {
        atdat->nat_act.doct = 0;
        axtdat->nat_act.doct = 0;
      } else {
        atdat->ca.act_type = DP_SET_NOP;
        axtdat->ca.act_type = DP_SET_NOP;
      }
    } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
      bpf_map_delete_elem(&ct_map, &xkey);
      bpf_map_delete_elem(&ct_map, &key);
    }
  }

  return smr; 
}
