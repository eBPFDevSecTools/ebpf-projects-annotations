/*
 *  llb_kern_composer.c: LoxiLB Kernel eBPF packet composer/decomposer
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 39,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_eth",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_composer.c: LoxiLB Kernel eBPF packet composer/decomposer *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_eth (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    eth = DP_TC_PTR (p -> dbegin);\n",
    "    if (eth + 1 > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    if (p->inp) {\n",
    "        xf->il2m.valid = 1;\n",
    "        memcpy (xf->il2m.dl_dst, eth->h_dest, 2 * 6);\n",
    "        memcpy (xf->pm.lkup_dmac, eth->h_dest, 6);\n",
    "        xf->il2m.dl_type = eth->h_proto;\n",
    "    }\n",
    "    else {\n",
    "        xf->l2m.valid = 1;\n",
    "        memcpy (xf->l2m.dl_dst, eth->h_dest, 2 * 6);\n",
    "        memcpy (xf->pm.lkup_dmac, eth->h_dest, 6);\n",
    "        xf->l2m.dl_type = eth->h_proto;\n",
    "    }\n",
    "    if (!ETH_TYPE_ETH2(eth->h_proto)) {\n",
    "        return DP_PRET_PASS;\n",
    "    }\n",
    "    p->dbegin = DP_ADD_PTR (eth, sizeof (*eth));\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_TC_PTR",
    "DP_ADD_PTR",
    "ETH_TYPE_ETH2",
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
dp_parse_eth(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct ethhdr *eth;
  eth = DP_TC_PTR(p->dbegin);

  if (eth + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (p->inp) {
    xf->il2m.valid = 1;
    memcpy(xf->il2m.dl_dst, eth->h_dest, 2*6);
    memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);
    xf->il2m.dl_type = eth->h_proto;
  } else {
    xf->l2m.valid = 1;
    memcpy(xf->l2m.dl_dst, eth->h_dest, 2*6);
    memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);
    xf->l2m.dl_type = eth->h_proto;
  }

  if (!ETH_TYPE_ETH2(eth->h_proto)) {
    return DP_PRET_PASS;
  }

  p->dbegin = DP_ADD_PTR(eth, sizeof(*eth));

  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 41,
  "endLine": 72,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_vlan",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_vlan (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "\n",
    "#ifndef LL_TC_EBPF\n",
    "    struct vlanhdr *vlh;\n",
    "    int vlan_depth;\n",
    "    vlh = DP_TC_PTR (p -> dbegin);\n",
    "\n",
    "#endif\n",
    "\n",
    "#ifndef LL_TC_EBPF\n",
    "\n",
    "#pragma unroll\n",
    "    for (vlan_depth = 0; vlan_depth < MAX_STACKED_VLANS; vlan_depth++) {\n",
    "        if (!proto_is_vlan (xf->l2m.dl_type))\n",
    "            break;\n",
    "        if (vlh + 1 > p->dend) {\n",
    "            return DP_PRET_FAIL;\n",
    "        }\n",
    "        xf->l2m.dl_type = vlh->h_vlan_encapsulated_proto;\n",
    "        xf->l2m.vlan[vlan_depth] = vlh->h_vlan_TCI & bpf_htons (VLAN_VID_MASK);\n",
    "        vlh++;\n",
    "    }\n",
    "    p->dbegin = DP_TC_PTR (vlh);\n",
    "\n",
    "#else\n",
    "    dp_vlan_info (xf, md);\n",
    "\n",
    "#endif\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_TC_PTR",
    "bpf_htons",
    "dp_vlan_info",
    "proto_is_vlan"
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
dp_parse_vlan(struct parser *p,
              void *md,
              struct xfi *xf)
{
#ifndef LL_TC_EBPF
  struct vlanhdr *vlh;
  int vlan_depth;
  vlh = DP_TC_PTR(p->dbegin);
#endif

#ifndef LL_TC_EBPF
#pragma unroll
  for (vlan_depth = 0; vlan_depth < MAX_STACKED_VLANS; vlan_depth++) {
    if (!proto_is_vlan(xf->l2m.dl_type))
      break;

    if (vlh + 1 > p->dend) {
      return DP_PRET_FAIL;
    }

    xf->l2m.dl_type = vlh->h_vlan_encapsulated_proto;
    xf->l2m.vlan[vlan_depth] = vlh->h_vlan_TCI & bpf_htons(VLAN_VID_MASK);
    vlh++;
  }
  p->dbegin = DP_TC_PTR(vlh);
#else
  dp_vlan_info(xf, md); 
#endif

  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 74,
  "endLine": 97,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_vlan_d1",
  "developer_inline_comments": [
    {
      "start_line": 83,
      "end_line": 83,
      "text": " Only one inner vlan is supported "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_vlan_d1 (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct vlanhdr *vlh;\n",
    "    vlh = DP_TC_PTR (p -> dbegin);\n",
    "    if (proto_is_vlan (xf->il2m.dl_type)) {\n",
    "        if (vlh + 1 > p->dend) {\n",
    "            return DP_PRET_FAIL;\n",
    "        }\n",
    "        xf->il2m.dl_type = vlh->h_vlan_encapsulated_proto;\n",
    "        xf->il2m.vlan[0] = vlh->h_vlan_TCI & bpf_htons (VLAN_VID_MASK);\n",
    "        vlh++;\n",
    "        p->dbegin = DP_TC_PTR (vlh);\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_TC_PTR",
    "bpf_htons",
    "proto_is_vlan"
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
dp_parse_vlan_d1(struct parser *p,
               void *md,
               struct xfi *xf)
{
  struct vlanhdr *vlh;

  vlh = DP_TC_PTR(p->dbegin);

  /* Only one inner vlan is supported */
  if (proto_is_vlan(xf->il2m.dl_type)) {

    if (vlh + 1 > p->dend) {
      return DP_PRET_FAIL;
    }

    xf->il2m.dl_type = vlh->h_vlan_encapsulated_proto;
    xf->il2m.vlan[0] = vlh->h_vlan_TCI & bpf_htons(VLAN_VID_MASK);
    vlh++;
    p->dbegin = DP_TC_PTR(vlh);
  }

  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 99,
  "endLine": 127,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_arp",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_arp (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct arp_ethhdr *arp = DP_TC_PTR (p->dbegin);\n",
    "    if (arp + 1 > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    if (p->inp) {\n",
    "        if (arp->ar_pro == bpf_htons (ETH_P_IP) && arp->ar_pln == 4) {\n",
    "            xf->il34m.saddr4 = arp->ar_spa;\n",
    "            xf->il34m.daddr4 = arp->ar_tpa;\n",
    "        }\n",
    "        xf->il34m.nw_proto = bpf_ntohs (arp->ar_op) & 0xff;\n",
    "    }\n",
    "    else {\n",
    "        if (arp->ar_pro == bpf_htons (ETH_P_IP) && arp->ar_pln == 4) {\n",
    "            xf->l34m.saddr4 = arp->ar_spa;\n",
    "            xf->l34m.daddr4 = arp->ar_tpa;\n",
    "        }\n",
    "        xf->l34m.nw_proto = bpf_ntohs (arp->ar_op) & 0xff;\n",
    "    }\n",
    "    return DP_PRET_TRAP;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_ntohs",
    "DP_TC_PTR",
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
dp_parse_arp(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct arp_ethhdr *arp = DP_TC_PTR(p->dbegin);

  if (arp + 1 > p->dend) {
      return DP_PRET_FAIL;
  }

  if (p->inp) {
    if (arp->ar_pro == bpf_htons(ETH_P_IP) && 
        arp->ar_pln == 4) {
      xf->il34m.saddr4 = arp->ar_spa;
      xf->il34m.daddr4 = arp->ar_tpa;
    }
    xf->il34m.nw_proto = bpf_ntohs(arp->ar_op) & 0xff;
  } else {
    if (arp->ar_pro == bpf_htons(ETH_P_IP) && 
        arp->ar_pln == 4) {
      xf->l34m.saddr4 = arp->ar_spa;
      xf->l34m.daddr4 = arp->ar_tpa;
    }
    xf->l34m.nw_proto = bpf_ntohs(arp->ar_op) & 0xff;
  }

  return DP_PRET_TRAP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 129,
  "endLine": 176,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_tcp",
  "developer_inline_comments": [
    {
      "start_line": 138,
      "end_line": 138,
      "text": " In case of fragmented packets "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_tcp (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct tcphdr *tcp = DP_TC_PTR (p->dbegin);\n",
    "    __u8 tcp_flags = 0;\n",
    "    if (tcp + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    if (tcp->fin)\n",
    "        tcp_flags = LLB_TCP_FIN;\n",
    "    if (tcp->rst)\n",
    "        tcp_flags |= LLB_TCP_RST;\n",
    "    if (tcp->syn)\n",
    "        tcp_flags |= LLB_TCP_SYN;\n",
    "    if (tcp->psh)\n",
    "        tcp_flags |= LLB_TCP_PSH;\n",
    "    if (tcp->ack)\n",
    "        tcp_flags |= LLB_TCP_ACK;\n",
    "    if (tcp->urg)\n",
    "        tcp_flags |= LLB_TCP_URG;\n",
    "    if (p->inp) {\n",
    "        if (tcp_flags & (LLB_TCP_FIN | LLB_TCP_RST)) {\n",
    "            xf->pm.il4fin = 1;\n",
    "        }\n",
    "        xf->il34m.source = tcp->source;\n",
    "        xf->il34m.dest = tcp->dest;\n",
    "        xf->il34m.seq = tcp->seq;\n",
    "        xf->pm.itcp_flags = tcp_flags;\n",
    "    }\n",
    "    else {\n",
    "        if (tcp_flags & (LLB_TCP_FIN | LLB_TCP_RST)) {\n",
    "            xf->pm.l4fin = 1;\n",
    "        }\n",
    "        xf->l34m.source = tcp->source;\n",
    "        xf->l34m.dest = tcp->dest;\n",
    "        xf->l34m.seq = tcp->seq;\n",
    "        xf->pm.tcp_flags = tcp_flags;\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
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
dp_parse_tcp(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct tcphdr *tcp = DP_TC_PTR(p->dbegin);
  __u8 tcp_flags = 0;

  if (tcp + 1 > p->dend) {
    /* In case of fragmented packets */
    return DP_PRET_OK;
  }

  if (tcp->fin)
    tcp_flags = LLB_TCP_FIN;
  if (tcp->rst)
    tcp_flags |= LLB_TCP_RST;
  if (tcp->syn)
    tcp_flags |= LLB_TCP_SYN;
  if (tcp->psh)
    tcp_flags |= LLB_TCP_PSH;
  if (tcp->ack)
    tcp_flags |= LLB_TCP_ACK;
  if (tcp->urg)
    tcp_flags |= LLB_TCP_URG;

  if (p->inp) {
    if (tcp_flags & (LLB_TCP_FIN|LLB_TCP_RST)) {
      xf->pm.il4fin = 1;
    }

    xf->il34m.source = tcp->source;
    xf->il34m.dest = tcp->dest;
    xf->il34m.seq = tcp->seq;
    xf->pm.itcp_flags = tcp_flags;
  } else {
    if (tcp_flags & (LLB_TCP_FIN|LLB_TCP_RST)) {
      xf->pm.l4fin = 1;
    }

    xf->l34m.source = tcp->source;
    xf->l34m.dest = tcp->dest;
    xf->l34m.seq = tcp->seq;
    xf->pm.tcp_flags = tcp_flags;
  }

  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 178,
  "endLine": 200,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_icmp",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_icmp (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct icmphdr *icmp = DP_TC_PTR (p->dbegin);\n",
    "    if (icmp + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    if ((icmp->type == ICMP_ECHOREPLY || icmp->type == ICMP_ECHO)) {\n",
    "        if (p->inp) {\n",
    "            xf->il34m.source = icmp->un.echo.id;\n",
    "            xf->il34m.dest = icmp->un.echo.id;\n",
    "        }\n",
    "        else {\n",
    "            xf->l34m.source = icmp->un.echo.id;\n",
    "            xf->l34m.dest = icmp->un.echo.id;\n",
    "        }\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
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
dp_parse_icmp(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct icmphdr *icmp = DP_TC_PTR(p->dbegin);

  if (icmp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if ((icmp->type == ICMP_ECHOREPLY ||
    icmp->type == ICMP_ECHO)) {
    if (p->inp) {
      xf->il34m.source = icmp->un.echo.id;
      xf->il34m.dest = icmp->un.echo.id;
    } else {
      xf->l34m.source = icmp->un.echo.id;
      xf->l34m.dest = icmp->un.echo.id;
    }
  }
  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 202,
  "endLine": 217,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_iudp",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_iudp (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct udphdr *udp = DP_TC_PTR (p->dbegin);\n",
    "    if (udp + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    xf->il34m.source = udp->source;\n",
    "    xf->il34m.dest = udp->dest;\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
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
dp_parse_iudp(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct udphdr *udp = DP_TC_PTR(p->dbegin);
  
  if (udp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  xf->il34m.source = udp->source;
  xf->il34m.dest = udp->dest;

  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 219,
  "endLine": 260,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_sctp",
  "developer_inline_comments": [
    {
      "start_line": 241,
      "end_line": 241,
      "text": " Chunks need not be present in all sctp packets "
    },
    {
      "start_line": 246,
      "end_line": 246,
      "text": " Parsing only one-level of chunk "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_sctp (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct sctp_dch *c;\n",
    "    struct sctphdr *sctp = DP_TC_PTR (p->dbegin);\n",
    "    if (sctp + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    if (p->inp) {\n",
    "        xf->il34m.source = sctp->source;\n",
    "        xf->il34m.dest = sctp->dest;\n",
    "    }\n",
    "    else {\n",
    "        xf->l34m.source = sctp->source;\n",
    "        xf->l34m.dest = sctp->dest;\n",
    "    }\n",
    "    c = DP_TC_PTR (DP_ADD_PTR (sctp, sizeof (* sctp)));\n",
    "    if (c + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    if (c->type == SCTP_ERROR || c->type == SCTP_ABORT || c->type == SCTP_SHUT || c->type == SCTP_SHUT_ACK || c->type == SCTP_SHUT_COMPLETE) {\n",
    "        if (p->inp) {\n",
    "            xf->pm.il4fin = 1;\n",
    "        }\n",
    "        else {\n",
    "            xf->pm.l4fin = 1;\n",
    "        }\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_TC_PTR",
    "DP_ADD_PTR"
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
dp_parse_sctp(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct sctp_dch *c;
  struct sctphdr *sctp = DP_TC_PTR(p->dbegin);

  if (sctp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if (p->inp) {
    xf->il34m.source = sctp->source;
    xf->il34m.dest = sctp->dest;
  } else {
    xf->l34m.source = sctp->source;
    xf->l34m.dest = sctp->dest;
  }

  c = DP_TC_PTR(DP_ADD_PTR(sctp, sizeof(*sctp)));

  /* Chunks need not be present in all sctp packets */
  if (c + 1 > p->dend) {
    return DP_PRET_OK;
  }

  /* Parsing only one-level of chunk */
  if (c->type == SCTP_ERROR ||
    c->type == SCTP_ABORT ||
    c->type == SCTP_SHUT  ||
    c->type == SCTP_SHUT_ACK ||
    c->type == SCTP_SHUT_COMPLETE) {
    if (p->inp) {
      xf->pm.il4fin = 1;
    } else {
      xf->pm.l4fin = 1;
    }
  }

  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 262,
  "endLine": 288,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_icmp6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_icmp6 (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct icmp6hdr *icmp6 = DP_TC_PTR (p->dbegin);\n",
    "    if (icmp6 + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    if ((icmp6->icmp6_type == ICMPV6_ECHO_REPLY || icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)) {\n",
    "        if (p->inp) {\n",
    "            xf->il34m.source = icmp6->icmp6_dataun.u_echo.identifier;\n",
    "            xf->il34m.dest = icmp6->icmp6_dataun.u_echo.identifier;\n",
    "        }\n",
    "        else {\n",
    "            xf->l34m.source = icmp6->icmp6_dataun.u_echo.identifier;\n",
    "            xf->l34m.dest = icmp6->icmp6_dataun.u_echo.identifier;\n",
    "        }\n",
    "    }\n",
    "    else if (icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 137) {\n",
    "        return DP_PRET_PASS;\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
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
dp_parse_icmp6(struct parser *p,
               void *md,
               struct xfi *xf)
{
  struct icmp6hdr *icmp6 = DP_TC_PTR(p->dbegin);

  if (icmp6 + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if ((icmp6->icmp6_type == ICMPV6_ECHO_REPLY ||
      icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)) {
    if (p->inp) {
      xf->il34m.source = icmp6->icmp6_dataun.u_echo.identifier;
      xf->il34m.dest = icmp6->icmp6_dataun.u_echo.identifier;
    } else {
      xf->l34m.source = icmp6->icmp6_dataun.u_echo.identifier;
      xf->l34m.dest = icmp6->icmp6_dataun.u_echo.identifier;
    }
  } else if (icmp6->icmp6_type >= 133 &&
            icmp6->icmp6_type <= 137) {
    return DP_PRET_PASS;
  }

  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 290,
  "endLine": 343,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_ipv4_d1",
  "developer_inline_comments": [
    {
      "start_line": 315,
      "end_line": 319,
      "text": " Earlier we used to have the following check here :   * !ip_is_fragment(iph) || ip_is_first_fragment(iph))   * But it seems to be unncessary as proper bound checking   * is already taken care by eBPF verifier   "
    },
    {
      "start_line": 333,
      "end_line": 333,
      "text": " Let xfrm handle it "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_ipv4_d1 (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct iphdr *iph = DP_TC_PTR (p->dbegin);\n",
    "    int iphl = iph->ihl << 2;\n",
    "    if (iph + 1 > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    if (DP_ADD_PTR (iph, iphl) > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    xf->pm.il3_len = bpf_ntohs (iph->tot_len);\n",
    "    xf->pm.il3_plen = xf->pm.il3_len - iphl;\n",
    "    xf->il34m.valid = 1;\n",
    "    xf->il34m.tos = iph->tos & 0xfc;\n",
    "    xf->il34m.nw_proto = iph->protocol;\n",
    "    xf->il34m.saddr4 = iph->saddr;\n",
    "    xf->il34m.daddr4 = iph->daddr;\n",
    "    xf->pm.il4_off = DP_DIFF_PTR (DP_ADD_PTR (iph, iphl), p->start);\n",
    "    p->dbegin = DP_ADD_PTR (iph, iphl);\n",
    "    if (xf->il34m.nw_proto == IPPROTO_TCP) {\n",
    "        return dp_parse_tcp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->il34m.nw_proto == IPPROTO_UDP) {\n",
    "        return dp_parse_iudp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->il34m.nw_proto == IPPROTO_SCTP) {\n",
    "        return dp_parse_sctp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->il34m.nw_proto == IPPROTO_ICMP) {\n",
    "        return dp_parse_icmp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->il34m.nw_proto == IPPROTO_ESP || xf->il34m.nw_proto == IPPROTO_AH) {\n",
    "        return DP_PRET_PASS;\n",
    "    }\n",
    "    if (ip_is_fragment (iph)) {\n",
    "        xf->il34m.source = 0;\n",
    "        xf->il34m.dest = 0;\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_DIFF_PTR",
    "ip_is_fragment",
    "DP_ADD_PTR",
    "dp_parse_tcp",
    "bpf_ntohs",
    "DP_TC_PTR",
    "dp_parse_sctp",
    "dp_parse_iudp",
    "dp_parse_icmp"
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
dp_parse_ipv4_d1(struct parser *p,
                 void *md,
                 struct xfi *xf)
{
  struct iphdr *iph = DP_TC_PTR(p->dbegin);
  int iphl = iph->ihl << 2;

  if (iph + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (DP_ADD_PTR(iph, iphl) > p->dend) {
    return DP_PRET_FAIL;
  }

  xf->pm.il3_len = bpf_ntohs(iph->tot_len);
  xf->pm.il3_plen = xf->pm.il3_len - iphl;

  xf->il34m.valid = 1;
  xf->il34m.tos = iph->tos & 0xfc;
  xf->il34m.nw_proto = iph->protocol;
  xf->il34m.saddr4 = iph->saddr;
  xf->il34m.daddr4 = iph->daddr;

  /* Earlier we used to have the following check here :
   * !ip_is_fragment(iph) || ip_is_first_fragment(iph))
   * But it seems to be unncessary as proper bound checking
   * is already taken care by eBPF verifier
   */
  xf->pm.il4_off = DP_DIFF_PTR(DP_ADD_PTR(iph, iphl), p->start);
  p->dbegin = DP_ADD_PTR(iph, iphl);

  if (xf->il34m.nw_proto == IPPROTO_TCP) {
    return dp_parse_tcp(p, md, xf);
  } else if (xf->il34m.nw_proto == IPPROTO_UDP) {
    return dp_parse_iudp(p, md, xf);
  } else if (xf->il34m.nw_proto == IPPROTO_SCTP) {
    return dp_parse_sctp(p, md, xf);
  } else if (xf->il34m.nw_proto == IPPROTO_ICMP) {
    return dp_parse_icmp(p, md, xf);
  } else if (xf->il34m.nw_proto == IPPROTO_ESP ||
             xf->il34m.nw_proto == IPPROTO_AH) {
    /* Let xfrm handle it */
    return DP_PRET_PASS;
  }

  if (ip_is_fragment(iph)) {
    xf->il34m.source = 0;
    xf->il34m.dest = 0;
  }
  
  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 345,
  "endLine": 382,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_ipv6_d1",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_ipv6_d1 (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct ipv6hdr *ip6 = DP_TC_PTR (p->dbegin);\n",
    "    if (ip6 + 1 > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    if (ipv6_addr_is_multicast (&ip6->daddr) || ipv6_addr_is_multicast (&ip6->saddr)) {\n",
    "        return DP_PRET_PASS;\n",
    "    }\n",
    "    xf->pm.il3_plen = bpf_ntohs (ip6->payload_len);\n",
    "    xf->pm.il3_len = xf->pm.il3_plen + sizeof (*ip6);\n",
    "    xf->il34m.valid = 1;\n",
    "    xf->il34m.tos = ((ip6->priority << 4) | ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;\n",
    "    xf->il34m.nw_proto = ip6->nexthdr;\n",
    "    memcpy (&xf->il34m.saddr, &ip6->saddr, sizeof (ip6->saddr));\n",
    "    memcpy (&xf->il34m.daddr, &ip6->daddr, sizeof (ip6->daddr));\n",
    "    xf->pm.il4_off = DP_DIFF_PTR (DP_ADD_PTR (ip6, sizeof (*ip6)), p->start);\n",
    "    p->dbegin = DP_ADD_PTR (ip6, sizeof (*ip6));\n",
    "    if (xf->il34m.nw_proto == IPPROTO_TCP) {\n",
    "        return dp_parse_tcp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->il34m.nw_proto == IPPROTO_UDP) {\n",
    "        return dp_parse_iudp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {\n",
    "        return dp_parse_icmp6 (p, md, xf);\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_DIFF_PTR",
    "DP_ADD_PTR",
    "dp_parse_tcp",
    "dp_parse_icmp6",
    "bpf_ntohs",
    "DP_TC_PTR",
    "dp_parse_iudp",
    "ipv6_addr_is_multicast",
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
dp_parse_ipv6_d1(struct parser *p,
                 void *md,
                 struct xfi *xf)
{
  struct ipv6hdr *ip6 = DP_TC_PTR(p->dbegin);

  if (ip6 + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (ipv6_addr_is_multicast(&ip6->daddr) ||
      ipv6_addr_is_multicast(&ip6->saddr)) {
    return DP_PRET_PASS;
  }

  xf->pm.il3_plen = bpf_ntohs(ip6->payload_len);
  xf->pm.il3_len =  xf->pm.il3_plen + sizeof(*ip6);

  xf->il34m.valid = 1;
  xf->il34m.tos = ((ip6->priority << 4) |
               ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
  xf->il34m.nw_proto = ip6->nexthdr;
  memcpy(&xf->il34m.saddr, &ip6->saddr, sizeof(ip6->saddr));
  memcpy(&xf->il34m.daddr, &ip6->daddr, sizeof(ip6->daddr));

  xf->pm.il4_off = DP_DIFF_PTR(DP_ADD_PTR(ip6, sizeof(*ip6)), p->start);
  p->dbegin = DP_ADD_PTR(ip6, sizeof(*ip6));

  if (xf->il34m.nw_proto == IPPROTO_TCP) {
    return dp_parse_tcp(p, md, xf);
  } else if (xf->il34m.nw_proto == IPPROTO_UDP) {
    return dp_parse_iudp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {
    return dp_parse_icmp6(p, md, xf);
  }
  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 384,
  "endLine": 418,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_d1",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_d1 (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    int ret = 0;\n",
    "    if (p->skip_l2) {\n",
    "        if (xf->il2m.dl_type == 0)\n",
    "            return DP_PRET_TRAP;\n",
    "        goto proc_inl3;\n",
    "    }\n",
    "    if ((ret = dp_parse_eth (p, md, xf))) {\n",
    "        return ret;\n",
    "    }\n",
    "    if ((ret = dp_parse_vlan_d1 (p, md, xf))) {\n",
    "        return ret;\n",
    "    }\n",
    "proc_inl3 :\n",
    "    xf->pm.il3_off = DP_DIFF_PTR (p->dbegin, p->start);\n",
    "    if (xf->il2m.dl_type == bpf_htons (ETH_P_ARP)) {\n",
    "        ret = dp_parse_arp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->il2m.dl_type == bpf_htons (ETH_P_IP)) {\n",
    "        ret = dp_parse_ipv4_d1 (p, md, xf);\n",
    "    }\n",
    "    else if (xf->il2m.dl_type == bpf_htons (ETH_P_IPV6)) {\n",
    "        if (p->skip_v6 == 0)\n",
    "            ret = dp_parse_ipv6_d1 (p, md, xf);\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_DIFF_PTR",
    "dp_parse_ipv4_d1",
    "bpf_htons",
    "dp_parse_ipv6_d1",
    "dp_parse_eth",
    "dp_parse_arp",
    "dp_parse_vlan_d1"
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
dp_parse_d1(struct parser *p,
            void *md,
            struct xfi *xf)
{
  int ret = 0;

  if (p->skip_l2) {
    if (xf->il2m.dl_type == 0)
      return DP_PRET_TRAP;
    goto proc_inl3;
  }

  if ((ret = dp_parse_eth(p, md, xf))) {
    return ret;
  }

  if ((ret = dp_parse_vlan_d1(p, md, xf))) {
    return ret;
  }

proc_inl3:
  xf->pm.il3_off = DP_DIFF_PTR(p->dbegin, p->start);

  if (xf->il2m.dl_type == bpf_htons(ETH_P_ARP)) {
    ret = dp_parse_arp(p, md, xf);
  } else if (xf->il2m.dl_type == bpf_htons(ETH_P_IP)) {
    ret = dp_parse_ipv4_d1(p, md, xf);
  } else if (xf->il2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    if (p->skip_v6 == 0)
      ret = dp_parse_ipv6_d1(p, md, xf);
  }

  return ret;
} 

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 420,
  "endLine": 442,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_gtp_ehdr",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *nh",
    " void *dend"
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
    "static int __always_inline dp_parse_gtp_ehdr (void *nh, void *dend)\n",
    "{\n",
    "    uint8_t *nhl = DP_TC_PTR (nh);\n",
    "    uint8_t *neh;\n",
    "    int elen;\n",
    "    if (nhl + 1 > dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    elen = *nhl << 2;\n",
    "    if (nhl + elen > dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    neh = nhl + (elen - 1);\n",
    "    if (*neh)\n",
    "        return elen;\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
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
dp_parse_gtp_ehdr(void *nh, void *dend)
{
  uint8_t *nhl = DP_TC_PTR(nh);
  uint8_t *neh;
  int elen;

  if (nhl + 1 > dend) {
    return DP_PRET_FAIL;
  }

  elen = *nhl<<2;

  if (nhl + elen > dend) {
    return DP_PRET_FAIL;
  }

  neh = nhl + (elen - 1);

  if (*neh) return elen;

  return DP_PRET_OK;
}

#ifdef HAVE_LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") gparser = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(int),  /* Index CPU idx */
  .value_size = sizeof(struct gtp_parser),
  .max_entries = 1,
};
#else
struct {
        __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key,         int);
        __type(value,       struct gtp_parser);
        __uint(max_entries, 1);
} gparser SEC(".maps");
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
  "startLine": 460,
  "endLine": 597,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_gtp",
  "developer_inline_comments": [
    {
      "start_line": 447,
      "end_line": 447,
      "text": " Index CPU idx "
    },
    {
      "start_line": 499,
      "end_line": 499,
      "text": " PDU session container is always first "
    },
    {
      "start_line": 544,
      "end_line": 544,
      "text": " Parse maximum GTP_MAX_EXTH  gtp extension headers "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  gparser"
  ],
  "input": [
    "struct parser *p",
    " void *md",
    " void *inp",
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
    "static int __always_inline dp_parse_gtp (struct parser *p, void *md, void *inp, struct xfi *xf)\n",
    "{\n",
    "    int var = 0;\n",
    "    struct gtp_parser *gp;\n",
    "    gp = bpf_map_lookup_elem (& gparser, & var);\n",
    "    if (!gp) {\n",
    "        goto drop;\n",
    "    }\n",
    "    gp->hlen = GTP_HDR_LEN;\n",
    "    gp->gh = DP_TC_PTR (inp);\n",
    "    if (gp->gh + 1 > p->dend) {\n",
    "        goto drop;\n",
    "    }\n",
    "    if (gp->gh->ver != GTP_VER_1) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    if (gp->gh->espn)\n",
    "        gp->hlen += sizeof (struct gtp_v1_ehdr);\n",
    "    xf->tm.tunnel_id = bpf_ntohl (gp->gh->teid);\n",
    "    xf->tm.tun_type = LLB_TUN_GTP;\n",
    "    if (gp->gh->espn & GTP_EXT_FM) {\n",
    "        gp->geh = DP_ADD_PTR (gp->gh, sizeof (struct gtp_v1_hdr));\n",
    "        if (gp->geh + 1 > p->dend) {\n",
    "            goto drop;\n",
    "        }\n",
    "        gp->nh = DP_ADD_PTR (gp->geh, sizeof (struct gtp_v1_ehdr));\n",
    "        if (gp->geh->next_hdr == GTP_NH_PDU_SESS) {\n",
    "            struct gtp_pdu_sess_cmnhdr *pch = DP_TC_PTR (gp->nh);\n",
    "            if (pch + 1 > p->dend) {\n",
    "                goto drop;\n",
    "            }\n",
    "            if (pch->len != 1) {\n",
    "                goto drop;\n",
    "            }\n",
    "            if (pch->pdu_type == GTP_PDU_SESS_UL) {\n",
    "                struct gtp_ul_pdu_sess_hdr *pul = DP_TC_PTR (pch);\n",
    "                if (pul + 1 > p->dend) {\n",
    "                    goto drop;\n",
    "                }\n",
    "                gp->hlen += sizeof (*pul);\n",
    "                xf->qm.qfi = pul->qfi;\n",
    "                gp->nh = pul + 1;\n",
    "                if (pul->next_hdr == 0)\n",
    "                    goto done;\n",
    "            }\n",
    "            else if (pch->pdu_type == GTP_PDU_SESS_DL) {\n",
    "                struct gtp_dl_pdu_sess_hdr *pdl = DP_TC_PTR (pch);\n",
    "                if (pdl + 1 > p->dend) {\n",
    "                    goto drop;\n",
    "                }\n",
    "                gp->hlen += sizeof (*pdl);\n",
    "                xf->qm.qfi = pdl->qfi;\n",
    "                gp->nh = pdl + 1;\n",
    "                if (pdl->next_hdr == 0)\n",
    "                    goto done;\n",
    "            }\n",
    "            else {\n",
    "                goto drop;\n",
    "            }\n",
    "        }\n",
    "        gp->nhl = DP_TC_PTR (gp->nh);\n",
    "        for (var = 0; var < GTP_MAX_EXTH; var++) {\n",
    "            if (gp->nhl + 1 > p->dend) {\n",
    "                goto drop;\n",
    "            }\n",
    "            gp->elen = *(gp->nhl) << 2;\n",
    "            gp->neh = gp->nhl + (gp->elen - 1);\n",
    "            if (gp->neh + 1 > p->dend) {\n",
    "                goto drop;\n",
    "            }\n",
    "            gp->hlen += gp->elen;\n",
    "            if (*(gp->neh) == 0)\n",
    "                break;\n",
    "            gp->nhl = DP_ADD_PTR (gp->nhl, gp->elen);\n",
    "        }\n",
    "        if (var >= GTP_MAX_EXTH) {\n",
    "            goto pass;\n",
    "        }\n",
    "    }\n",
    "done :\n",
    "    gp->gtp_next = DP_ADD_PTR (gp->gh, gp->hlen);\n",
    "    xf->pm.tun_off = DP_DIFF_PTR (gp->gtp_next, DP_PDATA (md));\n",
    "    gp->neh = DP_TC_PTR (gp->gtp_next);\n",
    "    if (gp->neh + 1 > p->dend) {\n",
    "        return 0;\n",
    "    }\n",
    "    var = ((*(gp->neh) & 0xf0) >> 4);\n",
    "    if (var == 4) {\n",
    "        xf->il2m.dl_type = bpf_htons (ETH_P_IP);\n",
    "    }\n",
    "    else if (var == 6) {\n",
    "        xf->il2m.dl_type = bpf_htons (ETH_P_IPV6);\n",
    "    }\n",
    "    else {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    p->inp = 1;\n",
    "    p->skip_l2 = 1;\n",
    "    p->dbegin = gp->gtp_next;\n",
    "    return dp_parse_d1 (p, md, xf);\n",
    "drop :\n",
    "    return DP_PRET_FAIL;\n",
    "pass :\n",
    "    return DP_PRET_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "DP_DIFF_PTR",
    "dp_parse_d1",
    "DP_ADD_PTR",
    "bpf_htons",
    "DP_TC_PTR",
    "bpf_ntohl"
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
dp_parse_gtp(struct parser *p,
             void *md,
             void *inp,
             struct xfi *xf)
{
  int var = 0;
  struct gtp_parser *gp;

  gp = bpf_map_lookup_elem(&gparser, &var);
  if (!gp) {
    goto drop;
  }

  gp->hlen = GTP_HDR_LEN;
  gp->gh = DP_TC_PTR(inp);

  if (gp->gh + 1 > p->dend) {
    goto drop;
  }

  if (gp->gh->ver != GTP_VER_1) {
    return DP_PRET_OK;
  }

  if (gp->gh->espn) gp->hlen += sizeof(struct gtp_v1_ehdr);

  xf->tm.tunnel_id = bpf_ntohl(gp->gh->teid);
  xf->tm.tun_type = LLB_TUN_GTP;

  if (gp->gh->espn & GTP_EXT_FM) {
    gp->geh = DP_ADD_PTR(gp->gh, sizeof(struct gtp_v1_hdr));

    if (gp->geh + 1 > p->dend) {
      goto drop;
    }

    gp->nh = DP_ADD_PTR(gp->geh, sizeof(struct gtp_v1_ehdr));

    /* PDU session container is always first */
    if (gp->geh->next_hdr == GTP_NH_PDU_SESS) {
      struct gtp_pdu_sess_cmnhdr *pch = DP_TC_PTR(gp->nh);

      if (pch + 1 > p->dend) {
        goto drop;
      }

      if (pch->len != 1) {
        goto drop;
      }

      if (pch->pdu_type == GTP_PDU_SESS_UL) {
        struct gtp_ul_pdu_sess_hdr *pul = DP_TC_PTR(pch);

        if (pul + 1 > p->dend) {
          goto drop;
        }

        gp->hlen += sizeof(*pul);
        xf->qm.qfi = pul->qfi;
        gp->nh = pul+1;

        if (pul->next_hdr == 0) goto done;

      } else if (pch->pdu_type == GTP_PDU_SESS_DL) {
        struct gtp_dl_pdu_sess_hdr *pdl = DP_TC_PTR(pch);

        if (pdl + 1 > p->dend) {
          goto drop;
        }

        gp->hlen += sizeof(*pdl);
        xf->qm.qfi = pdl->qfi;
        gp->nh = pdl+1;

        if (pdl->next_hdr == 0) goto done;

      } else {
        goto drop;
      }
    }

    gp->nhl = DP_TC_PTR(gp->nh);

    /* Parse maximum GTP_MAX_EXTH  gtp extension headers */
    for (var = 0; var < GTP_MAX_EXTH; var++) {

      if (gp->nhl + 1 > p->dend) {
        goto drop;
      }

      gp->elen = *(gp->nhl)<<2;

      gp->neh = gp->nhl + (gp->elen - 1);
      if (gp->neh + 1 > p->dend) {
        goto drop;
      }

      gp->hlen += gp->elen;
      if (*(gp->neh) == 0) break;
      gp->nhl = DP_ADD_PTR(gp->nhl, gp->elen);
    }

    if (var >= GTP_MAX_EXTH) {
      goto pass;
    }
  }

done:
  gp->gtp_next = DP_ADD_PTR(gp->gh, gp->hlen);
  xf->pm.tun_off = DP_DIFF_PTR(gp->gtp_next, DP_PDATA(md));

  gp->neh = DP_TC_PTR(gp->gtp_next);
  if (gp->neh + 1 > p->dend) {
    return 0;
  }

  var = ((*(gp->neh) & 0xf0) >> 4);

  if (var == 4) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IP);
  } else if (var == 6) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IPV6);
  } else {
    return DP_PRET_OK;
  }

  p->inp = 1;
  p->skip_l2 = 1;
  p->dbegin = gp->gtp_next;
  return dp_parse_d1(p, md, xf);

drop:
  return DP_PRET_FAIL;

pass:
  return DP_PRET_PASS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 599,
  "endLine": 643,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_outer_udp",
  "developer_inline_comments": [
    {
      "start_line": 641,
      "end_line": 641,
      "text": " Not reached "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
    " void *udp_next",
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
    "static int __always_inline dp_parse_outer_udp (struct parser *p, void *md, void *udp_next, struct xfi *xf)\n",
    "{\n",
    "    struct vxlanhdr *vx;\n",
    "    struct gtp_v1_hdr *gh;\n",
    "    void *dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    void *vx_next;\n",
    "    switch (xf->l34m.dest) {\n",
    "    case bpf_htons (VXLAN_OUDP_DPORT) :\n",
    "        vx = DP_TC_PTR (udp_next);\n",
    "        if (vx + 1 > dend) {\n",
    "            return DP_PRET_FAIL;\n",
    "        }\n",
    "        xf->tm.tunnel_id = (bpf_ntohl (vx->vx_vni)) >> 8 & 0xfffffff;\n",
    "        xf->tm.tun_type = LLB_TUN_VXLAN;\n",
    "        vx_next = vx + 1;\n",
    "        xf->pm.tun_off = DP_DIFF_PTR (vx_next, DP_PDATA (md));\n",
    "        LL_DBG_PRINTK (\"[PRSR] UDP VXLAN %u\\n\", xf->tm.tunnel_id);\n",
    "        p->inp = 1;\n",
    "        p->skip_l2 = 0;\n",
    "        p->dbegin = vx_next;\n",
    "        return dp_parse_d1 (p, md, xf);\n",
    "        break;\n",
    "    case bpf_htons (GTPU_UDP_DPORT) :\n",
    "    case bpf_htons (GTPC_UDP_DPORT) :\n",
    "        gh = DP_TC_PTR (udp_next);\n",
    "        if (gh + 1 > dend) {\n",
    "            return DP_PRET_FAIL;\n",
    "        }\n",
    "        return dp_parse_gtp (p, md, gh, xf);\n",
    "        break;\n",
    "    default :\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_parse_gtp",
    "DP_DIFF_PTR",
    "DP_PDATA",
    "dp_parse_d1",
    "bpf_htons",
    "LL_DBG_PRINTK",
    "DP_PDATA_END",
    "DP_TC_PTR",
    "bpf_ntohl"
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
dp_parse_outer_udp(struct parser *p,
                   void *md,
                   void *udp_next,
                   struct xfi *xf)
{
  struct vxlanhdr *vx;
  struct gtp_v1_hdr *gh; 
  void *dend = DP_TC_PTR(DP_PDATA_END(md)); 
  void *vx_next;

  switch (xf->l34m.dest) {
  case bpf_htons(VXLAN_OUDP_DPORT) :
    vx = DP_TC_PTR(udp_next);
    if (vx + 1 > dend) {
      return DP_PRET_FAIL;
    }

    xf->tm.tunnel_id = (bpf_ntohl(vx->vx_vni)) >> 8 & 0xfffffff;
    xf->tm.tun_type = LLB_TUN_VXLAN;
    vx_next = vx + 1;
    xf->pm.tun_off = DP_DIFF_PTR(vx_next, DP_PDATA(md));

    LL_DBG_PRINTK("[PRSR] UDP VXLAN %u\n", xf->tm.tunnel_id);
    p->inp = 1;
    p->skip_l2 = 0;
    p->dbegin = vx_next;
    return dp_parse_d1(p, md, xf);
    break;
  case bpf_htons(GTPU_UDP_DPORT):
  case bpf_htons(GTPC_UDP_DPORT):
    gh = DP_TC_PTR(udp_next);
    if (gh + 1 > dend) {
      return DP_PRET_FAIL;
    }

    return dp_parse_gtp(p, md, gh, xf);
    break;
  default:
    return DP_PRET_OK;
  }

  /* Not reached */
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
          "Description": "Adjust the address pointed by xdp_md->data_meta by <[ delta ]>(IP: 1) (which can be positive or negative). Note that this operation modifies the address stored in xdp_md->data , so the latter must be loaded only after the helper has been called. The use of xdp_md->data_meta is optional and programs are not required to use it. The rationale is that when the packet is processed with XDP (e. g. as DoS filter) , it is possible to push further meta data along with it before passing to the stack , and to give the guarantee that an ingress eBPF program attached as a TC classifier on the same device can pick this up for further post-processing. Since TC works with socket buffers , it remains possible to set from XDP the mark or priority pointers , or other pointers for the socket buffer. Having this scratch space generic and programmable allows for more flexibility as the user is free to store whatever meta data they need. A call to this helper is susceptible to change the underlying packet buffer. Therefore , at load time , all checks on pointers previously done by the verifier are invalidated and must be performed again , if the helper is used in combination with direct packet access. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_xdp_adjust_meta",
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
  "startLine": 645,
  "endLine": 696,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_llb",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
    " struct xfi *xf"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_xdp_adjust_meta"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline dp_parse_llb (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct ethhdr *eth;\n",
    "    struct llb_ethhdr *llb = DP_TC_PTR (p->dbegin);\n",
    "    LL_DBG_PRINTK (\"[PRSR] LLB \\n\");\n",
    "\n",
    "#ifdef LL_TC_EBPF\n",
    "    return DP_PRET_FAIL;\n",
    "\n",
    "#endif\n",
    "    if (DP_TC_PTR (p->dbegin) + (sizeof (struct ethhdr) + sizeof (*llb)) > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    llb = DP_ADD_PTR (p -> dbegin, sizeof (struct ethhdr));\n",
    "    xf->pm.oport = (llb->oport);\n",
    "    xf->pm.iport = (llb->iport);\n",
    "    eth = DP_ADD_PTR (p -> dbegin, (int) sizeof (struct llb_ethhdr));\n",
    "    memcpy (eth->h_dest, xf->l2m.dl_dst, 6);\n",
    "    memcpy (eth->h_source, xf->l2m.dl_src, 6);\n",
    "    eth->h_proto = llb->ntype;\n",
    "    if (dp_remove_l2 (md, (int) sizeof (*llb))) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "\n",
    "#ifndef LL_TC_EBPF\n",
    "    if (1) {\n",
    "        struct ll_xmdi *xm;\n",
    "        if (bpf_xdp_adjust_meta (md, -(int) sizeof (*xm)) < 0) {\n",
    "            LL_DBG_PRINTK (\"[PRSR] adjust meta fail\\n\");\n",
    "            return DP_PRET_FAIL;\n",
    "        }\n",
    "        p->dbegin = DP_TC_PTR (DP_PDATA (md));\n",
    "        xm = DP_TC_PTR (DP_MDATA (md));\n",
    "        if (xm + 1 > p->dbegin) {\n",
    "            return DP_PRET_FAIL;\n",
    "        }\n",
    "        xm->pi.oport = xf->pm.oport;\n",
    "        xm->pi.iport = xf->pm.iport;\n",
    "        xm->pi.skip = 0;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "dp_remove_l2",
    "DP_ADD_PTR",
    "LL_DBG_PRINTK",
    "DP_MDATA",
    "DP_TC_PTR",
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
dp_parse_llb(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct ethhdr *eth;
  struct llb_ethhdr *llb = DP_TC_PTR(p->dbegin);

  LL_DBG_PRINTK("[PRSR] LLB \n");

#ifdef LL_TC_EBPF
  return DP_PRET_FAIL;
#endif

  if (DP_TC_PTR(p->dbegin) + (sizeof(struct ethhdr) + sizeof(*llb)) > p->dend) {
    return DP_PRET_FAIL;
  }

  llb = DP_ADD_PTR(p->dbegin, sizeof(struct ethhdr));
  xf->pm.oport = (llb->oport);
  xf->pm.iport = (llb->iport);

  eth = DP_ADD_PTR(p->dbegin, (int)sizeof(struct llb_ethhdr));
  memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
  memcpy(eth->h_source, xf->l2m.dl_src, 6);
  eth->h_proto = llb->ntype;

  if (dp_remove_l2(md, (int)sizeof(*llb))) {
    return DP_PRET_FAIL;
  }

#ifndef LL_TC_EBPF
  if (1) {
    struct ll_xmdi *xm;
    if (bpf_xdp_adjust_meta(md, -(int)sizeof(*xm)) < 0) {
      LL_DBG_PRINTK("[PRSR] adjust meta fail\n");
      return DP_PRET_FAIL;
    }

    p->dbegin = DP_TC_PTR(DP_PDATA(md));
    xm = DP_TC_PTR(DP_MDATA(md));
    if (xm + 1 >  p->dbegin) {
      return DP_PRET_FAIL;
    }

    xm->pi.oport = xf->pm.oport;
    xm->pi.iport = xf->pm.iport;
    xm->pi.skip = 0;
  }
#endif
  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 698,
  "endLine": 717,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_udp",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_udp (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct udphdr *udp = DP_TC_PTR (p->dbegin);\n",
    "    if (udp + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    xf->l34m.source = udp->source;\n",
    "    xf->l34m.dest = udp->dest;\n",
    "    if (dp_pkt_is_l2mcbc (xf, md) == 1) {\n",
    "        LLBS_PPLN_TRAP (xf);\n",
    "    }\n",
    "    return dp_parse_outer_udp (p, md, udp + 1, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_pkt_is_l2mcbc",
    "DP_TC_PTR",
    "dp_parse_outer_udp",
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
dp_parse_udp(struct parser *p,
             void *md,
             struct xfi *xf)
{
  struct udphdr *udp = DP_TC_PTR(p->dbegin);
  
  if (udp + 1 > p->dend) {
    return DP_PRET_OK;
  }

  xf->l34m.source = udp->source;
  xf->l34m.dest = udp->dest;

  if (dp_pkt_is_l2mcbc(xf, md) == 1) {
    LLBS_PPLN_TRAP(xf);
  }

  return dp_parse_outer_udp(p, md, udp + 1, xf);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 719,
  "endLine": 748,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_ipip",
  "developer_inline_comments": [
    {
      "start_line": 741,
      "end_line": 741,
      "text": " No real use"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_ipip (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct iphdr *ip = DP_TC_PTR (p->dbegin);\n",
    "    int iphl = ip->ihl << 2;\n",
    "    if (ip + 1 > p->dend) {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    if (DP_ADD_PTR (ip, iphl) > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    if (ip->version == 4) {\n",
    "        xf->il2m.dl_type = bpf_htons (ETH_P_IP);\n",
    "    }\n",
    "    else {\n",
    "        return DP_PRET_OK;\n",
    "    }\n",
    "    xf->tm.tunnel_id = 1;\n",
    "    xf->tm.tun_type = LLB_TUN_IPIP;\n",
    "    p->inp = 1;\n",
    "    p->skip_l2 = 1;\n",
    "    p->dbegin = ip;\n",
    "    return dp_parse_d1 (p, md, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_parse_d1",
    "DP_TC_PTR",
    "DP_ADD_PTR",
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
dp_parse_ipip(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct iphdr *ip = DP_TC_PTR(p->dbegin);
  int iphl = ip->ihl << 2;
  
  if (ip + 1 > p->dend) {
    return DP_PRET_OK;
  }

  if (DP_ADD_PTR(ip, iphl) > p->dend) {
    return DP_PRET_FAIL;
  }

  if (ip->version == 4) {
    xf->il2m.dl_type = bpf_htons(ETH_P_IP);
  } else {
    return DP_PRET_OK;
  }

  xf->tm.tunnel_id = 1; // No real use
  xf->tm.tun_type = LLB_TUN_IPIP;

  p->inp = 1;
  p->skip_l2 = 1;
  p->dbegin = ip;
  return dp_parse_d1(p, md, xf);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 750,
  "endLine": 805,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_ipv4",
  "developer_inline_comments": [
    {
      "start_line": 775,
      "end_line": 779,
      "text": " Earlier we used to have the following check here :   * !ip_is_fragment(iph) || ip_is_first_fragment(iph))   * But it seems to be unncessary as proper bound checking   * is already taken care by eBPF verifier   "
    },
    {
      "start_line": 795,
      "end_line": 795,
      "text": " Let xfrm handle it "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_ipv4 (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct iphdr *iph = DP_TC_PTR (p->dbegin);\n",
    "    int iphl = iph->ihl << 2;\n",
    "    if (iph + 1 > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    if (DP_ADD_PTR (iph, iphl) > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    xf->pm.l3_len = bpf_ntohs (iph->tot_len);\n",
    "    xf->pm.l3_plen = xf->pm.l3_len - iphl;\n",
    "    xf->l34m.valid = 1;\n",
    "    xf->l34m.tos = iph->tos & 0xfc;\n",
    "    xf->l34m.nw_proto = iph->protocol;\n",
    "    xf->l34m.saddr4 = iph->saddr;\n",
    "    xf->l34m.daddr4 = iph->daddr;\n",
    "    xf->pm.l4_off = DP_DIFF_PTR (DP_ADD_PTR (iph, iphl), p->start);\n",
    "    p->dbegin = DP_ADD_PTR (iph, iphl);\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        return dp_parse_tcp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_UDP) {\n",
    "        return dp_parse_udp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_SCTP) {\n",
    "        return dp_parse_sctp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ICMP) {\n",
    "        return dp_parse_icmp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_IPIP) {\n",
    "        return dp_parse_ipip (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ESP || xf->l34m.nw_proto == IPPROTO_AH) {\n",
    "        return DP_PRET_PASS;\n",
    "    }\n",
    "    if (ip_is_fragment (iph)) {\n",
    "        xf->l34m.source = 0;\n",
    "        xf->l34m.dest = 0;\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_DIFF_PTR",
    "ip_is_fragment",
    "dp_parse_ipip",
    "DP_ADD_PTR",
    "dp_parse_tcp",
    "bpf_ntohs",
    "DP_TC_PTR",
    "dp_parse_sctp",
    "dp_parse_udp",
    "dp_parse_icmp"
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
dp_parse_ipv4(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct iphdr *iph = DP_TC_PTR(p->dbegin);
  int iphl = iph->ihl << 2;

  if (iph + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (DP_ADD_PTR(iph, iphl) > p->dend) {
    return DP_PRET_FAIL;
  }

  xf->pm.l3_len = bpf_ntohs(iph->tot_len);
  xf->pm.l3_plen = xf->pm.l3_len - iphl;

  xf->l34m.valid = 1;
  xf->l34m.tos = iph->tos & 0xfc;
  xf->l34m.nw_proto = iph->protocol;
  xf->l34m.saddr4 = iph->saddr;
  xf->l34m.daddr4 = iph->daddr;

  /* Earlier we used to have the following check here :
   * !ip_is_fragment(iph) || ip_is_first_fragment(iph))
   * But it seems to be unncessary as proper bound checking
   * is already taken care by eBPF verifier
   */
  xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(iph, iphl), p->start);
  p->dbegin = DP_ADD_PTR(iph, iphl);

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    return dp_parse_tcp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
    return dp_parse_udp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP) {
    return dp_parse_sctp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP) {
    return dp_parse_icmp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_IPIP) {
    return dp_parse_ipip(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ESP ||
             xf->l34m.nw_proto == IPPROTO_AH) {
    /* Let xfrm handle it */
    return DP_PRET_PASS;
  }

  if (ip_is_fragment(iph)) {
    xf->l34m.source = 0;
    xf->l34m.dest = 0;
  }
  
  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 807,
  "endLine": 850,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_ipv6",
  "developer_inline_comments": [
    {
      "start_line": 846,
      "end_line": 846,
      "text": " Let xfrm handle it "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct parser *p",
    " void *md",
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
    "static int __always_inline dp_parse_ipv6 (struct parser *p, void *md, struct xfi *xf)\n",
    "{\n",
    "    struct ipv6hdr *ip6 = DP_TC_PTR (p->dbegin);\n",
    "    if (ip6 + 1 > p->dend) {\n",
    "        return DP_PRET_FAIL;\n",
    "    }\n",
    "    if (ipv6_addr_is_multicast (&ip6->daddr) || ipv6_addr_is_multicast (&ip6->saddr)) {\n",
    "        return DP_PRET_PASS;\n",
    "    }\n",
    "    xf->pm.l3_plen = bpf_ntohs (ip6->payload_len);\n",
    "    xf->pm.l3_len = xf->pm.l3_plen + sizeof (*ip6);\n",
    "    xf->l34m.valid = 1;\n",
    "    xf->l34m.tos = ((ip6->priority << 4) | ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;\n",
    "    xf->l34m.nw_proto = ip6->nexthdr;\n",
    "    memcpy (&xf->l34m.saddr, &ip6->saddr, sizeof (ip6->saddr));\n",
    "    memcpy (&xf->l34m.daddr, &ip6->daddr, sizeof (ip6->daddr));\n",
    "    xf->pm.l4_off = DP_DIFF_PTR (DP_ADD_PTR (ip6, sizeof (*ip6)), p->start);\n",
    "    p->dbegin = DP_ADD_PTR (ip6, sizeof (*ip6));\n",
    "    if (xf->l34m.nw_proto == IPPROTO_TCP) {\n",
    "        return dp_parse_tcp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_UDP) {\n",
    "        return dp_parse_udp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_SCTP) {\n",
    "        return dp_parse_sctp (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {\n",
    "        return dp_parse_icmp6 (p, md, xf);\n",
    "    }\n",
    "    else if (xf->l34m.nw_proto == IPPROTO_ESP || xf->l34m.nw_proto == IPPROTO_AH) {\n",
    "        return DP_PRET_PASS;\n",
    "    }\n",
    "    return DP_PRET_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_DIFF_PTR",
    "DP_ADD_PTR",
    "dp_parse_tcp",
    "dp_parse_icmp6",
    "bpf_ntohs",
    "DP_TC_PTR",
    "dp_parse_sctp",
    "dp_parse_udp",
    "ipv6_addr_is_multicast",
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
dp_parse_ipv6(struct parser *p,
              void *md,
              struct xfi *xf)
{
  struct ipv6hdr *ip6 = DP_TC_PTR(p->dbegin);

  if (ip6 + 1 > p->dend) {
    return DP_PRET_FAIL;
  }

  if (ipv6_addr_is_multicast(&ip6->daddr) ||
      ipv6_addr_is_multicast(&ip6->saddr)) {
    return DP_PRET_PASS;
  }

  xf->pm.l3_plen = bpf_ntohs(ip6->payload_len);
  xf->pm.l3_len =  xf->pm.l3_plen + sizeof(*ip6);

  xf->l34m.valid = 1;
  xf->l34m.tos = ((ip6->priority << 4) |
               ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
  xf->l34m.nw_proto = ip6->nexthdr;
  memcpy(&xf->l34m.saddr, &ip6->saddr, sizeof(ip6->saddr));
  memcpy(&xf->l34m.daddr, &ip6->daddr, sizeof(ip6->daddr));

  xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(ip6, sizeof(*ip6)), p->start);
  p->dbegin = DP_ADD_PTR(ip6, sizeof(*ip6));

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    return dp_parse_tcp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
    return dp_parse_udp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_SCTP) {
    return dp_parse_sctp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {
    return dp_parse_icmp6(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ESP ||
             xf->l34m.nw_proto == IPPROTO_AH) {
    /* Let xfrm handle it */
    return DP_PRET_PASS;
  }
  return DP_PRET_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 852,
  "endLine": 923,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_parse_d0",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *md",
    " struct xfi *xf",
    " int skip_v6"
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
    "static int __always_inline dp_parse_d0 (void *md, struct xfi *xf, int skip_v6)\n",
    "{\n",
    "    int ret = 0;\n",
    "    struct parser p;\n",
    "    p.inp = 0;\n",
    "    p.skip_l2 = 0;\n",
    "    p.skip_v6 = skip_v6;\n",
    "    p.start = DP_TC_PTR (DP_PDATA (md));\n",
    "    p.dbegin = DP_TC_PTR (p.start);\n",
    "    p.dend = DP_TC_PTR (DP_PDATA_END (md));\n",
    "    xf->pm.py_bytes = DP_DIFF_PTR (p.dend, p.dbegin);\n",
    "    if ((ret = dp_parse_eth (&p, md, xf))) {\n",
    "        goto handle_excp;\n",
    "    }\n",
    "    if (DP_NEED_MIRR (md)) {\n",
    "        xf->pm.mirr = DP_GET_MIRR (md);\n",
    "        LL_DBG_PRINTK (\"[PRSR] LB %d %d\\n\", xf->pm.mirr, DP_IFI (md));\n",
    "    }\n",
    "\n",
    "#ifdef HAVE_DP_IPC\n",
    "    if (xdp2tc_has_xmd (md, xf)) {\n",
    "        return 1;\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if ((ret = dp_parse_vlan (&p, md, xf))) {\n",
    "        goto handle_excp;\n",
    "    }\n",
    "    xf->pm.l3_off = DP_DIFF_PTR (p.dbegin, p.start);\n",
    "    if (xf->l2m.dl_type == bpf_htons (ETH_P_ARP)) {\n",
    "        ret = dp_parse_arp (& p, md, xf);\n",
    "    }\n",
    "    else if (xf->l2m.dl_type == bpf_htons (ETH_P_IP)) {\n",
    "        ret = dp_parse_ipv4 (& p, md, xf);\n",
    "    }\n",
    "    else if (xf->l2m.dl_type == bpf_htons (ETH_P_IPV6)) {\n",
    "        if (p.skip_v6 == 1) {\n",
    "            return 0;\n",
    "        }\n",
    "        ret = dp_parse_ipv6 (& p, md, xf);\n",
    "    }\n",
    "    else if (xf->l2m.dl_type == bpf_htons (ETH_TYPE_LLB)) {\n",
    "        ret = dp_parse_llb (& p, md, xf);\n",
    "    }\n",
    "    if (ret != 0) {\n",
    "        goto handle_excp;\n",
    "    }\n",
    "    if (dp_pkt_is_l2mcbc (xf, md) == 1) {\n",
    "        LLBS_PPLN_PASS (xf);\n",
    "    }\n",
    "    return 0;\n",
    "handle_excp :\n",
    "    if (ret > DP_PRET_OK) {\n",
    "        if (ret == DP_PRET_PASS) {\n",
    "            LLBS_PPLN_PASS (xf);\n",
    "        }\n",
    "        else {\n",
    "            LLBS_PPLN_TRAPC (xf, LLB_PIPE_RC_PARSER);\n",
    "        }\n",
    "    }\n",
    "    else if (ret < DP_PRET_OK) {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_parse_ipv4",
    "dp_parse_ipv6",
    "DP_GET_MIRR",
    "dp_parse_arp",
    "DP_PDATA",
    "LL_DBG_PRINTK",
    "dp_parse_eth",
    "DP_TC_PTR",
    "dp_parse_llb",
    "DP_PDATA_END",
    "LLBS_PPLN_DROP",
    "LLBS_PPLN_TRAPC",
    "LLBS_PPLN_PASS",
    "dp_pkt_is_l2mcbc",
    "dp_parse_vlan",
    "xdp2tc_has_xmd",
    "DP_DIFF_PTR",
    "DP_IFI",
    "bpf_htons",
    "DP_NEED_MIRR"
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
dp_parse_d0(void *md,
            struct xfi *xf,
            int skip_v6)
{
  int ret = 0;
  struct parser p;

  p.inp = 0;
  p.skip_l2 = 0;
  p.skip_v6 = skip_v6;
  p.start = DP_TC_PTR(DP_PDATA(md));
  p.dbegin = DP_TC_PTR(p.start);
  p.dend = DP_TC_PTR(DP_PDATA_END(md));
  xf->pm.py_bytes = DP_DIFF_PTR(p.dend, p.dbegin);

  if ((ret = dp_parse_eth(&p, md, xf))) {
    goto handle_excp;
  }

  if (DP_NEED_MIRR(md)) {
    xf->pm.mirr = DP_GET_MIRR(md);
    LL_DBG_PRINTK("[PRSR] LB %d %d\n", xf->pm.mirr, DP_IFI(md));
  }

#ifdef HAVE_DP_IPC
  if (xdp2tc_has_xmd(md, xf)) {
    return 1;
  }
#endif

  if ((ret = dp_parse_vlan(&p, md, xf))) {
    goto handle_excp;
  }

  xf->pm.l3_off = DP_DIFF_PTR(p.dbegin, p.start);

  if (xf->l2m.dl_type == bpf_htons(ETH_P_ARP)) {
    ret = dp_parse_arp(&p, md, xf);
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IP)) {
    ret = dp_parse_ipv4(&p, md, xf);
  } else if (xf->l2m.dl_type == bpf_htons(ETH_P_IPV6)) {
    if (p.skip_v6 == 1) {
      return 0;
    }
    ret = dp_parse_ipv6(&p, md, xf);
  } else if (xf->l2m.dl_type == bpf_htons(ETH_TYPE_LLB)) {
    ret = dp_parse_llb(&p, md, xf);
  }

  if (ret != 0) {
    goto handle_excp;
  }

  if (dp_pkt_is_l2mcbc(xf, md) == 1) {
    LLBS_PPLN_PASS(xf);
  }

  return 0;

handle_excp:
  if (ret > DP_PRET_OK) {
    if (ret == DP_PRET_PASS) {
      LLBS_PPLN_PASS(xf);
    } else {
      LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_PARSER);
    }
  } else if (ret < DP_PRET_OK) {
    LLBS_PPLN_DROP(xf);
  }
  return ret;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 925,
  "endLine": 987,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_unparse_packet_always_slow",
  "developer_inline_comments": [
    {
      "start_line": 930,
      "end_line": 930,
      "text": " If packet is v6 "
    },
    {
      "start_line": 937,
      "end_line": 937,
      "text": " TODO "
    },
    {
      "start_line": 940,
      "end_line": 940,
      "text": " If packet is v4 "
    },
    {
      "start_line": 959,
      "end_line": 959,
      "text": " If packet is v6 "
    },
    {
      "start_line": 970,
      "end_line": 970,
      "text": " If packet is v4 "
    },
    {
      "start_line": 976,
      "end_line": 976,
      "text": " TODO "
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
    "static int __always_inline dp_unparse_packet_always_slow (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    if (xf->pm.nf & LLB_NAT_SRC) {\n",
    "        LL_DBG_PRINTK (\"[DEPR] LL_SNAT 0x%lx:%x\\n\", xf->nm.nxip4, xf->nm.nxport);\n",
    "        if (xf->l2m.dl_type == bpf_ntohs (ETH_P_IPV6)) {\n",
    "            if (xf->nm.nv6) {\n",
    "                if (dp_do_snat6 (ctx, xf, xf->nm.nxip, xf->nm.nxport) != 0) {\n",
    "                    return DP_DROP;\n",
    "                }\n",
    "            }\n",
    "            else {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            if (xf->nm.nv6 == 0) {\n",
    "                if (dp_do_snat (ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {\n",
    "                    return DP_DROP;\n",
    "                }\n",
    "            }\n",
    "            else {\n",
    "                if (dp_do_snat46 (ctx, xf) != 0) {\n",
    "                    return DP_DROP;\n",
    "                }\n",
    "                if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) {\n",
    "                    xf->pm.oport = xf->pm.iport;\n",
    "                    return dp_rewire_port (&tx_intf_map, xf);\n",
    "                }\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else if (xf->pm.nf & LLB_NAT_DST) {\n",
    "        LL_DBG_PRINTK (\"[DEPR] LL_DNAT 0x%x\\n\", xf->nm.nxip4, xf->nm.nxport);\n",
    "        if (xf->l2m.dl_type == bpf_ntohs (ETH_P_IPV6)) {\n",
    "            if (xf->nm.nv6 == 1) {\n",
    "                if (dp_do_dnat6 (ctx, xf, xf->nm.nxip, xf->nm.nxport) != 0) {\n",
    "                    return DP_DROP;\n",
    "                }\n",
    "            }\n",
    "            else {\n",
    "                if (dp_do_dnat64 (ctx, xf)) {\n",
    "                    return DP_DROP;\n",
    "                }\n",
    "            }\n",
    "        }\n",
    "        else {\n",
    "            if (xf->nm.nv6 == 0) {\n",
    "                if (dp_do_dnat (ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {\n",
    "                    return DP_DROP;\n",
    "                }\n",
    "            }\n",
    "            else {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    xf->pm.nf = 0;\n",
    "    RETURN_TO_MP_OUT ();\n",
    "    return DP_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "RETURN_TO_MP_OUT",
    "dp_do_snat46",
    "dp_do_dnat64",
    "dp_do_snat",
    "LL_DBG_PRINTK",
    "bpf_ntohs",
    "dp_do_dnat6",
    "dp_do_snat6",
    "dp_do_dnat",
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
dp_unparse_packet_always_slow(void *ctx,  struct xfi *xf)
{
  if (xf->pm.nf & LLB_NAT_SRC) {
    LL_DBG_PRINTK("[DEPR] LL_SNAT 0x%lx:%x\n", xf->nm.nxip4, xf->nm.nxport);
    /* If packet is v6 */
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
        if (xf->nm.nv6) {
          if (dp_do_snat6(ctx, xf, xf->nm.nxip, xf->nm.nxport) != 0) {
             return DP_DROP;
          }
        } else {
          /* TODO */
          return DP_DROP;
        }
    } else { /* If packet is v4 */

      if (xf->nm.nv6 == 0) {
        if (dp_do_snat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
          return DP_DROP;
        }
      } else {
        if (dp_do_snat46(ctx, xf) != 0) {
          return DP_DROP;
        }
        if (xf->pm.pipe_act & (LLB_PIPE_TRAP | LLB_PIPE_PASS)) {
          xf->pm.oport = xf->pm.iport;
          return dp_rewire_port(&tx_intf_map, xf);
        }
      }
    }
  } else if (xf->pm.nf & LLB_NAT_DST) {
    LL_DBG_PRINTK("[DEPR] LL_DNAT 0x%x\n", xf->nm.nxip4, xf->nm.nxport);

    /* If packet is v6 */
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
      if (xf->nm.nv6 == 1) {
        if (dp_do_dnat6(ctx, xf, xf->nm.nxip, xf->nm.nxport) != 0) {
          return DP_DROP;
        }
      } else {
        if (dp_do_dnat64(ctx, xf)) {
          return DP_DROP;
        }
      }
    } else { /* If packet is v4 */
      if (xf->nm.nv6 == 0) {
        if (dp_do_dnat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
          return DP_DROP;
        }
      } else {
          /* TODO */
          return DP_DROP;
      }
    }
  }

  xf->pm.nf = 0;

  RETURN_TO_MP_OUT();

  return DP_DROP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 989,
  "endLine": 1036,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_unparse_packet_always",
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
    "static int __always_inline dp_unparse_packet_always (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    if (xf->pm.nf & LLB_NAT_SRC && xf->nm.dsr == 0) {\n",
    "        LL_DBG_PRINTK (\"[DEPR] LL_SNAT 0x%lx:%x\\n\", xf->nm.nxip4, xf->nm.nxport);\n",
    "        if (xf->l2m.dl_type == bpf_ntohs (ETH_P_IPV6) || xf->nm.nv6) {\n",
    "            dp_sunp_tcall (ctx, xf);\n",
    "        }\n",
    "        else {\n",
    "            if (dp_do_snat (ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else if (xf->pm.nf & LLB_NAT_DST && xf->nm.dsr == 0) {\n",
    "        LL_DBG_PRINTK (\"[DEPR] LL_DNAT 0x%x\\n\", xf->nm.nxip4, xf->nm.nxport);\n",
    "        if (xf->l2m.dl_type == bpf_ntohs (ETH_P_IPV6)) {\n",
    "            dp_sunp_tcall (ctx, xf);\n",
    "        }\n",
    "        else {\n",
    "            if (dp_do_dnat (ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (xf->tm.tun_decap) {\n",
    "        if (xf->tm.tun_type == LLB_TUN_GTP) {\n",
    "            LL_DBG_PRINTK (\"[DEPR] LL STRIP-GTP\\n\");\n",
    "            if (dp_do_strip_gtp (ctx, xf, xf->pm.tun_off) != 0) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else if (xf->tm.new_tunnel_id) {\n",
    "        if (xf->tm.tun_type == LLB_TUN_GTP) {\n",
    "            if (dp_do_ins_gtp (ctx, xf, xf->tm.tun_rip, xf->tm.tun_sip, xf->tm.new_tunnel_id, xf->qm.qfi, 1)) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "LL_DBG_PRINTK",
    "dp_do_strip_gtp",
    "bpf_ntohs",
    "dp_sunp_tcall",
    "dp_do_ins_gtp",
    "dp_do_snat",
    "dp_do_dnat"
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
dp_unparse_packet_always(void *ctx,  struct xfi *xf)
{

  if (xf->pm.nf & LLB_NAT_SRC && xf->nm.dsr == 0) {
    LL_DBG_PRINTK("[DEPR] LL_SNAT 0x%lx:%x\n",
                 xf->nm.nxip4, xf->nm.nxport);
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6) || xf->nm.nv6) {
      dp_sunp_tcall(ctx, xf);
    } else {
      if (dp_do_snat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->pm.nf & LLB_NAT_DST && xf->nm.dsr == 0) {
    LL_DBG_PRINTK("[DEPR] LL_DNAT 0x%x\n",
                  xf->nm.nxip4, xf->nm.nxport);
    if (xf->l2m.dl_type == bpf_ntohs(ETH_P_IPV6)) {
      dp_sunp_tcall(ctx, xf);
    } else {
      if (dp_do_dnat(ctx, xf, xf->nm.nxip4, xf->nm.nxport) != 0) {
        return DP_DROP;
      }
    }
  }

  if (xf->tm.tun_decap) {
    if (xf->tm.tun_type == LLB_TUN_GTP) {
      LL_DBG_PRINTK("[DEPR] LL STRIP-GTP\n");
      if (dp_do_strip_gtp(ctx, xf, xf->pm.tun_off) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->tm.new_tunnel_id) {
    if (xf->tm.tun_type == LLB_TUN_GTP) {
      if (dp_do_ins_gtp(ctx, xf,
                        xf->tm.tun_rip,
                        xf->tm.tun_sip,
                        xf->tm.new_tunnel_id,
                        xf->qm.qfi,
                        1)) {
        return DP_DROP;
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
  "startLine": 1038,
  "endLine": 1078,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_compose.c",
  "funcName": "dp_unparse_packet",
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
    "static int __always_inline dp_unparse_packet (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    if (xf->tm.tun_decap) {\n",
    "        if (xf->tm.tun_type == LLB_TUN_VXLAN) {\n",
    "            LL_DBG_PRINTK (\"[DEPR] LL STRIP-VXLAN\\n\");\n",
    "            if (dp_do_strip_vxlan (ctx, xf, xf->pm.tun_off) != 0) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "        else if (xf->tm.tun_type == LLB_TUN_IPIP) {\n",
    "            LL_DBG_PRINTK (\"[DEPR] LL STRIP-IPIP\\n\");\n",
    "            if (dp_do_strip_ipip (ctx, xf) != 0) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else if (xf->tm.new_tunnel_id) {\n",
    "        LL_DBG_PRINTK (\"[DEPR] LL_NEW-TUN 0x%x\\n\", bpf_ntohl (xf->tm.new_tunnel_id));\n",
    "        if (xf->tm.tun_type == LLB_TUN_VXLAN) {\n",
    "            if (dp_do_ins_vxlan (ctx, xf, xf->tm.tun_rip, xf->tm.tun_sip, xf->tm.new_tunnel_id, 1)) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "        else if (xf->tm.tun_type == LLB_TUN_IPIP) {\n",
    "            LL_DBG_PRINTK (\"[DEPR] LL_NEW-IPTUN 0x%x\\n\", bpf_ntohl (xf->tm.new_tunnel_id));\n",
    "            if (dp_do_ins_ipip (ctx, xf, xf->tm.tun_rip, xf->tm.tun_sip, xf->tm.new_tunnel_id, 1)) {\n",
    "                return DP_DROP;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    return dp_do_out_vlan (ctx, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_ins_ipip",
    "dp_do_out_vlan",
    "LL_DBG_PRINTK",
    "dp_do_strip_ipip",
    "dp_do_ins_vxlan",
    "bpf_ntohl",
    "dp_do_strip_vxlan"
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
dp_unparse_packet(void *ctx,  struct xfi *xf)
{
  if (xf->tm.tun_decap) {
    if (xf->tm.tun_type == LLB_TUN_VXLAN) {
      LL_DBG_PRINTK("[DEPR] LL STRIP-VXLAN\n");
      if (dp_do_strip_vxlan(ctx, xf, xf->pm.tun_off) != 0) {
        return DP_DROP;
      }
    } else if (xf->tm.tun_type == LLB_TUN_IPIP) {
      LL_DBG_PRINTK("[DEPR] LL STRIP-IPIP\n");
      if (dp_do_strip_ipip(ctx, xf) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->tm.new_tunnel_id) {
    LL_DBG_PRINTK("[DEPR] LL_NEW-TUN 0x%x\n",
                  bpf_ntohl(xf->tm.new_tunnel_id));
    if (xf->tm.tun_type == LLB_TUN_VXLAN) {
      if (dp_do_ins_vxlan(ctx, xf,
                          xf->tm.tun_rip,
                          xf->tm.tun_sip,
                          xf->tm.new_tunnel_id,
                          1)) {
        return DP_DROP;
      }
    } else if (xf->tm.tun_type == LLB_TUN_IPIP) {
      LL_DBG_PRINTK("[DEPR] LL_NEW-IPTUN 0x%x\n",
                  bpf_ntohl(xf->tm.new_tunnel_id));
      if (dp_do_ins_ipip(ctx, xf,
                         xf->tm.tun_rip,
                         xf->tm.tun_sip,
                         xf->tm.new_tunnel_id,
                         1)) {
        return DP_DROP;
      }
    }
  }

  return dp_do_out_vlan(ctx, xf);
}
