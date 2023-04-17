/*
 *  llb_kern_fw.c: LoxiLB Kernel eBPF firewall Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_MAX_LOOPS_PER_FWLKUP (400)

#define RETURN_TO_MP() bpf_tail_call(ctx, &pgm_tbl, LLB_DP_CT_PGM_ID)

#define PDI_PKEY_EQ(v1, v2)                             \
  (((PDI_MATCH(&(v1)->dest, &(v2)->dest)))        &&    \
  ((PDI_MATCH(&(v1)->source, &(v2)->source)))     &&    \
  ((PDI_RMATCH(&(v1)->dport, &(v2)->dport)))      &&    \
  ((PDI_RMATCH(&(v1)->sport, &(v2)->sport)))      &&    \
  ((PDI_MATCH(&(v1)->inport, &(v2)->inport)))     &&    \
  ((PDI_MATCH(&(v1)->zone, &(v2)->zone)))         &&    \
  ((PDI_MATCH(&(v1)->protocol, &(v2)->protocol))) &&    \
  ((PDI_MATCH(&(v1)->bd, &(v2)->bd))))


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
  "startLine": 23,
  "endLine": 128,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_fw.c",
  "funcName": "dp_do_fw4_main",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_fw.c: LoxiLB Kernel eBPF firewall Implementation *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 60,
      "end_line": 60,
      "text": " End of lookup "
    },
    {
      "start_line": 77,
      "end_line": 77,
      "text": " End of lookup "
    },
    {
      "start_line": 85,
      "end_line": 85,
      "text": " No match in this iteration "
    },
    {
      "start_line": 89,
      "end_line": 89,
      "text": " End of lookup "
    },
    {
      "start_line": 99,
      "end_line": 99,
      "text": " This condition should never hit "
    },
    {
      "start_line": 116,
      "end_line": 116,
      "text": " Same for DP_SET_DROP "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  fw_v4_map"
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
    "static int __always_inline dp_do_fw4_main (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    __u32 idx = 0;\n",
    "    int i = 0;\n",
    "    struct dp_fwv4_ent *fwe;\n",
    "    struct pdi_key key;\n",
    "    struct dp_fwv4_tact *act = NULL;\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    PDI_VAL_INIT (&key.inport, xf->pm.iport);\n",
    "    PDI_VAL_INIT (&key.zone, xf->pm.zone);\n",
    "    PDI_VAL_INIT (&key.bd, xf->pm.bd);\n",
    "    PDI_VAL_INIT (&key.dest, bpf_ntohl (xf->l34m.daddr4));\n",
    "    PDI_VAL_INIT (&key.source, bpf_ntohl (xf->l34m.saddr4));\n",
    "    PDI_RVAL_INIT (&key.dport, bpf_htons (xf->l34m.dest));\n",
    "    PDI_RVAL_INIT (&key.sport, bpf_htons (xf->l34m.source));\n",
    "    PDI_VAL_INIT (&key.protocol, xf->l34m.nw_proto);\n",
    "    LL_DBG_PRINTK (\"[FW4] -- Lookup\\n\");\n",
    "    LL_DBG_PRINTK (\"[FW4] key-sz %d\\n\", sizeof (key));\n",
    "    LL_DBG_PRINTK (\"[FW4] port %x\\n\", key.inport);\n",
    "    LL_DBG_PRINTK (\"[FW4] daddr %x\\n\", key.dest);\n",
    "    LL_DBG_PRINTK (\"[FW4] saddr %d\\n\", key.source);\n",
    "    LL_DBG_PRINTK (\"[FW4] sport %d\\n\", key.sport);\n",
    "    LL_DBG_PRINTK (\"[FW4] dport %d\\n\", key.dport);\n",
    "    LL_DBG_PRINTK (\"[FW4] l4proto %d\\n\", key.protocol);\n",
    "    xf->pm.table_id = LL_DP_FW4_MAP;\n",
    "    idx = xf->pm.fw_lid;\n",
    "    for (i = 0; i < DP_MAX_LOOPS_PER_FWLKUP; i++) {\n",
    "        fwe = bpf_map_lookup_elem (& fw_v4_map, & idx);\n",
    "        if (!fwe) {\n",
    "            LL_DBG_PRINTK (\"[FW4] miss\");\n",
    "            xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;\n",
    "            RETURN_TO_MP ();\n",
    "            return DP_DROP;\n",
    "        }\n",
    "        else {\n",
    "            if (idx == 0) {\n",
    "                xf->pm.fw_mid = fwe->k.nr.val;\n",
    "            }\n",
    "            else if (i + xf->pm.fw_lid >= xf->pm.fw_mid) {\n",
    "                i = DP_MAX_LOOPS_PER_FWLKUP;\n",
    "                break;\n",
    "            }\n",
    "            idx++;\n",
    "            if (fwe->k.zone.val != 0 && PDI_PKEY_EQ (&key, &fwe->k)) {\n",
    "                xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;\n",
    "                break;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (i >= DP_MAX_LOOPS_PER_FWLKUP) {\n",
    "        xf->pm.fw_lid += DP_MAX_LOOPS_PER_FWLKUP;\n",
    "        if (xf->pm.fw_lid >= LLB_FW4_MAP_ENTRIES || xf->pm.fw_lid > xf->pm.fw_mid) {\n",
    "            xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;\n",
    "        }\n",
    "        LL_DBG_PRINTK (\"[FW4] done\");\n",
    "        RETURN_TO_MP ();\n",
    "        return DP_DROP;\n",
    "    }\n",
    "    xf->pm.phit |= LLB_DP_FW_HIT;\n",
    "    if (!fwe)\n",
    "        return 0;\n",
    "    act = &fwe->fwa;\n",
    "    xf->pm.dp_mark = act->ca.mark;\n",
    "    xf->pm.dp_rec = act->ca.record;\n",
    "    if (act->ca.act_type == DP_SET_NOP) {\n",
    "        goto done;\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_RDR_PORT) {\n",
    "        struct dp_rdr_act *ar = &act->port_act;\n",
    "        LLBS_PPLN_RDR_PRIO (xf);\n",
    "        xf->pm.oport = ar->oport;\n",
    "    }\n",
    "    else if (act->ca.act_type == DP_SET_TOCP) {\n",
    "        LLBS_PPLN_TRAPC (xf, LLB_PIPE_RC_FW_RDR);\n",
    "    }\n",
    "    else {\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    xf->pm.phit |= LLB_DP_RES_HIT;\n",
    "done :\n",
    "    dp_do_map_stats (ctx, xf, LL_DP_FW4_STATS_MAP, act->ca.cidx);\n",
    "    xf->pm.fw_rid = act->ca.cidx;\n",
    "    RETURN_TO_MP ();\n",
    "    return DP_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP",
    "LLBS_PPLN_TRAPC",
    "PDI_VAL_INIT",
    "memset",
    "bpf_htons",
    "dp_do_map_stats",
    "LL_DBG_PRINTK",
    "LLBS_PPLN_RDR_PRIO",
    "RETURN_TO_MP",
    "PDI_PKEY_EQ",
    "bpf_ntohl",
    "PDI_RVAL_INIT"
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
dp_do_fw4_main(void *ctx, struct xfi *xf)
{
  __u32 idx = 0;
  int i = 0;
  struct dp_fwv4_ent *fwe;
  struct pdi_key key;
  struct dp_fwv4_tact *act = NULL;

  memset(&key, 0, sizeof(key));
  PDI_VAL_INIT(&key.inport, xf->pm.iport);
  PDI_VAL_INIT(&key.zone, xf->pm.zone);
  PDI_VAL_INIT(&key.bd, xf->pm.bd);
  PDI_VAL_INIT(&key.dest, bpf_ntohl(xf->l34m.daddr4));
  PDI_VAL_INIT(&key.source, bpf_ntohl(xf->l34m.saddr4));
  PDI_RVAL_INIT(&key.dport, bpf_htons(xf->l34m.dest));
  PDI_RVAL_INIT(&key.sport, bpf_htons(xf->l34m.source));
  PDI_VAL_INIT(&key.protocol, xf->l34m.nw_proto);

  LL_DBG_PRINTK("[FW4] -- Lookup\n");
  LL_DBG_PRINTK("[FW4] key-sz %d\n", sizeof(key));
  LL_DBG_PRINTK("[FW4] port %x\n", key.inport);
  LL_DBG_PRINTK("[FW4] daddr %x\n", key.dest);
  LL_DBG_PRINTK("[FW4] saddr %d\n", key.source);
  LL_DBG_PRINTK("[FW4] sport %d\n", key.sport);
  LL_DBG_PRINTK("[FW4] dport %d\n", key.dport);
  LL_DBG_PRINTK("[FW4] l4proto %d\n", key.protocol);

  xf->pm.table_id = LL_DP_FW4_MAP;

  idx = xf->pm.fw_lid;

  for (i = 0; i < DP_MAX_LOOPS_PER_FWLKUP; i++) {

    fwe = bpf_map_lookup_elem(&fw_v4_map, &idx);
    if (!fwe) {
      LL_DBG_PRINTK("[FW4] miss");
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
      RETURN_TO_MP();
      return DP_DROP;
    } else {
      if (idx == 0) {
        xf->pm.fw_mid = fwe->k.nr.val;
      } else if (i + xf->pm.fw_lid >= xf->pm.fw_mid) {
        i = DP_MAX_LOOPS_PER_FWLKUP;
        break;
      }

      idx++;

      if (fwe->k.zone.val != 0 && 
          PDI_PKEY_EQ(&key, &fwe->k)) {

        /* End of lookup */
        xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
        break;
      }
    }
  }

  if (i >= DP_MAX_LOOPS_PER_FWLKUP) {
    /* No match in this iteration */
    xf->pm.fw_lid += DP_MAX_LOOPS_PER_FWLKUP;
    if (xf->pm.fw_lid >= LLB_FW4_MAP_ENTRIES ||
        xf->pm.fw_lid > xf->pm.fw_mid) {
      /* End of lookup */
      xf->pm.fw_lid = LLB_FW4_MAP_ENTRIES;
    }
    LL_DBG_PRINTK("[FW4] done");
    RETURN_TO_MP();
    return DP_DROP;
  }

  xf->pm.phit |= LLB_DP_FW_HIT;

  /* This condition should never hit */
  if (!fwe) return 0;

  act = &fwe->fwa;

  xf->pm.dp_mark = act->ca.mark;
  xf->pm.dp_rec = act->ca.record;

  if (act->ca.act_type == DP_SET_NOP) {
    goto done;
  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ar = &act->port_act;
    LLBS_PPLN_RDR_PRIO(xf);
    xf->pm.oport = ar->oport;
  } else if (act->ca.act_type == DP_SET_TOCP) {
    LLBS_PPLN_TRAPC(xf, LLB_PIPE_RC_FW_RDR);
  } else {
    /* Same for DP_SET_DROP */
    LLBS_PPLN_DROP(xf);
  }

  xf->pm.phit |= LLB_DP_RES_HIT;

done:
  dp_do_map_stats(ctx, xf, LL_DP_FW4_STATS_MAP, act->ca.cidx);
  xf->pm.fw_rid = act->ca.cidx;

  RETURN_TO_MP();
  return DP_DROP;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 130,
  "endLine": 134,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_fw.c",
  "funcName": "dp_do_fw_main",
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
    "static int __always_inline dp_do_fw_main (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    return dp_do_fw4_main (ctx, xf);\n",
    "}\n"
  ],
  "called_function_list": [
    "dp_do_fw4_main"
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
dp_do_fw_main(void *ctx, struct xfi *xf)
{
  return dp_do_fw4_main(ctx, xf);
}

