/*
 *  llb_kern_policer.c: LoxiLB eBPF Policer Processing Implementation
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 *  SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */
#define USECS_IN_SEC   (1000*1000)
#define NSECS_IN_USEC  (1000)

/* The intent here is to make this function non-inline
 * to keep code size in check
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
  "startLine": 13,
  "endLine": 142,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_policer.c",
  "funcName": "do_dp_policer",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_policer.c: LoxiLB eBPF Policer Processing Implementation *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  *  SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 10,
      "end_line": 12,
      "text": " The intent here is to make this function non-inline * to keep code size in check "
    },
    {
      "start_line": 35,
      "end_line": 35,
      "text": "|| pla->ca.act_type != DP_SET_DO_POLICER) { "
    },
    {
      "start_line": 43,
      "end_line": 43,
      "text": " Calculate and add tokens to CBS "
    },
    {
      "start_line": 61,
      "end_line": 63,
      "text": " No tokens were added so we revert to last timestamp when tokens     * were collected     "
    },
    {
      "start_line": 67,
      "end_line": 67,
      "text": " Calculate and add tokens to EBS "
    },
    {
      "start_line": 85,
      "end_line": 87,
      "text": " No tokens were added so we revert to last timestamp when tokens     * were collected     "
    },
    {
      "start_line": 92,
      "end_line": 92,
      "text": " Color-blind mode "
    },
    {
      "start_line": 104,
      "end_line": 104,
      "text": " Color-aware mode "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  polx_map"
  ],
  "input": [
    "void *ctx",
    " struct xfi *xf",
    " int egr"
  ],
  "output": "staticint",
  "helper": [
    "bpf_spin_lock",
    "bpf_map_lookup_elem",
    "bpf_ktime_get_ns",
    "bpf_spin_unlock"
  ],
  "compatibleHookpoints": [
    "socket_filter",
    "xdp",
    "sock_ops",
    "sched_act",
    "sk_reuseport",
    "lwt_seg6local",
    "sk_msg",
    "lwt_in",
    "sk_skb",
    "lwt_xmit",
    "cgroup_sock",
    "lwt_out",
    "sched_cls",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int do_dp_policer (void *ctx, struct xfi *xf, int egr)\n",
    "{\n",
    "    struct dp_pol_tact *pla;\n",
    "    int ret = 0;\n",
    "    __u64 ts_now;\n",
    "    __u64 ts_last;\n",
    "    __u32 ntoks;\n",
    "    __u32 polid;\n",
    "    __u32 inbytes;\n",
    "    __u64 acc_toks;\n",
    "    __u64 usecs_elapsed;\n",
    "    ts_now = bpf_ktime_get_ns ();\n",
    "    if (egr) {\n",
    "        polid = xf->qm.opolid;\n",
    "    }\n",
    "    else {\n",
    "        polid = xf->qm.ipolid;\n",
    "    }\n",
    "    pla = bpf_map_lookup_elem (& polx_map, & polid);\n",
    "    if (!pla) {\n",
    "        return 0;\n",
    "    }\n",
    "    inbytes = xf->pm.l3_len;\n",
    "    bpf_spin_lock (&pla->lock);\n",
    "    ts_last = pla->pol.lastc_uts;\n",
    "    pla->pol.lastc_uts = ts_now;\n",
    "    usecs_elapsed = (ts_now - ts_last) / NSECS_IN_USEC;\n",
    "    acc_toks = pla->pol.toksc_pus * usecs_elapsed;\n",
    "    if (acc_toks > 0) {\n",
    "        if (pla->pol.cbs > pla->pol.tok_c) {\n",
    "            ntoks = pla->pol.cbs - pla->pol.tok_c;\n",
    "            if (acc_toks > ntoks) {\n",
    "                acc_toks -= ntoks;\n",
    "                pla->pol.tok_c += ntoks;\n",
    "            }\n",
    "            else {\n",
    "                pla->pol.tok_c += acc_toks;\n",
    "                acc_toks = 0;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        pla->pol.lastc_uts = ts_last;\n",
    "    }\n",
    "    ts_last = pla->pol.laste_uts;\n",
    "    pla->pol.laste_uts = ts_now;\n",
    "    usecs_elapsed = (ts_now - ts_last) / NSECS_IN_USEC;\n",
    "    acc_toks = pla->pol.tokse_pus * usecs_elapsed;\n",
    "    if (acc_toks) {\n",
    "        if (pla->pol.ebs > pla->pol.tok_e) {\n",
    "            ntoks = pla->pol.ebs - pla->pol.tok_e;\n",
    "            if (acc_toks > ntoks) {\n",
    "                acc_toks -= ntoks;\n",
    "                pla->pol.tok_e += ntoks;\n",
    "            }\n",
    "            else {\n",
    "                pla->pol.tok_e += acc_toks;\n",
    "                acc_toks = 0;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        pla->pol.laste_uts = ts_last;\n",
    "    }\n",
    "    if (pla->pol.color_aware == 0) {\n",
    "        if (pla->pol.tok_e < inbytes) {\n",
    "            xf->qm.ocol = LLB_PIPE_COL_RED;\n",
    "        }\n",
    "        else if (pla->pol.tok_c < inbytes) {\n",
    "            xf->qm.ocol = LLB_PIPE_COL_YELLOW;\n",
    "            pla->pol.tok_e -= inbytes;\n",
    "        }\n",
    "        else {\n",
    "            pla->pol.tok_c -= inbytes;\n",
    "            pla->pol.tok_e -= inbytes;\n",
    "            xf->qm.ocol = LLB_PIPE_COL_GREEN;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        if (xf->qm.icol == LLB_PIPE_COL_NONE) {\n",
    "            ret = -1;\n",
    "            goto out;\n",
    "        }\n",
    "        if (xf->qm.icol == LLB_PIPE_COL_RED) {\n",
    "            xf->qm.ocol = LLB_PIPE_COL_RED;\n",
    "            goto out;\n",
    "        }\n",
    "        if (pla->pol.tok_e < inbytes) {\n",
    "            xf->qm.ocol = LLB_PIPE_COL_RED;\n",
    "        }\n",
    "        else if (pla->pol.tok_c < inbytes) {\n",
    "            if (xf->qm.icol == LLB_PIPE_COL_GREEN) {\n",
    "                xf->qm.ocol = LLB_PIPE_COL_YELLOW;\n",
    "            }\n",
    "            else {\n",
    "                xf->qm.ocol = xf->qm.icol;\n",
    "            }\n",
    "            pla->pol.tok_e -= inbytes;\n",
    "        }\n",
    "        else {\n",
    "            pla->pol.tok_c -= inbytes;\n",
    "            pla->pol.tok_e -= inbytes;\n",
    "            xf->qm.ocol = xf->qm.icol;\n",
    "        }\n",
    "    }\n",
    "out :\n",
    "    if (pla->pol.drop_prio < xf->qm.ocol) {\n",
    "        ret = 1;\n",
    "        pla->pol.ps.drop_packets += 1;\n",
    "        LLBS_PPLN_DROP (xf);\n",
    "    }\n",
    "    else {\n",
    "        pla->pol.ps.pass_packets += 1;\n",
    "    }\n",
    "    bpf_spin_unlock (&pla->lock);\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "LLBS_PPLN_DROP"
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
do_dp_policer(void *ctx, struct xfi *xf, int egr)
{
  struct dp_pol_tact *pla;
  int ret = 0;
  __u64 ts_now;
  __u64 ts_last;
  __u32 ntoks;
  __u32 polid;
  __u32 inbytes;
  __u64 acc_toks;
  __u64 usecs_elapsed;

  ts_now = bpf_ktime_get_ns();

  if (egr) {
    polid = xf->qm.opolid;
  } else {
    polid = xf->qm.ipolid;
  }

  pla = bpf_map_lookup_elem(&polx_map, &polid);
  if (!pla) { /*|| pla->ca.act_type != DP_SET_DO_POLICER) { */
    return 0;
  }

  inbytes = xf->pm.l3_len;

  bpf_spin_lock(&pla->lock);

  /* Calculate and add tokens to CBS */
  ts_last = pla->pol.lastc_uts;
  pla->pol.lastc_uts = ts_now;

  usecs_elapsed = (ts_now - ts_last)/NSECS_IN_USEC;
  acc_toks = pla->pol.toksc_pus * usecs_elapsed;
  if (acc_toks > 0) {
    if (pla->pol.cbs > pla->pol.tok_c) {
      ntoks = pla->pol.cbs - pla->pol.tok_c;  
      if (acc_toks > ntoks) {
        acc_toks -= ntoks;
        pla->pol.tok_c += ntoks;
      } else {
        pla->pol.tok_c += acc_toks;
        acc_toks = 0;
      }
    }
  } else {
    /* No tokens were added so we revert to last timestamp when tokens
     * were collected
     */
    pla->pol.lastc_uts = ts_last;
  }

  /* Calculate and add tokens to EBS */
  ts_last = pla->pol.laste_uts;
  pla->pol.laste_uts = ts_now;

  usecs_elapsed = (ts_now - ts_last)/NSECS_IN_USEC;
  acc_toks = pla->pol.tokse_pus * usecs_elapsed;
  if (acc_toks) {
    if (pla->pol.ebs > pla->pol.tok_e) {
      ntoks = pla->pol.ebs - pla->pol.tok_e;
      if (acc_toks > ntoks) {
        acc_toks -= ntoks;
        pla->pol.tok_e += ntoks;
      } else {
        pla->pol.tok_e += acc_toks;
        acc_toks = 0;
      }
    }
  } else {
    /* No tokens were added so we revert to last timestamp when tokens
     * were collected
     */
    pla->pol.laste_uts = ts_last;
  }

  if (pla->pol.color_aware == 0) {
    /* Color-blind mode */
    if (pla->pol.tok_e < inbytes) {
      xf->qm.ocol = LLB_PIPE_COL_RED;
    } else if (pla->pol.tok_c < inbytes) {
      xf->qm.ocol = LLB_PIPE_COL_YELLOW;
      pla->pol.tok_e -= inbytes;
    } else {
      pla->pol.tok_c -= inbytes;
      pla->pol.tok_e -= inbytes;
      xf->qm.ocol = LLB_PIPE_COL_GREEN;
    }
  } else {
    /* Color-aware mode */
    if (xf->qm.icol == LLB_PIPE_COL_NONE) {
      ret = -1;
      goto out;
    }

    if (xf->qm.icol == LLB_PIPE_COL_RED) {
      xf->qm.ocol = LLB_PIPE_COL_RED;
      goto out;
    }

    if (pla->pol.tok_e < inbytes) {
      xf->qm.ocol = LLB_PIPE_COL_RED;
    } else if (pla->pol.tok_c < inbytes) {
      if (xf->qm.icol == LLB_PIPE_COL_GREEN) {
        xf->qm.ocol = LLB_PIPE_COL_YELLOW;
      } else {
        xf->qm.ocol = xf->qm.icol;
      }
      pla->pol.tok_e -= inbytes;
    } else {
      pla->pol.tok_c -= inbytes;
      pla->pol.tok_e -= inbytes;
      xf->qm.ocol = xf->qm.icol;
    }
  }

out:
  if (pla->pol.drop_prio < xf->qm.ocol) { 
    ret = 1;
    pla->pol.ps.drop_packets += 1;
    LLBS_PPLN_DROP(xf);
  } else {
    pla->pol.ps.pass_packets += 1;
  }
  bpf_spin_unlock(&pla->lock); 
 
  return ret;
}
