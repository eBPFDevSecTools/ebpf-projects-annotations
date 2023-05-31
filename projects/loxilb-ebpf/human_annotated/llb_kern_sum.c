/*
 *  llb_kern_sum.c: LoxiLB Kernel in-eBPF checksums 
 *  Copyright (C) 2022,  NetLOX <www.netlox.io>
 * 
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
 */

#define DP_MAX_LOOPS_PER_TCALL (256)

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
  "startLine": 10,
  "endLine": 22,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_sum.c",
  "funcName": "get_crc32c_map",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 6,
      "text": " *  llb_kern_sum.c: LoxiLB Kernel in-eBPF checksums  *  Copyright (C) 2022,  NetLOX <www.netlox.io> *  * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) "
    },
    {
      "start_line": 17,
      "end_line": 17,
      "text": " Not Reached "
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  crc32c_map"
  ],
  "input": [
    "__u32 off"
  ],
  "output": "static__u32__always_inline",
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
    "static __u32 __always_inline get_crc32c_map (__u32 off)\n",
    "{\n",
    "    __u32 *val;\n",
    "    val = bpf_map_lookup_elem (& crc32c_map, & off);\n",
    "    if (!val) {\n",
    "        return 0;\n",
    "    }\n",
    "    return *val;\n",
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
get_crc32c_map(__u32 off)
{
  __u32 *val;

  val = bpf_map_lookup_elem(&crc32c_map, &off); 
  if (!val) {
    /* Not Reached */
    return 0;
  }

  return *val;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 95,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_sum.c",
  "funcName": "dp_sctp_csum",
  "developer_inline_comments": [
    {
      "start_line": 36,
      "end_line": 36,
      "text": " Next tail-call"
    },
    {
      "start_line": 58,
      "end_line": 58,
      "text": " Update crc in sctp "
    },
    {
      "start_line": 59,
      "end_line": 59,
      "text": " Reset any flag which indicates further sctp processing "
    },
    {
      "start_line": 70,
      "end_line": 70,
      "text": "csum = bpf_htonl(crc ^ 0xffffffff);"
    },
    {
      "start_line": 79,
      "end_line": 79,
      "text": " Update state-variables "
    },
    {
      "start_line": 85,
      "end_line": 85,
      "text": " Jump to next helper section for checksum "
    },
    {
      "start_line": 93,
      "end_line": 93,
      "text": " Something went wrong here "
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
    "static int __always_inline dp_sctp_csum (void *ctx, struct xfi *xf)\n",
    "{\n",
    "    int ret;\n",
    "    int off;\n",
    "    int rlen;\n",
    "    __u8 tcall;\n",
    "    __u32 tbval;\n",
    "    __u8 pb;\n",
    "    int loop = 0;\n",
    "    __u32 crc = 0xffffffff;\n",
    "    tcall = ~xf->km.skey[0];\n",
    "    off = *(__u16*) &xf->km.skey[2];\n",
    "    rlen = *(__u16*) &xf->km.skey[4];\n",
    "    if (off) {\n",
    "        crc = *(__u32*) &xf->km.skey[8];\n",
    "    }\n",
    "    for (loop = 0; loop < DP_MAX_LOOPS_PER_TCALL; loop++) {\n",
    "        __u8 idx;\n",
    "        if (rlen > 0) {\n",
    "            ret = dp_pktbuf_read (ctx, off, & pb, sizeof (pb));\n",
    "            if (ret < 0) {\n",
    "                goto drop;\n",
    "            }\n",
    "            idx = (crc ^ pb) & 0xff;\n",
    "            tbval = get_crc32c_map (idx);\n",
    "            crc = tbval ^ (crc >> 8);\n",
    "            off++;\n",
    "            rlen--;\n",
    "        }\n",
    "        else\n",
    "            break;\n",
    "    }\n",
    "    if (rlen <= 0) {\n",
    "        if (xf->l34m.nw_proto == IPPROTO_SCTP) {\n",
    "            void *dend = DP_TC_PTR (DP_PDATA_END (ctx));\n",
    "            struct sctphdr *sctp = DP_ADD_PTR (DP_PDATA (ctx), xf->pm.l4_off);\n",
    "            int sctp_csum_off = xf->pm.l4_off + offsetof (struct sctphdr, checksum);\n",
    "            __be32 csum;\n",
    "            if (sctp + 1 > dend) {\n",
    "                LLBS_PPLN_DROP (xf);\n",
    "                return DP_DROP;\n",
    "            }\n",
    "            csum = (crc ^ 0xffffffff);\n",
    "            dp_pktbuf_write (ctx, sctp_csum_off, &csum, sizeof (csum), 0);\n",
    "            xf->pm.nf = 0;\n",
    "        }\n",
    "        RETURN_TO_MP_OUT ();\n",
    "    }\n",
    "    xf->km.skey[0] = tcall;\n",
    "    *(__u16*) &xf->km.skey[2] = off;\n",
    "    *(__u16*) &xf->km.skey[4] = rlen;\n",
    "    *(__u32*) &xf->km.skey[8] = crc;\n",
    "    if (tcall) {\n",
    "        TCALL_CRC2 ();\n",
    "    }\n",
    "    else {\n",
    "        TCALL_CRC1 ();\n",
    "    }\n",
    "drop :\n",
    "    return DP_DROP;\n",
    "}\n"
  ],
  "called_function_list": [
    "DP_PDATA",
    "LLBS_PPLN_DROP",
    "dp_pktbuf_read",
    "offsetof",
    "RETURN_TO_MP_OUT",
    "TCALL_CRC2",
    "dp_pktbuf_write",
    "DP_ADD_PTR",
    "DP_TC_PTR",
    "DP_PDATA_END",
    "get_crc32c_map",
    "TCALL_CRC1"
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
dp_sctp_csum(void *ctx, struct xfi *xf)
{
  int ret;
  int off;
  int rlen;
  __u8 tcall;
  __u32 tbval;
  __u8 pb;
  int loop = 0;
  __u32 crc = 0xffffffff;

  tcall = ~xf->km.skey[0]; // Next tail-call
  off = *(__u16 *)&xf->km.skey[2];
  rlen = *(__u16 *)&xf->km.skey[4];
  if (off) {
    crc = *(__u32 *)&xf->km.skey[8];
  }

  for (loop = 0; loop < DP_MAX_LOOPS_PER_TCALL; loop++) {
      __u8 idx;
      if (rlen > 0) {
        ret = dp_pktbuf_read(ctx, off, &pb, sizeof(pb));
        if (ret < 0) {
          goto drop;
        }
        idx =(crc ^ pb) & 0xff;
        tbval = get_crc32c_map(idx);
        crc = tbval ^ (crc >> 8);
        off++;
        rlen--;
    } else break;
  }
  if (rlen <= 0) {
     /* Update crc in sctp */
      /* Reset any flag which indicates further sctp processing */
      if (xf->l34m.nw_proto == IPPROTO_SCTP)  {
        void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
        struct sctphdr *sctp = DP_ADD_PTR(DP_PDATA(ctx), xf->pm.l4_off);
        int sctp_csum_off = xf->pm.l4_off + offsetof(struct sctphdr, checksum);
        __be32 csum;

        if (sctp + 1 > dend) {
          LLBS_PPLN_DROP(xf);
          return DP_DROP;
        }
        //csum = bpf_htonl(crc ^ 0xffffffff);
        csum = (crc ^ 0xffffffff);
        dp_pktbuf_write(ctx, sctp_csum_off, &csum , sizeof(csum), 0); 
        xf->pm.nf = 0;
      }
        
      RETURN_TO_MP_OUT();
  }

  /* Update state-variables */
  xf->km.skey[0] = tcall;
  *(__u16 *)&xf->km.skey[2] = off;
  *(__u16 *)&xf->km.skey[4] = rlen;
  *(__u32 *)&xf->km.skey[8] = crc;

  /* Jump to next helper section for checksum */
  if (tcall) {
    TCALL_CRC2();
  } else {
    TCALL_CRC1();
  }
 
drop:
  /* Something went wrong here */
  return DP_DROP;
}
