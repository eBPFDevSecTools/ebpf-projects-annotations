/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <assert.h>
#include "common_frame.h"
#include "common_sum.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 22,
  "endLine": 73,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_frame.c",
  "funcName": "create_raw_tcp6",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": " * Copyright (c) 2022 NetLOX Inc * * SPDX short identifier: BSD-3-Clause "
    },
    {
      "start_line": 37,
      "end_line": 37,
      "text": " Fill in the IP header "
    },
    {
      "start_line": 45,
      "end_line": 45,
      "text": " Fill in the TCP header "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *packet",
    " size_t *plen",
    " struct mkr_args *args"
  ],
  "output": "int",
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
    "int create_raw_tcp6 (void *packet, size_t *plen, struct mkr_args *args)\n",
    "{\n",
    "    size_t orig_len;\n",
    "    struct ip6_hdr *pip;\n",
    "    struct tcphdr *ptcp;\n",
    "    if (!packet || !plen)\n",
    "        return -1;\n",
    "    if (!args->v6 || args->protocol != 0x6)\n",
    "        return -1;\n",
    "    orig_len = *plen;\n",
    "    memset (packet, 0, orig_len);\n",
    "    pip = (void *) packet;\n",
    "    pip->ip6_vfc = 0x6 << 4 & 0xff;\n",
    "    pip->ip6_plen = htons (sizeof (struct tcphdr));\n",
    "    pip->ip6_nxt = 0x6;\n",
    "    pip->ip6_hlim = 64;\n",
    "    memcpy (&pip->ip6_src, args->sip, sizeof (pip->ip6_src));\n",
    "    memcpy (&pip->ip6_dst, args->dip, sizeof (pip->ip6_dst));\n",
    "    ptcp = (struct tcphdr *) (pip + 1);\n",
    "    ptcp->source = htons (args->sport);\n",
    "    ptcp->dest = htons (args->dport);\n",
    "    ptcp->seq = htonl (args->t.seq);\n",
    "    ptcp->doff = 5;\n",
    "    if (args->t.fin) {\n",
    "        ptcp->fin = 1;\n",
    "    }\n",
    "    if (args->t.syn) {\n",
    "        ptcp->syn = 1;\n",
    "    }\n",
    "    if (args->t.rst) {\n",
    "        ptcp->rst = 1;\n",
    "    }\n",
    "    if (args->t.ack) {\n",
    "        ptcp->ack = 1;\n",
    "    }\n",
    "    if (args->t.psh) {\n",
    "        ptcp->psh = 1;\n",
    "    }\n",
    "    if (args->t.urg) {\n",
    "        ptcp->urg = 1;\n",
    "    }\n",
    "    calc_tcp6_checksum (pip, (void *) ptcp);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "calc_tcp6_checksum",
    "memset",
    "htons",
    "htonl",
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
int
create_raw_tcp6(void *packet, size_t *plen, struct mkr_args *args)
{
  size_t orig_len;
  struct ip6_hdr *pip;
  struct tcphdr *ptcp;

  if (!packet || !plen) return -1;

  if (!args->v6 || args->protocol != 0x6) return -1;
  orig_len = *plen;

  memset(packet, 0, orig_len);
  pip = (void *)packet;

  /* Fill in the IP header */
  pip->ip6_vfc = 0x6 << 4 & 0xff;
  pip->ip6_plen = htons(sizeof(struct tcphdr));
  pip->ip6_nxt = 0x6;
  pip->ip6_hlim = 64;
  memcpy(&pip->ip6_src, args->sip, sizeof(pip->ip6_src));
  memcpy(&pip->ip6_dst, args->dip, sizeof(pip->ip6_dst));

  /* Fill in the TCP header */
  ptcp = (struct tcphdr *)(pip+1);
  ptcp->source = htons(args->sport);
  ptcp->dest = htons(args->dport);
  ptcp->seq = htonl(args->t.seq);
  ptcp->doff = 5;
  if (args->t.fin) {
    ptcp->fin = 1;
  }
  if (args->t.syn) {
    ptcp->syn = 1;
  }
  if (args->t.rst) {
    ptcp->rst = 1;
  }
  if (args->t.ack) {
    ptcp->ack = 1;
  }
  if (args->t.psh) {
    ptcp->psh = 1;
  }
  if (args->t.urg) {
    ptcp->urg = 1;
  }

  calc_tcp6_checksum(pip, (void *)ptcp);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 75,
  "endLine": 131,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_frame.c",
  "funcName": "create_raw_tcp",
  "developer_inline_comments": [
    {
      "start_line": 84,
      "end_line": 84,
      "text": " Unsupported for now "
    },
    {
      "start_line": 91,
      "end_line": 91,
      "text": " Fill in the IP header "
    },
    {
      "start_line": 103,
      "end_line": 103,
      "text": " Fill in the TCP header "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *packet",
    " size_t *plen",
    " struct mkr_args *args"
  ],
  "output": "int",
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
    "int create_raw_tcp (void *packet, size_t *plen, struct mkr_args *args)\n",
    "{\n",
    "    size_t orig_len;\n",
    "    struct iphdr *pip;\n",
    "    struct tcphdr *ptcp;\n",
    "    if (!packet || !plen)\n",
    "        return -1;\n",
    "    if (args->v6 || args->protocol != 0x6)\n",
    "        return -1;\n",
    "    orig_len = *plen;\n",
    "    memset (packet, 0, orig_len);\n",
    "    pip = (void *) packet;\n",
    "    pip->version = 4;\n",
    "    pip->ihl = 5;\n",
    "    pip->tot_len = htons (sizeof (struct iphdr) + sizeof (struct tcphdr));\n",
    "    pip->id = 0xbeef;\n",
    "    pip->frag_off = 0x0000;\n",
    "    pip->protocol = 0x6;\n",
    "    pip->ttl = 64;\n",
    "    pip->saddr = htonl (args->sip[0]);\n",
    "    pip->daddr = htonl (args->dip[0]);\n",
    "    calc_ip_csum (pip);\n",
    "    ptcp = (struct tcphdr *) (pip + 1);\n",
    "    ptcp->source = htons (args->sport);\n",
    "    ptcp->dest = htons (args->dport);\n",
    "    ptcp->seq = htonl (args->t.seq);\n",
    "    ptcp->doff = 5;\n",
    "    if (args->t.fin) {\n",
    "        ptcp->fin = 1;\n",
    "    }\n",
    "    if (args->t.syn) {\n",
    "        ptcp->syn = 1;\n",
    "    }\n",
    "    if (args->t.rst) {\n",
    "        ptcp->rst = 1;\n",
    "    }\n",
    "    if (args->t.ack) {\n",
    "        ptcp->ack = 1;\n",
    "    }\n",
    "    if (args->t.psh) {\n",
    "        ptcp->psh = 1;\n",
    "    }\n",
    "    if (args->t.urg) {\n",
    "        ptcp->urg = 1;\n",
    "    }\n",
    "    calc_tcp_checksum (pip, (void *) ptcp);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "calc_ip_csum",
    "memset",
    "calc_tcp_checksum",
    "htons",
    "htonl"
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
int
create_raw_tcp(void *packet, size_t *plen, struct mkr_args *args)
{
  size_t orig_len;
  struct iphdr *pip;
  struct tcphdr *ptcp;

  if (!packet || !plen) return -1;

  /* Unsupported for now */
  if (args->v6 || args->protocol != 0x6) return -1;
  orig_len = *plen;

  memset(packet, 0, orig_len);
  pip = (void *)packet;

  /* Fill in the IP header */
  pip->version = 4;
  pip->ihl = 5;
  pip->tot_len = htons(sizeof(struct iphdr)+sizeof(struct tcphdr));
  pip->id = 0xbeef;
  pip->frag_off = 0x0000;
  pip->protocol = 0x6;
  pip->ttl = 64;
  pip->saddr = htonl(args->sip[0]);
  pip->daddr = htonl(args->dip[0]);
  calc_ip_csum(pip);

  /* Fill in the TCP header */
  ptcp = (struct tcphdr *)(pip+1);
  ptcp->source = htons(args->sport);
  ptcp->dest = htons(args->dport);
  ptcp->seq = htonl(args->t.seq);
  ptcp->doff = 5;
  if (args->t.fin) {
    ptcp->fin = 1;
  }
  if (args->t.syn) {
    ptcp->syn = 1;
  }
  if (args->t.rst) {
    ptcp->rst = 1;
  }
  if (args->t.ack) {
    ptcp->ack = 1;
  }
  if (args->t.psh) {
    ptcp->psh = 1;
  }
  if (args->t.urg) {
    ptcp->urg = 1;
  }

  calc_tcp_checksum(pip, (void *)ptcp);

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
          "Project": "cilium",
          "Return Type": "int",
          "Description": "Emulate a call to setsockopt() on the socket associated to <[ socket ]>(IP: 0) , which must be a full socket. The <[ level ]>(IP: 1) at which the option resides and the name <[ optname ]>(IP: 2) of the option must be specified , see setsockopt(2) for more information. The option value of length <[ optlen ]>(IP: 4) is pointed by optval. This helper actually implements a subset of setsockopt(). It supports the following levels: \u00b7 SOL_SOCKET , which supports the following optnames: SO_RCVBUF , SO_SNDBUF , SO_MAX_PACING_RATE , SO_PRIORITY , SO_RCVLOWAT , SO_MARK. \u00b7 IPPROTO_TCP , which supports the following optnames: TCP_CONGESTION , TCP_BPF_IW , TCP_BPF_SNDCWND_CLAMP. \u00b7 IPPROTO_IP , which supports <[ optname ]>(IP: 2) IP_TOS. \u00b7 IPPROTO_IPV6 , which supports <[ optname ]>(IP: 2) IPV6_TCLASS. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "setsockopt",
          "Input Params": [
            "{Type: struct sock_ops ,Var: *socket}",
            "{Type:  int ,Var: level}",
            "{Type:  int ,Var: optname}",
            "{Type:  char ,Var: *optval}",
            "{Type:  int ,Var: optlen}"
          ],
          "compatible_hookpoints": [
            "sock_ops"
          ],
          "capabilities": [
            "update_pkt"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 133,
  "endLine": 188,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_frame.c",
  "funcName": "xmit_raw",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *packet",
    " size_t plen",
    " struct mkr_args *args"
  ],
  "output": "staticint",
  "helper": [
    "setsockopt"
  ],
  "compatibleHookpoints": [
    "sock_ops"
  ],
  "source": [
    "static int xmit_raw (void *packet, size_t plen, struct mkr_args *args)\n",
    "{\n",
    "    struct sockaddr_in caddr;\n",
    "    struct sockaddr_in6 caddr6;\n",
    "    void *sockaddr = NULL;\n",
    "    int raw_socket;\n",
    "    int hdr_incl = 1;\n",
    "    int sent_bytes;\n",
    "    if (args->v6 == 0) {\n",
    "        if ((raw_socket = socket (AF_INET, SOCK_RAW, args->protocol)) < 0) {\n",
    "            return -1;\n",
    "        }\n",
    "        if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, &hdr_incl, sizeof (hdr_incl)) < 0) {\n",
    "            close (raw_socket);\n",
    "            return -1;\n",
    "        }\n",
    "        memset (&caddr, 0, sizeof (caddr));\n",
    "        caddr.sin_family = AF_INET;\n",
    "        caddr.sin_port = htons (args->dport);\n",
    "        caddr.sin_addr.s_addr = htonl (args->dip[0]);\n",
    "        sockaddr = &caddr;\n",
    "    }\n",
    "    else {\n",
    "        if ((raw_socket = socket (AF_INET6, SOCK_RAW, IPPROTO_UDP)) < 0) {\n",
    "            return -1;\n",
    "        }\n",
    "        if (setsockopt (raw_socket, IPPROTO_IPV6, IPV6_HDRINCL, &hdr_incl, sizeof (hdr_incl)) < 0) {\n",
    "            close (raw_socket);\n",
    "            return -1;\n",
    "        }\n",
    "        memset (&caddr6, 0, sizeof (caddr6));\n",
    "        caddr6.sin6_family = AF_INET6;\n",
    "        caddr6.sin6_port = 0;\n",
    "        memcpy (&caddr6.sin6_addr, args->dip, 16);\n",
    "        sockaddr = &caddr6;\n",
    "    }\n",
    "    sent_bytes = sendto (raw_socket, packet, plen, 0, (struct sockaddr *) sockaddr, args -> v6 ? sizeof (struct sockaddr_in6) : sizeof (struct sockaddr_in));\n",
    "    if (sent_bytes < 0) {\n",
    "        close (raw_socket);\n",
    "        return -1;\n",
    "    }\n",
    "    close (raw_socket);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "socket",
    "memset",
    "close",
    "sendto",
    "htons",
    "htonl",
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
static int
xmit_raw(void *packet, size_t plen, struct mkr_args *args)  
{
  struct sockaddr_in caddr;
  struct sockaddr_in6 caddr6;
  void *sockaddr = NULL;
  int raw_socket;
  int hdr_incl = 1;
  int sent_bytes;

  if (args->v6 == 0) {
    if ((raw_socket = socket(AF_INET, SOCK_RAW, args->protocol)) < 0) {
      return -1;
    }

    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL,
                 &hdr_incl, sizeof(hdr_incl)) < 0) {
      close(raw_socket);
      return -1;
    }

    memset(&caddr, 0, sizeof(caddr));
    caddr.sin_family = AF_INET;
    caddr.sin_port = htons(args->dport);
    caddr.sin_addr.s_addr = htonl(args->dip[0]);
    sockaddr = &caddr;
  } else {
    if ((raw_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)) < 0) {
      return -1;
    }

    if (setsockopt(raw_socket, IPPROTO_IPV6, IPV6_HDRINCL,
                 &hdr_incl, sizeof(hdr_incl)) < 0) {
      close(raw_socket);
      return -1;
    }

    memset(&caddr6, 0, sizeof(caddr6));
    caddr6.sin6_family = AF_INET6;
    caddr6.sin6_port = 0;
    memcpy(&caddr6.sin6_addr, args->dip, 16);
    sockaddr = &caddr6;
  }

  sent_bytes = sendto(raw_socket, packet, plen, 0,
                      (struct sockaddr *)sockaddr,
                      args->v6 ? sizeof(struct sockaddr_in6) :
                                 sizeof(struct sockaddr_in));
  if (sent_bytes < 0) {
    close(raw_socket);
    return -1;
  }

  close(raw_socket);
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 190,
  "endLine": 209,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_frame.c",
  "funcName": "create_xmit_raw_tcp",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct mkr_args *args"
  ],
  "output": "int",
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
    "int create_xmit_raw_tcp (struct mkr_args *args)\n",
    "{\n",
    "    uint8_t frame [64] = {0};\n",
    "    size_t len;\n",
    "    int ret;\n",
    "    if (args->v6) {\n",
    "        len = sizeof (struct ip6_hdr) + sizeof (struct tcphdr);\n",
    "        ret = create_raw_tcp6 (frame, & len, args);\n",
    "    }\n",
    "    else {\n",
    "        len = sizeof (struct iphdr) + sizeof (struct tcphdr);\n",
    "        ret = create_raw_tcp (frame, & len, args);\n",
    "    }\n",
    "    if (ret < 0) {\n",
    "        return -1;\n",
    "    }\n",
    "    return xmit_raw (frame, len, args);\n",
    "}\n"
  ],
  "called_function_list": [
    "xmit_raw",
    "create_raw_tcp6",
    "create_raw_tcp"
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
int
create_xmit_raw_tcp(struct mkr_args *args)
{
  uint8_t frame[64] = { 0 };
  size_t len;
  int ret;

  if (args->v6) {
    len = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
    ret = create_raw_tcp6(frame, &len, args);
  } else {
    len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ret = create_raw_tcp(frame, &len, args);
  }
  if (ret < 0) {
    return -1;
  }

  return xmit_raw(frame, len, args);
}
