#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <assert.h>

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 11,
  "endLine": 33,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_sum.c",
  "funcName": "calc_csum",
  "developer_inline_comments": [
    {
      "start_line": 20,
      "end_line": 20,
      "text": "if any bytes left, pad the bytes and add"
    },
    {
      "start_line": 25,
      "end_line": 25,
      "text": "Fold sum to 16 bits: add carrier to result"
    },
    {
      "start_line": 30,
      "end_line": 30,
      "text": "one's complement"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "unsigned short *addr",
    " unsigned int count"
  ],
  "output": "staticunsignedshort",
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
    "static unsigned short calc_csum (unsigned short *addr, unsigned int count)\n",
    "{\n",
    "    register unsigned long sum = 0;\n",
    "    while (count > 1) {\n",
    "        sum += *addr++;\n",
    "        count -= 2;\n",
    "    }\n",
    "    if (count > 0) {\n",
    "        sum += ((*addr) & htons (0xFF00));\n",
    "    }\n",
    "    while (sum >> 16) {\n",
    "        sum = (sum & 0xffff) + (sum >> 16);\n",
    "    }\n",
    "    sum = ~sum;\n",
    "    return ((unsigned short) sum);\n",
    "}\n"
  ],
  "called_function_list": [
    "htons"
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
static unsigned short
calc_csum(unsigned short *addr, unsigned int count)
{
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }

  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }

  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }

  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 35,
  "endLine": 93,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_sum.c",
  "funcName": "calc_tcp6_checksum",
  "developer_inline_comments": [
    {
      "start_line": 42,
      "end_line": 42,
      "text": "add the pseudo header "
    },
    {
      "start_line": 43,
      "end_line": 43,
      "text": "the source ip"
    },
    {
      "start_line": 56,
      "end_line": 56,
      "text": "the dest ip"
    },
    {
      "start_line": 69,
      "end_line": 69,
      "text": "protocol and reserved: 6"
    },
    {
      "start_line": 72,
      "end_line": 72,
      "text": "the length"
    },
    {
      "start_line": 75,
      "end_line": 75,
      "text": "add the IP payload"
    },
    {
      "start_line": 76,
      "end_line": 76,
      "text": "initialize checksum to 0"
    },
    {
      "start_line": 82,
      "end_line": 82,
      "text": "if any bytes left, pad the bytes and add"
    },
    {
      "start_line": 86,
      "end_line": 86,
      "text": "Fold 32-bit sum to 16 bits: add carrier to result"
    },
    {
      "start_line": 91,
      "end_line": 91,
      "text": "set computation result"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct ip6_hdr *pIph",
    " unsigned short *ipPayload"
  ],
  "output": "void",
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
    "void calc_tcp6_checksum (struct ip6_hdr *pIph, unsigned short *ipPayload)\n",
    "{\n",
    "    register unsigned long sum = 0;\n",
    "    unsigned short tcpLen = ntohs (pIph -> ip6_plen);\n",
    "    struct tcphdr *tcphdrp = (struct tcphdr *) (ipPayload);\n",
    "    sum += (pIph->ip6_src.s6_addr32[0] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_src.s6_addr32[0]) & 0xFFFF;\n",
    "    sum += (pIph->ip6_src.s6_addr32[1] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_src.s6_addr32[1]) & 0xFFFF;\n",
    "    sum += (pIph->ip6_src.s6_addr32[2] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_src.s6_addr32[2]) & 0xFFFF;\n",
    "    sum += (pIph->ip6_src.s6_addr32[3] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_src.s6_addr32[3]) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[0] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[0]) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[1] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[1]) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[2] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[2]) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[3] >> 16) & 0xFFFF;\n",
    "    sum += (pIph->ip6_dst.s6_addr32[3]) & 0xFFFF;\n",
    "    sum += htons (IPPROTO_TCP);\n",
    "    sum += htons (tcpLen);\n",
    "    tcphdrp->check = 0;\n",
    "    while (tcpLen > 1) {\n",
    "        sum += *ipPayload++;\n",
    "        tcpLen -= 2;\n",
    "    }\n",
    "    if (tcpLen > 0) {\n",
    "        sum += ((*ipPayload) & htons (0xFF00));\n",
    "    }\n",
    "    while (sum >> 16) {\n",
    "        sum = (sum & 0xffff) + (sum >> 16);\n",
    "    }\n",
    "    sum = ~sum;\n",
    "    tcphdrp->check = (unsigned short) sum;\n",
    "}\n"
  ],
  "called_function_list": [
    "htons",
    "ntohs"
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
void
calc_tcp6_checksum(struct ip6_hdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->ip6_plen);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);

    //add the pseudo header 
    //the source ip
    sum += (pIph->ip6_src.s6_addr32[0]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[0])&0xFFFF;

    sum += (pIph->ip6_src.s6_addr32[1]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[1])&0xFFFF;

    sum += (pIph->ip6_src.s6_addr32[2]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[2])&0xFFFF;

    sum += (pIph->ip6_src.s6_addr32[3]>>16)&0xFFFF;
    sum += (pIph->ip6_src.s6_addr32[3])&0xFFFF;

    //the dest ip
    sum += (pIph->ip6_dst.s6_addr32[0]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[0])&0xFFFF;

    sum += (pIph->ip6_dst.s6_addr32[1]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[1])&0xFFFF;

    sum += (pIph->ip6_dst.s6_addr32[2]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[2])&0xFFFF;

    sum += (pIph->ip6_dst.s6_addr32[3]>>16)&0xFFFF;
    sum += (pIph->ip6_dst.s6_addr32[3])&0xFFFF;

    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);

    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 95,
  "endLine": 131,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_sum.c",
  "funcName": "calc_tcp_checksum",
  "developer_inline_comments": [
    {
      "start_line": 101,
      "end_line": 101,
      "text": "add the pseudo header "
    },
    {
      "start_line": 102,
      "end_line": 102,
      "text": "the source ip"
    },
    {
      "start_line": 105,
      "end_line": 105,
      "text": "the dest ip"
    },
    {
      "start_line": 108,
      "end_line": 108,
      "text": "protocol and reserved: 6"
    },
    {
      "start_line": 110,
      "end_line": 110,
      "text": "the length"
    },
    {
      "start_line": 113,
      "end_line": 113,
      "text": "add the IP payload"
    },
    {
      "start_line": 114,
      "end_line": 114,
      "text": "initialize checksum to 0"
    },
    {
      "start_line": 120,
      "end_line": 120,
      "text": "if any bytes left, pad the bytes and add"
    },
    {
      "start_line": 124,
      "end_line": 124,
      "text": "Fold 32-bit sum to 16 bits: add carrier to result"
    },
    {
      "start_line": 129,
      "end_line": 129,
      "text": "set computation result"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct iphdr *pIph",
    " unsigned short *ipPayload"
  ],
  "output": "void",
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
    "void calc_tcp_checksum (struct iphdr *pIph, unsigned short *ipPayload)\n",
    "{\n",
    "    register unsigned long sum = 0;\n",
    "    unsigned short tcpLen = ntohs (pIph->tot_len) - (pIph->ihl << 2);\n",
    "    struct tcphdr *tcphdrp = (struct tcphdr *) (ipPayload);\n",
    "    sum += (pIph->saddr >> 16) & 0xFFFF;\n",
    "    sum += (pIph->saddr) & 0xFFFF;\n",
    "    sum += (pIph->daddr >> 16) & 0xFFFF;\n",
    "    sum += (pIph->daddr) & 0xFFFF;\n",
    "    sum += htons (IPPROTO_TCP);\n",
    "    sum += htons (tcpLen);\n",
    "    tcphdrp->check = 0;\n",
    "    while (tcpLen > 1) {\n",
    "        sum += *ipPayload++;\n",
    "        tcpLen -= 2;\n",
    "    }\n",
    "    if (tcpLen > 0) {\n",
    "        sum += ((*ipPayload) & htons (0xFF00));\n",
    "    }\n",
    "    while (sum >> 16) {\n",
    "        sum = (sum & 0xffff) + (sum >> 16);\n",
    "    }\n",
    "    sum = ~sum;\n",
    "    tcphdrp->check = (unsigned short) sum;\n",
    "}\n"
  ],
  "called_function_list": [
    "htons",
    "ntohs"
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
void
calc_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 133,
  "endLine": 138,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_sum.c",
  "funcName": "calc_ip_csum",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct iphdr *iph"
  ],
  "output": "void",
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
    "void calc_ip_csum (struct iphdr *iph)\n",
    "{\n",
    "    iph->check = 0;\n",
    "    iph->check = calc_csum ((unsigned short *) iph, (iph->ihl) << 2);\n",
    "}\n"
  ],
  "called_function_list": [
    "calc_csum"
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
void
calc_ip_csum(struct iphdr *iph)
{
  iph->check = 0;
  iph->check = calc_csum((unsigned short*)iph, (iph->ihl) <<2);
}
