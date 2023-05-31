/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

struct vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 41,
  "endLine": 57,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/lb.c",
  "funcName": "ipv4_hash",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 16,
      "text": "/* Copyright (C) 2018 Open Information Security Foundation\n *\n * You can copy, redistribute or modify this Program under the terms of\n * the GNU General Public License version 2 as published by the Free\n * Software Foundation.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License\n * version 2 along with this program; if not, write to the Free Software\n * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA\n * 02110-1301, USA.\n *"
    },
    {
      "start_line": 53,
      "end_line": 53,
      "text": "//char fmt2[] = \"Got hash %u\\n\";"
    },
    {
      "start_line": 54,
      "end_line": 54,
      "text": "//bpf_trace_printk(fmt2, sizeof(fmt2), src + dst);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "cgroup_sock",
    "socket_filter",
    "lwt_xmit",
    "sk_skb",
    "tracepoint",
    "sched_act",
    "cgroup_skb",
    "sched_cls",
    "sk_msg",
    "raw_tracepoint_writable",
    "perf_event",
    "sk_reuseport",
    "lwt_out",
    "cgroup_device",
    "flow_dissector",
    "sock_ops",
    "kprobe",
    "lwt_seg6local",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int ipv4_hash (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u32 nhoff;\n",
    "    __u32 src, dst;\n",
    "    nhoff = skb->cb[0];\n",
    "    src = load_word (skb, nhoff + offsetof (struct iphdr, saddr));\n",
    "    dst = load_word (skb, nhoff + offsetof (struct iphdr, daddr));\n",
    "\n",
    "#if 0\n",
    "    char fmt [] = \"Got addr: %x -> %x at %d\\n\";\n",
    "    bpf_trace_printk (fmt, sizeof (fmt), src, dst, nhoff);\n",
    "\n",
    "#endif\n",
    "    return src + dst;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof",
    "load_word"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "The function computes a hash for a given packet, by adding the source and destination IP addresses.",
      "author": "Pragna Mamidipaka",
      "authorEmail": "pragna.pune@gmail.com",
      "date": "2023-04-05"
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
static __always_inline int ipv4_hash(struct __sk_buff *skb)
{
    __u32 nhoff;
    __u32 src, dst;

    nhoff = skb->cb[0];
    src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

#if 0
    char fmt[] = "Got addr: %x -> %x at %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), src, dst, nhoff);
    //char fmt2[] = "Got hash %u\n";
    //bpf_trace_printk(fmt2, sizeof(fmt2), src + dst);
#endif
    return  src + dst;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 59,
  "endLine": 67,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/lb.c",
  "funcName": "ipv6_addr_hash",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *ctx",
    " __u64 off"
  ],
  "output": "staticinline__u32",
  "helper": [],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "cgroup_sock",
    "socket_filter",
    "lwt_xmit",
    "sk_skb",
    "tracepoint",
    "sched_act",
    "cgroup_skb",
    "sched_cls",
    "sk_msg",
    "raw_tracepoint_writable",
    "perf_event",
    "sk_reuseport",
    "lwt_out",
    "cgroup_device",
    "flow_dissector",
    "sock_ops",
    "kprobe",
    "lwt_seg6local",
    "lwt_in"
  ],
  "source": [
    "static inline __u32 ipv6_addr_hash (struct  __sk_buff *ctx, __u64 off)\n",
    "{\n",
    "    __u64 w0 = load_word (ctx, off);\n",
    "    __u64 w1 = load_word (ctx, off + 4);\n",
    "    __u64 w2 = load_word (ctx, off + 8);\n",
    "    __u64 w3 = load_word (ctx, off + 12);\n",
    "    return (__u32) (w0 ^ w1 ^ w2 ^ w3);\n",
    "}\n"
  ],
  "called_function_list": [
    "load_word"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "The function takes an IPv6 address and computes a hash by bitwise XOR of its four octets.",
      "author": "Pragna Mamidipaka",
      "authorEmail": "pragna.pune@gmail.com",
      "date": "2023-04-05"
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
static inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off)
{
    __u64 w0 = load_word(ctx, off);
    __u64 w1 = load_word(ctx, off + 4);
    __u64 w2 = load_word(ctx, off + 8);
    __u64 w3 = load_word(ctx, off + 12);

    return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 69,
  "endLine": 81,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/lb.c",
  "funcName": "ipv6_hash",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "cgroup_sock",
    "socket_filter",
    "lwt_xmit",
    "sk_skb",
    "tracepoint",
    "sched_act",
    "cgroup_skb",
    "sched_cls",
    "sk_msg",
    "raw_tracepoint_writable",
    "perf_event",
    "sk_reuseport",
    "lwt_out",
    "cgroup_device",
    "flow_dissector",
    "sock_ops",
    "kprobe",
    "lwt_seg6local",
    "lwt_in"
  ],
  "source": [
    "static __always_inline int ipv6_hash (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u32 nhoff;\n",
    "    __u32 src_hash, dst_hash;\n",
    "    nhoff = skb->cb[0];\n",
    "    src_hash = ipv6_addr_hash (skb, nhoff + offsetof (struct ipv6hdr, saddr));\n",
    "    dst_hash = ipv6_addr_hash (skb, nhoff + offsetof (struct ipv6hdr, daddr));\n",
    "    return src_hash + dst_hash;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof",
    "ipv6_addr_hash"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "The function uses source address hash and destination address hash of a packet, and returns the sum of the two as the final hash value.",
      "author": "Pragna Mamidipaka",
      "authorEmail": "pragna.pune@gmail.com",
      "date": "2023-04-05"
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
static __always_inline int ipv6_hash(struct __sk_buff *skb)
{
    __u32 nhoff;
    __u32 src_hash, dst_hash;

    nhoff = skb->cb[0];
    src_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, saddr));
    dst_hash = ipv6_addr_hash(skb,
                              nhoff + offsetof(struct ipv6hdr, daddr));

    return src_hash + dst_hash;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 145,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/lb.c",
  "funcName": "lb",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "\\loadbalancer\\)",
  "helper": [
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "cgroup_sock",
    "socket_filter",
    "lwt_xmit",
    "sk_skb",
    "tracepoint",
    "sched_act",
    "cgroup_skb",
    "sched_cls",
    "sk_msg",
    "raw_tracepoint_writable",
    "perf_event",
    "sk_reuseport",
    "lwt_out",
    "cgroup_device",
    "flow_dissector",
    "sock_ops",
    "kprobe",
    "lwt_seg6local",
    "lwt_in"
  ],
  "source": [
    "int  __section (\"loadbalancer\") lb (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u64 nhoff = ETH_HLEN;\n",
    "    __u16 proto = load_half (skb, ETH_HLEN - ETH_TLEN);\n",
    "    __u16 ret = proto;\n",
    "    switch (proto) {\n",
    "    case ETH_P_8021Q :\n",
    "    case ETH_P_8021AD :\n",
    "        {\n",
    "            __u16 vproto = load_half (skb, nhoff + offsetof (struct vlan_hdr, h_vlan_encapsulated_proto));\n",
    "            switch (vproto) {\n",
    "            case ETH_P_8021AD :\n",
    "            case ETH_P_8021Q :\n",
    "                nhoff += sizeof (struct vlan_hdr);\n",
    "                proto = load_half (skb, nhoff + offsetof (struct vlan_hdr, h_vlan_encapsulated_proto));\n",
    "                break;\n",
    "            default :\n",
    "                proto = vproto;\n",
    "            }\n",
    "            nhoff += sizeof (struct vlan_hdr);\n",
    "            skb->cb[0] = nhoff;\n",
    "            switch (proto) {\n",
    "            case ETH_P_IP :\n",
    "\n",
    "#if 0\n",
    "                {\n",
    "                    char fmt [] = \"ipv4\\n\";\n",
    "                    bpf_trace_printk (fmt, sizeof (fmt));\n",
    "                }\n",
    "\n",
    "#endif\n",
    "                ret = ipv4_hash (skb);\n",
    "                break;\n",
    "            case ETH_P_IPV6 :\n",
    "                ret = ipv6_hash (skb);\n",
    "                break;\n",
    "            default :\n",
    "\n",
    "#if 0\n",
    "                {\n",
    "                    char fmt [] = \"Dflt VLAN proto %u\\n\";\n",
    "                    bpf_trace_printk (fmt, sizeof (fmt), proto);\n",
    "                    break;\n",
    "                }\n",
    "\n",
    "#else\n",
    "                break;\n",
    "\n",
    "#endif\n",
    "            }\n",
    "        }\n",
    "        break;\n",
    "    case ETH_P_IP :\n",
    "        ret = ipv4_hash (skb);\n",
    "        break;\n",
    "    case ETH_P_IPV6 :\n",
    "        ret = ipv6_hash (skb);\n",
    "        break;\n",
    "    default :\n",
    "\n",
    "#if 0\n",
    "        {\n",
    "            char fmt [] = \"Got proto %x\\n\";\n",
    "            bpf_trace_printk (fmt, sizeof (fmt), proto);\n",
    "            break;\n",
    "        }\n",
    "\n",
    "#else\n",
    "        break;\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    return ret;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof",
    "ipv4_hash",
    "load_half",
    "ipv6_hash"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "The function parses the ethernet and VLAN headers to extract the IP header. Based on whether it is an IPv4 packet or IPv6 packet, the corresponding hashing functions are called and hash values are returned. If IP header is not present, the ether type is returned. ",
      "author": "Pragna Mamidipaka",
      "authorEmail": "pragna.pune@gmail.com",
      "date": "2023-04-05"
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
int  __section("loadbalancer") lb(struct __sk_buff *skb) {
    __u64 nhoff = ETH_HLEN;
    __u16 proto = load_half(skb, ETH_HLEN - ETH_TLEN);
    __u16 ret = proto;
    switch (proto) {
        case ETH_P_8021Q:
        case ETH_P_8021AD:
            {
                __u16 vproto = load_half(skb, nhoff +  offsetof(struct vlan_hdr, h_vlan_encapsulated_proto));
                switch(vproto) {
                    case ETH_P_8021AD:
                    case ETH_P_8021Q:
                        nhoff += sizeof(struct vlan_hdr);
                        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr, h_vlan_encapsulated_proto));
                        break;
                    default:
                        proto = vproto;
                }

                nhoff += sizeof(struct vlan_hdr);
                skb->cb[0] = nhoff;
                switch (proto) {
                    case ETH_P_IP:
#if 0
                        { char fmt[] = "ipv4\n"; bpf_trace_printk(fmt, sizeof(fmt));}
#endif
                        ret = ipv4_hash(skb);
                        break;
                    case ETH_P_IPV6:
                        ret = ipv6_hash(skb);
                        break;
                    default:
#if 0
                        {
                            char fmt[] = "Dflt VLAN proto %u\n";
                            bpf_trace_printk(fmt, sizeof(fmt), proto);
                            break;
                        }
#else
                        break;
#endif
                }
            }
            break;
        case ETH_P_IP:
            ret = ipv4_hash(skb);
            break;
        case ETH_P_IPV6:
            ret = ipv6_hash(skb);
            break;
        default:
#if 0
            {
                char fmt[] = "Got proto %x\n";
                bpf_trace_printk(fmt, sizeof(fmt), proto);
                break;
            }
#else
            break;
#endif
    }
    return ret;
}

char __license[] __section("license") = "GPL";

/* libbpf needs version section to check sync of eBPF code and kernel
 * but socket filter don't need it */
__u32 __version __section("version") = LINUX_VERSION_CODE;
