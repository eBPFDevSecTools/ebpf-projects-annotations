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

/* vlan tracking: set it to 0 if you don't use VLAN for flow tracking */
#define VLAN_TRACKING    1

#define LINUX_VERSION_CODE 263682

struct flowv4_keys {
    __u32 src;
    __u32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct flowv6_keys {
    __u32 src[4];
    __u32 dst[4];
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct pair {
    __u64 packets;
    __u64 bytes;
};

struct bpf_map_def SEC("maps") flow_table_v4 = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct flowv4_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

struct bpf_map_def SEC("maps") flow_table_v6 = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct flowv6_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

/**
 * IPv4 filter
 *
 * \return 0 to drop packet out and -1 to accept it
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
  "startLine": 88,
  "endLine": 148,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/bypass_filter.c",
  "funcName": "ipv4_filter",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 16,
      "text": "/* Copyright (C) 2018 Open Information Security Foundation\n *\n * You can copy, redistribute or modify this Program under the terms of\n * the GNU General Public License version 2 as published by the Free\n * Software Foundation.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License\n * version 2 along with this program; if not, write to the Free Software\n * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA\n * 02110-1301, USA.\n */"
    },
    {
      "start_line": 30,
      "end_line": 30,
      "text": "/* vlan tracking: set it to 0 if you don't use VLAN for flow tracking */"
    },
    {
      "start_line": 83,
      "end_line": 87,
      "text": "/**\n * IPv4 filter\n *\n * \\return 0 to drop packet out and -1 to accept it\n */"
    },
    {
      "start_line": 99,
      "end_line": 99,
      "text": "/* only support TCP and UDP for now */"
    },
    {
      "start_line": 114,
      "end_line": 114,
      "text": "/*offsetof(struct iphdr, ihl)*/"
    },
    {
      "start_line": 127,
      "end_line": 127,
      "text": "//__u16 dp = tuple.port16[1];"
    },
    {
      "start_line": 132,
      "end_line": 132,
      "text": "/* Test if src is in hash */"
    },
    {
      "start_line": 138,
      "end_line": 138,
      "text": "//__u16 dp = tuple.port16[1];"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  flow_table_v4"
  ],
  "input": [
    "struct  __sk_buff *skb",
    " __u16 vlan0",
    " __u16 vlan1"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_map_lookup_elem",
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
    "tracepoint",
    "sk_skb",
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
    "static __always_inline int ipv4_filter (struct  __sk_buff *skb, __u16 vlan0, __u16 vlan1)\n",
    "{\n",
    "    __u32 nhoff, verlen;\n",
    "    struct flowv4_keys tuple;\n",
    "    struct pair *value;\n",
    "    __u16 port;\n",
    "    __u8 ip_proto;\n",
    "    nhoff = skb->cb[0];\n",
    "    ip_proto = load_byte (skb, nhoff + offsetof (struct iphdr, protocol));\n",
    "    switch (ip_proto) {\n",
    "    case IPPROTO_TCP :\n",
    "        tuple.ip_proto = 1;\n",
    "        break;\n",
    "    case IPPROTO_UDP :\n",
    "        tuple.ip_proto = 0;\n",
    "        break;\n",
    "    default :\n",
    "        return -1;\n",
    "    }\n",
    "    tuple.src = load_word (skb, nhoff + offsetof (struct iphdr, saddr));\n",
    "    tuple.dst = load_word (skb, nhoff + offsetof (struct iphdr, daddr));\n",
    "    verlen = load_byte (skb, nhoff + 0);\n",
    "    nhoff += (verlen & 0xF) << 2;\n",
    "    tuple.ports = load_word (skb, nhoff);\n",
    "    port = tuple.port16[1];\n",
    "    tuple.port16[1] = tuple.port16[0];\n",
    "    tuple.port16[0] = port;\n",
    "    tuple.vlan0 = vlan0;\n",
    "    tuple.vlan1 = vlan1;\n",
    "\n",
    "#if 0\n",
    "    if ((tuple.port16[0] == 22) || (tuple.port16[1] == 22)) {\n",
    "        __u16 sp = tuple.port16[0];\n",
    "        char fmt [] = \"Parsed SSH flow: %u %d -> %u\\n\";\n",
    "        bpf_trace_printk (fmt, sizeof (fmt), tuple.src, sp, tuple.dst);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    value = bpf_map_lookup_elem (& flow_table_v4, & tuple);\n",
    "    if (value) {\n",
    "\n",
    "#if 0\n",
    "        {\n",
    "            __u16 sp = tuple.port16[0];\n",
    "            char bfmt [] = \"Found flow: %u %d -> %u\\n\";\n",
    "            bpf_trace_printk (bfmt, sizeof (bfmt), tuple.src, sp, tuple.dst);\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        value->packets++;\n",
    "        value->bytes += skb->len;\n",
    "        return 0;\n",
    "    }\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "load_byte",
    "load_word",
    "offsetof"
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
static __always_inline int ipv4_filter(struct __sk_buff *skb, __u16 vlan0, __u16 vlan1)
{
    __u32 nhoff, verlen;
    struct flowv4_keys tuple;
    struct pair *value;
    __u16 port;
    __u8 ip_proto;

    nhoff = skb->cb[0];

    ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));
    /* only support TCP and UDP for now */
    switch (ip_proto) {
        case IPPROTO_TCP:
            tuple.ip_proto = 1;
            break;
        case IPPROTO_UDP:
            tuple.ip_proto = 0;
            break;
        default:
            return -1;
    }
    
    tuple.src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    tuple.dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

    verlen = load_byte(skb, nhoff + 0/*offsetof(struct iphdr, ihl)*/);
    nhoff += (verlen & 0xF) << 2;
    tuple.ports = load_word(skb, nhoff);
    port = tuple.port16[1];
    tuple.port16[1] = tuple.port16[0];
    tuple.port16[0] = port;
    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

#if 0
    if ((tuple.port16[0] == 22) || (tuple.port16[1] == 22))
    {
        __u16 sp = tuple.port16[0];
        //__u16 dp = tuple.port16[1];
        char fmt[] = "Parsed SSH flow: %u %d -> %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, sp, tuple.dst);
    }
#endif
    /* Test if src is in hash */
    value = bpf_map_lookup_elem(&flow_table_v4, &tuple);
    if (value) {
#if 0
        {
            __u16 sp = tuple.port16[0];
            //__u16 dp = tuple.port16[1];
            char bfmt[] = "Found flow: %u %d -> %u\n";
            bpf_trace_printk(bfmt, sizeof(bfmt), tuple.src, sp, tuple.dst);
        }
#endif
        value->packets++;
        value->bytes += skb->len;
        return 0;
    }
    return -1;
}

/**
 * IPv6 filter
 *
 * \return 0 to drop packet out and -1 to accept it
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
  "startLine": 155,
  "endLine": 210,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/bypass_filter.c",
  "funcName": "ipv6_filter",
  "developer_inline_comments": [
    {
      "start_line": 150,
      "end_line": 154,
      "text": "/**\n * IPv6 filter\n *\n * \\return 0 to drop packet out and -1 to accept it\n */"
    },
    {
      "start_line": 165,
      "end_line": 165,
      "text": "/* get next header */"
    },
    {
      "start_line": 168,
      "end_line": 168,
      "text": "/* only support direct TCP and UDP for now */"
    },
    {
      "start_line": 189,
      "end_line": 189,
      "text": "/* Parse TCP */"
    },
    {
      "start_line": 190,
      "end_line": 190,
      "text": "/* IPV6_HEADER_LEN */"
    },
    {
      "start_line": 198,
      "end_line": 198,
      "text": "//char fmt[] = \"Now Got IPv6 port %u and %u\\n\";"
    },
    {
      "start_line": 199,
      "end_line": 199,
      "text": "//bpf_trace_printk(fmt, sizeof(fmt), tuple.port16[0], tuple.port16[1]);"
    },
    {
      "start_line": 200,
      "end_line": 200,
      "text": "/* Test if src is in hash */"
    },
    {
      "start_line": 203,
      "end_line": 203,
      "text": "//char fmt[] = \"Got a match IPv6: %u and %u\\n\";"
    },
    {
      "start_line": 204,
      "end_line": 204,
      "text": "//bpf_trace_printk(fmt, sizeof(fmt), tuple.port16[0], tuple.port16[1]);"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  flow_table_v6"
  ],
  "input": [
    "struct  __sk_buff *skb",
    " __u16 vlan0",
    " __u16 vlan1"
  ],
  "output": "static__always_inlineint",
  "helper": [
    "bpf_map_lookup_elem"
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
    "static __always_inline int ipv6_filter (struct  __sk_buff *skb, __u16 vlan0, __u16 vlan1)\n",
    "{\n",
    "    __u32 nhoff;\n",
    "    __u8 nhdr;\n",
    "    struct flowv6_keys tuple;\n",
    "    struct pair *value;\n",
    "    __u16 port;\n",
    "    nhoff = skb->cb[0];\n",
    "    nhdr = load_byte (skb, nhoff + offsetof (struct ipv6hdr, nexthdr));\n",
    "    switch (nhdr) {\n",
    "    case IPPROTO_TCP :\n",
    "        tuple.ip_proto = 1;\n",
    "        break;\n",
    "    case IPPROTO_UDP :\n",
    "        tuple.ip_proto = 0;\n",
    "        break;\n",
    "    default :\n",
    "        return -1;\n",
    "    }\n",
    "    tuple.src[0] = load_word (skb, nhoff + offsetof (struct ipv6hdr, saddr));\n",
    "    tuple.src[1] = load_word (skb, nhoff + offsetof (struct ipv6hdr, saddr) + 4);\n",
    "    tuple.src[2] = load_word (skb, nhoff + offsetof (struct ipv6hdr, saddr) + 8);\n",
    "    tuple.src[3] = load_word (skb, nhoff + offsetof (struct ipv6hdr, saddr) + 12);\n",
    "    tuple.dst[0] = load_word (skb, nhoff + offsetof (struct ipv6hdr, daddr));\n",
    "    tuple.dst[1] = load_word (skb, nhoff + offsetof (struct ipv6hdr, daddr) + 4);\n",
    "    tuple.dst[2] = load_word (skb, nhoff + offsetof (struct ipv6hdr, daddr) + 8);\n",
    "    tuple.dst[3] = load_word (skb, nhoff + offsetof (struct ipv6hdr, daddr) + 12);\n",
    "    tuple.ports = load_word (skb, nhoff + 40);\n",
    "    port = tuple.port16[1];\n",
    "    tuple.port16[1] = tuple.port16[0];\n",
    "    tuple.port16[0] = port;\n",
    "    tuple.vlan0 = vlan0;\n",
    "    tuple.vlan1 = vlan1;\n",
    "    value = bpf_map_lookup_elem (& flow_table_v6, & tuple);\n",
    "    if (value) {\n",
    "        value->packets++;\n",
    "        value->bytes += skb->len;\n",
    "        return 0;\n",
    "    }\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "load_byte",
    "load_word",
    "offsetof"
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
static __always_inline int ipv6_filter(struct __sk_buff *skb, __u16 vlan0, __u16 vlan1)
{
    __u32 nhoff;
    __u8 nhdr;
    struct flowv6_keys tuple;
    struct pair *value;
    __u16 port;

    nhoff = skb->cb[0];

    /* get next header */
    nhdr = load_byte(skb, nhoff + offsetof(struct ipv6hdr, nexthdr));

    /* only support direct TCP and UDP for now */
    switch (nhdr) {
        case IPPROTO_TCP:
            tuple.ip_proto = 1;
            break;
        case IPPROTO_UDP:
            tuple.ip_proto = 0;
            break;
        default:
            return -1;
    }

    tuple.src[0] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr));
    tuple.src[1] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 4);
    tuple.src[2] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 8);
    tuple.src[3] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 12);
    tuple.dst[0] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr));
    tuple.dst[1] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 4);
    tuple.dst[2] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 8);
    tuple.dst[3] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 12);

    /* Parse TCP */
    tuple.ports = load_word(skb, nhoff + 40 /* IPV6_HEADER_LEN */);
    port = tuple.port16[1];
    tuple.port16[1] = tuple.port16[0];
    tuple.port16[0] = port;

    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    //char fmt[] = "Now Got IPv6 port %u and %u\n";
    //bpf_trace_printk(fmt, sizeof(fmt), tuple.port16[0], tuple.port16[1]);
    /* Test if src is in hash */
    value = bpf_map_lookup_elem(&flow_table_v6, &tuple);
    if (value) {
        //char fmt[] = "Got a match IPv6: %u and %u\n";
        //bpf_trace_printk(fmt, sizeof(fmt), tuple.port16[0], tuple.port16[1]);
        value->packets++;
        value->bytes += skb->len;
        return 0;
    }
    return -1;
}

/**
 * filter function
 *
 * It is loaded in kernel by Suricata that uses the section name specified
 * by the SEC call to find it in the Elf binary object and load it.
 *
 * \return 0 to drop packet out and -1 to accept it
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 220,
  "endLine": 256,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/bypass_filter.c",
  "funcName": "hashfilter",
  "developer_inline_comments": [
    {
      "start_line": 212,
      "end_line": 219,
      "text": "/**\n * filter function\n *\n * It is loaded in kernel by Suricata that uses the section name specified\n * by the SEC call to find it in the Elf binary object and load it.\n *\n * \\return 0 to drop packet out and -1 to accept it\n */"
    },
    {
      "start_line": 231,
      "end_line": 231,
      "text": "/* one vlan layer is stripped by OS so get vlan 1 at first pass */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "\\filter\\)",
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
    "int SEC (\"filter\") hashfilter (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u32 nhoff = ETH_HLEN;\n",
    "    __u16 proto = load_half (skb, offsetof (struct ethhdr, h_proto));\n",
    "    __u16 vlan0 = skb->vlan_tci & 0x0fff;\n",
    "    __u16 vlan1 = 0;\n",
    "    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {\n",
    "        proto = load_half (skb, nhoff + offsetof (struct vlan_hdr, h_vlan_encapsulated_proto));\n",
    "\n",
    "#if VLAN_TRACKING\n",
    "        vlan1 = load_half (skb, nhoff + offsetof (struct vlan_hdr, h_vlan_TCI)) & 0x0fff;\n",
    "\n",
    "#endif\n",
    "        nhoff += sizeof (struct vlan_hdr);\n",
    "    }\n",
    "    skb->cb[0] = nhoff;\n",
    "    switch (proto) {\n",
    "    case ETH_P_IP :\n",
    "        return ipv4_filter (skb, vlan0, vlan1);\n",
    "    case ETH_P_IPV6 :\n",
    "        return ipv6_filter (skb, vlan0, vlan1);\n",
    "    default :\n",
    "\n",
    "#if 0\n",
    "        {\n",
    "            char fmt [] = \"Got proto %u\\n\";\n",
    "            bpf_trace_printk (fmt, sizeof (fmt), h_proto);\n",
    "            break;\n",
    "        }\n",
    "\n",
    "#else\n",
    "        break;\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof",
    "ipv4_filter",
    "load_half",
    "ipv6_filter"
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
int SEC("filter") hashfilter(struct __sk_buff *skb) {
    __u32 nhoff = ETH_HLEN;

    __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    __u16 vlan0 = skb->vlan_tci & 0x0fff;
    __u16 vlan1 = 0;

    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_encapsulated_proto));
#if VLAN_TRACKING
        /* one vlan layer is stripped by OS so get vlan 1 at first pass */
        vlan1 = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_TCI)) & 0x0fff;
#endif
        nhoff += sizeof(struct vlan_hdr);
    }

    skb->cb[0] = nhoff;
    switch (proto) {
        case ETH_P_IP:
            return ipv4_filter(skb, vlan0, vlan1);
        case ETH_P_IPV6:
            return ipv6_filter(skb, vlan0, vlan1);
        default:
#if 0
            {
                char fmt[] = "Got proto %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), h_proto);
                break;
            }
#else
            break;
#endif
    }
    return -1;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
