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

#define DEBUG 0

#define LINUX_VERSION_CODE 263682

struct bpf_map_def SEC("maps") ipv4_drop = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32768,
};

struct vlan_hdr {
    __u16   h_vlan_TCI;
    __u16   h_vlan_encapsulated_proto;
};

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
  "startLine": 46,
  "endLine": 81,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/filter.c",
  "funcName": "ipv4_filter",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 16,
      "text": "/* Copyright (C) 2018 Open Information Security Foundation\n *\n * You can copy, redistribute or modify this Program under the terms of\n * the GNU General Public License version 2 as published by the Free\n * Software Foundation.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License\n * version 2 along with this program; if not, write to the Free Software\n * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA\n * 02110-1301, USA.\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  ipv4_drop"
  ],
  "input": [
    "struct  __sk_buff *skb"
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
    "static __always_inline int ipv4_filter (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u32 nhoff;\n",
    "    __u32 *value;\n",
    "    __u32 ip = 0;\n",
    "    nhoff = skb->cb[0];\n",
    "    ip = load_word (skb, nhoff + offsetof (struct iphdr, saddr));\n",
    "    value = bpf_map_lookup_elem (& ipv4_drop, & ip);\n",
    "    if (value) {\n",
    "\n",
    "#if DEBUG\n",
    "        char fmt [] = \"Found value for saddr: %u\\n\";\n",
    "        bpf_trace_printk (fmt, sizeof (fmt), value);\n",
    "\n",
    "#endif\n",
    "        *value = *value + 1;\n",
    "        return 0;\n",
    "    }\n",
    "    ip = load_word (skb, nhoff + offsetof (struct iphdr, daddr));\n",
    "    value = bpf_map_lookup_elem (& ipv4_drop, & ip);\n",
    "    if (value) {\n",
    "\n",
    "#if DEBUG\n",
    "        char fmt [] = \"Found value for daddr: %u\\n\";\n",
    "        bpf_trace_printk (fmt, sizeof (fmt), value);\n",
    "\n",
    "#endif\n",
    "        *value = *value + 1;\n",
    "        return 0;\n",
    "    }\n",
    "\n",
    "#if DEBUG\n",
    "    char fmt [] = \"Nothing so ok\\n\";\n",
    "    bpf_trace_printk (fmt, sizeof (fmt));\n",
    "\n",
    "#endif\n",
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
      "description": "The function extracts the src and dest IP addresses of the IPv4 packet, and checks whether they are in the list of IPs to be dropped. If yes, count of packet drops is incremented by 1, and function returns 0. If not, function returns -1.",
      "author": "Pragna Mamidipaka",
      "authorEmail": "pragna.pune@gmail.com",
      "date": "2023-04-04"
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
static __always_inline int ipv4_filter(struct __sk_buff *skb)
{
    __u32 nhoff;
    __u32 *value;
    __u32 ip = 0;

    nhoff = skb->cb[0];

    ip = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for saddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        *value = *value + 1;
        return 0;
    }

    ip = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for daddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        *value = *value + 1;
        return 0;
    }

#if DEBUG
    char fmt[] = "Nothing so ok\n";
    bpf_trace_printk(fmt, sizeof(fmt));
#endif
    return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 83,
  "endLine": 86,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/filter.c",
  "funcName": "ipv6_filter",
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
    "static __always_inline int ipv6_filter (struct  __sk_buff *skb)\n",
    "{\n",
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
      "description": "The function does not filter any IPv6 packets. It returns -1 for all packets.",
      "author": "Pragna Mamidipaka",
      "authorEmail": "pragna.pune@gmail.com",
      "date": "2023-04-04"
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
static __always_inline int ipv6_filter(struct __sk_buff *skb)
{
    return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 88,
  "endLine": 110,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/filter.c",
  "funcName": "hashfilter",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "\\filter\\)",
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
    "int SEC (\"filter\") hashfilter (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u32 nhoff = ETH_HLEN;\n",
    "    __u16 proto = load_half (skb, offsetof (struct ethhdr, h_proto));\n",
    "    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {\n",
    "        proto = load_half (skb, nhoff + offsetof (struct vlan_hdr, h_vlan_encapsulated_proto));\n",
    "        nhoff += sizeof (struct vlan_hdr);\n",
    "    }\n",
    "    skb->cb[0] = nhoff;\n",
    "    switch (proto) {\n",
    "    case ETH_P_IP :\n",
    "        return ipv4_filter (skb);\n",
    "    case ETH_P_IPV6 :\n",
    "        return ipv6_filter (skb);\n",
    "    default :\n",
    "        break;\n",
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
      "description": "The function checks whether the packet is an IPv4 packet or an IPv6 packet, and correspondingly calls the filter functions.",
      "author": "Pragna Mamidipaka",
      "authorEmail": "pragna.pune@gmail.com",
      "date": "2023-04-04"
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
int SEC("filter") hashfilter(struct __sk_buff *skb)
{
    __u32 nhoff = ETH_HLEN;

    __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));

    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_encapsulated_proto));
        nhoff += sizeof(struct vlan_hdr);
    }

    skb->cb[0] = nhoff;
    switch (proto) {
        case ETH_P_IP:
            return ipv4_filter(skb);
        case ETH_P_IPV6:
            return ipv6_filter(skb);
        default:
            break;
    }
    return -1;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
