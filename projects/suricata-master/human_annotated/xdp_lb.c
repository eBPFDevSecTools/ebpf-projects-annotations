/* Copyright (C) 2019 Open Information Security Foundation
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

#define KBUILD_MODNAME "foo"
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
/* Workaround to avoid the need of 32bit headers */
#define _LINUX_IF_H
#define IFNAMSIZ 16
#include <linux/if_tunnel.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#include "hash_func01.h"

#define LINUX_VERSION_CODE 263682

/* Hashing initval */
#define INITVAL 15485863

/* Increase CPUMAP_MAX_CPUS if ever you have more than 128 CPUs */
#define CPUMAP_MAX_CPUS 128

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct bpf_map_def SEC("maps") cpu_map = {
    .type		= BPF_MAP_TYPE_CPUMAP,
    .key_size	= sizeof(__u32),
    .value_size	= sizeof(__u32),
    .max_entries	= CPUMAP_MAX_CPUS,
};

struct bpf_map_def SEC("maps") cpus_available = {
    .type		= BPF_MAP_TYPE_ARRAY,
    .key_size	= sizeof(__u32),
    .value_size	= sizeof(__u32),
    .max_entries	= CPUMAP_MAX_CPUS,
};

struct bpf_map_def SEC("maps") cpus_count = {
    .type		= BPF_MAP_TYPE_ARRAY,
    .key_size	= sizeof(__u32),
    .value_size	= sizeof(__u32),
    .max_entries	= 1,
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
    },
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_ABORTED",
          "Return": 0,
          "Description": "which serves denoting an exception like state from the program and has the same behavior as XDP_DROP only that XDP_ABORTED passes the trace_xdp_exception tracepoint which can be additionally monitored to detect misbehavior.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    },
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 73,
  "endLine": 99,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_lb.c",
  "funcName": "hash_ipv4",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 16,
      "text": "/* Copyright (C) 2019 Open Information Security Foundation\n *\n * You can copy, redistribute or modify this Program under the terms of\n * the GNU General Public License version 2 as published by the Free\n * Software Foundation.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License\n * version 2 along with this program; if not, write to the Free Software\n * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA\n * 02110-1301, USA.\n */"
    },
    {
      "start_line": 26,
      "end_line": 26,
      "text": "/* Workaround to avoid the need of 32bit headers */"
    },
    {
      "start_line": 40,
      "end_line": 40,
      "text": "/* Hashing initval */"
    },
    {
      "start_line": 43,
      "end_line": 43,
      "text": "/* Increase CPUMAP_MAX_CPUS if ever you have more than 128 CPUs */"
    },
    {
      "start_line": 51,
      "end_line": 51,
      "text": "/* Special map type that can XDP_REDIRECT frames to another CPU */"
    },
    {
      "start_line": 85,
      "end_line": 85,
      "text": "/* IP-pairs hit same CPU */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " cpus_count",
    "  cpus_available"
  ],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "XDP_ABORTED",
    "bpf_redirect_map",
    "bpf_redirect",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline hash_ipv4 (void *data, void *data_end)\n",
    "{\n",
    "    struct iphdr *iph = data;\n",
    "    if ((void *) (iph + 1) > data_end)\n",
    "        return XDP_PASS;\n",
    "    __u32 key0 = 0;\n",
    "    __u32 cpu_dest;\n",
    "    __u32 *cpu_max = bpf_map_lookup_elem (&cpus_count, &key0);\n",
    "    __u32 *cpu_selected;\n",
    "    __u32 cpu_hash;\n",
    "    cpu_hash = iph->saddr + iph->daddr;\n",
    "    cpu_hash = SuperFastHash ((char *) & cpu_hash, 4, INITVAL);\n",
    "    if (cpu_max && *cpu_max) {\n",
    "        cpu_dest = cpu_hash % *cpu_max;\n",
    "        cpu_selected = bpf_map_lookup_elem (& cpus_available, & cpu_dest);\n",
    "        if (!cpu_selected)\n",
    "            return XDP_ABORTED;\n",
    "        cpu_dest = *cpu_selected;\n",
    "        return bpf_redirect_map (&cpu_map, cpu_dest, 0);\n",
    "    }\n",
    "    else {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "SuperFastHash"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function composes the hash of the extracted IPv4 packet. After the initial bounds check, the cpu_hash is composed by adding the source and destination addresses. This is done in order to be able to hit the same CPU in case the source and destination IP pairs are the same. The SuperFastHash method is used to compose the hash. It takes in 3 arguments- constant character format of the composed cpu_hash, its length and a variable to add randomness called INITVAL. If the CPU assigned is greater than the maximum CPUs, modulus operator is used to wrap around and find a CPU within the maximum allocated range. If no CPU is assigned, the XDP-ABORTED action is returned. Else, the bpf_redirect_map is called to redirect the flow from one CPU to another allocated CPU.",",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
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
static int __always_inline hash_ipv4(void *data, void *data_end)
{
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;

    /* IP-pairs hit same CPU */
    cpu_hash = iph->saddr + iph->daddr;
    cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL);

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected)
            return XDP_ABORTED;
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }
}

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
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_ABORTED",
          "Return": 0,
          "Description": "which serves denoting an exception like state from the program and has the same behavior as XDP_DROP only that XDP_ABORTED passes the trace_xdp_exception tracepoint which can be additionally monitored to detect misbehavior.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_stop_processing_drop_packet"
          ]
        }
      ]
    },
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 101,
  "endLine": 132,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_lb.c",
  "funcName": "hash_ipv6",
  "developer_inline_comments": [
    {
      "start_line": 113,
      "end_line": 113,
      "text": "/* IP-pairs hit same CPU */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " cpus_count",
    "  cpus_available"
  ],
  "input": [
    "void *data",
    " void *data_end"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "bpf_map_lookup_elem",
    "XDP_ABORTED",
    "bpf_redirect_map",
    "bpf_redirect",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline hash_ipv6 (void *data, void *data_end)\n",
    "{\n",
    "    struct ipv6hdr *ip6h = data;\n",
    "    if ((void *) (ip6h + 1) > data_end)\n",
    "        return XDP_PASS;\n",
    "    __u32 key0 = 0;\n",
    "    __u32 cpu_dest;\n",
    "    __u32 *cpu_max = bpf_map_lookup_elem (&cpus_count, &key0);\n",
    "    __u32 *cpu_selected;\n",
    "    __u32 cpu_hash;\n",
    "    cpu_hash = ip6h->saddr.s6_addr32[0] + ip6h->daddr.s6_addr32[0];\n",
    "    cpu_hash += ip6h->saddr.s6_addr32[1] + ip6h->daddr.s6_addr32[1];\n",
    "    cpu_hash += ip6h->saddr.s6_addr32[2] + ip6h->daddr.s6_addr32[2];\n",
    "    cpu_hash += ip6h->saddr.s6_addr32[3] + ip6h->daddr.s6_addr32[3];\n",
    "    cpu_hash = SuperFastHash ((char *) & cpu_hash, 4, INITVAL);\n",
    "    if (cpu_max && *cpu_max) {\n",
    "        cpu_dest = cpu_hash % *cpu_max;\n",
    "        cpu_selected = bpf_map_lookup_elem (& cpus_available, & cpu_dest);\n",
    "        if (!cpu_selected)\n",
    "            return XDP_ABORTED;\n",
    "        cpu_dest = *cpu_selected;\n",
    "        return bpf_redirect_map (&cpu_map, cpu_dest, 0);\n",
    "    }\n",
    "    else {\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "SuperFastHash"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function composes the hash of the extracted IPv6 packet. After the initial bounds check, the cpu_hash is composed by adding the source and destination addresses. This is done in order to be able to hit the same CPU in case the source and destination IP pairs are the same. The SuperFastHash method is used to compose the hash. It takes in 3 arguments- constant character format of the composed cpu_hash, its length and a variable to add randomness called INITVAL. If the CPU assigned is greater than the maximum CPUs, modulus operator is used to wrap around and find a CPU within the maximum allocated range. If no CPU is assigned, the XDP-ABORTED action is returned. Else, the bpf_redirect_map is called to redirect the flow from one CPU to another allocated CPU.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
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
static int __always_inline hash_ipv6(void *data, void *data_end)
{
    struct ipv6hdr *ip6h = data;
    if ((void *)(ip6h + 1) > data_end)
        return XDP_PASS;

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;

    /* IP-pairs hit same CPU */
    cpu_hash  = ip6h->saddr.s6_addr32[0] + ip6h->daddr.s6_addr32[0];
    cpu_hash += ip6h->saddr.s6_addr32[1] + ip6h->daddr.s6_addr32[1];
    cpu_hash += ip6h->saddr.s6_addr32[2] + ip6h->daddr.s6_addr32[2];
    cpu_hash += ip6h->saddr.s6_addr32[3] + ip6h->daddr.s6_addr32[3];
    cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL);

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected)
            return XDP_ABORTED;
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }

    return XDP_PASS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 134,
  "endLine": 202,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_lb.c",
  "funcName": "filter_gre",
  "developer_inline_comments": [
    {
      "start_line": 161,
      "end_line": 161,
      "text": "/* Update offset to skip ERPSAN header if we have one */"
    },
    {
      "start_line": 174,
      "end_line": 174,
      "text": "/* we have now data starting at Ethernet header */"
    },
    {
      "start_line": 177,
      "end_line": 177,
      "text": "/* we want to hash on IP so we need to get to ip hdr */"
    },
    {
      "start_line": 183,
      "end_line": 184,
      "text": "/* we need to increase offset and update protocol\n     * in the case we have VLANs */"
    },
    {
      "start_line": 195,
      "end_line": 195,
      "text": "/* proto should now be IP style */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " void *data",
    " __u64 nh_off",
    " void *data_end"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline filter_gre (struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)\n",
    "{\n",
    "    struct iphdr *iph = data + nh_off;\n",
    "    __u16 proto;\n",
    "    struct gre_hdr {\n",
    "        __be16 flags;\n",
    "        __be16 proto;\n",
    "    }\n",
    "    ;\n",
    "    nh_off += sizeof (struct iphdr);\n",
    "    struct gre_hdr *grhdr = (struct gre_hdr *) (iph + 1);\n",
    "    if ((void *) (grhdr + 1) > data_end)\n",
    "        return XDP_PASS;\n",
    "    if (grhdr->flags & (GRE_VERSION | GRE_ROUTING))\n",
    "        return XDP_PASS;\n",
    "    nh_off += 4;\n",
    "    proto = grhdr->proto;\n",
    "    if (grhdr->flags & GRE_CSUM)\n",
    "        nh_off += 4;\n",
    "    if (grhdr->flags & GRE_KEY)\n",
    "        nh_off += 4;\n",
    "    if (grhdr->flags & GRE_SEQ)\n",
    "        nh_off += 4;\n",
    "    if (proto == __constant_htons (ETH_P_ERSPAN)) {\n",
    "        nh_off += 8;\n",
    "    }\n",
    "    if (data + nh_off > data_end)\n",
    "        return XDP_PASS;\n",
    "    if (bpf_xdp_adjust_head (ctx, 0 + nh_off))\n",
    "        return XDP_PASS;\n",
    "    data = (void *) (long) ctx->data;\n",
    "    data_end = (void *) (long) ctx->data_end;\n",
    "    struct ethhdr *eth = data;\n",
    "    proto = eth->h_proto;\n",
    "    nh_off = sizeof (*eth);\n",
    "    if (data + nh_off > data_end)\n",
    "        return XDP_PASS;\n",
    "    if (proto == __constant_htons (ETH_P_8021Q)) {\n",
    "        struct vlan_hdr *vhdr = (struct vlan_hdr *) (data + nh_off);\n",
    "        if ((void *) (vhdr + 1) > data_end)\n",
    "            return XDP_PASS;\n",
    "        proto = vhdr->h_vlan_encapsulated_proto;\n",
    "        nh_off += sizeof (struct vlan_hdr);\n",
    "    }\n",
    "    if (data + nh_off > data_end)\n",
    "        return XDP_PASS;\n",
    "    if (proto == __constant_htons (ETH_P_IP)) {\n",
    "        return hash_ipv4 (data + nh_off, data_end);\n",
    "    }\n",
    "    else if (proto == __constant_htons (ETH_P_IPV6)) {\n",
    "        return hash_ipv6 (data + nh_off, data_end);\n",
    "    }\n",
    "    else\n",
    "        return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "__constant_htons",
    "hash_ipv4",
    "hash_ipv6"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function extracts the encapsulated IP header packet to be hashed. Initially the GRE header is processed to get the GRE_VERSION and GRE_ROUTING information. Then any ERPSAN and VLAN headers present are stripped to reach the ETHERNET HEADER. Based on the version of the IP packet mentioned the relevant function handles the hashing. i.e. either hash_ipv4 or hash_ipv6. If an IP header is not present the packet is passed onto the usual system packet processing stack.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
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
static int __always_inline filter_gre(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    __u16 proto;
    struct gre_hdr {
        __be16 flags;
        __be16 proto;
    };

    nh_off += sizeof(struct iphdr);
    struct gre_hdr *grhdr = (struct gre_hdr *)(iph + 1);

    if ((void *)(grhdr + 1) > data_end)
        return XDP_PASS;

    if (grhdr->flags & (GRE_VERSION|GRE_ROUTING))
        return XDP_PASS;

    nh_off += 4;
    proto = grhdr->proto;
    if (grhdr->flags & GRE_CSUM)
        nh_off += 4;
    if (grhdr->flags & GRE_KEY)
        nh_off += 4;
    if (grhdr->flags & GRE_SEQ)
        nh_off += 4;

    /* Update offset to skip ERPSAN header if we have one */
    if (proto == __constant_htons(ETH_P_ERSPAN)) {
        nh_off += 8;
    }

    if (data + nh_off > data_end)
        return XDP_PASS;
    if (bpf_xdp_adjust_head(ctx, 0 + nh_off))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* we have now data starting at Ethernet header */
    struct ethhdr *eth = data;
    proto = eth->h_proto;
    /* we want to hash on IP so we need to get to ip hdr */
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_PASS;

    /* we need to increase offset and update protocol
     * in the case we have VLANs */
    if (proto == __constant_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vhdr = (struct vlan_hdr *)(data + nh_off);
        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;
        proto = vhdr->h_vlan_encapsulated_proto;
        nh_off += sizeof(struct vlan_hdr);
    }

    if (data + nh_off > data_end)
        return XDP_PASS;
    /* proto should now be IP style */
    if (proto == __constant_htons(ETH_P_IP)) {
        return hash_ipv4(data + nh_off, data_end);
    } else if (proto == __constant_htons(ETH_P_IPV6)) {
        return hash_ipv6(data + nh_off, data_end);
    } else
        return XDP_PASS;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 204,
  "endLine": 214,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_lb.c",
  "funcName": "filter_ipv4",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " void *data",
    " __u64 nh_off",
    " void *data_end"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline filter_ipv4 (struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)\n",
    "{\n",
    "    struct iphdr *iph = data + nh_off;\n",
    "    if ((void *) (iph + 1) > data_end)\n",
    "        return XDP_PASS;\n",
    "    if (iph->protocol == IPPROTO_GRE) {\n",
    "        return filter_gre (ctx, data, nh_off, data_end);\n",
    "    }\n",
    "    return hash_ipv4 (data + nh_off, data_end);\n",
    "}\n"
  ],
  "called_function_list": [
    "SuperFastHash",
    "__sync_fetch_and_add",
    "hash_ipv4",
    "get_sport",
    "filter_gre",
    "__constant_ntohs",
    "get_dport"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function filters the IPv4 packets. It initially does the basic bounds checking for the packet length, the packet is checked for a GRE header. If there is a GRE header it is handled by the filter_gre function, else the IPv4 packet is extracted to be hashed by hash_ipv4 funtion.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
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
static int __always_inline filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_GRE) {
        return filter_gre(ctx, data, nh_off, data_end);
    }
    return hash_ipv4(data + nh_off, data_end);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 216,
  "endLine": 220,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_lb.c",
  "funcName": "filter_ipv6",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " void *data",
    " __u64 nh_off",
    " void *data_end"
  ],
  "output": "staticint__always_inline",
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
    "static int __always_inline filter_ipv6 (struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)\n",
    "{\n",
    "    struct ipv6hdr *ip6h = data + nh_off;\n",
    "    return hash_ipv6 ((void *) ip6h, data_end);\n",
    "}\n"
  ],
  "called_function_list": [
    "SuperFastHash",
    "__sync_fetch_and_add",
    "hash_ipv6",
    "get_sport",
    "get_dport",
    "__builtin_memcpy"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function extracts the IPv6 packet and is then sent to be handled by the hash_ipv6 method.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
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
static int __always_inline filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct ipv6hdr *ip6h = data + nh_off;
    return hash_ipv6((void *)ip6h, data_end);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_go_to_next_module",
      "pkt_go_to_next_module": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_PASS",
          "Return": 2,
          "Description": "The XDP_PASS return code means that the packet is allowed to be passed up to the kernel\u2019s networking stack. Meaning, the current CPU that was processing this packet now allocates a skb, populates it, and passes it onwards into the GRO engine. This would be equivalent to the default packet handling behavior without XDP.",
          "compatible_hookpoints": [
            "xdp"
          ],
          "capabilities": [
            "pkt_go_to_next_module"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 222,
  "endLine": 267,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_lb.c",
  "funcName": "xdp_loadfilter",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "\\xdp\\)",
  "helper": [
    "XDP_PASS",
    "bpf_trace_printk"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int SEC (\"xdp\") xdp_loadfilter (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct ethhdr *eth = data;\n",
    "    __u16 h_proto;\n",
    "    __u64 nh_off;\n",
    "    nh_off = sizeof (*eth);\n",
    "    if (data + nh_off > data_end)\n",
    "        return XDP_PASS;\n",
    "    h_proto = eth->h_proto;\n",
    "\n",
    "#if 0\n",
    "    if (h_proto != __constant_htons (ETH_P_IP)) {\n",
    "        char fmt [] = \"Current proto: %u\\n\";\n",
    "        bpf_trace_printk (fmt, sizeof (fmt), h_proto);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if (h_proto == __constant_htons (ETH_P_8021Q) || h_proto == __constant_htons (ETH_P_8021AD)) {\n",
    "        struct vlan_hdr *vhdr;\n",
    "        vhdr = data + nh_off;\n",
    "        nh_off += sizeof (struct vlan_hdr);\n",
    "        if (data + nh_off > data_end)\n",
    "            return XDP_PASS;\n",
    "        h_proto = vhdr->h_vlan_encapsulated_proto;\n",
    "    }\n",
    "    if (h_proto == __constant_htons (ETH_P_8021Q) || h_proto == __constant_htons (ETH_P_8021AD)) {\n",
    "        struct vlan_hdr *vhdr;\n",
    "        vhdr = data + nh_off;\n",
    "        nh_off += sizeof (struct vlan_hdr);\n",
    "        if (data + nh_off > data_end)\n",
    "            return XDP_PASS;\n",
    "        h_proto = vhdr->h_vlan_encapsulated_proto;\n",
    "    }\n",
    "    if (h_proto == __constant_htons (ETH_P_IP))\n",
    "        return filter_ipv4 (ctx, data, nh_off, data_end);\n",
    "    else if (h_proto == __constant_htons (ETH_P_IPV6))\n",
    "        return filter_ipv6 (ctx, data, nh_off, data_end);\n",
    "    return XDP_PASS;\n",
    "}\n"
  ],
  "called_function_list": [
    "__constant_htons",
    "filter_ipv6",
    "filter_ipv4"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function parses the received packet to extract the VLAN header, followed by the Ethernet header. Based on the version of the IP packet relevant filter functions are called i.e, for IPv4 packets filter_ipv4 function is called and for IPv6 packets the filter_ipv6 function is called.",
      "author": "Madhuri Annavazzala",
      "authorEmail": "madhuriannavazzala@gmail.com",
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
int SEC("xdp") xdp_loadfilter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

#if 0
    if (h_proto != __constant_htons(ETH_P_IP)) {
        char fmt[] = "Current proto: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), h_proto);
    }
#endif
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == __constant_htons(ETH_P_IP))
        return filter_ipv4(ctx, data, nh_off, data_end);
    else if (h_proto == __constant_htons(ETH_P_IPV6))
        return filter_ipv6(ctx, data, nh_off, data_end);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
