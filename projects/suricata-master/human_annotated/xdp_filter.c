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

#define KBUILD_MODNAME "foo"
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#include "hash_func01.h"

#define LINUX_VERSION_CODE 263682

/* Hashing initval */
#define INITVAL 15485863

/* Set BUILD_CPUMAP to 0 if you want to run XDP bypass on kernel
 * older than 4.15 */
#define BUILD_CPUMAP        1
/* Increase CPUMAP_MAX_CPUS if ever you have more than 64 CPUs */
#define CPUMAP_MAX_CPUS     64

/* Set to 1 to bypass encrypted packets of TLS sessions. Suricata will
 * be blind to these packets or forged packets looking alike. */
#define ENCRYPTED_TLS_BYPASS    0

/* Set it to 0 if for example you plan to use the XDP filter in a
 * network card that don't support per CPU value (like netronome) */
#define USE_PERCPU_HASH     1
/* Set it to 0 if your XDP subsystem don't handle XDP_REDIRECT (like netronome) */
#define GOT_TX_PEER         1

/* set to non 0 to load balance in hardware mode on RSS_QUEUE_NUMBERS queues
 * and unset BUILD_CPUMAP (number must be a power of 2 for netronome) */
#define RSS_QUEUE_NUMBERS   32

/* no vlan tracking: set it to 0 if you don't use VLAN for tracking. Can
 * also be used as workaround of some hardware offload issue */
#define VLAN_TRACKING    1

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

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
#if USE_PERCPU_HASH
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#else
    .type = BPF_MAP_TYPE_HASH,
#endif
    .key_size = sizeof(struct flowv4_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

struct bpf_map_def SEC("maps") flow_table_v6 = {
#if USE_PERCPU_HASH
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#else
    .type = BPF_MAP_TYPE_HASH,
#endif
    .key_size = sizeof(struct flowv6_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};


#if ENCRYPTED_TLS_BYPASS
struct bpf_map_def SEC("maps") tls_bypass_count = {
#if USE_PERCPU_HASH
    .type		= BPF_MAP_TYPE_PERCPU_ARRAY,
#else
    .type		= BPF_MAP_TYPE_ARRAY,
#endif
    .key_size	= sizeof(__u32),
    .value_size	= sizeof(__u64),
    .max_entries	= 1,
};
#endif

#if BUILD_CPUMAP
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
#endif

#if GOT_TX_PEER
/* Map has only one element as we don't handle any sort of
 * routing for now. Key value set by user space is 0 and
 * value is the peer interface. */
struct bpf_map_def SEC("maps") tx_peer = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

/* single entry to indicate if we have peer, key value
 * set in user space is 0. It is only used to see if
 * a interface has a peer we need to send the information to */
struct bpf_map_def SEC("maps") tx_peer_int = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};
#endif

#define USE_GLOBAL_BYPASS   0
#if USE_GLOBAL_BYPASS
/* single entry to indicate if global bypass switch is on */
struct bpf_map_def SEC("maps") global_bypass = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(char),
    .value_size = sizeof(char),
    .max_entries = 1,
};
#endif


/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 191,
  "endLine": 211,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_filter.c",
  "funcName": "get_sport",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 16,
      "text": "/* Copyright (C) 2018 Open Information Security Foundation\n *\n * You can copy, redistribute or modify this Program under the terms of\n * the GNU General Public License version 2 as published by the Free\n * Software Foundation.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License\n * version 2 along with this program; if not, write to the Free Software\n * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA\n * 02110-1301, USA.\n */"
    },
    {
      "start_line": 36,
      "end_line": 36,
      "text": "/* Hashing initval */"
    },
    {
      "start_line": 39,
      "end_line": 40,
      "text": "/* Set BUILD_CPUMAP to 0 if you want to run XDP bypass on kernel\n * older than 4.15 */"
    },
    {
      "start_line": 42,
      "end_line": 42,
      "text": "/* Increase CPUMAP_MAX_CPUS if ever you have more than 64 CPUs */"
    },
    {
      "start_line": 45,
      "end_line": 46,
      "text": "/* Set to 1 to bypass encrypted packets of TLS sessions. Suricata will\n * be blind to these packets or forged packets looking alike. */"
    },
    {
      "start_line": 49,
      "end_line": 50,
      "text": "/* Set it to 0 if for example you plan to use the XDP filter in a\n * network card that don't support per CPU value (like netronome) */"
    },
    {
      "start_line": 52,
      "end_line": 52,
      "text": "/* Set it to 0 if your XDP subsystem don't handle XDP_REDIRECT (like netronome) */"
    },
    {
      "start_line": 55,
      "end_line": 56,
      "text": "/* set to non 0 to load balance in hardware mode on RSS_QUEUE_NUMBERS queues\n * and unset BUILD_CPUMAP (number must be a power of 2 for netronome) */"
    },
    {
      "start_line": 59,
      "end_line": 60,
      "text": "/* no vlan tracking: set it to 0 if you don't use VLAN for tracking. Can\n * also be used as workaround of some hardware offload issue */"
    },
    {
      "start_line": 134,
      "end_line": 134,
      "text": "/* Special map type that can XDP_REDIRECT frames to another CPU */"
    },
    {
      "start_line": 158,
      "end_line": 160,
      "text": "/* Map has only one element as we don't handle any sort of\n * routing for now. Key value set by user space is 0 and\n * value is the peer interface. */"
    },
    {
      "start_line": 168,
      "end_line": 170,
      "text": "/* single entry to indicate if we have peer, key value\n * set in user space is 0. It is only used to see if\n * a interface has a peer we need to send the information to */"
    },
    {
      "start_line": 181,
      "end_line": 181,
      "text": "/* single entry to indicate if global bypass switch is on */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *trans_data",
    " void *data_end",
    " __u8 protocol"
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
    "static __always_inline int get_sport (void *trans_data, void *data_end, __u8 protocol)\n",
    "{\n",
    "    struct tcphdr *th;\n",
    "    struct udphdr *uh;\n",
    "    switch (protocol) {\n",
    "    case IPPROTO_TCP :\n",
    "        th = (struct tcphdr *) trans_data;\n",
    "        if ((void *) (th + 1) > data_end)\n",
    "            return -1;\n",
    "        return th->source;\n",
    "    case IPPROTO_UDP :\n",
    "        uh = (struct udphdr *) trans_data;\n",
    "        if ((void *) (uh + 1) > data_end)\n",
    "            return -1;\n",
    "        return uh->source;\n",
    "    default :\n",
    "        return 0;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    {
      "description": "This function extracts and returns the source port of the TCP and UDP packets. Returns -1 if the packet is invalid. Returns 0 if the packet is neither TCP nor UDP.",
      "author": "R V B R N Aaseesh",
      "authorEmail": "ee20btech11060@iith.ac.in",
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
static __always_inline int get_sport(void *trans_data, void *data_end,
        __u8 protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end)
                return -1;
            return th->source;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->source;
        default:
            return 0;
    }
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 213,
  "endLine": 233,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_filter.c",
  "funcName": "get_dport",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void *trans_data",
    " void *data_end",
    " __u8 protocol"
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
    "static __always_inline int get_dport (void *trans_data, void *data_end, __u8 protocol)\n",
    "{\n",
    "    struct tcphdr *th;\n",
    "    struct udphdr *uh;\n",
    "    switch (protocol) {\n",
    "    case IPPROTO_TCP :\n",
    "        th = (struct tcphdr *) trans_data;\n",
    "        if ((void *) (th + 1) > data_end)\n",
    "            return -1;\n",
    "        return th->dest;\n",
    "    case IPPROTO_UDP :\n",
    "        uh = (struct udphdr *) trans_data;\n",
    "        if ((void *) (uh + 1) > data_end)\n",
    "            return -1;\n",
    "        return uh->dest;\n",
    "    default :\n",
    "        return 0;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    {
      "description": "This function extracts and returns the destination port of the TCP and UDP packets. Returns -1 if the packet is invalid. Returns 0 if the packet is neither TCP nor UDP.",
      "author": "R V B R N Aaseesh",
      "authorEmail": "ee20btech11060@iith.ac.in",
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
static __always_inline int get_dport(void *trans_data, void *data_end,
        __u8 protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end)
                return -1;
            return th->dest;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->dest;
        default:
            return 0;
    }
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
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
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
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
  "startLine": 235,
  "endLine": 377,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_filter.c",
  "funcName": "filter_ipv4",
  "developer_inline_comments": [
    {
      "start_line": 324,
      "end_line": 324,
      "text": "/* drop application data for tls 1.2 */"
    },
    {
      "start_line": 325,
      "end_line": 325,
      "text": "/* FIXME better parsing */"
    },
    {
      "start_line": 354,
      "end_line": 354,
      "text": "/* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */"
    },
    {
      "start_line": 370,
      "end_line": 370,
      "text": "/* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  flow_table_v4",
    "  tx_peer_int",
    " cpus_count",
    "  tls_bypass_count",
    "  cpus_available"
  ],
  "input": [
    "struct xdp_md *ctx",
    " void *data",
    " __u64 nh_off",
    " void *data_end",
    " __u16 vlan0",
    " __u16 vlan1"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "XDP_ABORTED",
    "bpf_redirect_map",
    "bpf_redirect",
    "bpf_trace_printk",
    "XDP_DROP",
    "bpf_map_lookup_elem",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline filter_ipv4 (struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)\n",
    "{\n",
    "    struct iphdr *iph = data + nh_off;\n",
    "    int dport;\n",
    "    int sport;\n",
    "    struct flowv4_keys tuple;\n",
    "    struct pair *value;\n",
    "\n",
    "#if BUILD_CPUMAP || GOT_TX_PEER\n",
    "    __u32 key0 = 0;\n",
    "\n",
    "#endif\n",
    "\n",
    "#if ENCRYPTED_TLS_BYPASS\n",
    "    __u32 key1 = 0;\n",
    "    __u32 *tls_count = NULL;\n",
    "\n",
    "#endif\n",
    "\n",
    "#if BUILD_CPUMAP\n",
    "    __u32 cpu_dest;\n",
    "    __u32 *cpu_max = bpf_map_lookup_elem (&cpus_count, &key0);\n",
    "    __u32 *cpu_selected;\n",
    "    __u32 cpu_hash;\n",
    "\n",
    "#endif\n",
    "\n",
    "#if GOT_TX_PEER\n",
    "    int *iface_peer;\n",
    "    int tx_port = 0;\n",
    "\n",
    "#endif\n",
    "    if ((void *) (iph + 1) > data_end)\n",
    "        return XDP_PASS;\n",
    "    if (iph->protocol == IPPROTO_TCP) {\n",
    "        tuple.ip_proto = 1;\n",
    "    }\n",
    "    else {\n",
    "        tuple.ip_proto = 0;\n",
    "    }\n",
    "    tuple.src = iph->saddr;\n",
    "    tuple.dst = iph->daddr;\n",
    "    dport = get_dport (iph + 1, data_end, iph -> protocol);\n",
    "    if (dport == -1)\n",
    "        return XDP_PASS;\n",
    "    sport = get_sport (iph + 1, data_end, iph -> protocol);\n",
    "    if (sport == -1)\n",
    "        return XDP_PASS;\n",
    "    tuple.port16[0] = (__u16) sport;\n",
    "    tuple.port16[1] = (__u16) dport;\n",
    "    tuple.vlan0 = vlan0;\n",
    "    tuple.vlan1 = vlan1;\n",
    "    value = bpf_map_lookup_elem (& flow_table_v4, & tuple);\n",
    "\n",
    "#if 0\n",
    "    {\n",
    "        char fmt [] = \"Current flow src: %u:%d\\n\";\n",
    "        char fmt1 [] = \"Current flow dst: %u:%d\\n\";\n",
    "        bpf_trace_printk (fmt, sizeof (fmt), tuple.src, tuple.port16[0]);\n",
    "        bpf_trace_printk (fmt1, sizeof (fmt1), tuple.dst, tuple.port16[1]);\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    if (value) {\n",
    "\n",
    "#if 0\n",
    "        char fmt [] = \"Found flow v4: %u %d -> %d\\n\";\n",
    "        bpf_trace_printk (fmt, sizeof (fmt), tuple.src, sport, dport);\n",
    "        char fmt [] = \"Data: t:%lu p:%lu n:%lu\\n\";\n",
    "        bpf_trace_printk (fmt, sizeof (fmt), value->time, value->packets, value->bytes);\n",
    "\n",
    "#endif\n",
    "\n",
    "#if USE_PERCPU_HASH\n",
    "        value->packets++;\n",
    "        value->bytes += data_end - data;\n",
    "\n",
    "#else\n",
    "        __sync_fetch_and_add (&value->packets, 1);\n",
    "        __sync_fetch_and_add (&value->bytes, data_end - data);\n",
    "\n",
    "#endif\n",
    "\n",
    "#if GOT_TX_PEER\n",
    "        iface_peer = bpf_map_lookup_elem (& tx_peer_int, & key0);\n",
    "        if (!iface_peer) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        else {\n",
    "            return bpf_redirect_map (&tx_peer, tx_port, 0);\n",
    "        }\n",
    "\n",
    "#else\n",
    "        return XDP_DROP;\n",
    "\n",
    "#endif\n",
    "    }\n",
    "\n",
    "#if ENCRYPTED_TLS_BYPASS\n",
    "    if ((dport == __constant_ntohs (443)) || (sport == __constant_ntohs (443))) {\n",
    "        __u8 *app_data;\n",
    "        nh_off += sizeof (struct iphdr) + sizeof (struct tcphdr);\n",
    "        if (data_end > data + nh_off + 4) {\n",
    "            app_data = data + nh_off;\n",
    "            if (app_data[0] == 0x17 && app_data[1] == 0x3 && app_data[2] == 0x3) {\n",
    "                tls_count = bpf_map_lookup_elem (& tls_bypass_count, & key1);\n",
    "                if (tls_count) {\n",
    "\n",
    "#if USE_PERCPU_HASH\n",
    "                    tls_count++;\n",
    "\n",
    "#else\n",
    "                    __sync_fetch_and_add (tls_count, 1);\n",
    "\n",
    "#endif\n",
    "                }\n",
    "\n",
    "#if GOT_TX_PEER\n",
    "                iface_peer = bpf_map_lookup_elem (& tx_peer_int, & key0);\n",
    "                if (!iface_peer) {\n",
    "                    return XDP_DROP;\n",
    "                }\n",
    "                else {\n",
    "                    return bpf_redirect_map (&tx_peer, tx_port, 0);\n",
    "                }\n",
    "\n",
    "#else\n",
    "                return XDP_DROP;\n",
    "\n",
    "#endif\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif\n",
    "\n",
    "#if BUILD_CPUMAP\n",
    "    cpu_hash = tuple.src + tuple.dst;\n",
    "    cpu_hash = SuperFastHash ((char *) & cpu_hash, 4, INITVAL + iph -> protocol);\n",
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
    "\n",
    "#else\n",
    "\n",
    "#if RSS_QUEUE_NUMBERS\n",
    "    __u32 xdp_hash = tuple.src + tuple.dst;\n",
    "    xdp_hash = SuperFastHash ((char *) & xdp_hash, 4, INITVAL + iph -> protocol);\n",
    "    ctx->rx_queue_index = xdp_hash % RSS_QUEUE_NUMBERS;\n",
    "\n",
    "#endif\n",
    "    return XDP_PASS;\n",
    "\n",
    "#endif\n",
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
      "description": "This function filters the IPv4 packets. If the L4 protocol is TCP, tuple.ip_proto is set to 1. If it is UDP, tuple.ip_proto is set to 0. The source port and destination port of the packet are also extracted. The packet is DROPPED if the packets' ports are not able to get extracted. The tuple array consists of the identification fields for the packet such as - src address, destination address, src port, dest port, vlan0 and vlan1 (used for VLAN flow tracking) which are then used as a key to lookup in the map. If it exists, the number of packets is incremented by 1 and the bytes is incremented by the length of the packet. The increments are done using atomic operations if the map type is BPF_MAP_TYPE_ARRAY. If GOT_TX_PEER flag is enabled, the key0 is initialized as 0. The key is then searched in tx_peer_int BPF MAP. The packet is dropped if the key doesn't exist. Otherwise, the packet is redirect to the corresponding port. If ENCRYPTED_TLS_BYPASS flag is set, the key1 variable is initialized to 0. Then, the transport protocol is checked if it is secured. If the protocol is secured, the key1 is searched in the tls_bypass_count and incremented appropriately. If BUILD_CPUMAP flag is set, the hash is generated using the src and dst addresses using the SuperFastHash function. A destination CPU is selected from the available CPUs using this hash as key. If the corresponding value exists in the map, the packet is redirected to the destination CPU, otherwise it is dropped. If the RSS_QUE_NUMBERS macro is defined, the hash is generated using src and dst addresses using the SuperFastHash function. The rx_queue_index field of the context variable is updated with the hash. The packet is PASSED.",
      "author": "R V B R N Aaseesh",
      "authorEmail": "ee20btech11060@iith.ac.in",
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
static int __always_inline filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct iphdr *iph = data + nh_off;
    int dport;
    int sport;
    struct flowv4_keys tuple;
    struct pair *value;
#if BUILD_CPUMAP || GOT_TX_PEER
    __u32 key0 = 0;
#endif
#if ENCRYPTED_TLS_BYPASS
    __u32 key1 = 0;
    __u32 *tls_count = NULL;
#endif
#if BUILD_CPUMAP
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;
#endif
#if GOT_TX_PEER
    int *iface_peer;
    int tx_port = 0;
#endif

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_TCP) {
        tuple.ip_proto = 1;
    } else {
        tuple.ip_proto = 0;
    }
    tuple.src = iph->saddr;
    tuple.dst = iph->daddr;

    dport = get_dport(iph + 1, data_end, iph->protocol);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(iph + 1, data_end, iph->protocol);
    if (sport == -1)
        return XDP_PASS;

    tuple.port16[0] = (__u16)sport;
    tuple.port16[1] = (__u16)dport;

    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    value = bpf_map_lookup_elem(&flow_table_v4, &tuple);
#if 0
    {
        char fmt[] = "Current flow src: %u:%d\n";
        char fmt1[] = "Current flow dst: %u:%d\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, tuple.port16[0]);
        bpf_trace_printk(fmt1, sizeof(fmt1), tuple.dst, tuple.port16[1]);
    }
#endif
    if (value) {
#if 0
        char fmt[] = "Found flow v4: %u %d -> %d\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, sport, dport);
        char fmt[] = "Data: t:%lu p:%lu n:%lu\n";
        bpf_trace_printk(fmt, sizeof(fmt), value->time, value->packets, value->bytes);
#endif
#if USE_PERCPU_HASH
        value->packets++;
        value->bytes += data_end - data;
#else
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, data_end - data);
#endif

#if GOT_TX_PEER
        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
#else
        return XDP_DROP;
#endif
    }

#if ENCRYPTED_TLS_BYPASS
    if ((dport == __constant_ntohs(443)) || (sport == __constant_ntohs(443))) {
        __u8 *app_data;
        /* drop application data for tls 1.2 */
        /* FIXME better parsing */
        nh_off += sizeof(struct iphdr) + sizeof(struct tcphdr);
        if (data_end > data + nh_off + 4) {
            app_data = data + nh_off;
            if (app_data[0] == 0x17 && app_data[1] == 0x3 && app_data[2] == 0x3) {
                tls_count = bpf_map_lookup_elem(&tls_bypass_count, &key1);
                if (tls_count) {
#if USE_PERCPU_HASH
                    tls_count++;
#else
                    __sync_fetch_and_add(tls_count, 1);
#endif
                }
#if GOT_TX_PEER
                iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
                if (!iface_peer) {
                    return XDP_DROP;
                } else {
                    return bpf_redirect_map(&tx_peer, tx_port, 0);
                }
#else
                return XDP_DROP;
#endif
            }
        }
    }
#endif

#if BUILD_CPUMAP
    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    cpu_hash = tuple.src + tuple.dst;
    cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL + iph->protocol);

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
#else
#if RSS_QUEUE_NUMBERS
    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    __u32 xdp_hash = tuple.src + tuple.dst;
    xdp_hash = SuperFastHash((char *)&xdp_hash, 4, INITVAL + iph->protocol);
    ctx->rx_queue_index = xdp_hash % RSS_QUEUE_NUMBERS;
#endif
    return XDP_PASS;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
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
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
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
  "startLine": 379,
  "endLine": 483,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_filter.c",
  "funcName": "filter_ipv6",
  "developer_inline_comments": [
    {
      "start_line": 453,
      "end_line": 453,
      "text": "/* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */"
    },
    {
      "start_line": 472,
      "end_line": 472,
      "text": "/* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    "  cpus_available",
    " cpus_count",
    "  flow_table_v6",
    "  tx_peer_int"
  ],
  "input": [
    "struct xdp_md *ctx",
    " void *data",
    " __u64 nh_off",
    " void *data_end",
    " __u16 vlan0",
    " __u16 vlan1"
  ],
  "output": "staticint__always_inline",
  "helper": [
    "XDP_ABORTED",
    "bpf_redirect_map",
    "bpf_redirect",
    "bpf_trace_printk",
    "XDP_DROP",
    "bpf_map_lookup_elem",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static int __always_inline filter_ipv6 (struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)\n",
    "{\n",
    "    struct ipv6hdr *ip6h = data + nh_off;\n",
    "    int dport;\n",
    "    int sport;\n",
    "    struct flowv6_keys tuple;\n",
    "    struct pair *value;\n",
    "\n",
    "#if BUILD_CPUMAP || GOT_TX_PEER\n",
    "    __u32 key0 = 0;\n",
    "\n",
    "#endif\n",
    "\n",
    "#if BUILD_CPUMAP\n",
    "    __u32 cpu_dest;\n",
    "    int *cpu_max = bpf_map_lookup_elem (&cpus_count, &key0);\n",
    "    __u32 *cpu_selected;\n",
    "    __u32 cpu_hash;\n",
    "\n",
    "#endif\n",
    "\n",
    "#if GOT_TX_PEER\n",
    "    int tx_port = 0;\n",
    "    int *iface_peer;\n",
    "\n",
    "#endif\n",
    "    if ((void *) (ip6h + 1) > data_end)\n",
    "        return 0;\n",
    "    if (!((ip6h->nexthdr == IPPROTO_UDP) || (ip6h->nexthdr == IPPROTO_TCP)))\n",
    "        return XDP_PASS;\n",
    "    dport = get_dport (ip6h + 1, data_end, ip6h -> nexthdr);\n",
    "    if (dport == -1)\n",
    "        return XDP_PASS;\n",
    "    sport = get_sport (ip6h + 1, data_end, ip6h -> nexthdr);\n",
    "    if (sport == -1)\n",
    "        return XDP_PASS;\n",
    "    if (ip6h->nexthdr == IPPROTO_TCP) {\n",
    "        tuple.ip_proto = 1;\n",
    "    }\n",
    "    else {\n",
    "        tuple.ip_proto = 0;\n",
    "    }\n",
    "    __builtin_memcpy (tuple.src, ip6h->saddr.s6_addr32, sizeof (tuple.src));\n",
    "    __builtin_memcpy (tuple.dst, ip6h->daddr.s6_addr32, sizeof (tuple.dst));\n",
    "    tuple.port16[0] = sport;\n",
    "    tuple.port16[1] = dport;\n",
    "    tuple.vlan0 = vlan0;\n",
    "    tuple.vlan1 = vlan1;\n",
    "    value = bpf_map_lookup_elem (& flow_table_v6, & tuple);\n",
    "    if (value) {\n",
    "\n",
    "#if 0\n",
    "        char fmt6 [] = \"Found IPv6 flow: %d -> %d\\n\";\n",
    "        bpf_trace_printk (fmt6, sizeof (fmt6), sport, dport);\n",
    "\n",
    "#endif\n",
    "\n",
    "#if USE_PERCPU_HASH\n",
    "        value->packets++;\n",
    "        value->bytes += data_end - data;\n",
    "\n",
    "#else\n",
    "        __sync_fetch_and_add (&value->packets, 1);\n",
    "        __sync_fetch_and_add (&value->bytes, data_end - data);\n",
    "\n",
    "#endif\n",
    "\n",
    "#if GOT_TX_PEER\n",
    "        iface_peer = bpf_map_lookup_elem (& tx_peer_int, & key0);\n",
    "        if (!iface_peer) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        else {\n",
    "            return bpf_redirect_map (&tx_peer, tx_port, 0);\n",
    "        }\n",
    "\n",
    "#else\n",
    "        return XDP_DROP;\n",
    "\n",
    "#endif\n",
    "    }\n",
    "\n",
    "#if BUILD_CPUMAP\n",
    "    cpu_hash = tuple.src[0] + tuple.dst[0];\n",
    "    cpu_hash += tuple.src[1] + tuple.dst[1];\n",
    "    cpu_hash += tuple.src[2] + tuple.dst[2];\n",
    "    cpu_hash += tuple.src[3] + tuple.dst[3];\n",
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
    "\n",
    "#else\n",
    "\n",
    "#if RSS_QUEUE_NUMBERS\n",
    "    __u32 xdp_hash = tuple.src[0] + tuple.dst[0];\n",
    "    xdp_hash += tuple.src[1] + tuple.dst[1];\n",
    "    xdp_hash += tuple.src[2] + tuple.dst[2];\n",
    "    xdp_hash += tuple.src[3] + tuple.dst[3];\n",
    "    xdp_hash = SuperFastHash ((char *) & xdp_hash, 4, INITVAL);\n",
    "    ctx->rx_queue_index = xdp_hash % RSS_QUEUE_NUMBERS;\n",
    "\n",
    "#endif\n",
    "    return XDP_PASS;\n",
    "\n",
    "#endif\n",
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
      "description": "This function filters the IPv6 packets. If the L4 protocol is TCP, tuple.ip_proto is set to 1. If it is UDP, tuple.ip_proto is set to 0. The source port and destination port of the packet are also extracted. The packet is DROPPED if the packets' ports are not able to get extracted. The tuple array consists of the identification fields for the packet such as - src address, destination address, src port, dest port, vlan0 and vlan1 (used for VLAN flow tracking) which are then used as a key to lookup in the map. If it exists, the number of packets is incremented by 1 and the bytes is incremented by the length of the packet. The increments are done using atomic operations if the map type is BPF_MAP_TYPE_ARRAY. If GOT_TX_PEER flag is enabled, the key0 is initialized as 0. The key is then searched in tx_peer_int BPF MAP. The packet is dropped if the key doesn't exist. Otherwise, the packet is redirect to the corresponding port. If ENCRYPTED_TLS_BYPASS flag is set, the key1 variable is initialized to 0. Then, the transport protocol is checked if it is secured. If the protocol is secured, the key1 is searched in the tls_bypass_count and incremented appropriately. If BUILD_CPUMAP flag is set, the hash is generated using the src and dst addresses using the SuperFastHash function. A destination CPU is selected from the available CPUs using this hash as key. If the corresponding value exists in the map, the packet is redirected to the destination CPU, otherwise it is dropped. If the RSS_QUE_NUMBERS macro is defined, the hash is generated using src and dst addresses using the SuperFastHash function. The rx_queue_index field of the context variable is updated with the hash. The packet is PASSED.",
      "author": "R V B R N Aaseesh",
      "authorEmail": "ee20btech11060@iith.ac.in",
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
static int __always_inline filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct ipv6hdr *ip6h = data + nh_off;
    int dport;
    int sport;
    struct flowv6_keys tuple;
    struct pair *value;
#if BUILD_CPUMAP || GOT_TX_PEER
    __u32 key0 = 0;
#endif
#if BUILD_CPUMAP
    __u32 cpu_dest;
    int *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;
#endif
#if GOT_TX_PEER
    int tx_port = 0;
    int *iface_peer;
#endif

    if ((void *)(ip6h + 1) > data_end)
        return 0;
    if (!((ip6h->nexthdr == IPPROTO_UDP) || (ip6h->nexthdr == IPPROTO_TCP)))
        return XDP_PASS;

    dport = get_dport(ip6h + 1, data_end, ip6h->nexthdr);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(ip6h + 1, data_end, ip6h->nexthdr);
    if (sport == -1)
        return XDP_PASS;

    if (ip6h->nexthdr == IPPROTO_TCP) {
        tuple.ip_proto = 1;
    } else {
        tuple.ip_proto = 0;
    }
    __builtin_memcpy(tuple.src, ip6h->saddr.s6_addr32, sizeof(tuple.src));
    __builtin_memcpy(tuple.dst, ip6h->daddr.s6_addr32, sizeof(tuple.dst));
    tuple.port16[0] = sport;
    tuple.port16[1] = dport;

    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    value = bpf_map_lookup_elem(&flow_table_v6, &tuple);
    if (value) {
#if 0
        char fmt6[] = "Found IPv6 flow: %d -> %d\n";
        bpf_trace_printk(fmt6, sizeof(fmt6), sport, dport);
#endif
#if USE_PERCPU_HASH
        value->packets++;
        value->bytes += data_end - data;
#else
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, data_end - data);
#endif

#if GOT_TX_PEER
        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
#else
        return XDP_DROP;
#endif
    }

#if BUILD_CPUMAP
    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    cpu_hash  = tuple.src[0] + tuple.dst[0];
    cpu_hash += tuple.src[1] + tuple.dst[1];
    cpu_hash += tuple.src[2] + tuple.dst[2];
    cpu_hash += tuple.src[3] + tuple.dst[3];
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
#else
#if RSS_QUEUE_NUMBERS
    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    __u32 xdp_hash  = tuple.src[0] + tuple.dst[0];
    xdp_hash += tuple.src[1] + tuple.dst[1];
    xdp_hash += tuple.src[2] + tuple.dst[2];
    xdp_hash += tuple.src[3] + tuple.dst[3];
    xdp_hash = SuperFastHash((char *)&xdp_hash, 4, INITVAL);
    ctx->rx_queue_index = xdp_hash % RSS_QUEUE_NUMBERS;
#endif

    return XDP_PASS;
#endif
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "pkt_stop_processing_drop_packet",
      "pkt_stop_processing_drop_packet": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Input Params": [],
          "Function Name": "XDP_DROP",
          "Return": 1,
          "Description": "will drop the packet right at the driver level without wasting any further resources. This is in particular useful for BPF programs implementing DDoS mitigation mechanisms or firewalling in general.",
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
  "startLine": 485,
  "endLine": 552,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/xdp_filter.c",
  "funcName": "xdp_hashfilter",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    "  global_bypass",
    "  tx_peer_int"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "\\xdp\\)",
  "helper": [
    "bpf_redirect_map",
    "bpf_redirect",
    "XDP_DROP",
    "bpf_map_lookup_elem",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "int SEC (\"xdp\") xdp_hashfilter (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data_end = (void *) (long) ctx->data_end;\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct ethhdr *eth = data;\n",
    "    __u16 h_proto;\n",
    "    __u64 nh_off;\n",
    "    __u16 vlan0 = 0;\n",
    "    __u16 vlan1 = 0;\n",
    "\n",
    "#if USE_GLOBAL_BYPASS\n",
    "    int *iface_peer;\n",
    "    char *g_switch = 0;\n",
    "    char key0;\n",
    "    int tx_port = 0;\n",
    "    g_switch = bpf_map_lookup_elem (& global_bypass, & key0);\n",
    "    if (g_switch && *g_switch) {\n",
    "        iface_peer = bpf_map_lookup_elem (& tx_peer_int, & key0);\n",
    "        if (!iface_peer) {\n",
    "            return XDP_DROP;\n",
    "        }\n",
    "        else {\n",
    "            return bpf_redirect_map (&tx_peer, tx_port, 0);\n",
    "        }\n",
    "    }\n",
    "\n",
    "#endif\n",
    "    nh_off = sizeof (*eth);\n",
    "    if (data + nh_off > data_end)\n",
    "        return XDP_PASS;\n",
    "    h_proto = eth->h_proto;\n",
    "    if (h_proto == __constant_htons (ETH_P_8021Q) || h_proto == __constant_htons (ETH_P_8021AD)) {\n",
    "        struct vlan_hdr *vhdr;\n",
    "        vhdr = data + nh_off;\n",
    "        nh_off += sizeof (struct vlan_hdr);\n",
    "        if (data + nh_off > data_end)\n",
    "            return XDP_PASS;\n",
    "        h_proto = vhdr->h_vlan_encapsulated_proto;\n",
    "\n",
    "#if VLAN_TRACKING\n",
    "        vlan0 = vhdr->h_vlan_TCI & 0x0fff;\n",
    "\n",
    "#else\n",
    "        vlan0 = 0;\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    if (h_proto == __constant_htons (ETH_P_8021Q) || h_proto == __constant_htons (ETH_P_8021AD)) {\n",
    "        struct vlan_hdr *vhdr;\n",
    "        vhdr = data + nh_off;\n",
    "        nh_off += sizeof (struct vlan_hdr);\n",
    "        if (data + nh_off > data_end)\n",
    "            return XDP_PASS;\n",
    "        h_proto = vhdr->h_vlan_encapsulated_proto;\n",
    "\n",
    "#if VLAN_TRACKING\n",
    "        vlan1 = vhdr->h_vlan_TCI & 0x0fff;\n",
    "\n",
    "#else\n",
    "        vlan1 = 0;\n",
    "\n",
    "#endif\n",
    "    }\n",
    "    if (h_proto == __constant_htons (ETH_P_IP))\n",
    "        return filter_ipv4 (ctx, data, nh_off, data_end, vlan0, vlan1);\n",
    "    else if (h_proto == __constant_htons (ETH_P_IPV6))\n",
    "        return filter_ipv6 (ctx, data, nh_off, data_end, vlan0, vlan1);\n",
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
      "description": "This hash function filter, filters the Ethernet packets based on the IP packet version. If GLOBAL_BYPASS flag is set, then the key0 is initialized to 0 and is checked in the global_bypass map. If the key exists, the same key0 is checked in tx_peer_int map. If the key doesn't exist, the packet is dropped. Othereise, the tx_port is written into the tx_peer map. If GLOBAL_BYPASS is not set, the fields vlan0 is set to the last 12 bits of the VLAN TCI field and vlan1 is set to 0 if the VLAN_TRACKING is off else it is set to the last 12 bits of the VLAN TCI field(since vlan0 is stripped by the OS). Based on the version of IP packets, the function filter_ipv4 or filter_ipv6 is invoked accordingly. If it is neither of them -1 is returned.",
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
int SEC("xdp") xdp_hashfilter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;
    __u16 vlan0 = 0;
    __u16 vlan1 = 0;
#if USE_GLOBAL_BYPASS
    int *iface_peer;
    char *g_switch = 0;
    char key0;
    int tx_port = 0;

    g_switch = bpf_map_lookup_elem(&global_bypass, &key0);
    if (g_switch && *g_switch) {
        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
    }
#endif

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
#if VLAN_TRACKING
        vlan0 = vhdr->h_vlan_TCI & 0x0fff;
#else
        vlan0 = 0;
#endif
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
#if VLAN_TRACKING
        vlan1 = vhdr->h_vlan_TCI & 0x0fff;
#else
        vlan1 = 0;
#endif
    }

    if (h_proto == __constant_htons(ETH_P_IP))
        return filter_ipv4(ctx, data, nh_off, data_end, vlan0, vlan1);
    else if (h_proto == __constant_htons(ETH_P_IPV6))
        return filter_ipv6(ctx, data, nh_off, data_end, vlan0, vlan1);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
