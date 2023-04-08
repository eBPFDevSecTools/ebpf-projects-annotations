// +build ignore
#include <inttypes.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>

#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "common.h"
#include "ingress_node_firewall.h"

#define MAX_CPUS		256

// FIXME: Hack this structure defined in linux/sctp.h however I am getting incomplete type when I reference it
struct sctphdr {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __le32 checksum;
};

/*
 * ingress_node_firewall_events_map: is perf event array map type
 * key is the rule id, packet header is captured and used to generate events.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} ingress_node_firewall_events_map SEC(".maps");

/*
 * ingress_node_firewall_statistics_map: is per cpu array map type
 * key is the rule id
 * user space collects statistics per CPU and aggregate them.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); // ruleId
    __type(value, struct ruleStatistics_st);
    __uint(max_entries, MAX_TARGETS);
} ingress_node_firewall_statistics_map SEC(".maps");

/*
 * ingress_node_firewall_table_map: is LPM trie map type
 * key is the ingress interface index and the sourceCIDR.
 * lookup returns an array of rules with actions for the XDP program
 * to process.
 * Note: this map is pinned to specific path in bpffs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key_st);
    __type(value, struct rulesVal_st);
    __uint(max_entries, MAX_TARGETS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_node_firewall_table_map SEC(".maps");

/*
 * ingress_node_firewall_printk: macro used to generate prog traces for debugging only
 * to enable uncomment the following line
 */
//#define ENABLE_BPF_PRINTK
#ifdef ENABLE_BPF_PRINTK
#define ingress_node_firewall_printk(fmt, args...) bpf_printk(fmt, ##args)
#else
#define ingress_node_firewall_printk(fmt, args...)
#endif

/*
 * ip_extract_l4info(): extracts L4 info for the supported protocols from
 * the incoming packet's headers.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * bool is_v4: true for ipv4 and false for ipv6.
 * Output:
 * __u8 *proto: L4 protocol type supported types are TCP/UDP/SCTP/ICMP/ICMPv6.
 * __u16 *dstPort: pointer to L4 destination port for TCP/UDP/SCTP protocols.
 * __u8 *icmpType: pointer to ICMP or ICMPv6's type value.
 * __u8 *icmpCode: pointer to ICMP or ICMPv6's code value.
 * Return:
 * 0 for Success.
 * -1 for Failure.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 95,
  "endLine": 174,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/ingress-node-firewall-master/original_source/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ip_extract_l4info",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": " +build ignore"
    },
    {
      "start_line": 22,
      "end_line": 22,
      "text": " FIXME: Hack this structure defined in linux/sctp.h however I am getting incomplete type when I reference it"
    },
    {
      "start_line": 30,
      "end_line": 33,
      "text": " * ingress_node_firewall_events_map: is perf event array map type * key is the rule id, packet header is captured and used to generate events. "
    },
    {
      "start_line": 41,
      "end_line": 45,
      "text": " * ingress_node_firewall_statistics_map: is per cpu array map type * key is the rule id * user space collects statistics per CPU and aggregate them. "
    },
    {
      "start_line": 48,
      "end_line": 48,
      "text": " ruleId"
    },
    {
      "start_line": 53,
      "end_line": 59,
      "text": " * ingress_node_firewall_table_map: is LPM trie map type * key is the ingress interface index and the sourceCIDR. * lookup returns an array of rules with actions for the XDP program * to process. * Note: this map is pinned to specific path in bpffs. "
    },
    {
      "start_line": 69,
      "end_line": 72,
      "text": " * ingress_node_firewall_printk: macro used to generate prog traces for debugging only * to enable uncomment the following line "
    },
    {
      "start_line": 73,
      "end_line": 73,
      "text": "#define ENABLE_BPF_PRINTK"
    },
    {
      "start_line": 80,
      "end_line": 94,
      "text": " * ip_extract_l4info(): extracts L4 info for the supported protocols from * the incoming packet's headers. * Input: * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index. * bool is_v4: true for ipv4 and false for ipv6. * Output: * __u8 *proto: L4 protocol type supported types are TCP/UDP/SCTP/ICMP/ICMPv6. * __u16 *dstPort: pointer to L4 destination port for TCP/UDP/SCTP protocols. * __u8 *icmpType: pointer to ICMP or ICMPv6's type value. * __u8 *icmpCode: pointer to ICMP or ICMPv6's code value. * Return: * 0 for Success. * -1 for Failure. "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx",
    " __u8 *proto",
    " __u16 *dstPort",
    " __u8 *icmpType",
    " __u8 *icmpCode",
    " __u8 is_v4"
  ],
  "output": "staticinlineint",
  "helper": [],
  "compatibleHookpoints": [
    "sched_act",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "flow_dissector",
    "xdp",
    "kprobe",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_xmit",
    "cgroup_sysctl",
    "perf_event",
    "cgroup_sock",
    "lwt_out",
    "lwt_in",
    "cgroup_sock_addr",
    "sock_ops",
    "tracepoint",
    "raw_tracepoint",
    "cgroup_skb",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device"
  ],
  "source": [
    "static inline int ip_extract_l4info (struct xdp_md *ctx, __u8 *proto, __u16 *dstPort, __u8 *icmpType, __u8 *icmpCode, __u8 is_v4)\n",
    "{\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    void *dataEnd = (void *) (long) ctx->data_end;\n",
    "    void *dataStart = data + sizeof (struct ethhdr);\n",
    "    if (likely (is_v4)) {\n",
    "        struct iphdr *iph = dataStart;\n",
    "        dataStart += sizeof (struct iphdr);\n",
    "        if (unlikely (dataStart > dataEnd)) {\n",
    "            return -1;\n",
    "        }\n",
    "        *proto = iph->protocol;\n",
    "    }\n",
    "    else {\n",
    "        struct ipv6hdr *iph = dataStart;\n",
    "        dataStart += sizeof (struct ipv6hdr);\n",
    "        if (unlikely (dataStart > dataEnd)) {\n",
    "            return -1;\n",
    "        }\n",
    "        *proto = iph->nexthdr;\n",
    "    }\n",
    "    switch (*proto) {\n",
    "    case IPPROTO_TCP :\n",
    "        {\n",
    "            struct tcphdr *tcph = (struct tcphdr *) dataStart;\n",
    "            dataStart += sizeof (struct tcphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *dstPort = tcph->dest;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_UDP :\n",
    "        {\n",
    "            struct udphdr *udph = (struct udphdr *) dataStart;\n",
    "            dataStart += sizeof (struct udphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *dstPort = udph->dest;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_SCTP :\n",
    "        {\n",
    "            struct sctphdr *sctph = (struct sctphdr *) dataStart;\n",
    "            dataStart += sizeof (struct sctphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *dstPort = sctph->dest;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_ICMP :\n",
    "        {\n",
    "            struct icmphdr *icmph = (struct icmphdr *) dataStart;\n",
    "            dataStart += sizeof (struct icmphdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *icmpType = icmph->type;\n",
    "            *icmpCode = icmph->code;\n",
    "            break;\n",
    "        }\n",
    "    case IPPROTO_ICMPV6 :\n",
    "        {\n",
    "            struct icmp6hdr *icmp6h = (struct icmp6hdr *) dataStart;\n",
    "            dataStart += sizeof (struct icmp6hdr);\n",
    "            if (unlikely (dataStart > dataEnd)) {\n",
    "                return -1;\n",
    "            }\n",
    "            *icmpType = icmp6h->icmp6_type;\n",
    "            *icmpCode = icmp6h->icmp6_code;\n",
    "            break;\n",
    "        }\n",
    "    default :\n",
    "        return -1;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "unlikely",
    "likely"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function takes in an xdp_md *ctx, a pointer to u8 *proto, pointer to u16 *dstPort, pointer to u8 *icmpType, pointer to u8 *icmpCode and u8 flag is_v4.Based on the packet if the packet protocol is TCP/UDP/SCTP it parses the packet protocol and dstPort and sets the values to the pointers proto and dstPort if the packet protocol is ICMP it dereferences icmpType and icmpCode and sets to the icmpType and icmpCode along with setting the protocol to ICMP. If able to successfully parse the information it returns 0 else -1.",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "05-Apr-2023"
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
__attribute__((__always_inline__)) static inline int
ip_extract_l4info(struct xdp_md *ctx, __u8 *proto, __u16 *dstPort,
                  __u8 *icmpType, __u8 *icmpCode, __u8 is_v4) {
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;
    void *dataStart = data + sizeof(struct ethhdr);

    if (likely(is_v4)) {
        struct iphdr *iph = dataStart;
        dataStart += sizeof(struct iphdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *proto = iph->protocol;
    } else {
        struct ipv6hdr *iph = dataStart;
        dataStart += sizeof(struct ipv6hdr);
        if (unlikely(dataStart > dataEnd)) {
            return -1;
        }
        *proto = iph->nexthdr;
    }
    switch (*proto) {
    case IPPROTO_TCP:
        {
            struct tcphdr *tcph = (struct tcphdr *)dataStart;
            dataStart += sizeof(struct tcphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = tcph->dest;
            break;
        }
    case IPPROTO_UDP:
        {
            struct udphdr *udph = (struct udphdr *)dataStart;
            dataStart += sizeof(struct udphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = udph->dest;
            break;
        }
    case IPPROTO_SCTP:
        {
            struct sctphdr *sctph = (struct sctphdr *)dataStart;
            dataStart += sizeof(struct sctphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *dstPort = sctph->dest;
            break;
        }
    case IPPROTO_ICMP:
        {
            struct icmphdr *icmph = (struct icmphdr *)dataStart;
            dataStart += sizeof(struct icmphdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *icmpType = icmph->type;
            *icmpCode = icmph->code;
            break;
        }
    case IPPROTO_ICMPV6:
        {
            struct icmp6hdr *icmp6h = (struct icmp6hdr *)dataStart;
            dataStart += sizeof(struct icmp6hdr);
            if (unlikely(dataStart > dataEnd)) {
                return -1;
            }
            *icmpType = icmp6h->icmp6_type;
            *icmpCode = icmp6h->icmp6_code;
            break;
        }
    default:
        return -1;
    }
    return 0;
}

/*
 * ipv4_firewall_lookup(): matches ipv4 packet with LPM map's key,
 * match L4 headers with the result rules in order and return the action.
 * if there is no match it will return UNDEF action.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 * __u32 action: returned action is the logical or of the rule id and action field
 * from the matching rule, in case of no match it returns UNDEF.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 189,
  "endLine": 259,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/ingress-node-firewall-master/original_source/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ipv4_firewall_lookup",
  "developer_inline_comments": [
    {
      "start_line": 176,
      "end_line": 188,
      "text": " * ipv4_firewall_lookup(): matches ipv4 packet with LPM map's key, * match L4 headers with the result rules in order and return the action. * if there is no match it will return UNDEF action. * Input: * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index. * __u32 ifID: ingress interface index where the packet is received from. * Output: * none. * Return: * __u32 action: returned action is the logical or of the rule id and action field * from the matching rule, in case of no match it returns UNDEF. "
    },
    {
      "start_line": 207,
      "end_line": 207,
      "text": " ipv4 address + ifId"
    },
    {
      "start_line": 251,
      "end_line": 251,
      "text": " Protocol is not set so just apply the action"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " ingress_node_firewall_table_map"
  ],
  "input": [
    "struct xdp_md *ctx",
    " __u32 ifId"
  ],
  "output": "staticinline__u32",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "flow_dissector",
    "xdp",
    "kprobe",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_xmit",
    "cgroup_sysctl",
    "perf_event",
    "cgroup_sock",
    "lwt_out",
    "lwt_in",
    "cgroup_sock_addr",
    "sock_ops",
    "tracepoint",
    "raw_tracepoint",
    "cgroup_skb",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device"
  ],
  "source": [
    "static inline __u32 ipv4_firewall_lookup (struct xdp_md *ctx, __u32 ifId)\n",
    "{\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct iphdr *iph = data + sizeof (struct ethhdr);\n",
    "    struct lpm_ip_key_st key;\n",
    "    __u32 srcAddr = 0;\n",
    "    __u16 dstPort = 0;\n",
    "    __u8 icmpCode = 0, icmpType = 0, proto = 0;\n",
    "    int i;\n",
    "    if (unlikely (ip_extract_l4info (ctx, &proto, &dstPort, &icmpType, &icmpCode, 1) < 0)) {\n",
    "        ingress_node_firewall_printk (\"failed to extract l4 info\");\n",
    "        return SET_ACTION (UNDEF);\n",
    "    }\n",
    "    srcAddr = iph->saddr;\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    key.prefixLen = 64;\n",
    "    key.ip_data[0] = srcAddr & 0xFF;\n",
    "    key.ip_data[1] = (srcAddr >> 8) & 0xFF;\n",
    "    key.ip_data[2] = (srcAddr >> 16) & 0xFF;\n",
    "    key.ip_data[3] = (srcAddr >> 24) & 0xFF;\n",
    "    key.ingress_ifindex = ifId;\n",
    "    struct rulesVal_st *rulesVal = (struct rulesVal_st *) bpf_map_lookup_elem (&ingress_node_firewall_table_map, &key);\n",
    "    if (likely (NULL != rulesVal)) {\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {\n",
    "            struct ruleType_st *rule = &rulesVal->rules[i];\n",
    "            if (rule->ruleId == INVALID_RULE_ID) {\n",
    "                continue;\n",
    "            }\n",
    "            if (likely ((rule->protocol != 0) && (rule->protocol == proto))) {\n",
    "                ingress_node_firewall_printk (\"ruleInfo (protocol %d, Id %d, action %d)\", rule->protocol, rule->ruleId, rule->action);\n",
    "                if ((rule->protocol == IPPROTO_TCP) || (rule->protocol == IPPROTO_UDP) || (rule->protocol == IPPROTO_SCTP)) {\n",
    "                    ingress_node_firewall_printk (\"TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d\", rule->dstPortStart, rule->dstPortEnd, bpf_ntohs (dstPort));\n",
    "                    if (rule->dstPortEnd == 0) {\n",
    "                        if (rule->dstPortStart == bpf_ntohs (dstPort)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                    else {\n",
    "                        if ((bpf_ntohs (dstPort) >= rule->dstPortStart) && (bpf_ntohs (dstPort) < rule->dstPortEnd)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                }\n",
    "                if (rule->protocol == IPPROTO_ICMP) {\n",
    "                    ingress_node_firewall_printk (\"ICMP packet rule(type:%d, code:%d) pkt(type:%d, code %d)\", rule->icmpType, rule->icmpCode, icmpType, icmpCode);\n",
    "                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {\n",
    "                        return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "            if (rule->protocol == 0) {\n",
    "                return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "            }\n",
    "        }\n",
    "        ingress_node_firewall_printk (\"Packet didn't match any rule proto %d port %d\", proto, bpf_ntohs (dstPort));\n",
    "    }\n",
    "    return SET_ACTION (UNDEF);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "likely",
    "bpf_ntohs",
    "ip_extract_l4info",
    "ingress_node_firewall_printk",
    "unlikely",
    "unroll",
    "SET_ACTION",
    "SET_ACTIONRULE_RESPONSE",
    "memset"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function takes in an xdp_md *ctx and a u32 as ifID. It first calls ip_extract_l4info to extract protocol type, dst port, icmp type and icmp code from the packet. The function dereferences source address from the ip header of the packet. It next forms a struct lpm_ip_key_st key with packetlen as 64(ipv4 address + size of ifId) fixed, ip_data byte array as the srcAddr represented as bytes and ingress_interface as the ifId. It performs a lookup on the map ingress_node_firewall_table_map using the constructed key to retrive the firewall rules to be applied to this packet. The map returns a struct rulesVal_st *rulesVal which is an array of struct ruleType_st. If the map lookup returns null it will return UNDEF action else it will perform a lookup on all the rules in the array one by one. Any rule in the array which has id set to INVALID_RULE_ID is skipped and for any valid rule the firewall rule is applied like this, if the rule contains no protocol info then a blanket action is applied to all packets which is programmed in the rule, else if the protocol in the rule matches the packet protocol, for TCP/UDP/SCTP packets if the rule contains dst port start but not end then the dst port of the packet is matched against the dst port start, else if dst port start and dst port end both are set then the packet dst port is checked to be in the range of [dst port start: end]. For ICMP packets the rule checks if the icmp code and icmp type of the packet matches that present in the rule. For any match, the rule's action is applied to the packet and the function returns. If a particular rule does not match according to the above algorithm then the next rule is tried and so on. If no match then action UNDEF is returned",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "05-Apr-2023"
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
__attribute__((__always_inline__)) static inline __u32
ipv4_firewall_lookup(struct xdp_md *ctx, __u32 ifId) {
    void *data = (void *)(long)ctx->data;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct lpm_ip_key_st key;
    __u32 srcAddr = 0;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (unlikely(ip_extract_l4info(ctx, &proto, &dstPort, &icmpType, &icmpCode, 1) < 0)) {
        ingress_node_firewall_printk("failed to extract l4 info");
        return SET_ACTION(UNDEF);
    }

    srcAddr = iph->saddr;

    memset(&key, 0, sizeof(key));
    key.prefixLen = 64; // ipv4 address + ifId
    key.ip_data[0] = srcAddr & 0xFF;
    key.ip_data[1] = (srcAddr >> 8) & 0xFF;
    key.ip_data[2] = (srcAddr >> 16) & 0xFF;
    key.ip_data[3] = (srcAddr >> 24) & 0xFF;
    key.ingress_ifindex = ifId;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);


    if (likely(NULL != rulesVal)) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            struct ruleType_st *rule = &rulesVal->rules[i];
            if (rule->ruleId == INVALID_RULE_ID) {
                continue;
            }

            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
                ingress_node_firewall_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    ingress_node_firewall_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
                    rule->dstPortStart, rule->dstPortEnd, bpf_ntohs(dstPort));
                    if (rule->dstPortEnd == 0 ) {
                        if (rule->dstPortStart == bpf_ntohs(dstPort)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    } else {
                        if ((bpf_ntohs(dstPort) >= rule->dstPortStart) && (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    }
                }

                if (rule->protocol == IPPROTO_ICMP) {
                    ingress_node_firewall_printk("ICMP packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
            // Protocol is not set so just apply the action
            if (rule->protocol == 0) {
                return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
        }
        ingress_node_firewall_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
    }
    return SET_ACTION(UNDEF);
}

/*
 * ipv6_firewall_lookup(): matches ipv6 packet with LPM map's key,
 * match L4 headers with the result rules in order and return the action.
 * if there is no rule match it will return UNDEF action.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * __u32 ifID: ingress interface index where the packet is received from.
 * Output:
 * none.
 * Return:
 __u32 action: returned action is the logical or of the rule id and action field
 * from the matching rule, in case of no match it returns UNDEF.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 274,
  "endLine": 337,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/ingress-node-firewall-master/original_source/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ipv6_firewall_lookup",
  "developer_inline_comments": [
    {
      "start_line": 261,
      "end_line": 273,
      "text": " * ipv6_firewall_lookup(): matches ipv6 packet with LPM map's key, * match L4 headers with the result rules in order and return the action. * if there is no rule match it will return UNDEF action. * Input: * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index. * __u32 ifID: ingress interface index where the packet is received from. * Output: * none. * Return: __u32 action: returned action is the logical or of the rule id and action field * from the matching rule, in case of no match it returns UNDEF. "
    },
    {
      "start_line": 290,
      "end_line": 290,
      "text": " ipv6 address _ ifId"
    },
    {
      "start_line": 329,
      "end_line": 329,
      "text": " Protocol is not set so just apply the action"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " ingress_node_firewall_table_map"
  ],
  "input": [
    "struct xdp_md *ctx",
    " __u32 ifId"
  ],
  "output": "staticinline__u32",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sched_act",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "flow_dissector",
    "xdp",
    "kprobe",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_xmit",
    "cgroup_sysctl",
    "perf_event",
    "cgroup_sock",
    "lwt_out",
    "lwt_in",
    "cgroup_sock_addr",
    "sock_ops",
    "tracepoint",
    "raw_tracepoint",
    "cgroup_skb",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device"
  ],
  "source": [
    "static inline __u32 ipv6_firewall_lookup (struct xdp_md *ctx, __u32 ifId)\n",
    "{\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    struct ipv6hdr *iph = data + sizeof (struct ethhdr);\n",
    "    struct lpm_ip_key_st key;\n",
    "    __u8 *srcAddr = NULL;\n",
    "    __u16 dstPort = 0;\n",
    "    __u8 icmpCode = 0, icmpType = 0, proto = 0;\n",
    "    int i;\n",
    "    if (unlikely (ip_extract_l4info (ctx, &proto, &dstPort, &icmpType, &icmpCode, 0) < 0)) {\n",
    "        ingress_node_firewall_printk (\"failed to extract l4 info\");\n",
    "        return SET_ACTION (UNDEF);\n",
    "    }\n",
    "    srcAddr = iph->saddr.in6_u.u6_addr8;\n",
    "    memset (&key, 0, sizeof (key));\n",
    "    key.prefixLen = 160;\n",
    "    memcpy (key.ip_data, srcAddr, 16);\n",
    "    key.ingress_ifindex = ifId;\n",
    "    struct rulesVal_st *rulesVal = (struct rulesVal_st *) bpf_map_lookup_elem (&ingress_node_firewall_table_map, &key);\n",
    "    if (NULL != rulesVal) {\n",
    "\n",
    "#pragma clang loop unroll(full)\n",
    "        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {\n",
    "            struct ruleType_st *rule = &rulesVal->rules[i];\n",
    "            if (rule->ruleId == INVALID_RULE_ID) {\n",
    "                continue;\n",
    "            }\n",
    "            if (likely ((rule->protocol != 0) && (rule->protocol == proto))) {\n",
    "                ingress_node_firewall_printk (\"ruleInfo (protocol %d, Id %d, action %d)\", rule->protocol, rule->ruleId, rule->action);\n",
    "                if ((rule->protocol == IPPROTO_TCP) || (rule->protocol == IPPROTO_UDP) || (rule->protocol == IPPROTO_SCTP)) {\n",
    "                    ingress_node_firewall_printk (\"TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d\", rule->dstPortStart, rule->dstPortEnd, bpf_ntohs (dstPort));\n",
    "                    if (rule->dstPortEnd == 0) {\n",
    "                        if (rule->dstPortStart == bpf_ntohs (dstPort)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                    else {\n",
    "                        if ((bpf_ntohs (dstPort) >= rule->dstPortStart) && (bpf_ntohs (dstPort) < rule->dstPortEnd)) {\n",
    "                            return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                        }\n",
    "                    }\n",
    "                }\n",
    "                if (rule->protocol == IPPROTO_ICMPV6) {\n",
    "                    ingress_node_firewall_printk (\"ICMPV6 packet rule(type:%d, code:%d) pkt(type:%d, code %d)\", rule->icmpType, rule->icmpCode, icmpType, icmpCode);\n",
    "                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {\n",
    "                        return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "                    }\n",
    "                }\n",
    "            }\n",
    "            if (rule->protocol == 0) {\n",
    "                return SET_ACTIONRULE_RESPONSE (rule->action, rule->ruleId);\n",
    "            }\n",
    "        }\n",
    "        ingress_node_firewall_printk (\"Packet didn't match any rule proto %d port %d\", proto, bpf_ntohs (dstPort));\n",
    "    }\n",
    "    return SET_ACTION (UNDEF);\n",
    "}\n"
  ],
  "called_function_list": [
    "memcpy",
    "",
    "likely",
    "bpf_ntohs",
    "ip_extract_l4info",
    "ingress_node_firewall_printk",
    "unlikely",
    "unroll",
    "SET_ACTION",
    "SET_ACTIONRULE_RESPONSE",
    "memset"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function takes in an xdp_md *ctx and a u32 as ifID. It first calls ip_extract_l4info to extract protocol type, dst port, icmp type and icmp code from the packet. The function dereferences source address from the ip header of the packet. It next forms a struct lpm_ip_key_st key with packetlen as 160(size of ipv6 address + size of ifId) fixed, ip_data byte array as the srcAddr represented as bytes and ingress_interface as the ifId. It performs a lookup on the map ingress_node_firewall_table_map using the constructed key to retrive the firewall rules to be applied to this packet. The map returns a struct rulesVal_st *rulesVal which is an array of struct ruleType_st. If the map lookup returns null it will return UNDEF action else it will perform a lookup on all the rules in the array one by one. Any rule in the array which has id set to INVALID_RULE_ID is skipped and for any valid rule the firewall rule is applied like this, if the rule contains no protocol info then a blanket action is applied to all packets which is programmed in the rule, else if the protocol in the rule matches the packet protocol, for TCP/UDP/SCTP packets if the rule contains dst port start but not end then the dst port of the packet is matched against the dst port start, else if dst port start and dst port end both are set then the packet dst port is checked to be in the range of [dst port start: end]. For ICMP packets the rule checks if the icmp code and icmp type of the packet matches that present in the rule. For any match, the rule's action is applied to the packet and the function returns. If a particular rule does not match according to the above algorithm then the next rule is tried and so on. If no match then action UNDEF is returned",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "05-Apr-2023"
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
__attribute__((__always_inline__)) static inline __u32
ipv6_firewall_lookup(struct xdp_md *ctx, __u32 ifId) {
    void *data = (void *)(long)ctx->data;
    struct ipv6hdr *iph = data + sizeof(struct ethhdr);
    struct lpm_ip_key_st key;
    __u8 *srcAddr = NULL;
    __u16 dstPort = 0;
    __u8 icmpCode = 0, icmpType = 0, proto = 0;
    int i;

    if (unlikely(ip_extract_l4info(ctx, &proto, &dstPort, &icmpType, &icmpCode, 0) < 0)) {
        ingress_node_firewall_printk("failed to extract l4 info");
        return SET_ACTION(UNDEF);
    }
    srcAddr = iph->saddr.in6_u.u6_addr8;
    memset(&key, 0, sizeof(key));
    key.prefixLen = 160; // ipv6 address _ ifId
    memcpy(key.ip_data, srcAddr, 16);
    key.ingress_ifindex = ifId;

    struct rulesVal_st *rulesVal = (struct rulesVal_st *)bpf_map_lookup_elem(
        &ingress_node_firewall_table_map, &key);

    if (NULL != rulesVal) {
#pragma clang loop unroll(full)
        for (i = 0; i < MAX_RULES_PER_TARGET; ++i) {
            struct ruleType_st *rule = &rulesVal->rules[i];
            if (rule->ruleId == INVALID_RULE_ID) {
                continue;
            }
            if (likely((rule->protocol != 0) && (rule->protocol == proto))) {
                ingress_node_firewall_printk("ruleInfo (protocol %d, Id %d, action %d)", rule->protocol, rule->ruleId, rule->action);
                if ((rule->protocol == IPPROTO_TCP) ||
                    (rule->protocol == IPPROTO_UDP) ||
                    (rule->protocol == IPPROTO_SCTP)) {
                    ingress_node_firewall_printk("TCP/UDP/SCTP packet rule_dstPortStart %d rule_dstPortEnd %d pkt_dstPort %d",
                        rule->dstPortStart, rule->dstPortEnd, bpf_ntohs(dstPort));
                    if (rule->dstPortEnd == 0) {
                        if (rule->dstPortStart == bpf_ntohs(dstPort)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    } else {
                        if ((bpf_ntohs(dstPort) >= rule->dstPortStart) && (bpf_ntohs(dstPort) < rule->dstPortEnd)) {
                            return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                        }
                    }
                }

                if (rule->protocol == IPPROTO_ICMPV6) {
                    ingress_node_firewall_printk("ICMPV6 packet rule(type:%d, code:%d) pkt(type:%d, code %d)", rule->icmpType, rule->icmpCode, icmpType, icmpCode);
                    if ((rule->icmpType == icmpType) && (rule->icmpCode == icmpCode)) {
                        return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
                    }
                }
            }
            // Protocol is not set so just apply the action
            if (rule->protocol == 0) {
                return SET_ACTIONRULE_RESPONSE(rule->action, rule->ruleId);
            }
        }
        ingress_node_firewall_printk("Packet didn't match any rule proto %d port %d", proto, bpf_ntohs(dstPort));
    }
    return SET_ACTION(UNDEF);
}

/*
 * generate_event_and_update_statistics() : it will generate eBPF event including the packet header
 * and update statistics for the specificed rule id.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context including input interface and packet pointer.
 * __u64 packet_len: packet length in bytes including layer2 header.
 * __u8 action: valid actions ALLOW/DENY/UNDEF.
 * __u16 ruleId: ruled id where the packet matches against (in case of match of course).
 * __u8 generateEvent: need to generate event for this packet or not.
 * __u32 ifID: input interface index where the packet is arrived from.
 * Output:
 * none.
 * Return:
 * none.
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
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
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
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 354,
  "endLine": 393,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/ingress-node-firewall-master/original_source/bpf/ingress_node_firewall_kernel.c",
  "funcName": "generate_event_and_update_statistics",
  "developer_inline_comments": [
    {
      "start_line": 339,
      "end_line": 353,
      "text": " * generate_event_and_update_statistics() : it will generate eBPF event including the packet header * and update statistics for the specificed rule id. * Input: * struct xdp_md *ctx: pointer to XDP context including input interface and packet pointer. * __u64 packet_len: packet length in bytes including layer2 header. * __u8 action: valid actions ALLOW/DENY/UNDEF. * __u16 ruleId: ruled id where the packet matches against (in case of match of course). * __u8 generateEvent: need to generate event for this packet or not. * __u32 ifID: input interface index where the packet is arrived from. * Output: * none. * Return: * none. "
    },
    {
      "start_line": 387,
      "end_line": 387,
      "text": " enable the following flag to dump packet header"
    }
  ],
  "updateMaps": [
    " ingress_node_firewall_statistics_map"
  ],
  "readMaps": [
    "  ingress_node_firewall_statistics_map"
  ],
  "input": [
    "struct xdp_md *ctx",
    " __u64 packet_len",
    " __u8 action",
    " __u16 ruleId",
    " __u8 generateEvent",
    " __u32 ifId"
  ],
  "output": "staticinlinevoid",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_map_update_elem",
    "bpf_perf_event_output"
  ],
  "compatibleHookpoints": [
    "sock_ops",
    "sched_act",
    "lwt_xmit",
    "perf_event",
    "raw_tracepoint",
    "sched_cls",
    "sk_skb",
    "xdp",
    "cgroup_skb",
    "lwt_in",
    "kprobe",
    "lwt_out",
    "tracepoint",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_seg6local"
  ],
  "source": [
    "static inline void generate_event_and_update_statistics (struct xdp_md *ctx, __u64 packet_len, __u8 action, __u16 ruleId, __u8 generateEvent, __u32 ifId)\n",
    "{\n",
    "    struct ruleStatistics_st *statistics, initialStats;\n",
    "    struct event_hdr_st hdr;\n",
    "    __u64 flags = BPF_F_CURRENT_CPU;\n",
    "    __u16 headerSize;\n",
    "    __u32 key = ruleId;\n",
    "    memset (&hdr, 0, sizeof (hdr));\n",
    "    hdr.ruleId = ruleId;\n",
    "    hdr.action = action;\n",
    "    hdr.pktLength = (__u16) packet_len;\n",
    "    hdr.ifId = (__u16) ifId;\n",
    "    memset (&initialStats, 0, sizeof (initialStats));\n",
    "    statistics = bpf_map_lookup_elem (& ingress_node_firewall_statistics_map, & key);\n",
    "    if (likely (statistics)) {\n",
    "        switch (action) {\n",
    "        case ALLOW :\n",
    "            __sync_fetch_and_add (&statistics->allow_stats.packets, 1);\n",
    "            __sync_fetch_and_add (&statistics->allow_stats.bytes, packet_len);\n",
    "            break;\n",
    "        case DENY :\n",
    "            __sync_fetch_and_add (&statistics->deny_stats.packets, 1);\n",
    "            __sync_fetch_and_add (&statistics->deny_stats.bytes, packet_len);\n",
    "            break;\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        bpf_map_update_elem (&ingress_node_firewall_statistics_map, &key, &initialStats, BPF_ANY);\n",
    "    }\n",
    "    if (generateEvent) {\n",
    "        headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;\n",
    "        flags |= (__u64) headerSize << 32;\n",
    "        (void) bpf_perf_event_output (ctx, &ingress_node_firewall_events_map, flags, &hdr, sizeof (hdr));\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "likely",
    "memset",
    "__sync_fetch_and_add"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function takes in a packet as xdp_md *ctx, packet_length, action, ruleId, generateEvent flag and the interface id as ifId. It looks up a map ingress_node_firewall_statistics_map with ruleId as the key, the map returns a struct ruleStatistics_st *statistics, if its not null then based on action either allow or deny statistic is updated with packet counter in the statistic incremented by 1 and the size counter in statistic incremented by packet_len. If it returns null then an initial statistic with values set to zero is updated in the map against the same ruleId as the key. Next if the generateEvent flag was set in the arguments it will send a perf event to userspace by calling bpf_perf_event_output helper function in the ingress_node_firewall_events_map events map. The passed event is of the form struct event_hdr_st and contians the information about ruleId, action, packet_len, ifId. This function returns nothing and has a void return type.",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "05-Apr-2023"
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
__attribute__((__always_inline__)) static inline void
generate_event_and_update_statistics(struct xdp_md *ctx, __u64 packet_len, __u8 action, __u16 ruleId, __u8 generateEvent, __u32 ifId) {
    struct ruleStatistics_st *statistics, initialStats;
    struct event_hdr_st hdr;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 headerSize;
    __u32 key = ruleId;

    memset(&hdr, 0, sizeof(hdr));
    hdr.ruleId = ruleId;
    hdr.action = action;
    hdr.pktLength = (__u16)packet_len;
    hdr.ifId = (__u16)ifId;

    memset(&initialStats, 0, sizeof(initialStats));
    statistics = bpf_map_lookup_elem(&ingress_node_firewall_statistics_map, &key);
    if (likely(statistics)) {
        switch (action) {
        case ALLOW:
            __sync_fetch_and_add(&statistics->allow_stats.packets, 1);
            __sync_fetch_and_add(&statistics->allow_stats.bytes, packet_len);
            break;
        case DENY:
            __sync_fetch_and_add(&statistics->deny_stats.packets, 1);
            __sync_fetch_and_add(&statistics->deny_stats.bytes, packet_len);
            break;
        }
    } else {
        bpf_map_update_elem(&ingress_node_firewall_statistics_map, &key, &initialStats, BPF_ANY);
    }

    if (generateEvent) {
        headerSize = packet_len < MAX_EVENT_DATA ? packet_len : MAX_EVENT_DATA;
        // enable the following flag to dump packet header
        flags |= (__u64)headerSize << 32;

        (void)bpf_perf_event_output(ctx, &ingress_node_firewall_events_map, flags,
                                    &hdr, sizeof(hdr));
    }
}

/*
 * ingress_node_firewall_main(): is the entry point for the XDP program to do
 * ingress node firewall.
 * Input:
 * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index.
 * Output:
 * none.
 * Return:
 * int XDP action: valid values XDP_DROP and XDP_PASS.
 */
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
  "startLine": 405,
  "endLine": 450,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/ingress-node-firewall-master/original_source/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ingress_node_firewall_main",
  "developer_inline_comments": [
    {
      "start_line": 395,
      "end_line": 404,
      "text": " * ingress_node_firewall_main(): is the entry point for the XDP program to do * ingress node firewall. * Input: * struct xdp_md *ctx: pointer to XDP context which contains packet pointer and input interface index. * Output: * none. * Return: * int XDP action: valid values XDP_DROP and XDP_PASS. "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "staticinlineint",
  "helper": [
    "XDP_DROP",
    "XDP_PASS"
  ],
  "compatibleHookpoints": [
    "xdp"
  ],
  "source": [
    "static inline int ingress_node_firewall_main (struct xdp_md *ctx)\n",
    "{\n",
    "    void *data = (void *) (long) ctx->data;\n",
    "    void *dataEnd = (void *) (long) ctx->data_end;\n",
    "    struct ethhdr *eth = data;\n",
    "    void *dataStart = data + sizeof (struct ethhdr);\n",
    "    __u32 result = UNDEF;\n",
    "    __u32 ifId = ctx->ingress_ifindex;\n",
    "    ingress_node_firewall_printk (\"Ingress node firewall start processing a packet on %d\", ifId);\n",
    "    if (unlikely (dataStart > dataEnd)) {\n",
    "        ingress_node_firewall_printk (\"Ingress node firewall bad packet XDP_DROP\");\n",
    "        return XDP_DROP;\n",
    "    }\n",
    "    switch (eth->h_proto) {\n",
    "    case bpf_htons (ETH_P_IP) :\n",
    "        ingress_node_firewall_printk (\"Ingress node firewall process IPv4 packet\");\n",
    "        result = ipv4_firewall_lookup (ctx, ifId);\n",
    "        break;\n",
    "    case bpf_htons (ETH_P_IPV6) :\n",
    "        ingress_node_firewall_printk (\"Ingress node firewall process IPv6 packet\");\n",
    "        result = ipv6_firewall_lookup (ctx, ifId);\n",
    "        break;\n",
    "    default :\n",
    "        ingress_node_firewall_printk (\"Ingress node firewall unknown L3 protocol XDP_PASS\");\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "    __u16 ruleId = GET_RULE_ID (result);\n",
    "    __u8 action = GET_ACTION (result);\n",
    "    switch (action) {\n",
    "    case DENY :\n",
    "        generate_event_and_update_statistics (ctx, bpf_xdp_get_buff_len (ctx), DENY, ruleId, 1, ifId);\n",
    "        ingress_node_firewall_printk (\"Ingress node firewall action DENY -> XDP_DROP\");\n",
    "        return XDP_DROP;\n",
    "    case ALLOW :\n",
    "        generate_event_and_update_statistics (ctx, bpf_xdp_get_buff_len (ctx), ALLOW, ruleId, 0, ifId);\n",
    "        ingress_node_firewall_printk (\"Ingress node firewall action ALLOW -> XDP_PASS\");\n",
    "        return XDP_PASS;\n",
    "    default :\n",
    "        ingress_node_firewall_printk (\"Ingress node firewall action UNDEF\");\n",
    "        return XDP_PASS;\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "GET_ACTION",
    "GET_RULE_ID",
    "ingress_node_firewall_printk",
    "ipv4_firewall_lookup",
    "generate_event_and_update_statistics",
    "bpf_xdp_get_buff_len",
    "unlikely",
    "bpf_htons",
    "ipv6_firewall_lookup"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function takes in a packet as struct xdp_mp *ctx. It first checks if the packet is well formed if not it returns XDP_DROP. Then it checks if the packet is an ipv4 or ipv6 packet and calls respective firewll lookup function ipv4_firewall_lookup/ipv6_firewall_lookup with ctx and ifId which is the packet ingress interface. Both the functions return a firewall rule and action to be applied to the packet and then this function will record the action and rule for this packet by calling generate_event_and_update_statistics function and will return XDP_DROP to drop the packet if the action is DENY else XDP_PASS to allow the packet if action is ALLOW or undefined.",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "05-Apr-2023"
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
__attribute__((__always_inline__)) static inline int
ingress_node_firewall_main(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *dataStart = data + sizeof(struct ethhdr);
    __u32 result = UNDEF;
    __u32 ifId = ctx->ingress_ifindex;

    ingress_node_firewall_printk("Ingress node firewall start processing a packet on %d", ifId);

    if (unlikely(dataStart > dataEnd)) {
        ingress_node_firewall_printk("Ingress node firewall bad packet XDP_DROP");
        return XDP_DROP;
    }
    switch (eth->h_proto) {
    case bpf_htons(ETH_P_IP):
        ingress_node_firewall_printk("Ingress node firewall process IPv4 packet");
        result = ipv4_firewall_lookup(ctx, ifId);
        break;
    case bpf_htons(ETH_P_IPV6):
        ingress_node_firewall_printk("Ingress node firewall process IPv6 packet");
        result = ipv6_firewall_lookup(ctx, ifId);
        break;
    default:
        ingress_node_firewall_printk("Ingress node firewall unknown L3 protocol XDP_PASS");
        return XDP_PASS;
    }

    __u16 ruleId = GET_RULE_ID(result);
    __u8 action = GET_ACTION(result);

    switch (action) {
    case DENY:
        generate_event_and_update_statistics(ctx, bpf_xdp_get_buff_len(ctx), DENY, ruleId, 1, ifId);
        ingress_node_firewall_printk("Ingress node firewall action DENY -> XDP_DROP");
        return XDP_DROP;
    case ALLOW:
        generate_event_and_update_statistics(ctx, bpf_xdp_get_buff_len(ctx), ALLOW, ruleId, 0, ifId);
        ingress_node_firewall_printk("Ingress node firewall action ALLOW -> XDP_PASS");
        return XDP_PASS;
    default:
        ingress_node_firewall_printk("Ingress node firewall action UNDEF");
        return XDP_PASS;
    }
}

SEC("xdp.frags")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 453,
  "endLine": 455,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/ingress-node-firewall-master/original_source/bpf/ingress_node_firewall_kernel.c",
  "funcName": "ingress_node_firewall_process",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sched_act",
    "sk_reuseport",
    "sched_cls",
    "sk_skb",
    "flow_dissector",
    "xdp",
    "kprobe",
    "raw_tracepoint_writable",
    "socket_filter",
    "lwt_xmit",
    "cgroup_sysctl",
    "perf_event",
    "cgroup_sock",
    "lwt_out",
    "lwt_in",
    "cgroup_sock_addr",
    "sock_ops",
    "tracepoint",
    "raw_tracepoint",
    "cgroup_skb",
    "sk_msg",
    "lwt_seg6local",
    "cgroup_device"
  ],
  "source": [
    "int ingress_node_firewall_process (struct xdp_md *ctx)\n",
    "{\n",
    "    return ingress_node_firewall_main (ctx);\n",
    "}\n"
  ],
  "called_function_list": [
    "",
    "ingress_node_firewall_main"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This is a wrapper funciton which attaches itself at XDP hook point and calls the function ingress_node_firewall_main and returns its results.",
      "author": "Dushyant Behl",
      "authorEmail": "dushyantbehl@in.ibm.com",
      "date": "05-Apr-2023"
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
int ingress_node_firewall_process(struct xdp_md *ctx) {
    return ingress_node_firewall_main(ctx);
}

char __license[] SEC("license") = "Dual BSD/GPL";
