/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/*
 * Solution to the assignment 1 in lesson packet02
 */
SEC("xdp_patch_ports")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 21,
  "endLine": 64,
  "File": "/root/examples/xdp-tutorials/xdp_prog_kern_02.c",
  "funcName": "xdp_patch_ports_func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "The function will decrease by one destination port number in any TCP or UDP packet.
                      The function xdp_patch_ports_func takes ctx of type struct xdp_md as input. struct xdp_md is the metadata for the XDP packet. 
                      Two pointers data and data_end points to the start and end of the XDP packet data respectively.
                      The packet contents are in between ctx->data and ctx->data_end.
                      eth is a pointer to an element of a structure ethhdr, ethhdr is an Ethernet frame header defined in <linux/if_ether.h>
                      parse_ethhdr(&nh, data_end, &eth) takes the current parsing position nh, the pos of packet end, and the eth as input and returns the packet type ID (or EtherType) which is stored in an integer variable eth_type.
                      If eth_type < 0, action is set to XDP_ABORTED and a call is made to xdp_stats_record_action(ctx, action).
                      If eth_type == bpf_htons(ETH_P_IP) i.e. eth_type == IPv4, it will call parse_iphdr(&nh, data_end, &iphdr) function which returns the type of packet (TCP or UDP) by parsing the packet header. The return value will be stored in a variable called ip_type.
                      Else if eth_type == bpf_htons(ETH_P_IPV6) i.e. eth_type == IPv6, it will call parse_iphdr(&nh, data_end, &iphdr) function which returns the type of packet (TCP or UDP) by parsing the packet header. The return value will be stored in a variable called ip_type.
                      Else a call is made to xdp_stats_record_action(ctx, action) where action is set to XDP_PASS.
                      If the packet is a UDP packet, the packet header is parsed and xdp_stats_record_action(ctx, action) is called where action is set to XDP_ABORTED.
                      Then it will decrease by one destination port number in UDP packet.
                      Else if the packet is a TCP packet, the packet header is parsed and xdp_stats_record_action(ctx, action) is called where action is set to XDP_ABORTED.
                      Then it will decrease by one destination port number in TCP packet.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "21.02.2023"
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
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
	}

out:
	return xdp_stats_record_action(ctx, action);
}

/*
 * Solution to the assignments 2 and 3 in lesson packet02: Will pop outermost
 * VLAN tag if it exists, otherwise push a new one with ID 1
 */
SEC("xdp_vlan_swap")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 71,
  "endLine": 92,
  "File": "/root/examples/xdp-tutorials/xdp_prog_kern_02.c",
  "funcName": "xdp_vlan_swap_func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "The function either removes the outermost VLAN tag if exists or add back a missing VLAN tag.
                      The function xdp_vlan_swap_func takes ctx of type struct xdp_md as input. struct xdp_md is the metadata for the XDP packet. 
                      Two pointers data and data_end points to the start and end of the XDP packet data respectively.
                      The packet contents are in between ctx->data and ctx->data_end.
                      The variable nh is of type struct hdr_cursor. struct hdr_cursor stores a void pointer pos, which is used to keep track of the current parsing position.
                      nh.pos initially points to the start of the packet data.
                      eth is a pointer to an element of a structure ethhdr, ethhdr is an Ethernet frame header defined in <linux/if_ether.h>
                      parse_ethhdr(&nh, data_end, &eth) takes the current parsing position nh, the pos of packet end, and the eth as input and returns the packet type ID (or EtherType) which is stored in an integer variable nh_type.
                      If nh_type < 0, it returns XDP_PASS, which indicates that the packet should be forwarded to the normal network stack for further processing.
                      Else if proto_is_vlan(eth->h_proto) is true, it calls vlan_tag_pop(ctx, eth) function which removes the VLAN tag from the ethernet header.
                      proto_is_vlan(eth->h_proto) function takes the ethernet frame's packet type ID field as input and checks if eth->h_proto is equal to the 16-bit number in the network byte order of ETH_P_8021Q (802.1Q VLAN Extended Header) or ETH_P_8021AD (802.1ad Service VLAN).
                      Else a VLAN tag is added with a value 1 by calling vlan_tag_push(ctx, eth, 1) function.
                      Finally, the function returns XDP_PASS, which indicates that the packet should be forwarded to the normal network stack for further processing.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "21.02.2023"
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
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

SEC("xdp_pass")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 95,
  "endLine": 98,
  "File": "/root/examples/xdp-tutorials/xdp_prog_kern_02.c",
  "funcName": "xdp_pass_func",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "The function xdp_pass_func takes ctx of type struct xdp_md as input. struct xdp_md is the metadata for XDP packet.
                      The function returns XDP_PASS, which indicates that the packet should be forwarded to the normal network stack for further processing.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "21.02.2023"
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
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
