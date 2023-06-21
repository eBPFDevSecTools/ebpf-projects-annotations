// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* NOTICE: Re-defining VLAN header levels to parse */
#define VLAN_MAX_DEPTH 10
#include "../common/parsing_helpers.h"

#if 0
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};
#endif

#if 0 /* moved to parsing_helpers.h */
/* Based on parse_ethhdr() */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 22,
  "endLine": 65,
  "File": "/root/examples/xdp-tutorials/xdp_vlan02_kern.c",
  "funcName": "__parse_ethhdr_vlan",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct hdr_cursor *nh",
    " void *data_end",
    " struct ethhdr **ethhdr",
    " struct collect_vlans *vlans"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "The function __parse_ethhdr_vlan parses the Ethernet header and VLAN header and returns the protocol number stored in Ethernet's packet in network byte order, if VLAN header is not present. Otherwise, it returns the protocol number in the VLAN header.
	  				  The function __parse_ethhdr_vlan takes the following arguments as input to the function: a pointer to a struct hdr_cursor, a pointer data_end to point to the end of the packet data, ethhdr which is a pointer to a pointer to an ethhdr struct and a pointer to a collect_vlans struct.
					  'hdr_cursor' stores the current position of the packet being parsed. 'ethhdr' which will be set to the currently parsed Ethernet header. 'collect_vlans' struct,  stores any VLAN header information found in the packet.
					  It checks if nh->pos + hdrsize > data_end i.e if the current parsing position plus the header size exceeds the location pointing to the end of the packet then it is an invalid packet, hence returns 0.
					  Else the pointer moves to the next header by performing nh->pos += hdrsize.
					  Then, the function checks if the Ethernet header contains any VLAN encapsulation by looping over the header and looking for VLAN header information. The loop is unrolled to avoid verification restrictions on loops, and it supports up to VLAN_MAX_DEPTH layers of VLAN encapsulation. The function retrieves the VLAN header information and stores it in the collect_vlans struct if it is provided.
					  Finally, the function sets the cursor position to the end of the VLAN headers and returns the protocol number from the Ethernet header in network-byte-order.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "24.04.2023"
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
static __always_inline int __parse_ethhdr_vlan(struct hdr_cursor *nh,
					       void *data_end,
					       struct ethhdr **ethhdr,
					       struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) {
			vlans->id[i] =
				bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
		}
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}
#endif

SEC("xdp_vlan02")
/* 
 OPENED COMMENT BEGIN 
{
	"capability": [],
	"helperCallParams": {},
	"startLine": 69,
	"endLine": 127,
	"File": "/root/examples/xdp-tutorials/xdp_vlan02_kern.c",
	"funcName": "xdp_vlan_02",
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
	"humanFuncDescription": [{
		"description": "The function xdp_vlan_02 parses incoming Ethernet packets and extracts VLAN tags. It checks if the id of the second VLAN tag is 42, it returns XDP_ABORTED. Else, it returns XDP_PASS. The function xdp_vlan_02 takes ctx of type struct xdp_md as input.  Two pointers data_end and data point to the end and the start of the packet data.  The packet contents are between ctx->data and ctx->data_end. Varibale nh is of type struct hdr_cursor. struct hdr_cursor stores a void pointer pos, which is used to keep track of the current parsing position. nh.pos initially points to the start of the packet data. Varibale vlans is of type struct collect_vlans. struct collect_vlans is structure to collect VLANs after parsing via parse_ethhdr_vlan. eth is a pointer to an element of a structure ethhdr, ethhdr is an Ethernet frame header defined in <linux/if_ether.h>. The function parse_ethhdr_vlan(&nh, data_end, &eth, &vlans) takes the current parsing position nh, the pos of packet end, the eth and vlans as input. It parses the ethernet header and checks if this is a VLAN tagged packet. If true it returns the ethernet type field which stored in variable eth_type of type int. If eth_type < 0 i.e an invalid EtherType, it returns XDP_ABORTED. It checks if vlans.id[1] == 42 i.e. ff the second VLAN tag in the packet is 42, the function returns XDP_ABORTED. Else it returns XDP_PASS, indicates that the packet should be forwarded to the normal network stack for further processing.",
		"author": "Utkalika Satapathy",
		"authorEmail": "utkalika.satapathy01@gmail.com",
		"date": "20.02.2023"
	}],
	"AI_func_description": [{
		"description": "",
		"author": "",
		"authorEmail": "",
		"date": "",
		"invocationParameters": ""
	}]
}
 OPENED COMMENT END 
 */ 
int xdp_vlan_02(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int eth_type;
	nh.pos = data;

	struct collect_vlans vlans;

	struct ethhdr *eth;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (eth_type < 0)
		return XDP_ABORTED;
	/* The eth_type have skipped VLAN-types, but collected VLAN ids. The
	 * eth ptr still points to Ethernet header, thus to check if this is a
	 * VLAN packet do proto_is_vlan(eth->h_proto).
	 */

	/* The LLVM compiler is very clever, it sees that program only access
	 * 2nd "inner" vlan (array index 1), and only does loop unroll of 2, and
	 * only does the VLAN_VID_MASK in the 2nd "inner" vlan case.
	 */
	if (vlans.id[1] == 42)
		return XDP_ABORTED;

	/* If using eth_type (even compare against zero), it will cause full
	 * loop unroll and walking all VLANs (for VLAN_MAX_DEPTH). Still only
	 * "inner" VLAN is masked out.
	 */
#if 0
	if (eth_type == 0)
		return XDP_PASS;
#endif

	/* Unless we only want to manipulate VLAN, then next step will naturally
	 * be parsing the next L3 headers. This (also) cause compiler to create
	 * VLAN loop, as this uses nh->pos
	 */
#if 0
	int ip_type;
	struct iphdr *iphdr;
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (eth_type < 0)
			return XDP_ABORTED;

		if (ip_type == IPPROTO_UDP)
			return XDP_DROP;
	}
#endif
	/* Hint: to inspect BPF byte-code run:
	 *  llvm-objdump --no-show-raw-insn -S xdp_vlan02_kern.o
	 */
	return XDP_PASS;
}
