// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* NOTICE: Re-defining VLAN header levels to parse */
#define VLAN_MAX_DEPTH 10
//#include "../common/parsing_helpers.h"
/*
 * NOTICE: Copied over parts of ../common/parsing_helpers.h
 *         to make it easier to point out compiler optimizations
 */

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 21,
  "endLine": 25,
  "File": "/root/examples/xdp-tutorials/xdp_vlan01_kern.c",
  "funcName": "proto_is_vlan",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u16 h_proto"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "This function checks is the packet has vlan tunnel header.
                      proto_is_vlan(eth->h_proto) takes the ethernet frame's packet type ID field as input.
                      The bpf_htons function takes a 16-bit number in host byte order and returns a 16-bit number in network byte order used in TCP/IP networks.
                      If input argument h_proto is equal to the network byte order of ETH_P_8021Q (802.1Q VLAN Extended Header) or ETH_P_8021AD (802.1ad Service VLAN), it will return true,
                      else it will return false.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "17.02.2023"
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
static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto; /* NOTICE: unsigned type */
};

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 42,
  "endLine": 79,
  "File": "/root/examples/xdp-tutorials/xdp_vlan01_kern.c",
  "funcName": "parse_ethhdr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct hdr_cursor *nh",
    " void *data_end",
    " struct ethhdr **ethhdr"
  ],
  "output": "static__always_inlineint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "The function will parse packet header, by traversing VLAN headers till VLAN_MAX_DEPTH, do bounds checking for header information, and return the next header type and position.
                      parse_ethhdr() takes the following input parameters: nh which is a pointer to an element of struct hdr_cursor, a void pointer data_end, and ethhdr, a pointer to pointer of type struct ethhdr).
                      Varibale nh is of type struct hdr_cursor. struct hdr_cursor stores a void pointer pos, which is used to keep track of the current parsing position.
                      eth points to the current parsing postion of the header. int hdrsize stores the Ethernet frame size.
                      struct vlan_hdr is a data structure to vlan header, which consist of 2 feilds: h_vlan_TCI of type __be16 to store the priority and VLAN ID and h_vlan_encapsulated_proto of type __be16 to store packet type ID or len.
                      It checks if current pointer plus size of header is greater than data_end, it returns -1.
                      The current pointer is updated to current pointer plus the header size.
                      ethhdr points to the eth and vlh points to the current parsing postion of the header. 
                      h_proto is initialized with the eth->h_proto value.
                      #pragma unroll is used to avoid the verifier restriction on loops.
                      It runs a for loop for VLAN_MAX_DEPTH=10 times, each time first checks if proto_is_vlan(h_proto) is 0 or not. If it is 0 then it break and come out of the loop.
                      It also checks if the vlh plus 1 exceeds data_end, if true it break. 
                      h_proto is updated to vlh->h_vlan_encapsulated_proto and vlh is increamented by 1.
                      Once the for is executed, the curerent parsing position is updated with the position pointed by vlh.
                      And finally the h_proto which is the IP port no in network-byte-order is returned.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "17.02.2023"
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
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **ethhdr)
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
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

SEC("xdp_vlan01")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 82,
  "endLine": 115,
  "File": "/root/examples/xdp-tutorials/xdp_vlan01_kern.c",
  "funcName": "xdp_vlan_01",
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
      "description": "This function checks if the innermost packet header (up to VLAN_MAX_DEPTH) is a VLAN header, if so it drops the packet. It also drops if the packet if the innermost header is invalid.
                      The function xdp_vlan_01 takes ctx of type struct xdp_md as input. 
                      Two pointers data_end and data point to the end and the start of the packet data. 
                      The packet contents are between ctx->data and ctx->data_end.
                      Varibale nh is of type struct hdr_cursor. struct hdr_cursor stores a void pointer pos, which is used to keep track of the current parsing position.
                      nh.pos initially points to the start of the packet data.
                      eth is a pointer to an element of a structure ethhdr, ethhdr is an Ethernet frame header defined in <linux/if_ether.h>
                      parse_ethhdr(&nh, data_end, &eth) takes the current parsing position nh, the pos of packet end, and the eth as input and returns the packet type ID (or EtherType) which is stored in an integer variable nh_type.
                      If nh_type < 0 i.e an invalid EtherType, it returns XDP_ABORTED.
                      Else it checks if proto_is_vlan(eth->h_proto) is true, it returns XDP_DROP.
                      proto_is_vlan(eth->h_proto) takes the ethernet frame's packet type ID field as input and checks if eth->h_proto is equal to the 16-bit number in network byte order of ETH_P_8021Q (802.1Q VLAN Extended Header) or ETH_P_8021AD (802.1ad Service VLAN).
                      That means if the eth->h_proto is of type 802.1Q VLAN Extended Header or 802.1ad Service VLAN, it returns XDP_DROP, which means all the incoming packets will be dropped.
                      Else it returns XDP_PASS, indicates that the packet should be forwarded to the normal network stack for further processing.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "17.02.2023"
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
int xdp_vlan_01(struct xdp_md *ctx)
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
		return XDP_ABORTED;

	/* The LLVM compiler is very clever, and will remove above walking of
	 * VLAN headers (the loop unroll).
	 *
	 * The returned value nh_type, variable (__u16) h_proto in
	 * parse_ethhdr(), is only compared against a negative value (signed).
	 * The compile see that it can remove the VLAN loop, because:
	 *  1. h_proto = vlh->h_vlan_encapsulated_proto can only be >= 0
	 *  2. we never read nh->pos (so it removes nh->pos = vlh;).
	 */

	/* Accessing eth pointer is still valid after compiler optimization */
	if (proto_is_vlan(eth->h_proto))
		return XDP_DROP;

	/* Hint: to inspect BPF byte-code run:
	 *  llvm-objdump -S xdp_vlan01_kern.o
	 */
	return XDP_PASS;
}
