/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_PACKET_OFF 0x7fff

/* This is a barrier_var() operation that makes specified variable
 * "a black box" for optimizing compiler.
 */
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

/*
 * This BPF-prog will FAIL, due to verifier rejecting it.
 *
 * General idea: Use packet length to find and access last byte in
 * packet.  The verifier cannot see this is safe, as it cannot deduce
 * the packet length at verification time.
 */

SEC("xdp_fail3")
/* 
 OPENED COMMENT BEGIN 
{
	"capability": [],
	"helperCallParams": {},
	"startLine": 21,
	"endLine": 55,
	"File": "/root/examples/xdp-tutorials/xdp_prog_fail3.c",
	"funcName": "_xdp_fail3",
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
		"description": "The function uses packet length to find and access last byte in packet. NOTE: The verifier cannot see this is safe, as it cannot deduce the packet length at verification time. The function _xdp_fail3 takes ctx of type struct xdp_md as input. Two pointers data and data_end points to the start and end of the packet data respectively. The packet contents are in between ctx - > data and ctx - > data_end. The length of the packet is stored in interger variable named offset of type __u64. The maximum offset value, MAX_PACKET_OFF is set to 0x7fff(32767 in decimal). 'offset & 0xFFFF' is used to mask the low 16 bits of offset and updated to offset. If the offset value is less than 2, the offset is updated to 2. Then it will check whether the start of the packet data plus the offset is greater than the packet_end.On true, it will return XDP_PASS. XDP_PASS indicates that the packet should be forwarded to the normal network stack for further processing. Else if the start of the packet data plus the offset is less than the packet_end, the pointer ptr is initialized with data plus(offset - sizeof( * ptr)) value. If ptr is eqaul to 0XFF, it will return XDP_ABORTED, which indicates the packet will be dropped.",
		"author": "Utkalika Satapathy",
		"authorEmail": "utkalika.satapathy01@gmail.com",
		"date": "17.02.2023"
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
int _xdp_fail3(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *ptr;

	/* (Correct me if I'm wrong)
	 *
	 * The verifier cannot use this packet length calculation as
	 * part of its static analysis.  It chooses to use zero as the
	 * offset value static value.
	 */
	__u64 offset = data_end - data;

	/* Help verifier with bounds checks */
	offset = offset & MAX_PACKET_OFF; /* Give verifier max_value */
	if (offset < 2)
		offset = 2; /* Give verifier min_value */

	if (data + offset > data_end)
		goto out;

	/* Fails at this line with:
	 *   "invalid access to packet, off=-1 size=1, R1(id=2,off=0,r=0)"
	 *   "R1 offset is outside of the packet"
	 *
	 * Because verifer used offset==0 it thinks that we are trying
	 * to access (data - 1), which is not within [data,data_end)
	 */
	ptr = data + (offset - sizeof(*ptr));
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
