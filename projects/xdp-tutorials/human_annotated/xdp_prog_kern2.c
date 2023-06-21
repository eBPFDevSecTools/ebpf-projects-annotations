/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MTU 1536
#define MIN_LEN 14

/*
 * This example show howto access packet last byte in XDP packet,
 * without parsing packet contents.
 *
 * It is not very effecient, as it advance the data pointer one-byte in a
 * loop until reaching data_end.  This is needed as the verifier only allows
 * accessing data via advancing the position of the data pointer. The bounded
 * loop with a max number of iterations allows the verifier to see the bound.
 */

SEC("xdp_end_loop")
/* 
 OPENED COMMENT BEGIN 
{
	"capability": [],
	"helperCallParams": {},
	"startLine": 19,
	"endLine": 63,
	"File": "/root/examples/xdp-tutorials/xdp_prog_kern2.c",
	"funcName": "_xdp_end_loop",
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
		"description": "The function _xdp_end_loop verifies that the data buffer processed is valid, and it returns XDP_ABORTED if it is not. The function _xdp_end_loop takes ctx of type struct xdp_md as input. Two pointers data and data_end points to the start and end of the packet data respectively. The packet contents are in between ctx - > data and ctx - > data_end. Variable offset is initialized with a minimum length which is stored in a constant MIN_LEN = 14. The void pointer pos initially points to the start of the received packet. A for loop will execute for each bit in the ethernet packet[MTU - MIN_LEN i.e.1536 - 14 which represents the ethernet packet(Ethernet Header + MTU)], and checks if pos plus offset is greater than data_end then it returns XDP_PASS. XDP_PASS indicates that the packet should be forwarded to the normal network stack for further processing. If pos plus offset is equal to data_end then calculate ptr = pos + (offset - sizeof( * ptr)). If * ptr == 0xFF, it returns XDP_ABORTED.",
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
int _xdp_end_loop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	unsigned char *ptr;
	unsigned int i;
	void *pos;

	/* Assume minimum length to reduce loops needed a bit */
	unsigned int offset = MIN_LEN;

	pos = data;

	/* Verifier can handle this bounded 'basic-loop' construct */
	for (i = 0; i < (MTU - MIN_LEN); i++ ) {
		if (pos + offset > data_end) {
			/* Promise verifier no access beyond data_end */
			goto out;
		}
		if (pos + offset == data_end) {
			/* Found data_end, exit for-loop and read data.
			 *
			 * It seems strange, that finding data_end via
			 * moving pos (data) pointer forward is needed.
			 * This is because pointer arithmetic on pkt_end is
			 * prohibited by verifer.
			 *
			 * In principle data_end points to byte that is not
			 * accessible. Thus, accessing last readable byte
			 * via (data_end - 1) is prohibited by verifer.
			 */
			goto read;
		}
		offset++;
	}
	/* Show verifier all other cases exit program */
	goto out;

read:
	ptr = pos + (offset - sizeof(*ptr)); /* Parentheses needed */
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
