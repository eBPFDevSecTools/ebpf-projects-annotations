/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * This BPF-prog will FAIL, due to verifier rejecting it.
 *
 * General idea: Use packet length to find and access last byte in
 * packet.  The verifier cannot see this is safe, as it cannot deduce
 * the packet length at verification time.
 */

SEC("xdp_fail1")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 46,
  "File": "/root/examples/xdp-tutorials/xdp_prog_fail1.c",
  "funcName": "_xdp_fail1",
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
      "description": " The function tries to use the packet length (calculated as data_end - data) to access the last byte as an offset added to data. 
                       The verifier rejects this, as the dynamic length calculation cannot be used for static analysis.
                       The function _xdp_fail1 takes ctx of type struct xdp_md as input. 
                       The packet contents are between ctx->data and ctx->data_end.
                       The length of the packet is stored in unsigned interger variable named offset.
                       pos is a void pointer pointing to the start of data packet.
                       If the packet lies in between the data and data_end it return XDP_PASS.
                       XDP_PASS indicates that the packet should be forwarded to the normal network stack for further processing. 
                       The XDP program can modify the content of the package before this happens.
                       Else, it will return XDP_ABORTED which indicates the packet will be dropped.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "14.02.2023"
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
int _xdp_fail1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *ptr;
	void *pos;

	/* (Correct me if I'm wrong)
	 *
	 * The verifier cannot use this packet length calculation as
	 * part of its static analysis.  It chooses to use zero as the
	 * offset value static value.
	 */
	unsigned int offset = data_end - data;

	pos = data;

	if (pos + offset > data_end)
		goto out;

	/* Fails at this line with:
	 *   "invalid access to packet, off=-1 size=1, R1(id=2,off=0,r=0)"
	 *   "R1 offset is outside of the packet"
	 *
	 * Because verifer used offset==0 it thinks that we are trying
	 * to access (data - 1), which is not within [data,data_end)
	 */
	ptr = pos + (offset - sizeof(*ptr));
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
