/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * This BPF-prog will FAIL, due to verifier rejecting it.
 *
 * General idea: Use data_end point to access last (2nd-last) byte in
 * packet.  That is not allowed by verifier, as pointer arithmetic on
 * pkt_end is prohibited.
 */

SEC("xdp_fail2")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 34,
  "File": "/root/examples/xdp-tutorials/xdp_prog_fail2.c",
  "funcName": "_xdp_fail2",
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
      "description": "The function tries to find the last byte in the packet.
                      The function _xdp_fail2 takes ctx of type struct xdp_md as input. 
                      The void pointer data_end points to the end of a packet data.
                      The void pointer pos of type volatile also points to the end of the packet data.
                      #pragma clang optimize off used to to selectively enable optimization.
                      #pragma clang optimize on does not selectively enable additional optimizations when compiling at low optimization levels. 
                      This feature can only be used to selectively disable optimizations.
                      if pos-1 > data_end which checks the data access out of bound and return XDP_PASS.
                      XDP_PASS indicates that the packet should be forwarded to the normal network stack for further processing. 
                      A unsigned char pointer ptr of type volatile points to the second last position on in the packet.
                      if ptr is equal to 0XFF then it will return XDP_ABORTED, which indicates the packet will be dropped.",
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
int _xdp_fail2(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	volatile unsigned char *ptr;
	volatile void *pos;

	pos = data_end;

#pragma clang optimize off
	if (pos - 1 > data_end)
		goto out;
#pragma clang optimize on

	/* Verifier fails with: "pointer arithmetic on pkt_end prohibited"
	 */
	ptr = pos - 2;
	if (*ptr == 0xFF)
		return XDP_ABORTED;
out:
	return XDP_PASS;
}
