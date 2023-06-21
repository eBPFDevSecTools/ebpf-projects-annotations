/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp_data_access_helpers.h"

SEC("xdp_test1")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 8,
  "endLine": 22,
  "File": "/root/examples/xdp-tutorials/xdp_prog_kern4.c",
  "funcName": "_xdp_test1",
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
      "description": "The fucntion _xdp_test1 stores two bytes from the end of the packet data and passes the packet to the next layer of network stack for processing.
                      The function _xdp_test1 takes ctx of type struct xdp_md as input. struct xdp_md is the metadata for the XDP packet. 
                      The void pointer data points to the start of the packet.
                      An integer variable len is initialized with the value 12.
                      An unsigned integer variable offset is initialized with the value len - 2.
                      It checks if ctx_store_bytes(ctx, offset, data, 2, 0) < 0, it returns XDP_ABORTED, which means it will drop the packet with a tracepoint exception.
                      Else, the function returns XDP_PASS, which indicates that the packet should be forwarded to the normal network stack for further processing.
                      The ctx_store_bytes helper function stores the first two bytes of the packet data at an offset of 10 bytes from the end of the packet data. 
                      Using ctx_store_bytes(ctx, offset, data, 2, 0) < 0, it is checking the bound condition that whether it is exceeding the size of the packet or not. 
                      If the return value is negative then error has occured, else it returns the number of bytes written to the packet.",
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
int _xdp_test1(struct xdp_md *ctx)
{
//	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned int len;
//	len = (data_end - data) - 2 ; // Not working, due to verifier
	len = 12;

	unsigned int offset = len - 2;

	if (ctx_store_bytes(ctx, offset, data, 2, 0) < 0)
		return XDP_ABORTED;

	return XDP_PASS;
}

