/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* This is a barrier_var() operation that makes specified variable
 * "a black box" for optimizing compiler.
 */
#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

/*
 * General idea: Use packet length to find and access last byte.
 */

SEC("xdp_works1")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 15,
  "endLine": 56,
  "File": "/root/examples/xdp-tutorials/xdp_prog_kern3.c",
  "funcName": "_xdp_works1",
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
      "description": "The function looks at the last second last byte and if the value is 0xFF drops the packet at XDP hookpoint, otherwise the packet is allowed to pass.
                      The function _xdp_works1 takes ctx of type struct xdp_md as input. struct xdp_md is the metadata for XDP packet. 
                      Two pointers data and data_end points to the start and end of the XDP packet data respectively.
                      The packet contents are in between ctx->data and ctx->data_end.
                      The length of the packet is calculated by data_end - data and stored in the offset variable.
                      barrier_var() operation that makes specified variable \"a black box\" for optimizing the compiler.
                      The offset value is decremented by 1 and updated after performing a bitwise AND operation with 0x7FFF.
                      A void pointer pos initially point to the start of the XDP packet. Then it is forwarded by adding the offset to it.
                      Now it checks if the pos + 1 is greater than data_end, it returns XDP_DROP, which means it will drop all incoming packets.
                      Also, an unsigned char pointer ptr points to the location where the pos are pointing. If ptr is pointing to a value 0xFF, it returns XDP_ABORTED, which means it will drop the packet with a tracepoint exception.
                      Else the function returns XDP_PASS. XDP_PASS indicates that the packet should be forwarded to the normal network stack for further processing.",
      "author": "Utkalika Satapathy",
      "authorEmail": "utkalika.satapathy01@gmail.com",
      "date": "20.02.2023"
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
int _xdp_works1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *ptr;
	void *pos;

	/* Important to understand that data_end points to the byte AFTER
	 * the data 'where-data-ends' (e.g one byte off the end).  This is
	 * practical to calculate the length when subtracting two pointers.
	 */
	unsigned int offset = data_end - data;

	/* The offset now contains the byte length, but instead we want an
	 * offset (from data pointer) that point to the last byte in the
	 * packet. Thus, subtract one byte, but we need to stop compiler
	 * from optimzing this (else BPF verifier will reject).
	 */
	barrier_var(offset);
	offset = offset - 1;

	offset &= 0x7FFF; /* Bound/limit max value to help verifier */

	/* Explicitly use a position pointer (corresponding to data) being
	 * moved forward, to show how verifier tracks this.
	 */
	pos = data;
	pos += offset;

	/* BPF verifier needs this step: It show that reading one byte via
	 * position pointer 'pos' is safe.
	 */
	if (pos + 1 > data_end)
		return XDP_DROP;

	/* Access data in byte-steps via an unsigned char pointer */
	ptr = pos;
	if (*ptr == 0xFF) /* Reads last byte before data_end */
		return XDP_ABORTED;

	return XDP_PASS;
}
