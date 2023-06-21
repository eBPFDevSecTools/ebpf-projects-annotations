/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

/* to u64 in host order */
/* 
 OPENED COMMENT BEGIN 
{
	"capability": [],
	"helperCallParams": {},
	"startLine": 20,
	"endLine": 28,
	"File": "/root/examples/xdp-tutorials/xdp_prog_kern.c",
	"funcName": "ether_addr_to_u64",
	"updateMaps": [],
	"readMaps": [],
	"input": [
		"const __u8 *addr"
	],
	"output": "staticinline__u64",
	"helper": [],
	"compatibleHookpoints": [
		"All_hookpoints"
	],
	"humanFuncDescription": [{
		"description": "ether_addr_to_u64() function takes an array named addr which stores values of type const__u8. ETH_ALEN is a constant defined in < if_ether.h > whose value is 6 which represents octets in one ethernet addr. A variable u of type __u64 is initialized to 0. A for loop will execute 6 times i.e.( for values i = 0 to i = ETH_ALEN - 1 i.e.6 - 1 = 5) Each time the variable 'u' is left shifted by 8 bits and then the binary OR operation is performed where operand 1 is u left shifted by 8 and operand 2 is the value at ith index in the array addr i.e.addr[i]. The result of OR is 1 if any of the two bits is 1 which is updated to the variable u. The function returns the value of u after executing the for loop",
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
static inline __u64 ether_addr_to_u64(const __u8 *addr)
{
	__u64 u = 0;
	int i;

	for (i = ETH_ALEN - 1; i >= 0; i--)
		u = u << 8 | addr[i];
	return u;
}

SEC("xdp")
/* 
 OPENED COMMENT BEGIN 
{
	"capability": [],
	"helperCallParams": {},
	"startLine": 31,
	"endLine": 47,
	"File": "/root/examples/xdp-tutorials/xdp_prog_kern.c",
	"funcName": "xdp_prog_simple",
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
		"description": "The function xdp_prog_simple takes ethernet address as an array of unsigned bytes of size 8 as input, converts it into a 64 byte unsigned integer and returns the ethernet address as a 64 byte integer. The function process an ethernet packet. The function xdp_prog_simple takes ctx of type struct xdp_md as input. Two pointers data and data_end points to the start and end of the packet data respectively. eth is a pointer to structure ethhdr where struct ethhdr represents an Ethernet frame header defined in Linux < if_ether.h > The size of the ethernet header is stored in a variable offset of type __u64. It checks if eth plus offset is greater than data_end, it returns 0. The helper function bpf_printk() is used to dump the following information about the ethernet packet: eth - > h_source(source hardware address), eth - > h_dest(destination hardware address), and eth - > h_proto(protocol type) and which can be watched through the trace_pipe file. Finally, the function returns XDP_PASS. XDP_PASS indicates that the packet should be forwarded to the normal network stack for further processing.",
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
int  xdp_prog_simple(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u64 offset = sizeof(*eth);

	if ((void *)eth + offset > data_end)
		return 0;

	bpf_printk("src: %llu, dst: %llu, proto: %u\n",
		   ether_addr_to_u64(eth->h_source),
		   ether_addr_to_u64(eth->h_dest),
		   bpf_ntohs(eth->h_proto));

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
