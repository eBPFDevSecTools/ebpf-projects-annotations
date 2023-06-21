// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 128

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

/* Metadata will be in the perf event before the packet data. */
struct S {
	__u16 cookie;
	__u16 pkt_len;
} __packed;

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = MAX_CPUS,
};

SEC("xdp_sample")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {
    "bpf_perf_event_output": [
      {
        "opVar": "\t\tret ",
        "inpVar": [
          " ctx",
          " &my_map",
          " flags",
          "\t\t\t\t\t    &metadata",
          " sizeofmetadata"
        ]
      }
    ]
  },
  "startLine": 35,
  "endLine": 69,
  "File": "/root/examples/xdp-tutorials/xdp_sample_pkts_kern.c",
  "funcName": "xdp_sample_prog",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_perf_event_output"
  ],
  "compatibleHookpoints": [
    "perf_event",
    "sched_cls",
    "lwt_in",
    "tracepoint",
    "lwt_out",
    "sk_skb",
    "lwt_xmit",
    "cgroup_skb",
    "sched_act",
    "socket_filter",
    "raw_tracepoint_writable",
    "lwt_seg6local",
    "raw_tracepoint",
    "sock_ops",
    "xdp",
    "kprobe"
  ],
  "humanFuncDescription": [
    {
      "description": "The function xdp_sample_prog sends data and packet sample into user space via perf event.
                      The function xdp_sample_prog takes ctx of type struct xdp_md as input. struct xdp_md is the metadata for the XDP packet.
                      Two pointers data and data_end points to the start and end of the XDP packet data respectively.
                      The packet contents are in between ctx->data and ctx->data_end.
                      If data is less than data_end, it performs the following:
                      A variable named flags of type __u64 is set to BPF_F_CURRENT_CPU, which indicates that the value for the current CPU should be retrieved.
                      A structure variable named metadata of type struct S is declared. struct S consists of the fields cookie and pkt_len, both of type __u16.
                      metadata.cookie is set to value 0xdead and metadata.pkt_len is set to data_end - data.
                      A variable named sample_size of type __u16 is set to min(metadata.pkt_len, SAMPLE_SIZE), where SAMPLE_SIZE = 1024ul.
                      The sample_size is left shifted 32 bits and a bitwise OR operation is performed with flag. After the calculations, the flag variable is updated with that value.
                      Using helper function bpf_perf_event_output(ctx, &my_map, flags, &metadata, sizeof(metadata)), sizeof(metadata) bytes of data from metadata gets copied to BPF perfbuf my_map, which is of type BPF_MAP_TYPE_PERF_EVENT_ARRAY.
                      The helper function also needs ctx, which is a pointer to the context on which the tracing program is executed.
                      On successfully copying the data, the helper function returns 0 which is stored in an integer variable ret.
                      If ret == 0, it will call bpf_printk() which is a wrapper to bpf_trace_printk() to print the error message 'perf_event_output failed' along with the ret value to the common tracepipe.
                      If data is not less than data_end, the function returns XDP_PASS, which indicates that the packet should be forwarded to the normal network stack for further processing.",
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
int xdp_sample_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	if (data < data_end) {
		/* The XDP perf_event_output handler will use the upper 32 bits
		 * of the flags argument as a number of bytes to include of the
		 * packet payload in the event data. If the size is too big, the
		 * call to bpf_perf_event_output will fail and return -EFAULT.
		 *
		 * See bpf_xdp_event_output in net/core/filter.c.
		 *
		 * The BPF_F_CURRENT_CPU flag means that the event output fd
		 * will be indexed by the CPU number in the event map.
		 */
		__u64 flags = BPF_F_CURRENT_CPU;
		__u16 sample_size;
		int ret;
		struct S metadata;

		metadata.cookie = 0xdead;
		metadata.pkt_len = (__u16)(data_end - data);
		sample_size = min(metadata.pkt_len, SAMPLE_SIZE);

		flags |= (__u64)sample_size << 32;

		ret = bpf_perf_event_output(ctx, &my_map, flags,
					    &metadata, sizeof(metadata));
		if (ret)
			bpf_printk("perf_event_output failed: %d\n", ret);
	} 

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
