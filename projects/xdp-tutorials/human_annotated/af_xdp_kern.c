/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(__u32),
	.max_entries = 64,
};

SEC("xdp_sock")
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [
    {
      "capability": "map_read",
      "map_read": [
        {
          "Return Type": "void*",
          "Description": "Perform a lookup in <[ map ]>(IP: 0) for an entry associated to key. ",
          "Return": " Map value associated to key, or NULL if no entry was found.",
          "Function Name": "bpf_map_lookup_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {
    "bpf_map_lookup_elem": [
      {
        "opVar": "    pkt_count ",
        "inpVar": [
          " &xdp_stats_map",
          " &index"
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "            if &xsks_map",
          " &index        return bpf_redirect_map&xsks_map",
          " index",
          " 0"
        ]
      }
    ]
  },
  "startLine": 22,
  "endLine": 41,
  "File": "/root/examples/xdp-tutorials/af_xdp_kern.c",
  "funcName": "xdp_sock_prog",
  "updateMaps": [],
  "readMaps": [
    " xsks_map",
    "  xdp_stats_map"
  ],
  "input": [
    "struct xdp_md *ctx"
  ],
  "output": "int",
  "helper": [
    "bpf_map_lookup_elem",
    "bpf_redirect"
  ],
  "compatibleHookpoints": [
    "sched_cls",
    "sched_act",
    "xdp",
    "lwt_xmit"
  ],
  "humanFuncDescription": [
    {
      "description": "xdp_sock_prog() function takes as input structure ctx of type
                      xdp_md. It finds rx_queue_index from ctx and stores it in 'index'.
                      This index is used as key to xdp_stats_map in helper function
                      'bpf_map_lookup_elem'. If we receive a match, we increment packet
                      count. If packet-count and 1 evaluate to TRUE,we return XDP_PASS. 
                      We then again use bpf_map_lookup_elem() to lookup whether an entry
                      exists for 'xsks_map' with 'index' as key. If yes, we redirect packets
                      in that queue to a socket using helper function bpf_redirect_map().
                      Function returns XDP_PASS on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "27.02.2023"
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
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    __u32 *pkt_count;

    pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
    if (pkt_count) {

        /* We pass every other packet */
        if ((*pkt_count)++ & 1)
            return XDP_PASS;
    }

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
