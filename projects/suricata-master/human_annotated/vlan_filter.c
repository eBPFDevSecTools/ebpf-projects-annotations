/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stddef.h>
#include <linux/bpf.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 25,
  "endLine": 36,
  "File": "/home/palani/github/ebpf-projects-annotations/projects/suricata-master/original_source/ebpf/vlan_filter.c",
  "funcName": "hashfilter",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 16,
      "text": "/* Copyright (C) 2018 Open Information Security Foundation\n *\n * You can copy, redistribute or modify this Program under the terms of\n * the GNU General Public License version 2 as published by the Free\n * Software Foundation.\n *\n * This program is distributed in the hope that it will be useful,\n * but WITHOUT ANY WARRANTY; without even the implied warranty of\n * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n * GNU General Public License for more details.\n *\n * You should have received a copy of the GNU General Public License\n * version 2 along with this program; if not, write to the Free Software\n * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA\n * 02110-1301, USA.\n */"
    },
    {
      "start_line": 27,
      "end_line": 27,
      "text": "/* accept VLAN 2 and 4 and drop the rest */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct  __sk_buff *skb"
  ],
  "output": "\\filter\\)",
  "helper": [],
  "compatibleHookpoints": [
    "xdp",
    "raw_tracepoint",
    "cgroup_sysctl",
    "cgroup_sock_addr",
    "cgroup_sock",
    "socket_filter",
    "lwt_xmit",
    "sk_skb",
    "tracepoint",
    "sched_act",
    "cgroup_skb",
    "sched_cls",
    "sk_msg",
    "raw_tracepoint_writable",
    "perf_event",
    "sk_reuseport",
    "lwt_out",
    "cgroup_device",
    "flow_dissector",
    "sock_ops",
    "kprobe",
    "lwt_seg6local",
    "lwt_in"
  ],
  "source": [
    "int SEC (\"filter\") hashfilter (struct  __sk_buff *skb)\n",
    "{\n",
    "    __u16 vlan_id = skb->vlan_tci & 0x0fff;\n",
    "    switch (vlan_id) {\n",
    "    case 2 :\n",
    "    case 4 :\n",
    "        return -1;\n",
    "    default :\n",
    "        return 0;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "offsetof",
    "ipv4_filter",
    "load_half",
    "ipv6_filter"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "This function checks the last 12 bits of VLAN TCI field of the skb. Returns -1 if vlan ID is either 2 or 4, otherwise 0.",
      "author": "R V B R N Aaseesh",
      "authorEmail": "ee20btech11060@iith.ac.in",
      "date": "2023-04-04"
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
int SEC("filter") hashfilter(struct __sk_buff *skb) {
    __u16 vlan_id = skb->vlan_tci & 0x0fff;
    /* accept VLAN 2 and 4 and drop the rest */
    switch (vlan_id) {
        case 2:
        case 4:
            return -1;
        default:
            return 0;
    }
    return 0;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
