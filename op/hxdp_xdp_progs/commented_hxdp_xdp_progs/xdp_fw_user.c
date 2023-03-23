#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <arpa/inet.h>


#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_fw_common.h"

static int ifindex_in = A_PORT;
static int ifindex_out = B_PORT;

static __u32 prog_id;
static __u32 xdp_flags = XDP_FLAGS_DRV_MODE;
static int flow_map_fd;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 29,
  "endLine": 34,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_fw_user.c",
  "funcName": "int_exit",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int sig"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "sk_msg",
    "sock_ops",
    "flow_dissector",
    "xdp",
    "lwt_in",
    "kprobe",
    "socket_filter",
    "cgroup_skb",
    "sk_skb",
    "perf_event",
    "lwt_xmit",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "cgroup_sysctl",
    "cgroup_device",
    "tracepoint",
    "lwt_out",
    "sched_act",
    "cgroup_sock",
    "lwt_seg6local",
    "raw_tracepoint",
    "sched_cls",
    "sk_reuseport"
  ],
  "source": [
    "static void int_exit (int sig)\n",
    "{\n",
    "    bpf_set_link_xdp_fd (ifindex_out, -1, xdp_flags);\n",
    "    bpf_set_link_xdp_fd (ifindex_in, -1, xdp_flags);\n",
    "    exit (0);\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_set_link_xdp_fd",
    "bpf_get_link_xdp_id",
    "printf",
    "exit"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
static void int_exit(int sig)
{
	bpf_set_link_xdp_fd(ifindex_out, -1, xdp_flags);
	bpf_set_link_xdp_fd(ifindex_in, -1, xdp_flags);
	exit(0);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 36,
  "endLine": 54,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_fw_user.c",
  "funcName": "poll_stats",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [
    " flow_map_fd"
  ],
  "input": [
    "int interval"
  ],
  "output": "staticvoid",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "sk_msg",
    "sock_ops",
    "flow_dissector",
    "xdp",
    "lwt_in",
    "kprobe",
    "socket_filter",
    "cgroup_skb",
    "sk_skb",
    "perf_event",
    "lwt_xmit",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "cgroup_sysctl",
    "cgroup_device",
    "tracepoint",
    "lwt_out",
    "sched_act",
    "cgroup_sock",
    "lwt_seg6local",
    "raw_tracepoint",
    "sched_cls",
    "sk_reuseport"
  ],
  "source": [
    "static void poll_stats (int interval)\n",
    "{\n",
    "    while (1) {\n",
    "        struct flow_ctx_table_key flow_key = {0}\n",
    "        ;\n",
    "        struct flow_ctx_table_key next_flow_key = {0}\n",
    "        ;\n",
    "        struct flow_ctx_table_leaf flow_leaf = {0}\n",
    "        ;\n",
    "        printf (\"\\n\");\n",
    "        while (bpf_map_get_next_key (flow_map_fd, &flow_key, &next_flow_key) == 0) {\n",
    "            bpf_map_lookup_elem (flow_map_fd, &next_flow_key, &flow_leaf);\n",
    "            printf (\"Flow table: [ ip_proto %d | ip s %x  d %x | l4 s %x d %x | in %d out %d]\\n\", next_flow_key.ip_proto, next_flow_key.ip_src, next_flow_key.ip_dst, next_flow_key.l4_src, next_flow_key.l4_dst, flow_leaf.in_port, flow_leaf.out_port);\n",
    "            flow_key = next_flow_key;\n",
    "        }\n",
    "        sleep (interval);\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "printf",
    "bpf_num_possible_cpus",
    "sleep",
    "assert",
    "bpf_map_get_next_key"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
static void poll_stats(int interval)
{
	while (1) {
		struct flow_ctx_table_key flow_key      = {0};
		struct flow_ctx_table_key next_flow_key = {0};
		struct flow_ctx_table_leaf flow_leaf    = {0};


		printf("\n");
		while (bpf_map_get_next_key(flow_map_fd, &flow_key, &next_flow_key) == 0) {
			bpf_map_lookup_elem(flow_map_fd, &next_flow_key, &flow_leaf);
			printf("Flow table: [ ip_proto %d | ip s %x  d %x | l4 s %x d %x | in %d out %d]\n" ,
			next_flow_key.ip_proto,next_flow_key.ip_src,next_flow_key.ip_dst,next_flow_key.l4_src,next_flow_key.l4_dst,flow_leaf.in_port,flow_leaf.out_port);
			flow_key = next_flow_key;
		}

		sleep(interval);
	}
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "map_update",
      "map_update": [
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Add or update the <[ value ]>(IP: 2) of the entry associated to <[ key ]>(IP: 1) in <[ map ]>(IP: 0) with value. <[ flags ]>(IP: 3) is one of: BPF_NOEXIST The entry for <[ key ]>(IP: 1) must not exist in the map. BPF_EXIST The entry for <[ key ]>(IP: 1) must already exist in the map. BPF_ANY No condition on the existence of the entry for key. Flag <[ value ]>(IP: 2) BPF_NOEXIST cannot be used for maps of types BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements always exist) , the helper would return an error. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_map_update_elem",
          "Input Params": [
            "{Type: struct bpf_map ,Var: *map}",
            "{Type:  const void ,Var: *key}",
            "{Type:  const void ,Var: *value}",
            "{Type:  u64 ,Var: flags}"
          ],
          "compatible_hookpoints": [
            "socket_filter",
            "kprobe",
            "sched_cls",
            "sched_act",
            "tracepoint",
            "xdp",
            "perf_event",
            "cgroup_skb",
            "cgroup_sock",
            "lwt_in",
            "lwt_out",
            "lwt_xmit",
            "sock_ops",
            "sk_skb",
            "cgroup_device",
            "sk_msg",
            "raw_tracepoint",
            "cgroup_sock_addr",
            "lwt_seg6local",
            "sk_reuseport",
            "flow_dissector",
            "cgroup_sysctl",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "map_update"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 56,
  "endLine": 129,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_fw_user.c",
  "funcName": "main",
  "developer_inline_comments": [],
  "updateMaps": [
    " tx_port_map_fd"
  ],
  "readMaps": [],
  "input": [
    "int argc",
    " char **argv"
  ],
  "output": "int",
  "helper": [
    "bpf_map_update_elem"
  ],
  "compatibleHookpoints": [
    "sk_msg",
    "sock_ops",
    "flow_dissector",
    "xdp",
    "lwt_in",
    "kprobe",
    "socket_filter",
    "cgroup_skb",
    "sk_skb",
    "perf_event",
    "lwt_xmit",
    "cgroup_sock_addr",
    "raw_tracepoint_writable",
    "cgroup_sysctl",
    "cgroup_device",
    "tracepoint",
    "lwt_out",
    "sched_act",
    "cgroup_sock",
    "lwt_seg6local",
    "raw_tracepoint",
    "sched_cls",
    "sk_reuseport"
  ],
  "source": [
    "int main (int argc, char **argv)\n",
    "{\n",
    "    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY}\n",
    "    ;\n",
    "    struct bpf_prog_load_attr prog_load_attr = {\n",
    "        .prog_type = BPF_PROG_TYPE_XDP,}\n",
    "    ;\n",
    "    struct bpf_prog_info info = {}\n",
    "    ;\n",
    "    __u32 info_len = sizeof (info);\n",
    "    int prog_fd;\n",
    "    struct bpf_object *obj;\n",
    "    int ret, key = 0;\n",
    "    char filename [256];\n",
    "    int tx_port_map_fd;\n",
    "    if (setrlimit (RLIMIT_MEMLOCK, &r)) {\n",
    "        perror (\"setrlimit(RLIMIT_MEMLOCK)\");\n",
    "        return 1;\n",
    "    }\n",
    "    snprintf (filename, sizeof (filename), \"%s_kern.o\", argv[0]);\n",
    "    prog_load_attr.file = filename;\n",
    "    if (bpf_prog_load_xattr (&prog_load_attr, &obj, &prog_fd))\n",
    "        return 1;\n",
    "    tx_port_map_fd = bpf_object__find_map_fd_by_name (obj, \"tx_port\");\n",
    "    if (tx_port_map_fd < 0) {\n",
    "        printf (\"bpf_object__find_map_fd_by_name failed\\n\");\n",
    "        return 1;\n",
    "    }\n",
    "    flow_map_fd = bpf_object__find_map_fd_by_name (obj, \"flow_ctx_table\");\n",
    "    if (flow_map_fd < 0) {\n",
    "        printf (\"bpf_object__find_map_fd_by_name failed\\n\");\n",
    "        return 1;\n",
    "    }\n",
    "    if (bpf_set_link_xdp_fd (ifindex_in, prog_fd, xdp_flags) < 0) {\n",
    "        printf (\"ERROR: link set xdp fd failed on %d\\n\", ifindex_in);\n",
    "        return 1;\n",
    "    }\n",
    "    if (bpf_set_link_xdp_fd (ifindex_out, prog_fd, xdp_flags) < 0) {\n",
    "        printf (\"ERROR: link set xdp fd failed on %d\\n\", ifindex_in);\n",
    "        return 1;\n",
    "    }\n",
    "    ret = bpf_obj_get_info_by_fd (prog_fd, & info, & info_len);\n",
    "    if (ret) {\n",
    "        printf (\"can't get prog info - %s\\n\", strerror (errno));\n",
    "        return ret;\n",
    "    }\n",
    "    prog_id = info.id;\n",
    "    signal (SIGINT, int_exit);\n",
    "    signal (SIGTERM, int_exit);\n",
    "    key = B_PORT;\n",
    "    ifindex_out = B_PORT;\n",
    "    ret = bpf_map_update_elem (tx_port_map_fd, & key, & ifindex_out, 0);\n",
    "    if (ret) {\n",
    "        perror (\"bpf_update_elem\");\n",
    "        goto out;\n",
    "    }\n",
    "    poll_stats (10);\n",
    "out :\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_prog_load_xattr",
    "poll_stats",
    "bpf_map__fd",
    "printf",
    "strerror",
    "bpf_object__find_map_fd_by_name",
    "signal",
    "bpf_set_link_xdp_fd",
    "perror",
    "setrlimit",
    "if_nametoindex",
    "usage",
    "basename",
    "bpf_map__next",
    "snprintf",
    "getopt",
    "bpf_obj_get_info_by_fd"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {}
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
int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int prog_fd;
	struct bpf_object *obj;
	int ret,  key = 0;
	char filename[256];
	int tx_port_map_fd;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	tx_port_map_fd = bpf_object__find_map_fd_by_name(obj, "tx_port");
	if (tx_port_map_fd < 0) {
		printf("bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	flow_map_fd = bpf_object__find_map_fd_by_name(obj, "flow_ctx_table");
	if (flow_map_fd < 0) {
		printf("bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	if (bpf_set_link_xdp_fd(ifindex_in, prog_fd, xdp_flags) < 0) {
		printf("ERROR: link set xdp fd failed on %d\n", ifindex_in);
		return 1;
	}

	if (bpf_set_link_xdp_fd(ifindex_out, prog_fd, xdp_flags) < 0) {
		printf("ERROR: link set xdp fd failed on %d\n", ifindex_in);
		return 1;
	}

	ret = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (ret) {
		printf("can't get prog info - %s\n", strerror(errno));
		return ret;
	}
	prog_id = info.id;

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	
	key = B_PORT;
	ifindex_out = B_PORT;
	
	ret = bpf_map_update_elem(tx_port_map_fd, &key, &ifindex_out, 0);
	if (ret) {
		perror("bpf_update_elem");
		goto out;
	}


	poll_stats(10);
	
out:
	return 0;


}
