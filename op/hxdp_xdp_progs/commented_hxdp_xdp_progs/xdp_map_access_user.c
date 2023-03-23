// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 PLUMgrid
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_map_access_common.h"

static int ifindex;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 27,
  "endLine": 42,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_map_access_user.c",
  "funcName": "int_exit",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": "// SPDX-License-Identifier: GPL-2.0-only"
    },
    {
      "start_line": 2,
      "end_line": 3,
      "text": "/* Copyright (c) 2016 PLUMgrid\n */"
    }
  ],
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
    "    __u32 curr_prog_id = 0;\n",
    "    if (bpf_get_link_xdp_id (ifindex, &curr_prog_id, xdp_flags)) {\n",
    "        printf (\"bpf_get_link_xdp_id failed\\n\");\n",
    "        exit (1);\n",
    "    }\n",
    "    if (prog_id == curr_prog_id)\n",
    "        bpf_set_link_xdp_fd (ifindex, -1, xdp_flags);\n",
    "    else if (!curr_prog_id)\n",
    "        printf (\"couldn't find a prog id on a given interface\\n\");\n",
    "    else\n",
    "        printf (\"program on interface changed, not removing\\n\");\n",
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
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(1);
	}
	if (prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
	exit(0);
}

/* simple per-protocol drop counter
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 71,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_map_access_user.c",
  "funcName": "poll_stats",
  "developer_inline_comments": [
    {
      "start_line": 44,
      "end_line": 45,
      "text": "/* simple per-protocol drop counter\n */"
    }
  ],
  "updateMaps": [],
  "readMaps": [
    " map_fd"
  ],
  "input": [
    "int map_fd",
    " int interval"
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
    "static void poll_stats (int map_fd, int interval)\n",
    "{\n",
    "    unsigned int nr_cpus = bpf_num_possible_cpus ();\n",
    "    __u64 values [nr_cpus], prev [UINT8_MAX] = {0};\n",
    "    int i;\n",
    "    while (1) {\n",
    "        struct dummy_key key = {0}\n",
    "        ;\n",
    "        struct dummy_key next_key = {0}\n",
    "        ;\n",
    "        sleep (interval);\n",
    "        while (bpf_map_get_next_key (map_fd, &key, &next_key) != -1) {\n",
    "            __u64 sum = 0;\n",
    "            assert (bpf_map_lookup_elem (map_fd, &next_key, values) == 0);\n",
    "            for (i = 0; i < nr_cpus; i++)\n",
    "                sum += values[i];\n",
    "            if (sum > prev[next_key.key])\n",
    "                printf (\"proto %u: %10llu pkt/s\\n\", next_key.key, (sum - prev[next_key.key]) / interval);\n",
    "            prev[next_key.key] = sum;\n",
    "            key = next_key;\n",
    "        }\n",
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
static void poll_stats(int map_fd, int interval)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus], prev[UINT8_MAX] = { 0 };
	int i;

	while (1) {
		struct dummy_key key = {0};
		struct dummy_key next_key = {0};

		sleep(interval);

		while (bpf_map_get_next_key(map_fd, &key, &next_key) != -1) {
			__u64 sum = 0;

			assert(bpf_map_lookup_elem(map_fd, &next_key, values) == 0);
			for (i = 0; i < nr_cpus; i++)
				sum += values[i];
			if (sum > prev[next_key.key])
				printf("proto %u: %10llu pkt/s\n",
				       next_key.key, (sum - prev[next_key.key]) / interval);
			prev[next_key.key] = sum;
			key = next_key; 
		}
	}
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 73,
  "endLine": 82,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_map_access_user.c",
  "funcName": "usage",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *prog"
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
    "static void usage (const char *prog)\n",
    "{\n",
    "    fprintf (stderr, \"usage: %s [OPTS] IFACE\\n\\n\" \"OPTS:\\n\" \"    -S    use skb-mode\\n\" \"    -N    enforce native mode\\n\" \"    -F    force loading prog\\n\", prog);\n",
    "}\n"
  ],
  "called_function_list": [
    "fprintf"
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
static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] IFACE\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		"    -N    enforce native mode\n"
		"    -F    force loading prog\n",
		prog);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 84,
  "endLine": 171,
  "File": "/home/sayandes/ebpf-projects-annotations/examples/hxdp_xdp_progs/xdp_map_access_user.c",
  "funcName": "main",
  "developer_inline_comments": [
    {
      "start_line": 105,
      "end_line": 105,
      "text": "/* default, set below */"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int argc",
    " char **argv"
  ],
  "output": "int",
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
    "    const char *optstr = \"FSN\";\n",
    "    int prog_fd, map_fd, opt;\n",
    "    struct bpf_object *obj;\n",
    "    struct bpf_map *map;\n",
    "    char filename [256];\n",
    "    int err;\n",
    "    while ((opt = getopt (argc, argv, optstr)) != -1) {\n",
    "        switch (opt) {\n",
    "        case 'S' :\n",
    "            xdp_flags |= XDP_FLAGS_SKB_MODE;\n",
    "            break;\n",
    "        case 'N' :\n",
    "            break;\n",
    "        case 'F' :\n",
    "            xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;\n",
    "            break;\n",
    "        default :\n",
    "            usage (basename (argv[0]));\n",
    "            return 1;\n",
    "        }\n",
    "    }\n",
    "    if (!(xdp_flags & XDP_FLAGS_SKB_MODE))\n",
    "        xdp_flags |= XDP_FLAGS_DRV_MODE;\n",
    "    if (optind == argc) {\n",
    "        usage (basename (argv[0]));\n",
    "        return 1;\n",
    "    }\n",
    "    if (setrlimit (RLIMIT_MEMLOCK, &r)) {\n",
    "        perror (\"setrlimit(RLIMIT_MEMLOCK)\");\n",
    "        return 1;\n",
    "    }\n",
    "    ifindex = if_nametoindex (argv [optind]);\n",
    "    if (!ifindex) {\n",
    "        perror (\"if_nametoindex\");\n",
    "        return 1;\n",
    "    }\n",
    "    snprintf (filename, sizeof (filename), \"%s_kern.o\", argv[0]);\n",
    "    prog_load_attr.file = filename;\n",
    "    if (bpf_prog_load_xattr (&prog_load_attr, &obj, &prog_fd))\n",
    "        return 1;\n",
    "    map = bpf_map__next (NULL, obj);\n",
    "    if (!map) {\n",
    "        printf (\"finding a map in obj file failed\\n\");\n",
    "        return 1;\n",
    "    }\n",
    "    map_fd = bpf_map__fd (map);\n",
    "    if (!prog_fd) {\n",
    "        printf (\"bpf_prog_load_xattr: %s\\n\", strerror (errno));\n",
    "        return 1;\n",
    "    }\n",
    "    signal (SIGINT, int_exit);\n",
    "    signal (SIGTERM, int_exit);\n",
    "    if (bpf_set_link_xdp_fd (ifindex, prog_fd, xdp_flags) < 0) {\n",
    "        printf (\"link set xdp fd failed\\n\");\n",
    "        return 1;\n",
    "    }\n",
    "    err = bpf_obj_get_info_by_fd (prog_fd, & info, & info_len);\n",
    "    if (err) {\n",
    "        printf (\"can't get prog info - %s\\n\", strerror (errno));\n",
    "        return err;\n",
    "    }\n",
    "    prog_id = info.id;\n",
    "    poll_stats (map_fd, 2);\n",
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
	const char *optstr = "FSN";
	int prog_fd, map_fd, opt;
	struct bpf_object *obj;
	struct bpf_map *map;
	char filename[256];
	int err;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'N':
			/* default, set below */
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	map = bpf_map__next(NULL, obj);
	if (!map) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	map_fd = bpf_map__fd(map);

	if (!prog_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;

	poll_stats(map_fd, 2);

	return 0;
}
