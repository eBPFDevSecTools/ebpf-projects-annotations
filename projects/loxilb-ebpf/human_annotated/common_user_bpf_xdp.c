#include <bpf/libbpf.h> /* bpf_get_link_xdp_id + bpf_set_link_xdp_id */
#include <string.h>     /* strerror */
#include <net/if.h>     /* IF_NAMESIZE */
#include <stdlib.h>     /* exit(3) */
#include <errno.h>

#include "bpf.h"

#include <linux/if_link.h> /* Need XDP flags */
#include <linux/err.h>

#include "common_defines.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int verbose = 1;

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 20,
  "endLine": 62,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "xdp_link_attach",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": " bpf_get_link_xdp_id + bpf_set_link_xdp_id "
    },
    {
      "start_line": 2,
      "end_line": 2,
      "text": " strerror "
    },
    {
      "start_line": 3,
      "end_line": 3,
      "text": " IF_NAMESIZE "
    },
    {
      "start_line": 4,
      "end_line": 4,
      "text": " exit(3) "
    },
    {
      "start_line": 9,
      "end_line": 9,
      "text": " Need XDP flags "
    },
    {
      "start_line": 24,
      "end_line": 24,
      "text": " libbpf provide the XDP net_device link-level hook attach helper "
    },
    {
      "start_line": 27,
      "end_line": 30,
      "text": " Force mode didn't work, probably because a program of the\t\t * opposite type is loaded. Let's unload that and try loading\t\t * again.\t\t "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int ifindex",
    " __u32 xdp_flags",
    " int prog_fd"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "int xdp_link_attach (int ifindex, __u32 xdp_flags, int prog_fd)\n",
    "{\n",
    "    int err;\n",
    "    err = bpf_set_link_xdp_fd (ifindex, prog_fd, xdp_flags);\n",
    "    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {\n",
    "        __u32 old_flags = xdp_flags;\n",
    "        xdp_flags &= ~XDP_FLAGS_MODES;\n",
    "        xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;\n",
    "        err = bpf_set_link_xdp_fd (ifindex, - 1, xdp_flags);\n",
    "        if (!err)\n",
    "            err = bpf_set_link_xdp_fd (ifindex, prog_fd, old_flags);\n",
    "    }\n",
    "    if (err < 0) {\n",
    "        fprintf (stderr, \"ERR: \" \"ifindex(%d) link set xdp fd failed (%d): %s\\n\", ifindex, -err, strerror (-err));\n",
    "        switch (-err) {\n",
    "        case EBUSY :\n",
    "        case EEXIST :\n",
    "            fprintf (stderr, \"Hint: XDP already loaded on device\" \" use --force to swap/replace\\n\");\n",
    "            break;\n",
    "        case EOPNOTSUPP :\n",
    "            fprintf (stderr, \"Hint: Native-XDP not supported\" \" use --skb-mode or --auto-mode\\n\");\n",
    "            break;\n",
    "        default :\n",
    "            break;\n",
    "        }\n",
    "        return EXIT_FAIL_XDP;\n",
    "    }\n",
    "    return EXIT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "strerror",
    "fprintf",
    "bpf_set_link_xdp_fd"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}
	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return EXIT_FAIL_XDP;
	}

	return EXIT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 64,
  "endLine": 101,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "xdp_link_detach",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int ifindex",
    " __u32 xdp_flags",
    " __u32 expected_prog_id"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "int xdp_link_detach (int ifindex, __u32 xdp_flags, __u32 expected_prog_id)\n",
    "{\n",
    "    __u32 curr_prog_id;\n",
    "    int err;\n",
    "    err = bpf_get_link_xdp_id (ifindex, & curr_prog_id, xdp_flags);\n",
    "    if (err) {\n",
    "        fprintf (stderr, \"ERR: get link xdp id failed (err=%d): %s\\n\", -err, strerror (-err));\n",
    "        return EXIT_FAIL_XDP;\n",
    "    }\n",
    "    if (!curr_prog_id) {\n",
    "        if (verbose)\n",
    "            printf (\"INFO: %s() no curr XDP prog on ifindex:%d\\n\", __func__, ifindex);\n",
    "        return EXIT_OK;\n",
    "    }\n",
    "    if (expected_prog_id && curr_prog_id != expected_prog_id) {\n",
    "        fprintf (stderr, \"ERR: %s() \" \"expected prog ID(%d) no match(%d), not removing\\n\", __func__, expected_prog_id, curr_prog_id);\n",
    "        return EXIT_FAIL;\n",
    "    }\n",
    "    if ((err = bpf_set_link_xdp_fd (ifindex, -1, xdp_flags)) < 0) {\n",
    "        fprintf (stderr, \"ERR: %s() link set xdp failed (err=%d): %s\\n\", __func__, err, strerror (-err));\n",
    "        return EXIT_FAIL_XDP;\n",
    "    }\n",
    "    if (verbose)\n",
    "        printf (\"INFO: %s() removed XDP prog ID:%d on ifindex:%d\\n\", __func__, curr_prog_id, ifindex);\n",
    "    return EXIT_OK;\n",
    "}\n"
  ],
  "called_function_list": [
    "fprintf",
    "bpf_set_link_xdp_fd",
    "strerror",
    "bpf_get_link_xdp_id",
    "printf"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err) {
		fprintf(stderr, "ERR: get link xdp id failed (err=%d): %s\n",
			-err, strerror(-err));
		return EXIT_FAIL_XDP;
	}

	if (!curr_prog_id) {
		if (verbose)
			printf("INFO: %s() no curr XDP prog on ifindex:%d\n",
			       __func__, ifindex);
		return EXIT_OK;
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		fprintf(stderr, "ERR: %s() "
			"expected prog ID(%d) no match(%d), not removing\n",
			__func__, expected_prog_id, curr_prog_id);
		return EXIT_FAIL;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
			__func__, err, strerror(-err));
		return EXIT_FAIL_XDP;
	}

	if (verbose)
		printf("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n",
		       __func__, curr_prog_id, ifindex);

	return EXIT_OK;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 103,
  "endLine": 131,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "load_bpf_object_file",
  "developer_inline_comments": [
    {
      "start_line": 109,
      "end_line": 112,
      "text": " This struct allow us to set ifindex, this features is used for\t * hardware offloading XDP programs (note this sets libbpf\t * bpf_program->prog_ifindex and foreach bpf_map->map_ifindex).\t "
    },
    {
      "start_line": 119,
      "end_line": 121,
      "text": " Use libbpf for extracting BPF byte-code from BPF-ELF object, and\t * loading this into the kernel via bpf-syscall\t "
    },
    {
      "start_line": 129,
      "end_line": 129,
      "text": " Notice how a pointer to a libbpf bpf_object is returned "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *filename",
    " int ifindex"
  ],
  "output": "structbpf_object",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "struct bpf_object *load_bpf_object_file (const char *filename, int ifindex)\n",
    "{\n",
    "    int first_prog_fd = -1;\n",
    "    struct bpf_object *obj;\n",
    "    int err;\n",
    "    struct bpf_prog_load_attr prog_load_attr = {\n",
    "        .prog_type = BPF_PROG_TYPE_XDP,\n",
    "        .ifindex = ifindex,}\n",
    "    ;\n",
    "    prog_load_attr.file = filename;\n",
    "    err = bpf_prog_load_xattr (& prog_load_attr, & obj, & first_prog_fd);\n",
    "    if (err) {\n",
    "        fprintf (stderr, \"ERR: loading BPF-OBJ file(%s) (%d): %s\\n\", filename, err, strerror (-err));\n",
    "        return NULL;\n",
    "    }\n",
    "    return obj;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_prog_load_xattr",
    "fprintf",
    "strerror"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* This struct allow us to set ifindex, this features is used for
	 * hardware offloading XDP programs (note this sets libbpf
	 * bpf_program->prog_ifindex and foreach bpf_map->map_ifindex).
	 */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.ifindex   = ifindex,
	};
	prog_load_attr.file = filename;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	/* Notice how a pointer to a libbpf bpf_object is returned */
	return obj;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 133,
  "endLine": 171,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "open_bpf_object",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *file",
    " int ifindex"
  ],
  "output": "staticstructbpf_object",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static struct bpf_object *open_bpf_object (const char *file, int ifindex)\n",
    "{\n",
    "    int err;\n",
    "    struct bpf_object *obj;\n",
    "    struct bpf_map *map;\n",
    "    struct bpf_program *prog, *first_prog = NULL;\n",
    "    struct bpf_object_open_attr open_attr = {\n",
    "        .file = file,\n",
    "        .prog_type = BPF_PROG_TYPE_XDP,}\n",
    "    ;\n",
    "    obj = bpf_object__open_xattr (& open_attr);\n",
    "    if (IS_ERR_OR_NULL (obj)) {\n",
    "        err = -PTR_ERR(obj);\n",
    "        fprintf (stderr, \"ERR: opening BPF-OBJ file(%s) (%d): %s\\n\", file, err, strerror (-err));\n",
    "        return NULL;\n",
    "    }\n",
    "    bpf_object__for_each_program (prog, obj) {\n",
    "        bpf_program__set_type (prog, BPF_PROG_TYPE_XDP);\n",
    "        bpf_program__set_ifindex (prog, ifindex);\n",
    "        if (!first_prog)\n",
    "            first_prog = prog;\n",
    "    }\n",
    "    bpf_object__for_each_map (map, obj) {\n",
    "        if (!bpf_map__is_offload_neutral (map))\n",
    "            bpf_map__set_ifindex (map, ifindex);\n",
    "    }\n",
    "    if (!first_prog) {\n",
    "        fprintf (stderr, \"ERR: file %s contains no programs\\n\", file);\n",
    "        return NULL;\n",
    "    }\n",
    "    return obj;\n",
    "}\n"
  ],
  "called_function_list": [
    "fprintf",
    "strerror",
    "bpf_object__open_xattr",
    "PTR_ERR",
    "bpf_map__is_offload_neutral",
    "bpf_program__set_type",
    "IS_ERR_OR_NULL",
    "bpf_map__set_ifindex",
    "bpf_object__for_each_program",
    "bpf_program__set_ifindex",
    "bpf_object__for_each_map"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static struct bpf_object *open_bpf_object(const char *file, int ifindex)
{
	int err;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct bpf_program *prog, *first_prog = NULL;

	struct bpf_object_open_attr open_attr = {
		.file = file,
		.prog_type = BPF_PROG_TYPE_XDP,
	};

	obj = bpf_object__open_xattr(&open_attr);
	if (IS_ERR_OR_NULL(obj)) {
		err = -PTR_ERR(obj);
		fprintf(stderr, "ERR: opening BPF-OBJ file(%s) (%d): %s\n",
			file, err, strerror(-err));
		return NULL;
	}

	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
		bpf_program__set_ifindex(prog, ifindex);
		if (!first_prog)
			first_prog = prog;
	}

	bpf_object__for_each_map(map, obj) {
		if (!bpf_map__is_offload_neutral(map))
			bpf_map__set_ifindex(map, ifindex);
	}

	if (!first_prog) {
		fprintf(stderr, "ERR: file %s contains no programs\n", file);
		return NULL;
	}

	return obj;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 173,
  "endLine": 205,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "reuse_maps",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *obj",
    " const char *path"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "static int reuse_maps (struct bpf_object *obj, const char *path)\n",
    "{\n",
    "    struct bpf_map *map;\n",
    "    if (!obj)\n",
    "        return -ENOENT;\n",
    "    if (!path)\n",
    "        return -EINVAL;\n",
    "    bpf_object__for_each_map (map, obj) {\n",
    "        int len, err;\n",
    "        int pinned_map_fd;\n",
    "        char buf [PATH_MAX];\n",
    "        len = snprintf (buf, PATH_MAX, \"%s/%s\", path, bpf_map__name (map));\n",
    "        if (len < 0) {\n",
    "            return -EINVAL;\n",
    "        }\n",
    "        else if (len >= PATH_MAX) {\n",
    "            return -ENAMETOOLONG;\n",
    "        }\n",
    "        pinned_map_fd = bpf_obj_get (buf);\n",
    "        if (pinned_map_fd < 0)\n",
    "            return pinned_map_fd;\n",
    "        err = bpf_map__reuse_fd (map, pinned_map_fd);\n",
    "        if (err)\n",
    "            return err;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_map__name",
    "bpf_map__reuse_fd",
    "snprintf",
    "bpf_obj_get",
    "bpf_object__for_each_map"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
static int reuse_maps(struct bpf_object *obj, const char *path)
{
	struct bpf_map *map;

	if (!obj)
		return -ENOENT;

	if (!path)
		return -EINVAL;

	bpf_object__for_each_map(map, obj) {
		int len, err;
		int pinned_map_fd;
		char buf[PATH_MAX];

		len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
		if (len < 0) {
			return -EINVAL;
		} else if (len >= PATH_MAX) {
			return -ENAMETOOLONG;
		}

		pinned_map_fd = bpf_obj_get(buf);
		if (pinned_map_fd < 0)
			return pinned_map_fd;

		err = bpf_map__reuse_fd(map, pinned_map_fd);
		if (err)
			return err;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 207,
  "endLine": 235,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "load_bpf_object_file_reuse_maps",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *file",
    " int ifindex",
    " const char *pin_dir"
  ],
  "output": "structbpf_object",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "struct bpf_object *load_bpf_object_file_reuse_maps (const char *file, int ifindex, const char *pin_dir)\n",
    "{\n",
    "    int err;\n",
    "    struct bpf_object *obj;\n",
    "    obj = open_bpf_object (file, ifindex);\n",
    "    if (!obj) {\n",
    "        fprintf (stderr, \"ERR: failed to open object %s\\n\", file);\n",
    "        return NULL;\n",
    "    }\n",
    "    err = reuse_maps (obj, pin_dir);\n",
    "    if (err) {\n",
    "        fprintf (stderr, \"ERR: failed to reuse maps for object %s, pin_dir=%s\\n\", file, pin_dir);\n",
    "        return NULL;\n",
    "    }\n",
    "    err = bpf_object__load (obj);\n",
    "    if (err) {\n",
    "        fprintf (stderr, \"ERR: loading BPF-OBJ file(%s) (%d): %s\\n\", file, err, strerror (-err));\n",
    "        return NULL;\n",
    "    }\n",
    "    return obj;\n",
    "}\n"
  ],
  "called_function_list": [
    "fprintf",
    "reuse_maps",
    "strerror",
    "bpf_object__load",
    "open_bpf_object"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
struct bpf_object *load_bpf_object_file_reuse_maps(const char *file,
						   int ifindex,
						   const char *pin_dir)
{
	int err;
	struct bpf_object *obj;

	obj = open_bpf_object(file, ifindex);
	if (!obj) {
		fprintf(stderr, "ERR: failed to open object %s\n", file);
		return NULL;
	}

	err = reuse_maps(obj, pin_dir);
	if (err) {
		fprintf(stderr, "ERR: failed to reuse maps for object %s, pin_dir=%s\n",
				file, pin_dir);
		return NULL;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			file, err, strerror(-err));
		return NULL;
	}

	return obj;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 237,
  "endLine": 295,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "load_bpf_and_xdp_attach",
  "developer_inline_comments": [
    {
      "start_line": 245,
      "end_line": 245,
      "text": " If flags indicate hardware offload, supply ifindex "
    },
    {
      "start_line": 249,
      "end_line": 249,
      "text": " Load the BPF-ELF object file and get back libbpf bpf_object "
    },
    {
      "start_line": 260,
      "end_line": 264,
      "text": " At this point: All XDP/BPF programs from the cfg->filename have been\t * loaded into the kernel, and evaluated by the verifier. Only one of\t * these gets attached to XDP hook, the others will get freed once this\t * process exit.\t "
    },
    {
      "start_line": 267,
      "end_line": 267,
      "text": " Find a matching BPF prog section name "
    },
    {
      "start_line": 270,
      "end_line": 270,
      "text": " Find the first program "
    },
    {
      "start_line": 286,
      "end_line": 289,
      "text": " At this point: BPF-progs are (only) loaded by the kernel, and prog_fd\t * is our select file-descriptor handle. Next step is attaching this FD\t * to a kernel hook point, in this case XDP net_device link-level hook.\t "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct config *cfg"
  ],
  "output": "structbpf_object",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "struct bpf_object *load_bpf_and_xdp_attach (struct config *cfg)\n",
    "{\n",
    "    struct bpf_program *bpf_prog;\n",
    "    struct bpf_object *bpf_obj;\n",
    "    int offload_ifindex = 0;\n",
    "    int prog_fd = -1;\n",
    "    int err;\n",
    "    if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)\n",
    "        offload_ifindex = cfg->ifindex;\n",
    "    if (cfg->reuse_maps)\n",
    "        bpf_obj = load_bpf_object_file_reuse_maps (cfg->filename, offload_ifindex, cfg->pin_dir);\n",
    "    else\n",
    "        bpf_obj = load_bpf_object_file (cfg->filename, offload_ifindex);\n",
    "    if (!bpf_obj) {\n",
    "        fprintf (stderr, \"ERR: loading file: %s\\n\", cfg->filename);\n",
    "        exit (EXIT_FAIL_BPF);\n",
    "    }\n",
    "    if (cfg->progsec[0])\n",
    "        bpf_prog = bpf_object__find_program_by_title (bpf_obj, cfg->progsec);\n",
    "    else\n",
    "        bpf_prog = bpf_program__next (NULL, bpf_obj);\n",
    "    if (!bpf_prog) {\n",
    "        fprintf (stderr, \"ERR: couldn't find a program in ELF section '%s'\\n\", cfg->progsec);\n",
    "        exit (EXIT_FAIL_BPF);\n",
    "    }\n",
    "    strncpy (cfg->progsec, bpf_program__section_name (bpf_prog), sizeof (cfg->progsec));\n",
    "    prog_fd = bpf_program__fd (bpf_prog);\n",
    "    if (prog_fd <= 0) {\n",
    "        fprintf (stderr, \"ERR: bpf_program__fd failed\\n\");\n",
    "        exit (EXIT_FAIL_BPF);\n",
    "    }\n",
    "    err = xdp_link_attach (cfg -> ifindex, cfg -> xdp_flags, prog_fd);\n",
    "    if (err)\n",
    "        exit (err);\n",
    "    return bpf_obj;\n",
    "}\n"
  ],
  "called_function_list": [
    "fprintf",
    "bpf_program__fd",
    "load_bpf_object_file_reuse_maps",
    "bpf_program__section_name",
    "bpf_program__next",
    "bpf_object__find_program_by_title",
    "exit",
    "load_bpf_object_file",
    "xdp_link_attach",
    "strncpy"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int err;

	/* If flags indicate hardware offload, supply ifindex */
	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
		offload_ifindex = cfg->ifindex;

	/* Load the BPF-ELF object file and get back libbpf bpf_object */
	if (cfg->reuse_maps)
		bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename,
							  offload_ifindex,
							  cfg->pin_dir);
	else
		bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	if (cfg->progsec[0])
		/* Find a matching BPF prog section name */
		bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	else
		/* Find the first program */
		bpf_prog = bpf_program__next(NULL, bpf_obj);

	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
		exit(EXIT_FAIL_BPF);
	}

	strncpy(cfg->progsec, bpf_program__section_name(bpf_prog), sizeof(cfg->progsec));

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
	if (err)
		exit(err);

	return bpf_obj;
}

#define XDP_UNKNOWN	XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]   = "XDP_ABORTED",
	[XDP_DROP]      = "XDP_DROP",
	[XDP_PASS]      = "XDP_PASS",
	[XDP_TX]        = "XDP_TX",
	[XDP_REDIRECT]  = "XDP_REDIRECT",
	[XDP_UNKNOWN]	= "XDP_UNKNOWN",
};

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 311,
  "endLine": 316,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "action2str",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "__u32 action"
  ],
  "output": "constchar",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "const char *action2str (__u32 action)\n",
    "{\n",
    "    if (action < XDP_ACTION_MAX)\n",
    "        return xdp_action_names[action];\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [],
  "call_depth": 0,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
const char *action2str(__u32 action)
{
        if (action < XDP_ACTION_MAX)
                return xdp_action_names[action];
        return NULL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 318,
  "endLine": 347,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "check_map_fd_info",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_map_info *info",
    " const struct bpf_map_info *exp"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "int check_map_fd_info (const struct bpf_map_info *info, const struct bpf_map_info *exp)\n",
    "{\n",
    "    if (exp->key_size && exp->key_size != info->key_size) {\n",
    "        fprintf (stderr, \"ERR: %s() \" \"Map key size(%d) mismatch expected size(%d)\\n\", __func__, info->key_size, exp->key_size);\n",
    "        return EXIT_FAIL;\n",
    "    }\n",
    "    if (exp->value_size && exp->value_size != info->value_size) {\n",
    "        fprintf (stderr, \"ERR: %s() \" \"Map value size(%d) mismatch expected size(%d)\\n\", __func__, info->value_size, exp->value_size);\n",
    "        return EXIT_FAIL;\n",
    "    }\n",
    "    if (exp->max_entries && exp->max_entries != info->max_entries) {\n",
    "        fprintf (stderr, \"ERR: %s() \" \"Map max_entries(%d) mismatch expected size(%d)\\n\", __func__, info->max_entries, exp->max_entries);\n",
    "        return EXIT_FAIL;\n",
    "    }\n",
    "    if (exp->type && exp->type != info->type) {\n",
    "        fprintf (stderr, \"ERR: %s() \" \"Map type(%d) mismatch expected type(%d)\\n\", __func__, info->type, exp->type);\n",
    "        return EXIT_FAIL;\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "fprintf"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
int check_map_fd_info(const struct bpf_map_info *info,
		      const struct bpf_map_info *exp)
{
	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 349,
  "endLine": 381,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_user_bpf_xdp.c",
  "funcName": "open_bpf_map_file",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *pin_dir",
    " const char *mapname",
    " struct bpf_map_info *info"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "sk_reuseport",
    "raw_tracepoint",
    "sk_skb",
    "lwt_out",
    "sched_act",
    "perf_event",
    "cgroup_device",
    "lwt_xmit",
    "sched_cls",
    "tracepoint",
    "xdp",
    "raw_tracepoint_writable",
    "kprobe",
    "sk_msg",
    "cgroup_sysctl",
    "socket_filter",
    "sock_ops",
    "lwt_seg6local",
    "lwt_in",
    "cgroup_sock",
    "flow_dissector",
    "cgroup_skb",
    "cgroup_sock_addr"
  ],
  "source": [
    "int open_bpf_map_file (const char *pin_dir, const char *mapname, struct bpf_map_info *info)\n",
    "{\n",
    "    char filename [PATH_MAX];\n",
    "    int err, len, fd;\n",
    "    __u32 info_len = sizeof (*info);\n",
    "    len = snprintf (filename, PATH_MAX, \"%s/%s\", pin_dir, mapname);\n",
    "    if (len < 0) {\n",
    "        fprintf (stderr, \"ERR: constructing full mapname path\\n\");\n",
    "        return -1;\n",
    "    }\n",
    "    fd = bpf_obj_get (filename);\n",
    "    if (fd < 0) {\n",
    "        fprintf (stderr, \"WARN: Failed to open bpf map file:%s err(%d):%s\\n\", filename, errno, strerror (errno));\n",
    "        return fd;\n",
    "    }\n",
    "    if (info) {\n",
    "        err = bpf_obj_get_info_by_fd (fd, info, & info_len);\n",
    "        if (err) {\n",
    "            fprintf (stderr, \"ERR: %s() can't get info - %s\\n\", __func__, strerror (errno));\n",
    "            return EXIT_FAIL_BPF;\n",
    "        }\n",
    "    }\n",
    "    return fd;\n",
    "}\n"
  ],
  "called_function_list": [
    "fprintf",
    "bpf_obj_get_info_by_fd",
    "strerror",
    "snprintf",
    "bpf_obj_get"
  ],
  "call_depth": -1,
  "humanFuncDescription": [
    {
      "description": "",
      "author": "",
      "authorEmail": "",
      "date": ""
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
int open_bpf_map_file(const char *pin_dir,
		      const char *mapname,
		      struct bpf_map_info *info)
{
	char filename[PATH_MAX];
	int err, len, fd;
	__u32 info_len = sizeof(*info);

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if (len < 0) {
		fprintf(stderr, "ERR: constructing full mapname path\n");
		return -1;
	}

	fd = bpf_obj_get(filename);
	if (fd < 0) {
		fprintf(stderr,
			"WARN: Failed to open bpf map file:%s err(%d):%s\n",
			filename, errno, strerror(errno));
		return fd;
	}

	if (info) {
		err = bpf_obj_get_info_by_fd(fd, info, &info_len);
		if (err) {
			fprintf(stderr, "ERR: %s() can't get info - %s\n",
				__func__,  strerror(errno));
			return EXIT_FAIL_BPF;
		}
	}

	return fd;
}
