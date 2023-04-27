/* Common function that with time should be moved to libbpf */

#include <errno.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common_libbpf.h"

/* From: include/linux/err.h */
#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 17,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_libbpf.c",
  "funcName": "IS_ERR_OR_NULL",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": " Common function that with time should be moved to libbpf "
    },
    {
      "start_line": 11,
      "end_line": 11,
      "text": " From: include/linux/err.h "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *ptr"
  ],
  "output": "staticinlinebool",
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
    "static inline bool IS_ERR_OR_NULL (const void *ptr)\n",
    "{\n",
    "    return (!ptr) || IS_ERR_VALUE ((unsigned long) ptr);\n",
    "}\n"
  ],
  "called_function_list": [
    "IS_ERR_VALUE"
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
static inline bool IS_ERR_OR_NULL(const void *ptr)
{
        return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

#define pr_warning printf

/* As close as possible to libbpf bpf_prog_load_xattr(), with the
 * difference of handling pinned maps.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 162,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_libbpf.c",
  "funcName": "bpf_prog_load_xattr_maps",
  "developer_inline_comments": [
    {
      "start_line": 21,
      "end_line": 23,
      "text": " As close as possible to libbpf bpf_prog_load_xattr(), with the * difference of handling pinned maps. "
    },
    {
      "start_line": 50,
      "end_line": 53,
      "text": "\t\t * If type is not specified, try to guess it based on\t\t * section name.\t\t "
    },
    {
      "start_line": 55,
      "end_line": 55,
      "text": " Was: prog->prog_ifindex = attr->ifindex;"
    },
    {
      "start_line": 59,
      "end_line": 59,
      "text": " Use internal libbpf variables "
    },
    {
      "start_line": 78,
      "end_line": 78,
      "text": " Reset attr->pinned_maps.map_fd to identify successful file load "
    },
    {
      "start_line": 87,
      "end_line": 87,
      "text": " Was: map->map_ifindex = attr->ifindex; "
    },
    {
      "start_line": 96,
      "end_line": 96,
      "text": " Matched, try opening pinned file "
    },
    {
      "start_line": 99,
      "end_line": 99,
      "text": " Use FD from pinned map as replacement "
    },
    {
      "start_line": 101,
      "end_line": 104,
      "text": " TODO: Might want to set internal map \"name\"\t\t\t\t * if opened pinned map didn't, to allow\t\t\t\t * bpf_object__find_map_fd_by_name() to work.\t\t\t\t "
    },
    {
      "start_line": 108,
      "end_line": 111,
      "text": " Could not open pinned filename map, then this prog\t\t\t * should then pin the map, BUT this can only happen\t\t\t * after bpf_object__load().\t\t\t "
    },
    {
      "start_line": 127,
      "end_line": 127,
      "text": " Pin the maps that were not loaded via pinned filename "
    },
    {
      "start_line": 138,
      "end_line": 138,
      "text": " Matched, check if map is already loaded "
    },
    {
      "start_line": 142,
      "end_line": 142,
      "text": " Needs to be pinned "
    },
    {
      "start_line": 150,
      "end_line": 150,
      "text": " Help user if requested map name that doesn't exist "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const struct bpf_prog_load_attr_maps *attr",
    " struct bpf_object **pobj",
    " int *prog_fd"
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
    "int bpf_prog_load_xattr_maps (const struct bpf_prog_load_attr_maps *attr, struct bpf_object **pobj, int *prog_fd)\n",
    "{\n",
    "    struct bpf_object_open_attr open_attr = {\n",
    "        .file = attr->file,\n",
    "        .prog_type = attr->prog_type,}\n",
    "    ;\n",
    "    struct bpf_program *prog, *first_prog = NULL;\n",
    "    enum bpf_attach_type expected_attach_type;\n",
    "    enum bpf_prog_type prog_type;\n",
    "    struct bpf_object *obj;\n",
    "    struct bpf_map *map;\n",
    "    int err;\n",
    "    int i;\n",
    "    if (!attr)\n",
    "        return -EINVAL;\n",
    "    if (!attr->file)\n",
    "        return -EINVAL;\n",
    "    obj = bpf_object__open_xattr (& open_attr);\n",
    "    if (IS_ERR_OR_NULL (obj))\n",
    "        return -ENOENT;\n",
    "    bpf_object__for_each_program (prog, obj) {\n",
    "        prog_type = attr->prog_type;\n",
    "        bpf_program__set_ifindex (prog, attr->ifindex);\n",
    "        expected_attach_type = attr->expected_attach_type;\n",
    "\n",
    "#if 0 /* Use internal libbpf variables */\n",
    "        if (prog_type == BPF_PROG_TYPE_UNSPEC) {\n",
    "            err = bpf_program__identify_section (prog, & prog_type, & expected_attach_type);\n",
    "            if (err < 0) {\n",
    "                bpf_object__close (obj);\n",
    "                return -EINVAL;\n",
    "            }\n",
    "        }\n",
    "\n",
    "#endif\n",
    "        bpf_program__set_type (prog, prog_type);\n",
    "        bpf_program__set_expected_attach_type (prog, expected_attach_type);\n",
    "        if (!first_prog)\n",
    "            first_prog = prog;\n",
    "    }\n",
    "    for (i = 0; i < attr->nr_pinned_maps; i++)\n",
    "        attr->pinned_maps[i].map_fd = -1;\n",
    "    bpf_map__for_each (map, obj) {\n",
    "        const char *mapname = bpf_map__name (map);\n",
    "        if (!bpf_map__is_offload_neutral (map))\n",
    "            bpf_map__set_ifindex (map, attr->ifindex);\n",
    "        for (i = 0; i < attr->nr_pinned_maps; i++) {\n",
    "            struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];\n",
    "            int fd;\n",
    "            if (strcmp (mapname, pin_map->name) != 0)\n",
    "                continue;\n",
    "            fd = bpf_obj_get (pin_map -> filename);\n",
    "            if (fd > 0) {\n",
    "                bpf_map__reuse_fd (map, fd);\n",
    "                pin_map->map_fd = fd;\n",
    "                continue;\n",
    "            }\n",
    "        }\n",
    "    }\n",
    "    if (!first_prog) {\n",
    "        pr_warning (\"object file doesn't contain bpf program\\n\");\n",
    "        bpf_object__close (obj);\n",
    "        return -ENOENT;\n",
    "    }\n",
    "    err = bpf_object__load (obj);\n",
    "    if (err) {\n",
    "        bpf_object__close (obj);\n",
    "        return -EINVAL;\n",
    "    }\n",
    "    bpf_map__for_each (map, obj) {\n",
    "        const char *mapname = bpf_map__name (map);\n",
    "        for (i = 0; i < attr->nr_pinned_maps; i++) {\n",
    "            struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];\n",
    "            int err;\n",
    "            if (strcmp (mapname, pin_map->name) != 0)\n",
    "                continue;\n",
    "            if (pin_map->map_fd != -1)\n",
    "                continue;\n",
    "            err = bpf_map__pin (map, pin_map -> filename);\n",
    "            if (err)\n",
    "                continue;\n",
    "            pin_map->map_fd = bpf_map__fd (map);\n",
    "        }\n",
    "    }\n",
    "    for (i = 0; i < attr->nr_pinned_maps; i++) {\n",
    "        struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];\n",
    "        if (pin_map->map_fd < 0)\n",
    "            pr_warning (\"%s() requested mapname:%s not seen\\n\", __func__, pin_map->name);\n",
    "    }\n",
    "    *pobj = obj;\n",
    "    *prog_fd = bpf_program__fd (first_prog);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "bpf_object__open_xattr",
    "bpf_map__is_offload_neutral",
    "IS_ERR_OR_NULL",
    "bpf_object__for_each_program",
    "bpf_map__fd",
    "bpf_program__identify_section",
    "bpf_program__fd",
    "strcmp",
    "bpf_obj_get",
    "bpf_object__close",
    "bpf_map__reuse_fd",
    "bpf_program__set_expected_attach_type",
    "bpf_program__set_type",
    "bpf_object__load",
    "bpf_map__name",
    "pr_warning",
    "bpf_map__set_ifindex",
    "bpf_program__set_ifindex",
    "bpf_map__pin",
    "bpf_map__for_each"
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
int bpf_prog_load_xattr_maps(const struct bpf_prog_load_attr_maps *attr,
			     struct bpf_object **pobj, int *prog_fd)
{
	struct bpf_object_open_attr open_attr = {
		.file		= attr->file,
		.prog_type	= attr->prog_type,
	};
	struct bpf_program *prog, *first_prog = NULL;
	enum bpf_attach_type expected_attach_type;
	enum bpf_prog_type prog_type;
	struct bpf_object *obj;
	struct bpf_map *map;
	int err;
	int i;

	if (!attr)
		return -EINVAL;
	if (!attr->file)
		return -EINVAL;


	obj = bpf_object__open_xattr(&open_attr);
	if (IS_ERR_OR_NULL(obj))
		return -ENOENT;

	bpf_object__for_each_program(prog, obj) {
		/*
		 * If type is not specified, try to guess it based on
		 * section name.
		 */
		prog_type = attr->prog_type;
		// Was: prog->prog_ifindex = attr->ifindex;
		bpf_program__set_ifindex(prog, attr->ifindex);

		expected_attach_type = attr->expected_attach_type;
#if 0 /* Use internal libbpf variables */
		if (prog_type == BPF_PROG_TYPE_UNSPEC) {
			err = bpf_program__identify_section(prog, &prog_type,
							    &expected_attach_type);
			if (err < 0) {
				bpf_object__close(obj);
				return -EINVAL;
			}
		}
#endif

		bpf_program__set_type(prog, prog_type);
		bpf_program__set_expected_attach_type(prog,
						      expected_attach_type);

		if (!first_prog)
			first_prog = prog;
	}

	/* Reset attr->pinned_maps.map_fd to identify successful file load */
	for (i = 0; i < attr->nr_pinned_maps; i++)
		attr->pinned_maps[i].map_fd = -1;

	bpf_map__for_each(map, obj) {
		const char* mapname = bpf_map__name(map);

		if (!bpf_map__is_offload_neutral(map))
			bpf_map__set_ifindex(map, attr->ifindex);
                        /* Was: map->map_ifindex = attr->ifindex; */

		for (i = 0; i < attr->nr_pinned_maps; i++) {
			struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];
			int fd;

			if (strcmp(mapname, pin_map->name) != 0)
				continue;

			/* Matched, try opening pinned file */
			fd = bpf_obj_get(pin_map->filename);
			if (fd > 0) {
				/* Use FD from pinned map as replacement */
				bpf_map__reuse_fd(map, fd);
				/* TODO: Might want to set internal map "name"
				 * if opened pinned map didn't, to allow
				 * bpf_object__find_map_fd_by_name() to work.
				 */
				pin_map->map_fd = fd;
				continue;
			}
			/* Could not open pinned filename map, then this prog
			 * should then pin the map, BUT this can only happen
			 * after bpf_object__load().
			 */
		}
	}

	if (!first_prog) {
		pr_warning("object file doesn't contain bpf program\n");
		bpf_object__close(obj);
		return -ENOENT;
	}

	err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		return -EINVAL;
	}

	/* Pin the maps that were not loaded via pinned filename */
	bpf_map__for_each(map, obj) {
		const char* mapname = bpf_map__name(map);

		for (i = 0; i < attr->nr_pinned_maps; i++) {
			struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];
			int err;

			if (strcmp(mapname, pin_map->name) != 0)
				continue;

			/* Matched, check if map is already loaded */
			if (pin_map->map_fd != -1)
				continue;

			/* Needs to be pinned */
			err = bpf_map__pin(map, pin_map->filename);
			if (err)
				continue;
			pin_map->map_fd = bpf_map__fd(map);
		}
	}

	/* Help user if requested map name that doesn't exist */
	for (i = 0; i < attr->nr_pinned_maps; i++) {
		struct bpf_pinned_map *pin_map = &attr->pinned_maps[i];

		if (pin_map->map_fd < 0)
			pr_warning("%s() requested mapname:%s not seen\n",
				   __func__, pin_map->name);
	}

	*pobj = obj;
	*prog_fd = bpf_program__fd(first_prog);
	return 0;
}
