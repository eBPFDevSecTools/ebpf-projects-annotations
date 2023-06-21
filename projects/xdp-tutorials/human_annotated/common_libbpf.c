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
  "capability": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 17,
  "File": "/root/examples/xdp-tutorials/common_libbpf.c",
  "funcName": "IS_ERR_OR_NULL",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const void *ptr"
  ],
  "output": "staticinlinebool",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "IS_ERR_OR_NULL() is used to check if pointer is null or undefined. It is a static inline function of type boolean which takes as input a constant void pointer ptr. If on typecasting 'ptr' to type unsigned long, it returns error then IS_ERR_OR_NULL() returns True, else false. Function returns value of IS_ERR_OR_NULL() or negated value of ptr.",
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
  "capability": [],
  "helperCallParams": {},
  "startLine": 24,
  "endLine": 162,
  "File": "/root/examples/xdp-tutorials/common_libbpf.c",
  "funcName": "bpf_prog_load_xattr_maps",
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
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "bpf_prog_load_xattr_maps() is  called to load the eBPF program. It takes as input a constant struct pointer 'attr' of type bpf_prog_load_attr_maps, a structure pointer to pointer 'pobj' of type bpf_object and an integer pointer 'prog_fd'. Function then initializes three structures:
bpf_object_open_attr, bpf_object and bpf_map; two enums: bpf_attach_type and bpf_prog_type; and two integers 'err' and 'i'. It checks if attribute or attribute file is NULL ad returns error '-EINVAL' or invalid value. 'open_attr' which is defined earlier of type struct bpf_object_open_attr, is passed as argument to bpf_object__open_xattr() function and the value is stored in 'obj' of type bpf_object. If obj is error or NULL, returns error '-ENOENT'. It assigns attribute of prog_type to prog_type and expected attach type of attr using function bpf_object__for_each_program. If 'first_prog', which is a struct of type bpf_prog, is not NULL, assign first_prog as prog. Then we reset attr->pinned_maps.map_fd to identify successful file load by running a for loop from i=0 to attr->nr_pinned_maps and update the map_fd for each to -1. We load the map for each file. If first_prog is not NULL, we give a warning stating that 'object file doesn't contain bpf program' and close the object. We then use  bpf_map__for_each function to pin the maps that were not loaded via pinned filename. If matched, we check if map is already loaded and continue. Also check if map needs to be pinned. We finally use a for loop to iterate over the pinned maps and print a warning if the requested mapname is not seen. We update 'pobj' pointer to obj and prog_fd pointer to 'first_prog' via bpf_program_fd. Function returns 
 0 on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "10.03.2023"
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
