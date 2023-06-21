/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"reuse-maps",  no_argument,		NULL, 'M' },
	 "Reuse pinned maps"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";

/* Pinning maps under /sys/fs/bpf in subdir */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 73,
  "endLine": 107,
  "File": "/root/examples/xdp-tutorials/xdp_loader.c",
  "funcName": "pin_maps_in_bpf_object",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *bpf_obj",
    " struct config *cfg"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "pin_maps_in_bpf_object() function is used to check if a file exists and unpin all maps in that directory. Function takes as  arguments structure pointer 'bpf_obj' of type bpf_object and 'cfg' of type config. It then initializes a character array 'map_filename' of size  PATH_MAX, which is a predefined macro of size 4096, and two integer  variables 'err' and 'len'. It then uses snprintf() function to put 'pin_basedir', 'cfg->ifname' and 'map_name' in len variable. If len<0, we print an error message 'ERR: creating map_name'. If access to that map_filename is not equal to -1, we check if verbose, which is defined in file 'common_params.o' as 1 is true. If true, we print the message that we are unpinning previous maps in which configuration. bpf_object__unpin_maps() function is then used to unpin each map contained within the BPF object found in the cfg->pin_dir. If unsuccessful, i.e. err!=0, it displays an error message stating error in unpinning maps in that directory and returns 'EXIT_FAIL_BPF'. We then go on to check if verbose is TRUE, and the print a comment stating 'Pinning maps' in that directory. Finally we use bpf_object__pin_maps() function to pin each map contained within the BPF object 'bpf_obj' at the directory cfg->pin_dir. If error, returns EXIT_FAIL_BPF. Function returns 0 on successful completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "18.03.2023"
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
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, cfg->ifname, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 109,
  "endLine": 165,
  "File": "/root/examples/xdp-tutorials/xdp_loader.c",
  "funcName": "main",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int argc",
    " char **argv"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "xdp_loader_main() function is used to load XDP program to configuration. It takes as argument integer 'argc' and pointer to pointer array 'argv' of type character. It initializes two integer variables 'err' and 'len', a pointer bpf_obj of type struct bpf_object and structure 'cfg' of type config. strncpy() is used to set default BPF-ELF object file and BPF program name. parse_cmdline_args() function parses the command line arguments and stores them in a config cfg. If cfg.ifindex is equal to -1, it prints a error message 'ERR: required option --dev missing' and returns EXIT_FAIL_OPTION. If cfg.do_unload is TRUE then if reuse of maps is set as TRUE then we skip pinning of maps. We then pin the base directory to the configuration ifname and if error happens, print an error message 'ERR: creating pin dirname' and return EXIT_FAIL_OPTION. load_bpf_and_xdp_attach() function is then called with 'cfg' value and value is stored in bpf_obj. If bpf_obj is NULL, it returns EXIT_FAIL_BFP.  If 'verbose' is TRUE, we print two messages: 'successful in loading BPF-object 'filename' and used section 'cfg.progsec'' and 'XDP prog attached on device 'cfg.ifname'(ifindex: 'cfg.ifindex')'. If reuse maps is NULL, we display message stating error in pinning maps. Function returns EXIT_OK on successful completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "18.03.2023"
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
int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	int err, len;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload) {
		if (!cfg.reuse_maps) {
		/* TODO: Miss unpin of maps on unload */
		}
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	}

	len = snprintf(cfg.pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}


	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg.reuse_maps) {
		err = pin_maps_in_bpf_object(bpf_obj, &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	return EXIT_OK;
}
