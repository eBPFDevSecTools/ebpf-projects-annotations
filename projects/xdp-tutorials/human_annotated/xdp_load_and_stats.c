/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
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
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

static const char *default_filename = "xdp_prog_kern.o";
static const char *default_progsec = "xdp_stats1";

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

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }}
};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 63,
  "endLine": 78,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "find_map_fd",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct bpf_object *bpf_obj",
    " const char *mapname"
  ],
  "output": "int",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "find_map_fd() is a function used to find the file descriptor of a map. This function takes as input pointer 'bpf_obj' of type structure bpf_object and pointer 'mapname' of type constant character. It defines pointer 'map' of type structure bpf_map and an integer variable map_fd with value -1. bpf_object__find_map_by_name() function is then used to return BPF map of the given name, if it exists within the passed BPF object 'bpf_obj' and the return value is stored in 'map'. If map is NULL, we print error message stating we can't find map by name and go to 'out'. 'out' is defined later in the function as 'return map_fd'. map_fd function is used to get the file descriptor of the map. Function returns map_fd on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "19.03.2023"
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
int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* Lesson#3: bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 81,
  "endLine": 92,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "gettime",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
  ],
  "output": "static__u64",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "gettime() function is used to get the time in nanoseconds. It is a static function of type __u64. It defines a structure 't' of type timespec and an integer variable 'res'. clock_gettime() function is called on CLOCK_MONOTONIC and t to retreive the time of the specified clock CLOCK_MONOTONIC and store it in res. If res is negative, we print error message 'Error with gettimeofday! 'res''. Function returns the time after calculating it in nanoseconds.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "19.03.2023"
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
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats[1]; /* Assignment#2: Hint */
};

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 103,
  "endLine": 113,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "calc_period",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct record *r",
    " struct record *p"
  ],
  "output": "staticdouble",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "calc_period() is used to calculate the time difference between two records. It is a static function of type double which takes as input two structure pointers 'r' and ' p' both of type record. It initializes variable 'period_' of type double and 'period' of type __u64 as 0 each. Function then calculates period as difference of timestamp of r and p. If period is positive we calculate 'period_' by typecasting 'period' as 'double' after dividing it by macro 'NANOSEC_PER_SEC'. Function returns period_ on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "19.03.2023"
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
static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 115,
  "endLine": 141,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "stats_print",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct stats_record *stats_rec",
    " struct stats_record *stats_prev"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "stats_print() function is used to get details of two records 'rec' and 'prev'. It is a static function of type void which takes as input two structure pointers 'stats_rec' and 'stats_prev' of type stats_record. It declares two structure pointer 'rec' and 'prev' of type record; two variables 'period' and 'pps' of type double; and a variable 'packets' of type __u64. It then calculates the packets per seconds and prints it. action2str() function is then used to return a string representation of the XDP action, which is used to print out a description for each statistic record printed by stats_print(). Function stores two records in 'rec' and'prev' and then uses calc_period() to calculate the time difference between these two records and store it in variable
'period'. if period is equal to 0 then we simply return. The difference in total rx packets of 'rec' and 'prev' is stored in 'period'. Variable 'pps' is calculated by dividing 'packets' by 'period'. We print fmt, action, total packets of rec, pps and period. Function returns no value on.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "19.03.2023"
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
static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	double period;
	__u64 packets;
	double pps; /* packets per sec */

	/* Assignment#2: Print other XDP actions stats  */
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			//" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		const char *action = action2str(XDP_PASS);
		rec  = &stats_rec->stats[0];
		prev = &stats_prev->stats[0];

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps     = packets / period;

		printf(fmt, action, rec->total.rx_packets, pps, period);
	}
}

/* BPF_MAP_TYPE_ARRAY */
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
        "opVar": "\tif ((bpf_map_lookup_elem(fd, &key, value)) !",
        "inpVar": [
          " 0 "
        ]
      },
      {
        "opVar": "NA",
        "inpVar": [
          "\t\tfprintfstderr",
          "\t\t\t\"ERR:  failed key:0x%X\\n\"",
          " key"
        ]
      }
    ]
  },
  "startLine": 144,
  "endLine": 150,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "map_get_value_array",
  "updateMaps": [],
  "readMaps": [
    " fd",
    " failed key:0x%X\\n\""
  ],
  "input": [
    "int fd",
    " __u32 key",
    " struct datarec *value"
  ],
  "output": "void",
  "helper": [
    "bpf_map_lookup_elem"
  ],
  "compatibleHookpoints": [
    "cgroup_skb",
    "socket_filter",
    "cgroup_sock_addr",
    "sk_msg",
    "sock_ops",
    "flow_dissector",
    "sched_act",
    "sk_reuseport",
    "lwt_seg6local",
    "raw_tracepoint",
    "xdp",
    "cgroup_device",
    "lwt_in",
    "sk_skb",
    "cgroup_sock",
    "raw_tracepoint_writable",
    "perf_event",
    "sched_cls",
    "tracepoint",
    "lwt_out",
    "lwt_xmit",
    "cgroup_sysctl",
    "kprobe"
  ],
  "humanFuncDescription": [
    {
      "description": "map_get_value_array() is used to get an array of values from BPF map. Function takes as input function of type void which takes as input an integer 'fd', a variable 'key' of type __u32 and a structure pointer 'value' of type datarec. 'fd' is used to represent a file descriptor. It uses bpf_map_lookup_elem() helper function to look for file descriptor fd associated with 'key' and return it 'value'. If this 'value' is not equal to NULL, we print error stating 'bpf_map_lookup_elem; failed key.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "19.03.2023"
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
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 153,
  "endLine": 160,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "map_get_value_percpu_array",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int fd",
    " __u32 key",
    " struct datarec *value"
  ],
  "output": "void",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "map_get_value_percpu_array() is a void function which prints an error message to 'stderr' stating that this function is not yet implemented. Function takes as argument an integer variable 'fd', a 'key' of type __u32 and a structure pointer 'value' of type datarec.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "22.03.2023"
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
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	// unsigned int nr_cpus = bpf_num_possible_cpus();
	// struct datarec values[nr_cpus];

	fprintf(stderr, "ERR: %s() not impl. see assignment#3", __func__);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 162,
  "endLine": 185,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "map_collect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int fd",
    " __u32 map_type",
    " __u32 key",
    " struct record *rec"
  ],
  "output": "staticbool",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "map_collect() function calls the appropriate map getter based on the type of BPF Map. It is a static boolean function which takes as input an integer variable 'fd', two variables 'map_type' and 'key' of type __u32 and a structure pointer 'rec' of type record. It defines a structure 'value' of type datarec. It then uses gettime() function to update timestamp of record 'rec'. It then initializes a switch case with the case checker being 'map_type'. If map_type is 'BPF_MAP_TYPE_ARRAY', we call map_get_value_array() function with 'fd', 'key' and '&value' and break. If map_type is 'BPF_MAP_TYPE_PERCPU_ARRAY', we fall through. The default condition is to print an error stating 'Unknown map_type. Cannot handle' and return false and break. Total rx_packets are updated in 'rec'. Function returns true on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "22.03.2023"
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
static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		/* fall-through */
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}

	/* Assignment#1: Add byte counters */
	rec->total.rx_packets = value.rx_packets;
	return true;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 187,
  "endLine": 194,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "stats_collect",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int map_fd",
    " __u32 map_type",
    " struct stats_record *stats_rec"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "stats_collect() function is used to collect the statistics from the map. It is a static void function which takes as argument an integer variable 'map_fd', a variable 'map_type' of type __u32 and a structure pointer 'stats_rec' of type stats_record. Function stores XDP_PASS in a variable 'key' of type __u32. It then calls the map_collect() function with XDP_PASS as key which will return all of the statistics for packets passed through by XDP. The stats_record structure contains an array of counters for all actions that can be taken by XDP.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "22.03.2023"
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
static void stats_collect(int map_fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	/* Assignment#2: Collect other XDP actions stats  */
	__u32 key = XDP_PASS;

	map_collect(map_fd, map_type, key, &stats_rec->stats[0]);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 196,
  "endLine": 219,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "stats_poll",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int map_fd",
    " __u32 map_type",
    " int interval"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "stats_poll() function collects the statistics of the XDP program running on a particular interface. It is a static void function which takes as input two integer variables 'map_fd' and 'interval' and a variable 'map_type' of type __u32. It initializes two structure variable 'prev' and 'record' as 0 of type stats_record. It sets 'LC_NUMERIC' as English and then prints the header for stats as 'XDP-ACTION'. It then calls stats_collect() function with map_fd, map_type and record as arguments to get initial reading quickly. It then runs an infinite while loop to collect and print statistics of records.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "22.03.2023"
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
static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (verbose) {
		printf("\n");
		printf("%-12s\n", "XDP-action");
	}

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */
		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}
}

/* Lesson#4: It is userspace responsibility to known what map it is reading and
 * know the value size. Here get bpf_map_info and check if it match our expected
 * values.
 */
/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 225,
  "endLine": 268,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
  "funcName": "__check_map_fd_info",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "int map_fd",
    " struct bpf_map_info *info",
    " struct bpf_map_info *exp"
  ],
  "output": "staticint",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "__check_map_fd_info() function is used to check the map information. It is a static int function which takes as input an integer variable
'map_fd' and two structure pointers 'info' and 'exp' of type bpf_map_info. Function initializes a variable 'info_len' of type __u32 as size of 'info' and an integer variable 'err'. If 'map_fd' is negative we return EXIT_FAIL. It uses bpf_obj_get_info_by_fd() function to get information on 'map_fd'. If error, we print message 'ERR: can't get info' and return EXIT_FAIL_BPF. We further check for map 'key size', 'value size', 'max_entries' and 'type' mismatch and print message with expected values of same in case of mismatch. We return EXIT_FAIL in all four cases. Function returns 0.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "22.03.2023"
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
static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

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
  "capability": [],
  "helperCallParams": {},
  "startLine": 270,
  "endLine": 337,
  "File": "/root/examples/xdp-tutorials/xdp_load_and_stats.c",
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
      "description": "xdp_load_and_stats_main() function is used to call all the other functions. It takes as input an integer variable 'argc' and a  pointer to pointer 'argv' of type character. It defines two structures: 'map_expect' and 'info' of type bpf_map_info as 0. It also defines structure pointer 'bpf_obj' of type bpf_object, and three integer variables  'stats_map_fd', 'err' and 'interval'(equal to 2). strncpy() function is used to set  default BPF-ELF object file and BPF program name. cfg.ifindex id used to  check if the required option is missing or not. If 'cfg.do_unload' is true,  we use xdp_link_detach() to detach the XDP program from the interface. We  then call load_bpf_and_xdp_attach() function with 'cfg' as argument and  store it in bpf_obj. If bpf_obj is FALSE, we return EXIT_FAIL_BPF. If  'verbose' is TRUE, we print message stating successful in loading BPF-object of filename and used this section of program section; followed by another  message 'XDP program attached on device ifname with it's ifindex'. We then  use find_map_fd() to locate map descriptor file. Finally, we check if map  info is of expected size and prints an error message if not. If 'verbose' is TRUE, we collect stats like type, id, name, key_size, value_size and  max_entries of BPF map and print it. stats_poll() function is called to  collect the statistics of the XDP program running on that interface.  Function returns 'EXIT_OK' on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "22.03.2023"
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
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };
	struct bpf_object *bpf_obj;
	int stats_map_fd;
	int interval = 2;
	int err;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Lesson#3: Locate map file descriptor */
	stats_map_fd = find_map_fd(bpf_obj, "xdp_stats_map");
	if (stats_map_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}

	/* Lesson#4: check map info, e.g. datarec is expected size */
	map_expect.key_size    = sizeof(__u32);
	map_expect.value_size  = sizeof(struct datarec);
	map_expect.max_entries = XDP_ACTION_MAX;
	err = __check_map_fd_info(stats_map_fd, &info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}

	stats_poll(stats_map_fd, info.type, interval);
	return EXIT_OK;
}
