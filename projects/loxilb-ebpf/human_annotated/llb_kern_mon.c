// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"
#include "llb_kern_mon.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, unsigned int);
    __uint(max_entries, LLB_MAX_PMON_ENTRIES);
} map_events SEC(".maps");

#define MEM_READ(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "bcc",
          "FunctionName": "bpf_get_current_pid_tgid",
          "Return Type": "u64",
          "Description": "u64 bpf_get_current_pid_tgid(void) Return: current->tgid << 32 | current->pid Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID). By directly setting this to a u32, we discard the upper 32 bits. Examples in situ: \"https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Aexamples&type=Code search /examples , \"https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Atools&type=Code search /tools ",
          "Return": "current->tgid << 32 | current->pid Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID)",
          "Input Prameters": [],
          "compatible_hookpoints": [
            "kprobe",
            "tracepoint",
            "perf_event",
            "raw_tracepoint",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "For tracing programs , safely attempt to read <[ size ]>(IP: 1) bytes from address <[ src ]>(IP: 2) and store the data in dst. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_probe_read",
          "Input Params": [
            "{Type: void ,Var: *dst}",
            "{Type:  u32 ,Var: size}",
            "{Type:  const void ,Var: *src}"
          ],
          "compatible_hookpoints": [
            "kprobe",
            "tracepoint",
            "perf_event",
            "raw_tracepoint",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "Copy a NUL terminated string from an unsafe address <[ unsafe_ptr ]>(IP: 2) to dst. The <[ size ]>(IP: 1) should include the terminating NUL byte. In case the string length is smaller than <[ size ]>(IP: 1) , the target is not padded with further NUL bytes. If the string length is larger than <[ size ]>(IP: 1) , just size-1 bytes are copied and the last byte is set to NUL. On success , the length of the copied string is returned. This makes this helper useful in tracing programs for reading strings , and more importantly to get its length at runtime. See the following snippet: SEC(\"kprobe / sys_open\") void bpf_sys_open(struct pt_regs *ctx) { char buf[PATHLEN]; // PATHLEN is defined to 256 int res = bpf_probe_read_str(buf , sizeof(buf) , ctx->di); // Consume buf , for example push it to // userspace via bpf_perf_event_output(); we // can use res (the string length) as event // <[ size ]>(IP: 1) , after checking its boundaries. } In comparison , using bpf_probe_read() helper here instead to read the string would require to estimate the length at compile time , and would often result in copying more memory than necessary. Another useful use case is when parsing individual process arguments or individual environment variables navigating current->mm->arg_start and current->mm->env_start: using this helper and the return value , one can quickly iterate at the right offset of the memory area. ",
          "Return": " On  success,  the  strictly  positive  length  of  the string, including the                     trailing NUL character. On error, a negative value.",
          "Function Name": "bpf_probe_read_str",
          "Input Params": [
            "{Type: void ,Var: *dst}",
            "{Type:  int ,Var: size}",
            "{Type:  const void ,Var: *unsafe_ptr}"
          ],
          "compatible_hookpoints": [
            "kprobe",
            "tracepoint",
            "perf_event",
            "raw_tracepoint",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 19,
  "endLine": 72,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_mon.c",
  "funcName": "log_map_update",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 1,
      "text": " SPDX-License-Identifier: BSD-3-Clause"
    },
    {
      "start_line": 23,
      "end_line": 23,
      "text": " Get basic info about the map"
    },
    {
      "start_line": 30,
      "end_line": 30,
      "text": " Read the key and value into byte arrays"
    },
    {
      "start_line": 31,
      "end_line": 31,
      "text": " memset the whole struct to ensure verifier is happy"
    },
    {
      "start_line": 35,
      "end_line": 35,
      "text": " Parse the map name"
    },
    {
      "start_line": 45,
      "end_line": 45,
      "text": " Set basic data"
    },
    {
      "start_line": 52,
      "end_line": 52,
      "text": " Parse the Key"
    },
    {
      "start_line": 58,
      "end_line": 58,
      "text": " Parse the Value"
    },
    {
      "start_line": 69,
      "end_line": 69,
      "text": " Write data to be processed in userspace"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx",
    " struct bpf_map *updated_map",
    " char *pKey",
    " char *pValue",
    " enum map_updater update_type"
  ],
  "output": "staticvoid__always_inline",
  "helper": [
    "bpf_get_current_pid_tgid",
    "bpf_probe_read",
    "bpf_probe_read_str",
    "bpf_perf_event_output"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "kprobe",
    "perf_event",
    "tracepoint"
  ],
  "source": [
    "static void __always_inline log_map_update (struct pt_regs *ctx, struct bpf_map *updated_map, char *pKey, char *pValue, enum map_updater update_type)\n",
    "{\n",
    "    uint32_t map_id = MEM_READ (updated_map -> id);\n",
    "    uint32_t key_size = MEM_READ (updated_map -> key_size);\n",
    "    uint32_t value_size = MEM_READ (updated_map -> value_size);\n",
    "    char filter [] = {'c', 't', '_', 'm', 'a', 'p', '\\0'};\n",
    "    int i;\n",
    "    struct map_update_data out_data;\n",
    "    __builtin_memset (&out_data, 0, sizeof (out_data));\n",
    "    bpf_probe_read_str (out_data.name, BPF_NAME_LEN, updated_map->name);\n",
    "\n",
    "#pragma unroll\n",
    "    for (i = 0; i < sizeof (filter); i++) {\n",
    "        if (out_data.name[i] != filter[i]) {\n",
    "            return;\n",
    "        }\n",
    "    }\n",
    "    out_data.key_size = key_size;\n",
    "    out_data.value_size = value_size;\n",
    "    out_data.map_id = map_id;\n",
    "    out_data.pid = (unsigned int) bpf_get_current_pid_tgid ();\n",
    "    out_data.updater = update_type;\n",
    "    if (key_size <= MAX_KEY_SIZE) {\n",
    "        bpf_probe_read (out_data.key, key_size, pKey);\n",
    "    }\n",
    "    else {\n",
    "        bpf_probe_read (out_data.key, MAX_KEY_SIZE, pKey);\n",
    "    }\n",
    "    if (pValue) {\n",
    "        if (value_size <= MAX_VALUE_SIZE) {\n",
    "            bpf_probe_read (out_data.value, value_size, pValue);\n",
    "        }\n",
    "        else {\n",
    "            bpf_probe_read (out_data.value, MAX_VALUE_SIZE, pValue);\n",
    "        }\n",
    "    }\n",
    "    else {\n",
    "        out_data.value_size = 0;\n",
    "    }\n",
    "    bpf_perf_event_output (ctx, &map_events, BPF_F_CURRENT_CPU, &out_data, sizeof (out_data));\n",
    "}\n"
  ],
  "called_function_list": [
    "MEM_READ",
    "__builtin_memset"
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
static void __always_inline
log_map_update(struct pt_regs *ctx, struct bpf_map* updated_map,
               char *pKey, char *pValue, enum map_updater update_type)
{ 
  // Get basic info about the map
  uint32_t map_id = MEM_READ(updated_map->id);
  uint32_t key_size = MEM_READ(updated_map->key_size);
  uint32_t value_size = MEM_READ(updated_map->value_size);
  char filter[] = { 'c', 't', '_', 'm', 'a', 'p', '\0'};
  int i;
 
  // Read the key and value into byte arrays
  // memset the whole struct to ensure verifier is happy
  struct map_update_data out_data;
  __builtin_memset(&out_data, 0, sizeof(out_data));

  // Parse the map name
  bpf_probe_read_str(out_data.name, BPF_NAME_LEN, updated_map->name);

#pragma unroll
  for (i = 0 ; i < sizeof(filter); i++) {
    if (out_data.name[i] != filter[i]) {
      return;
    }
  }

  // Set basic data
  out_data.key_size = key_size;
  out_data.value_size = value_size;
  out_data.map_id = map_id;
  out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
  out_data.updater = update_type;

  // Parse the Key
  if (key_size <= MAX_KEY_SIZE) {
    bpf_probe_read(out_data.key, key_size, pKey);
  } else {
    bpf_probe_read(out_data.key, MAX_KEY_SIZE, pKey);
  }
  // Parse the Value
  if (pValue) {
    if (value_size <= MAX_VALUE_SIZE) {
      bpf_probe_read(out_data.value, value_size, pValue);
    } else {
      bpf_probe_read(out_data.value, MAX_VALUE_SIZE, pValue);
    }
  } else {
    out_data.value_size = 0;
  }

  // Write data to be processed in userspace
  bpf_perf_event_output(ctx, &map_events, BPF_F_CURRENT_CPU,
                        &out_data, sizeof(out_data));
}

SEC("kprobe/htab_map_update_elem")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 75,
  "endLine": 84,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_mon.c",
  "funcName": "bpf_prog_kern_hmapupdate",
  "developer_inline_comments": [
    {
      "start_line": 77,
      "end_line": 77,
      "text": " Parse functions params"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
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
    "int bpf_prog_kern_hmapupdate (struct pt_regs *ctx)\n",
    "{\n",
    "    struct bpf_map *updated_map = (struct bpf_map *) PT_REGS_PARM1 (ctx);\n",
    "    char *pKey = (char *) PT_REGS_PARM2 (ctx);\n",
    "    char *pValue = (char *) PT_REGS_PARM3 (ctx);\n",
    "    log_map_update (ctx, updated_map, pKey, pValue, UPDATER_KERNEL);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "PT_REGS_PARM3",
    "PT_REGS_PARM2",
    "PT_REGS_PARM1",
    "log_map_update"
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
int bpf_prog_kern_hmapupdate(struct pt_regs *ctx)
{
  // Parse functions params
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  char *pKey = (char*)PT_REGS_PARM2(ctx);
  char *pValue = (char*)PT_REGS_PARM3(ctx);

  log_map_update(ctx, updated_map, pKey, pValue, UPDATER_KERNEL);
  return 0;
}

SEC("kprobe/htab_map_delete_elem")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 87,
  "endLine": 96,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_mon.c",
  "funcName": "bpf_prog_kern_hmapdelete",
  "developer_inline_comments": [
    {
      "start_line": 89,
      "end_line": 89,
      "text": " Parse functions params"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
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
    "int bpf_prog_kern_hmapdelete (struct pt_regs *ctx)\n",
    "{\n",
    "    struct bpf_map *updated_map = (struct bpf_map *) PT_REGS_PARM1 (ctx);\n",
    "    char *pKey = (char *) PT_REGS_PARM2 (ctx);\n",
    "    char *pValue = NULL;\n",
    "    log_map_update (ctx, updated_map, pKey, pValue, DELETE_KERNEL);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "PT_REGS_PARM2",
    "PT_REGS_PARM1",
    "log_map_update"
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
int bpf_prog_kern_hmapdelete(struct pt_regs *ctx)
{
  // Parse functions params
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  char *pKey = (char*)PT_REGS_PARM2(ctx);
  char *pValue = NULL;

  log_map_update(ctx, updated_map, pKey, pValue, DELETE_KERNEL);
  return 0;
}

SEC("kprobe/htab_map_lookup_and_delete_elem")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 99,
  "endLine": 108,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_mon.c",
  "funcName": "bpf_prog_kern_hmaplkdelete",
  "developer_inline_comments": [
    {
      "start_line": 101,
      "end_line": 101,
      "text": " Parse functions params"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
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
    "int bpf_prog_kern_hmaplkdelete (struct pt_regs *ctx)\n",
    "{\n",
    "    struct bpf_map *updated_map = (struct bpf_map *) PT_REGS_PARM1 (ctx);\n",
    "    char *pKey = (char *) PT_REGS_PARM2 (ctx);\n",
    "    char *pValue = (char *) PT_REGS_PARM3 (ctx);\n",
    "    log_map_update (ctx, updated_map, pKey, pValue, DELETE_KERNEL);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "PT_REGS_PARM3",
    "PT_REGS_PARM2",
    "PT_REGS_PARM1",
    "log_map_update"
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
int bpf_prog_kern_hmaplkdelete(struct pt_regs *ctx)
{
  // Parse functions params
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  char *pKey = (char*)PT_REGS_PARM2(ctx);
  char *pValue = (char*)PT_REGS_PARM3(ctx);

  log_map_update(ctx, updated_map, pKey, pValue, DELETE_KERNEL);
  return 0;
}

#ifdef HAVE_DP_EXT_MON 

SEC("kprobe/bpf_map_update_value.isra.0")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 113,
  "endLine": 123,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_mon.c",
  "funcName": "bpf_prog_user_mapupdate",
  "developer_inline_comments": [
    {
      "start_line": 116,
      "end_line": 116,
      "text": " 'struct fd f' is PARAM2"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
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
    "int bpf_prog_user_mapupdate (struct pt_regs *ctx)\n",
    "{\n",
    "    struct bpf_map *updated_map = (struct bpf_map *) PT_REGS_PARM1 (ctx);\n",
    "    char *pKey = (char *) PT_REGS_PARM3 (ctx);\n",
    "    char *pValue = (char *) PT_REGS_PARM4 (ctx);\n",
    "    log_map_update (ctx, updated_map, pKey, pValue, UPDATER_USERMODE);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "PT_REGS_PARM3",
    "PT_REGS_PARM1",
    "PT_REGS_PARM4",
    "log_map_update"
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
int bpf_prog_user_mapupdate(struct pt_regs *ctx)
{
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  // 'struct fd f' is PARAM2
  char *pKey = (char*)PT_REGS_PARM3(ctx);
  char *pValue = (char*)PT_REGS_PARM4(ctx);

  log_map_update(ctx, updated_map, pKey, pValue, UPDATER_USERMODE);

  return 0;
}

SEC("kprobe/array_map_update_elem")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 126,
  "endLine": 135,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_mon.c",
  "funcName": "bpf_prog_kern_mapupdate",
  "developer_inline_comments": [
    {
      "start_line": 128,
      "end_line": 128,
      "text": " Parse functions params"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pt_regs *ctx"
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
    "int bpf_prog_kern_mapupdate (struct pt_regs *ctx)\n",
    "{\n",
    "    struct bpf_map *updated_map = (struct bpf_map *) PT_REGS_PARM1 (ctx);\n",
    "    char *pKey = (char *) PT_REGS_PARM2 (ctx);\n",
    "    char *pValue = (char *) PT_REGS_PARM3 (ctx);\n",
    "    log_map_update (ctx, updated_map, pKey, pValue, UPDATER_KERNEL);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "PT_REGS_PARM3",
    "PT_REGS_PARM2",
    "PT_REGS_PARM1",
    "log_map_update"
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
int bpf_prog_kern_mapupdate(struct pt_regs *ctx)
{
  // Parse functions params
  struct bpf_map* updated_map = (struct bpf_map* ) PT_REGS_PARM1(ctx);
  char *pKey = (char*)PT_REGS_PARM2(ctx);
  char *pValue = (char*)PT_REGS_PARM3(ctx);

  log_map_update(ctx, updated_map, pKey, pValue, UPDATER_KERNEL);
  return 0;
}

// The bpf syscall has 3 arguments:
//  1. cmd:   The command/action to take (get a map handle, load a program, etc.)
//  2. uattr: A union of structs that hold the arguments for the action
//  3. size:  The size of the union
struct syscall_bpf_args {
    unsigned long long unused;
    long syscall_nr;
    int cmd;
    // bpf_attr contains the arguments to pass to the
    // various bpf commands
    union bpf_attr* uattr;
    unsigned int size;
};
SEC("tp/syscalls/sys_enter_bpf")
/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [
    {
      "capability": "read_sys_info",
      "read_sys_info": [
        {
          "Project": "bcc",
          "FunctionName": "bpf_get_current_pid_tgid",
          "Return Type": "u64",
          "Description": "u64 bpf_get_current_pid_tgid(void) Return: current->tgid << 32 | current->pid Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID). By directly setting this to a u32, we discard the upper 32 bits. Examples in situ: \"https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Aexamples&type=Code search /examples , \"https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Atools&type=Code search /tools ",
          "Return": "current->tgid << 32 | current->pid Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID)",
          "Input Prameters": [],
          "compatible_hookpoints": [
            "kprobe",
            "tracepoint",
            "perf_event",
            "raw_tracepoint",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        },
        {
          "Project": "libbpf",
          "Return Type": "int",
          "Description": "For tracing programs , safely attempt to read <[ size ]>(IP: 1) bytes from address <[ src ]>(IP: 2) and store the data in dst. ",
          "Return": " 0 on success, or a negative error in case of failure.",
          "Function Name": "bpf_probe_read",
          "Input Params": [
            "{Type: void ,Var: *dst}",
            "{Type:  u32 ,Var: size}",
            "{Type:  const void ,Var: *src}"
          ],
          "compatible_hookpoints": [
            "kprobe",
            "tracepoint",
            "perf_event",
            "raw_tracepoint",
            "raw_tracepoint_writable"
          ],
          "capabilities": [
            "read_sys_info"
          ]
        }
      ]
    }
  ],
  "helperCallParams": {},
  "startLine": 151,
  "endLine": 190,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/kernel/llb_kern_mon.c",
  "funcName": "bpf_prog_syscall",
  "developer_inline_comments": [
    {
      "start_line": 137,
      "end_line": 137,
      "text": " The bpf syscall has 3 arguments:"
    },
    {
      "start_line": 138,
      "end_line": 138,
      "text": "  1. cmd:   The command/action to take (get a map handle, load a program, etc.)"
    },
    {
      "start_line": 139,
      "end_line": 139,
      "text": "  2. uattr: A union of structs that hold the arguments for the action"
    },
    {
      "start_line": 140,
      "end_line": 140,
      "text": "  3. size:  The size of the union"
    },
    {
      "start_line": 145,
      "end_line": 145,
      "text": " bpf_attr contains the arguments to pass to the"
    },
    {
      "start_line": 146,
      "end_line": 146,
      "text": " various bpf commands"
    },
    {
      "start_line": 153,
      "end_line": 153,
      "text": " Get The Map ID"
    },
    {
      "start_line": 157,
      "end_line": 157,
      "text": " memset the whole struct to ensure verifier is happy"
    },
    {
      "start_line": 164,
      "end_line": 164,
      "text": " We don't know any key or value size, as we are just getting a handle"
    },
    {
      "start_line": 168,
      "end_line": 168,
      "text": " Write data to perf event"
    },
    {
      "start_line": 175,
      "end_line": 175,
      "text": " memset the whole struct to ensure verifier is happy"
    },
    {
      "start_line": 182,
      "end_line": 182,
      "text": " We don't know any key or value size, as we are just getting a handle"
    },
    {
      "start_line": 186,
      "end_line": 186,
      "text": " Write data to perf event"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct syscall_bpf_args *args"
  ],
  "output": "int",
  "helper": [
    "bpf_get_current_pid_tgid",
    "bpf_probe_read",
    "bpf_perf_event_output"
  ],
  "compatibleHookpoints": [
    "raw_tracepoint",
    "raw_tracepoint_writable",
    "kprobe",
    "perf_event",
    "tracepoint"
  ],
  "source": [
    "int bpf_prog_syscall (struct syscall_bpf_args *args)\n",
    "{\n",
    "    if (args->cmd == BPF_MAP_GET_FD_BY_ID) {\n",
    "        unsigned int map_id = 0;\n",
    "        bpf_probe_read (&map_id, sizeof (map_id), &args->uattr->map_id);\n",
    "        struct map_update_data out_data;\n",
    "        __builtin_memset (&out_data, 0, sizeof (out_data));\n",
    "        out_data.map_id = map_id;\n",
    "        out_data.pid = (unsigned int) bpf_get_current_pid_tgid ();\n",
    "        out_data.updater = UPDATER_SYSCALL_GET;\n",
    "        out_data.key_size = 0;\n",
    "        out_data.value_size = 0;\n",
    "        bpf_perf_event_output (args, &map_events, BPF_F_CURRENT_CPU, &out_data, sizeof (out_data));\n",
    "    }\n",
    "    else if (args->cmd == BPF_MAP_UPDATE_ELEM) {\n",
    "        int map_fd = 0;\n",
    "        bpf_probe_read (&map_fd, sizeof (map_fd), &args->uattr->map_fd);\n",
    "        struct map_update_data out_data;\n",
    "        __builtin_memset (&out_data, 0, sizeof (out_data));\n",
    "        out_data.map_id = map_fd;\n",
    "        out_data.pid = (unsigned int) bpf_get_current_pid_tgid ();\n",
    "        out_data.updater = UPDATER_SYSCALL_UPDATE;\n",
    "        out_data.key_size = 0;\n",
    "        out_data.value_size = 0;\n",
    "        bpf_perf_event_output (args, &map_events, BPF_F_CURRENT_CPU, &out_data, sizeof (out_data));\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "__builtin_memset"
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
int bpf_prog_syscall(struct syscall_bpf_args *args) {
    if (args->cmd == BPF_MAP_GET_FD_BY_ID) {
        // Get The Map ID
        unsigned int map_id = 0;
        bpf_probe_read(&map_id, sizeof(map_id), &args->uattr->map_id);

        // memset the whole struct to ensure verifier is happy
        struct map_update_data out_data;
        __builtin_memset(&out_data, 0, sizeof(out_data));
        
        out_data.map_id = map_id;
        out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
        out_data.updater = UPDATER_SYSCALL_GET;
        // We don't know any key or value size, as we are just getting a handle
        out_data.key_size = 0;
        out_data.value_size = 0;

        // Write data to perf event
        bpf_perf_event_output(args, &map_events, BPF_F_CURRENT_CPU, &out_data, sizeof(out_data));
    }
    else if (args->cmd == BPF_MAP_UPDATE_ELEM) {
        int map_fd = 0;
        bpf_probe_read(&map_fd, sizeof(map_fd), &args->uattr->map_fd);
        
        // memset the whole struct to ensure verifier is happy
        struct map_update_data out_data;
        __builtin_memset(&out_data, 0, sizeof(out_data));

        out_data.map_id = map_fd;
        out_data.pid = (unsigned int)bpf_get_current_pid_tgid();
        out_data.updater = UPDATER_SYSCALL_UPDATE;
        // We don't know any key or value size, as we are just getting a handle
        out_data.key_size = 0;
        out_data.value_size = 0;
        
        // Write data to perf event
        bpf_perf_event_output(args, &map_events, BPF_F_CURRENT_CPU, &out_data, sizeof(out_data));
    }
    return 0;
}
#endif
