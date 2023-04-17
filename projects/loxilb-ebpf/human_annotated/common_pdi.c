/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * SPDX short identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include "pdi.h"

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 14,
  "endLine": 29,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_map_alloc",
  "developer_inline_comments": [
    {
      "start_line": 1,
      "end_line": 5,
      "text": " * Copyright (c) 2022 NetLOX Inc * * SPDX short identifier: BSD-3-Clause "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *name",
    " pdi_add_map_op_t add_map",
    " pdi_del_map_op_t del_map"
  ],
  "output": "structpdi_map",
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
    "struct pdi_map *pdi_map_alloc (const char *name, pdi_add_map_op_t add_map, pdi_del_map_op_t del_map)\n",
    "{\n",
    "    struct pdi_map *map = calloc (1, sizeof (struct pdi_map));\n",
    "    if (name) {\n",
    "        strncpy (map->name, name, PDI_MAP_NAME_LEN);\n",
    "        map->name[PDI_MAP_NAME_LEN - 1] = '\\0';\n",
    "    }\n",
    "    else {\n",
    "        strncpy (map->name, \"default\", PDI_MAP_NAME_LEN);\n",
    "    }\n",
    "    map->pdi_add_map_em = add_map;\n",
    "    map->pdi_del_map_em = del_map;\n",
    "    return map;\n",
    "}\n"
  ],
  "called_function_list": [
    "calloc",
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
struct pdi_map *
pdi_map_alloc(const char *name, pdi_add_map_op_t add_map, pdi_del_map_op_t del_map)
{
  struct pdi_map *map = calloc(1, sizeof(struct pdi_map));

  if (name) {
    strncpy(map->name, name, PDI_MAP_NAME_LEN);
    map->name[PDI_MAP_NAME_LEN-1] = '\0'; 
  } else {
    strncpy(map->name, "default", PDI_MAP_NAME_LEN);
  }
  map->pdi_add_map_em = add_map;
  map->pdi_del_map_em = del_map;

  return map;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 31,
  "endLine": 44,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_key2str",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_key *key",
    " char *fstr"
  ],
  "output": "void",
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
    "void pdi_key2str (struct pdi_key *key, char *fstr)\n",
    "{\n",
    "    int l = 0;\n",
    "    PDI_MATCH_PRINT (&key->dest, \"dest\", fstr, l, none);\n",
    "    PDI_MATCH_PRINT (&key->source, \"source\", fstr, l, none);\n",
    "    PDI_RMATCH_PRINT (&key->dport, \"dport\", fstr, l, none);\n",
    "    PDI_RMATCH_PRINT (&key->dport, \"sport\", fstr, l, none);\n",
    "    PDI_MATCH_PRINT (&key->inport, \"inport\", fstr, l, none);\n",
    "    PDI_MATCH_PRINT (&key->protocol, \"prot\", fstr, l, none);\n",
    "    PDI_MATCH_PRINT (&key->zone, \"zone\", fstr, l, none);\n",
    "    PDI_MATCH_PRINT (&key->bd, \"bd\", fstr, l, none);\n",
    "}\n"
  ],
  "called_function_list": [
    "PDI_RMATCH_PRINT",
    "PDI_MATCH_PRINT"
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
void
pdi_key2str(struct pdi_key *key, char *fstr)
{
  int l = 0;

  PDI_MATCH_PRINT(&key->dest, "dest", fstr, l, none);
  PDI_MATCH_PRINT(&key->source, "source", fstr, l, none);
  PDI_RMATCH_PRINT(&key->dport, "dport", fstr, l, none);
  PDI_RMATCH_PRINT(&key->dport, "sport", fstr, l, none);
  PDI_MATCH_PRINT(&key->inport, "inport", fstr, l, none);
  PDI_MATCH_PRINT(&key->protocol, "prot", fstr, l, none);
  PDI_MATCH_PRINT(&key->zone, "zone", fstr, l, none);
  PDI_MATCH_PRINT(&key->bd, "bd", fstr, l, none);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 46,
  "endLine": 55,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_rule2str",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_rule *node"
  ],
  "output": "void",
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
    "void pdi_rule2str (struct pdi_rule *node)\n",
    "{\n",
    "    char fmtstr [1000] = {0};\n",
    "    if (1) {\n",
    "        pdi_key2str (&node->key, fmtstr);\n",
    "        printf (\"(%s)%d\\n\", fmtstr, node->data.pref);\n",
    "    }\n",
    "}\n"
  ],
  "called_function_list": [
    "pdi_key2str",
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
void
pdi_rule2str(struct pdi_rule *node)
{
  char fmtstr[1000] = { 0 };

  if (1) {
    pdi_key2str(&node->key, fmtstr);
    printf("(%s)%d\n", fmtstr, node->data.pref);
  }
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 57,
  "endLine": 68,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_rules2str",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map"
  ],
  "output": "void",
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
    "void pdi_rules2str (struct pdi_map *map)\n",
    "{\n",
    "    struct pdi_rule *node = map->head;\n",
    "    printf (\"#### Rules ####\\n\");\n",
    "    while (node) {\n",
    "        pdi_rule2str (node);\n",
    "        node = node->next;\n",
    "    }\n",
    "    printf (\"##############\\n\");\n",
    "}\n"
  ],
  "called_function_list": [
    "pdi_rule2str",
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
void
pdi_rules2str(struct pdi_map *map)
{
  struct pdi_rule *node = map->head;

  printf("#### Rules ####\n");
  while (node) {
    pdi_rule2str(node);
    node = node->next;
  }
  printf("##############\n");
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 70,
  "endLine": 123,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_rule_insert",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map",
    " struct pdi_rule *new",
    " int *nr"
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
    "int pdi_rule_insert (struct pdi_map *map, struct pdi_rule *new, int *nr)\n",
    "{\n",
    "    struct pdi_rule *prev = NULL;\n",
    "    struct pdi_rule *node;\n",
    "    uint32_t pref = new->data.pref;\n",
    "    if (nr)\n",
    "        *nr = 0;\n",
    "    PDI_MAP_LOCK (map);\n",
    "    node = map->head;\n",
    "    while (node) {\n",
    "        if (pref > node->data.pref) {\n",
    "            if (prev) {\n",
    "                prev->next = new;\n",
    "                new->next = node;\n",
    "            }\n",
    "            else {\n",
    "                map->head = new;\n",
    "                new->next = node;\n",
    "            }\n",
    "            map->nr++;\n",
    "            PDI_MAP_ULOCK (map);\n",
    "            return 0;\n",
    "        }\n",
    "        if (pref == node->data.pref) {\n",
    "            if (PDI_KEY_EQ (&new->key, &node->key)) {\n",
    "                PDI_MAP_ULOCK (map);\n",
    "                return -EEXIST;\n",
    "            }\n",
    "        }\n",
    "        prev = node;\n",
    "        node = node->next;\n",
    "        if (nr) {\n",
    "            *nr = *nr + 1;\n",
    "            ;\n",
    "        }\n",
    "    }\n",
    "    if (prev) {\n",
    "        prev->next = new;\n",
    "        new->next = node;\n",
    "    }\n",
    "    else {\n",
    "        map->head = new;\n",
    "        new->next = node;\n",
    "    }\n",
    "    map->nr++;\n",
    "    PDI_MAP_ULOCK (map);\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "PDI_MAP_ULOCK",
    "PDI_KEY_EQ",
    "PDI_MAP_LOCK"
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
int
pdi_rule_insert(struct pdi_map *map, struct pdi_rule *new, int *nr)
{
  struct pdi_rule *prev =  NULL;
  struct pdi_rule *node;
  uint32_t pref = new->data.pref;

  if (nr) *nr = 0;

  PDI_MAP_LOCK(map);

  node = map->head;

  while (node) {
    if (pref > node->data.pref) {
      if (prev) {
        prev->next = new;
        new->next = node;
      } else {
        map->head = new;
        new->next = node;
      }

      map->nr++;
      PDI_MAP_ULOCK(map);
      return 0;
    }

    if (pref == node->data.pref)  {
      if (PDI_KEY_EQ(&new->key, &node->key)) {
        PDI_MAP_ULOCK(map);
        return -EEXIST;
      } 
    }
    prev = node;
    node = node->next;
    if (nr) {
      *nr = *nr + 1;;
    }
  }

  if (prev) {
    prev->next = new;
    new->next = node;
  } else {
    map->head = new;
    new->next = node;
  }
  map->nr++;

  PDI_MAP_ULOCK(map);

  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 125,
  "endLine": 153,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_rule_delete__",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map",
    " struct pdi_key *key",
    " uint32_t pref",
    " int *nr"
  ],
  "output": "structpdi_rule",
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
    "struct pdi_rule *pdi_rule_delete__ (struct pdi_map *map, struct pdi_key *key, uint32_t pref, int *nr)\n",
    "{\n",
    "    struct pdi_rule *prev = NULL;\n",
    "    struct pdi_rule *node;\n",
    "    node = map->head;\n",
    "    while (node) {\n",
    "        if (pref == node->data.pref) {\n",
    "            if (PDI_KEY_EQ (key, &node->key)) {\n",
    "                if (prev) {\n",
    "                    prev->next = node->next;\n",
    "                }\n",
    "                else {\n",
    "                    map->head = node->next;\n",
    "                }\n",
    "                map->nr--;\n",
    "                return node;\n",
    "            }\n",
    "        }\n",
    "        prev = node;\n",
    "        node = node->next;\n",
    "        if (nr) {\n",
    "            *nr = *nr + 1;\n",
    "        }\n",
    "    }\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "PDI_KEY_EQ"
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
struct pdi_rule *
pdi_rule_delete__(struct pdi_map *map, struct pdi_key *key, uint32_t pref, int *nr)
{
  struct pdi_rule *prev =  NULL;
  struct pdi_rule *node;

  node = map->head;

  while (node) {
    if (pref == node->data.pref)  {
      if (PDI_KEY_EQ(key, &node->key)) {
        if (prev) {
          prev->next = node->next;
        } else {
          map->head = node->next;
        }
        map->nr--;
        return node;
      } 
    }
    prev = node;
    node = node->next;
    if (nr) {
      *nr = *nr + 1;
    }
  }

  return NULL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 155,
  "endLine": 182,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_rule_delete",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map",
    " struct pdi_key *key",
    " uint32_t pref",
    " int *nr"
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
    "int pdi_rule_delete (struct pdi_map *map, struct pdi_key *key, uint32_t pref, int *nr)\n",
    "{\n",
    "    struct pdi_rule *node = NULL;\n",
    "    struct pdi_val *val, *tmp;\n",
    "    PDI_MAP_LOCK (map);\n",
    "    node = pdi_rule_delete__ (map, key, pref, nr);\n",
    "    if (node != NULL) {\n",
    "        pdi_rule2str (node);\n",
    "        HASH_ITER (hh, node -> hash, val, tmp) {\n",
    "            HASH_DEL (node->hash, val);\n",
    "            if (map->pdi_del_map_em) {\n",
    "                map->pdi_del_map_em (&val->val);\n",
    "            }\n",
    "            free (val);\n",
    "            printf (\"Hash del\\n\");\n",
    "        }\n",
    "\n",
    "        free (node);\n",
    "        PDI_MAP_ULOCK (map);\n",
    "        return 0;\n",
    "    }\n",
    "    PDI_MAP_ULOCK (map);\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "pdi_rule2str",
    "free",
    "PDI_MAP_ULOCK",
    "PDI_MAP_LOCK",
    "pdi_rule_delete__",
    "HASH_ITER",
    "printf",
    "HASH_DEL",
    "pdi_del_map_em"
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
int
pdi_rule_delete(struct pdi_map *map, struct pdi_key *key, uint32_t pref, int *nr)
{
  struct pdi_rule *node = NULL;
  struct pdi_val *val, *tmp;

  PDI_MAP_LOCK(map);

  node = pdi_rule_delete__(map, key, pref, nr);
  if (node != NULL) {
    pdi_rule2str(node);
    HASH_ITER(hh, node->hash, val, tmp) {
      HASH_DEL(node->hash, val);
      if (map->pdi_del_map_em) {
        map->pdi_del_map_em(&val->val);
      }
      free(val);
      printf("Hash del\n");
    }
    free(node);
    PDI_MAP_ULOCK(map);

    return 0;
  }

  PDI_MAP_ULOCK(map);
  return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 184,
  "endLine": 197,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_rule_get__",
  "developer_inline_comments": [
    {
      "start_line": 190,
      "end_line": 190,
      "text": "pdi_rule2str(node);"
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map",
    " struct pdi_key *val"
  ],
  "output": "structpdi_rule",
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
    "struct pdi_rule *pdi_rule_get__ (struct pdi_map *map, struct pdi_key *val)\n",
    "{\n",
    "    struct pdi_rule *node = map->head;\n",
    "    while (node) {\n",
    "        if (PDI_PKEY_EQ (val, &node->key)) {\n",
    "            return node;\n",
    "        }\n",
    "        node = node->next;\n",
    "    }\n",
    "    return NULL;\n",
    "}\n"
  ],
  "called_function_list": [
    "PDI_PKEY_EQ"
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
struct pdi_rule *
pdi_rule_get__(struct pdi_map *map, struct pdi_key *val)
{
  struct pdi_rule *node = map->head;

  while (node) {
    //pdi_rule2str(node);
    if (PDI_PKEY_EQ(val, &node->key)) {
      return node;
    } 
    node = node->next;
  }
  return NULL;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 199,
  "endLine": 233,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_add_val",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map",
    " struct pdi_key *kval"
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
    "int pdi_add_val (struct pdi_map *map, struct pdi_key *kval)\n",
    "{\n",
    "    struct pdi_val *hval = NULL;\n",
    "    struct pdi_rule *rule = NULL;\n",
    "    PDI_MAP_LOCK (map);\n",
    "    rule = pdi_rule_get__ (map, kval);\n",
    "    if (rule != NULL) {\n",
    "        printf (\"Found match --\\n\");\n",
    "        pdi_rule2str (rule);\n",
    "        HASH_FIND (hh, rule->hash, kval, sizeof (struct pdi_key), hval);\n",
    "        if (hval) {\n",
    "            printf (\"hval exists\\n\");\n",
    "            if (map->pdi_add_map_em) {\n",
    "                map->pdi_add_map_em (kval, &rule->data, sizeof (rule->data));\n",
    "            }\n",
    "            PDI_MAP_ULOCK (map);\n",
    "            return -EEXIST;\n",
    "        }\n",
    "        hval = calloc (1, sizeof (* hval));\n",
    "        memcpy (&hval->val, kval, sizeof (*kval));\n",
    "        hval->r = rule;\n",
    "        HASH_ADD (hh, rule->hash, val, sizeof (struct pdi_key), hval);\n",
    "        PDI_MAP_ULOCK (map);\n",
    "        return 0;\n",
    "    }\n",
    "    PDI_MAP_ULOCK (map);\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "pdi_rule2str",
    "PDI_MAP_ULOCK",
    "HASH_ADD",
    "HASH_FIND",
    "pdi_add_map_em",
    "PDI_MAP_LOCK",
    "printf",
    "calloc",
    "memcpy",
    "pdi_rule_get__"
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
int
pdi_add_val(struct pdi_map *map, struct pdi_key *kval)
{
  struct pdi_val *hval = NULL;
  struct pdi_rule *rule = NULL;

  PDI_MAP_LOCK(map);

  rule = pdi_rule_get__(map, kval);
  if (rule != NULL) {
    printf("Found match --\n");
    pdi_rule2str(rule);

    HASH_FIND(hh, rule->hash, kval, sizeof(struct pdi_key), hval);
    if (hval) {
      printf("hval exists\n");
      if (map->pdi_add_map_em) {
        map->pdi_add_map_em(kval, &rule->data, sizeof(rule->data));
      }
      PDI_MAP_ULOCK(map);
      return -EEXIST;
    }

    hval = calloc(1, sizeof(*hval));
    memcpy(&hval->val, kval, sizeof(*kval));
    hval->r = rule;
    HASH_ADD(hh, rule->hash, val, sizeof(struct pdi_key), hval);
    PDI_MAP_ULOCK(map);
    return 0;
  }

  PDI_MAP_ULOCK(map);

  return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 235,
  "endLine": 262,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_del_val",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map",
    " struct pdi_key *kval"
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
    "int pdi_del_val (struct pdi_map *map, struct pdi_key *kval)\n",
    "{\n",
    "    struct pdi_val *hval = NULL;\n",
    "    struct pdi_rule *rule = NULL;\n",
    "    PDI_MAP_LOCK (map);\n",
    "    rule = pdi_rule_get__ (map, kval);\n",
    "    if (rule != NULL) {\n",
    "        printf (\"Found match --\\n\");\n",
    "        pdi_rule2str (rule);\n",
    "        HASH_FIND (hh, rule->hash, kval, sizeof (struct pdi_key), hval);\n",
    "        if (hval == NULL) {\n",
    "            printf (\"hval does not exist\\n\");\n",
    "            PDI_MAP_ULOCK (map);\n",
    "            return -EINVAL;\n",
    "        }\n",
    "        HASH_DEL (rule->hash, hval);\n",
    "        PDI_MAP_ULOCK (map);\n",
    "        return 0;\n",
    "    }\n",
    "    PDI_MAP_ULOCK (map);\n",
    "    return -1;\n",
    "}\n"
  ],
  "called_function_list": [
    "pdi_rule2str",
    "PDI_MAP_ULOCK",
    "HASH_FIND",
    "PDI_MAP_LOCK",
    "printf",
    "HASH_DEL",
    "pdi_rule_get__"
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
int
pdi_del_val(struct pdi_map *map, struct pdi_key *kval)
{
  struct pdi_val *hval = NULL;
  struct pdi_rule *rule = NULL;

  PDI_MAP_LOCK(map);

  rule = pdi_rule_get__(map, kval);
  if (rule != NULL) {
    printf("Found match --\n");
    pdi_rule2str(rule);

    HASH_FIND(hh, rule->hash, kval, sizeof(struct pdi_key), hval);
    if (hval == NULL) {
      printf("hval does not exist\n");
      PDI_MAP_ULOCK(map);
      return -EINVAL;
    }

    HASH_DEL(rule->hash, hval);
    PDI_MAP_ULOCK(map);
    return 0;
  }

  PDI_MAP_ULOCK(map);
  return -1;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 264,
  "endLine": 269,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_val_expired",
  "developer_inline_comments": [
    {
      "start_line": 267,
      "end_line": 267,
      "text": " TODO "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_val *v"
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
    "static int pdi_val_expired (struct pdi_val *v)\n",
    "{\n",
    "    return 0;\n",
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
static int
pdi_val_expired(struct pdi_val *v)
{
  // TODO 
  return 0;
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 271,
  "endLine": 297,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_map_run",
  "developer_inline_comments": [],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "struct pdi_map *map"
  ],
  "output": "void",
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
    "void pdi_map_run (struct pdi_map *map)\n",
    "{\n",
    "    struct pdi_rule *node;\n",
    "    struct pdi_val *val, *tmp;\n",
    "    char fmtstr [512] = {0};\n",
    "    PDI_MAP_LOCK (map);\n",
    "    node = map->head;\n",
    "    while (node) {\n",
    "        HASH_ITER (hh, node -> hash, val, tmp) {\n",
    "            if (pdi_val_expired (val)) {\n",
    "                HASH_DEL (node->hash, val);\n",
    "                if (map->pdi_del_map_em) {\n",
    "                    map->pdi_del_map_em (&val->val);\n",
    "                }\n",
    "                pdi_key2str (&val->val, fmtstr);\n",
    "                printf (\"Expired entry %s\\n\", fmtstr);\n",
    "                free (val);\n",
    "            }\n",
    "        }\n",
    "\n",
    "        node = node->next;\n",
    "    }\n",
    "    PDI_MAP_ULOCK (map);\n",
    "}\n"
  ],
  "called_function_list": [
    "pdi_val_expired",
    "free",
    "PDI_MAP_ULOCK",
    "PDI_MAP_LOCK",
    "pdi_key2str",
    "HASH_ITER",
    "printf",
    "HASH_DEL",
    "pdi_del_map_em"
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
void
pdi_map_run(struct pdi_map *map)
{
  struct pdi_rule *node;
  struct pdi_val *val, *tmp;
  char fmtstr[512] = { 0 };

  PDI_MAP_LOCK(map);

  node = map->head;

  while (node) {
    HASH_ITER(hh, node->hash, val, tmp) {
      if (pdi_val_expired(val)) {
        HASH_DEL(node->hash, val);
        if (map->pdi_del_map_em) {
          map->pdi_del_map_em(&val->val);
        }
        pdi_key2str(&val->val, fmtstr);
        printf("Expired entry %s\n", fmtstr);
        free(val);
      }
    }
    node = node->next;
  }
  PDI_MAP_ULOCK(map);
}

/* 
 OPENED COMMENT BEGIN 
{
  "capabilities": [],
  "helperCallParams": {},
  "startLine": 299,
  "endLine": 396,
  "File": "/home/sayandes/ebpf-projects-annotations/projects/loxilb-ebpf/original_source/common/common_pdi.c",
  "funcName": "pdi_unit_test",
  "developer_inline_comments": [
    {
      "start_line": 349,
      "end_line": 349,
      "text": " Free "
    }
  ],
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "void"
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
    "int pdi_unit_test (void)\n",
    "{\n",
    "    struct pdi_map *map;\n",
    "    int r = 0;\n",
    "    map = pdi_map_alloc (\"ufw4\", NULL, NULL);\n",
    "    struct pdi_rule *new = calloc (1, sizeof (struct pdi_rule));\n",
    "    if (new) {\n",
    "        PDI_MATCH_INIT (&new->key.dest, 0x0a0a0a0a, 0xffffff00);\n",
    "        PDI_RMATCH_INIT (&new->key.dport, 1, 100, 200);\n",
    "        r = pdi_rule_insert (map, new, NULL);\n",
    "        if (r != 0) {\n",
    "            printf (\"Insert fail1\\n\");\n",
    "            exit (0);\n",
    "        }\n",
    "    }\n",
    "    struct pdi_rule *new1 = calloc (1, sizeof (struct pdi_rule));\n",
    "    if (new1) {\n",
    "        memcpy (new1, new, sizeof (*new));\n",
    "        new1->data.pref = 100;\n",
    "        r = pdi_rule_insert (map, new1, NULL);\n",
    "        if (r != 0) {\n",
    "            printf (\"Insert fail2\\n\");\n",
    "            exit (0);\n",
    "        }\n",
    "    }\n",
    "    struct pdi_rule *new2 = calloc (1, sizeof (struct pdi_rule));\n",
    "    if (new2) {\n",
    "        PDI_MATCH_INIT (&new2->key.dest, 0x0a0a0a0a, 0xffffff00);\n",
    "        PDI_RMATCH_INIT (&new2->key.dport, 0, 100, 0xffff);\n",
    "        r = pdi_rule_insert (map, new2, NULL);\n",
    "        if (r != 0) {\n",
    "            printf (\"Insert fail3\\n\");\n",
    "            exit (0);\n",
    "        }\n",
    "        r = pdi_rule_insert (map, new2, NULL);\n",
    "        if (r == 0) {\n",
    "            printf (\"Insert fail4\\n\");\n",
    "            exit (0);\n",
    "        }\n",
    "    }\n",
    "    if (pdi_rule_delete (map, &new1->key, 100, NULL) != 0) {\n",
    "        printf (\"Delete fail4\\n\");\n",
    "        exit (0);\n",
    "    }\n",
    "    struct pdi_rule *new4 = calloc (1, sizeof (struct pdi_rule));\n",
    "    if (new4) {\n",
    "        PDI_MATCH_INIT (&new4->key.dest, 0x0a0a0a0a, 0xffffff00);\n",
    "        PDI_MATCH_INIT (&new4->key.source, 0x0b0b0b00, 0xffffff00);\n",
    "        PDI_RMATCH_INIT (&new4->key.dport, 1, 500, 600);\n",
    "        PDI_RMATCH_INIT (&new4->key.sport, 1, 500, 600);\n",
    "        r = pdi_rule_insert (map, new4, NULL);\n",
    "        if (r != 0) {\n",
    "            printf (\"Insert fail1\\n\");\n",
    "            exit (0);\n",
    "        }\n",
    "    }\n",
    "    pdi_rules2str (map);\n",
    "    if (1) {\n",
    "        struct pdi_key key = {0}\n",
    "        ;\n",
    "        PDI_VAL_INIT (&key.source, 0x0b0b0b0b);\n",
    "        PDI_VAL_INIT (&key.dest, 0x0a0a0a0a);\n",
    "        PDI_RVAL_INIT (&key.dport, 501);\n",
    "        PDI_RVAL_INIT (&key.sport, 501);\n",
    "        if (pdi_add_val (map, &key) != 0) {\n",
    "            printf (\"Failed to add pdi val1\\n\");\n",
    "        }\n",
    "    }\n",
    "    if (1) {\n",
    "        struct pdi_key key = {0}\n",
    "        ;\n",
    "        PDI_VAL_INIT (&key.source, 0x0b0b0b0b);\n",
    "        PDI_VAL_INIT (&key.dest, 0x0a0a0a0a);\n",
    "        PDI_RVAL_INIT (&key.dport, 502);\n",
    "        PDI_RVAL_INIT (&key.sport, 502);\n",
    "        if (pdi_add_val (map, &key) != 0) {\n",
    "            printf (\"Failed to add pdi val2\\n\");\n",
    "        }\n",
    "    }\n",
    "    if (pdi_rule_delete (map, &new4->key, 0, NULL) != 0) {\n",
    "        printf (\"Failed delete--%d\\n\", __LINE__);\n",
    "    }\n",
    "    return 0;\n",
    "}\n"
  ],
  "called_function_list": [
    "pdi_map_alloc",
    "PDI_VAL_INIT",
    "PDI_RMATCH_INIT",
    "pdi_rule_insert",
    "pdi_rule_delete",
    "PDI_RVAL_INIT",
    "pdi_add_val",
    "PDI_MATCH_INIT",
    "exit",
    "printf",
    "pdi_rules2str",
    "calloc",
    "memcpy"
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
int
pdi_unit_test(void)
{
  struct pdi_map *map;
  int r = 0;

  map = pdi_map_alloc("ufw4", NULL, NULL);

  struct pdi_rule *new = calloc(1, sizeof(struct pdi_rule));
  if (new) {
    PDI_MATCH_INIT(&new->key.dest, 0x0a0a0a0a, 0xffffff00);
    PDI_RMATCH_INIT(&new->key.dport, 1, 100, 200); 
    r = pdi_rule_insert(map, new, NULL);
    if (r != 0) {
      printf("Insert fail1\n");
      exit(0);
    }
  }


  struct pdi_rule *new1 = calloc(1, sizeof(struct pdi_rule));
  if (new1) {
    memcpy(new1, new, sizeof(*new));
    new1->data.pref = 100;
    r = pdi_rule_insert(map, new1, NULL);
    if (r != 0) {
     printf("Insert fail2\n");
     exit(0);
    }
  }


  struct pdi_rule *new2 = calloc(1, sizeof(struct pdi_rule));
  if (new2) {
    PDI_MATCH_INIT(&new2->key.dest, 0x0a0a0a0a, 0xffffff00);
    PDI_RMATCH_INIT(&new2->key.dport, 0, 100, 0xffff); 
    r = pdi_rule_insert(map, new2, NULL);
    if (r != 0) {
      printf("Insert fail3\n");
      exit(0);
    }

    r = pdi_rule_insert(map, new2, NULL);
    if (r == 0) {
      printf("Insert fail4\n");
      exit(0);
    }
  }

  if (pdi_rule_delete(map, &new1->key, 100, NULL) != 0) {
    // Free //
    printf("Delete fail4\n");
    exit(0);
  }

  struct pdi_rule *new4 = calloc(1, sizeof(struct pdi_rule));
  if (new4) {
    PDI_MATCH_INIT(&new4->key.dest, 0x0a0a0a0a, 0xffffff00);
    PDI_MATCH_INIT(&new4->key.source, 0x0b0b0b00, 0xffffff00);
    PDI_RMATCH_INIT(&new4->key.dport, 1, 500, 600); 
    PDI_RMATCH_INIT(&new4->key.sport, 1, 500, 600); 
    r = pdi_rule_insert(map, new4, NULL);
    if (r != 0) {
      printf("Insert fail1\n");
      exit(0);
    }
  }

  pdi_rules2str(map);

  if (1) {
    struct pdi_key key =  { 0 } ;
    PDI_VAL_INIT(&key.source, 0x0b0b0b0b);
    PDI_VAL_INIT(&key.dest, 0x0a0a0a0a);
    PDI_RVAL_INIT(&key.dport, 501);
    PDI_RVAL_INIT(&key.sport, 501);
    if (pdi_add_val(map, &key) != 0) {
      printf("Failed to add pdi val1\n");
    }
  }

  if (1) {
    struct pdi_key key =  { 0 } ;
    PDI_VAL_INIT(&key.source, 0x0b0b0b0b);
    PDI_VAL_INIT(&key.dest, 0x0a0a0a0a);
    PDI_RVAL_INIT(&key.dport, 502);
    PDI_RVAL_INIT(&key.sport, 502);
    if (pdi_add_val(map, &key) != 0) {
      printf("Failed to add pdi val2\n");
    }
  }

  if (pdi_rule_delete(map, &new4->key, 0, NULL) != 0) {
     printf("Failed delete--%d\n", __LINE__);
  }

  return 0;
}
