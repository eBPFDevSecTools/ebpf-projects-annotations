/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/common_defines.h"
#include <netinet/ether.h>

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 16,
  "endLine": 24,
  "File": "/root/examples/xdp-tutorials/trace_read.c",
  "funcName": "print_ether_addr",
  "updateMaps": [],
  "readMaps": [],
  "input": [
    "const char *type",
    " char *str"
  ],
  "output": "staticvoid",
  "helper": [],
  "compatibleHookpoints": [
    "All_hookpoints"
  ],
  "humanFuncDescription": [
    {
      "description": "Function print_ether_addr() prints the ehternet protocol type
      		      and the ethernet address. It is of type static and takes as
                      input a constant character pointer 'type' and a character
                      pointer 'str'. It defines a variable 'addr' of type __u64,
                      i.e. unsigned 64 bit integer. First argument of scanf is
                      passed to 'addr' and if it equals 1, then ether_ntoa() 
                      function is called with a pointer to 'addr' typecast as a 
                      structure pointer of type 'ether_addr'. ether_ntoa() function
                      converts the 48-bit Ethernet host address addr from the 
                      standard hex-digits-and-colons notation into binary data in
                      network byte order and returns a pointer to it in a statically
                      allocated buffer, which subsequent calls will overwrite. Function
                      ether_aton() returns NULL if the address is invalid. This 
                      basically prints out the MAC address in human-readable format ",
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
static void print_ether_addr(const char *type, char *str)
{
	__u64 addr;

	if (1 != sscanf(str, "%llu", &addr))
		return;

	printf("%s: %s ", type, ether_ntoa((struct ether_addr *) &addr));
}

/* 
 OPENED COMMENT BEGIN 
{
  "capability": [],
  "helperCallParams": {},
  "startLine": 26,
  "endLine": 71,
  "File": "/root/examples/xdp-tutorials/trace_read.c",
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
      "description": "trace_read_main() function is used to print MAC addresses of source and
      		      destination and protocol. It takes as argument integer 'argc' and pointer 
                      to pointer array 'argv' of type character. It initializes variables
                      FILE pointer 'stream', 'line' of type character pointer, 'len' of
                      type size_t as 0 and 'nread'  of type ssize_t. Function opens
                      TRACEFS_PIPE for reading while displaying error message in case of 
                      unsuccessful opening. It reads each line using the function 'strtok_r()'
                      and splits on the basis of delimeter ' '. Function then prints the
                      source MAC address, destination MAC address and protocol details for
                      each line. Finally it closes the stream when all lines have been read.
                      Function returns 'EXIT_OK' on completion.",
      "author": "Neha Chowdhary",
      "authorEmail": "nehaniket79@gmail.com",
      "date": "17.03.2023"
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
	FILE *stream;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;

	stream = fopen(TRACEFS_PIPE, "r");
	if (stream == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}


	while ((nread = getline(&line, &len, stream)) != -1) {
		char *tok, *saveptr;
		unsigned int proto;

		tok = strtok_r(line, " ", &saveptr);

		while (tok) {
			if (!strncmp(tok, "src:", 4)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("src", tok);
			}

			if (!strncmp(tok, "dst:", 4)) {
				tok = strtok_r(NULL, " ", &saveptr);
				print_ether_addr("dst", tok);
			}

			if (!strncmp(tok, "proto:", 5)) {
				tok = strtok_r(NULL, " ", &saveptr);
				if (1 == sscanf(tok, "%u", &proto))
					printf("proto: %u", proto);
			}
			tok = strtok_r(NULL, " ", &saveptr);
		}

		printf("\n");
	}

	free(line);
	fclose(stream);
	return EXIT_OK;
}
