/*
 * Copyright (C) 2018 Firetunnel Authors
 *
 * This file is part of firetunnel project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "firetunnel.h"
#define MAXBUF 1024

typedef struct dns_t {
	char *server_ip;
	int response_time;
} DNS;
#define MAXDNS 16
static DNS storage[MAXDNS];
static int dnscnt = 0;
static int dig_not_found = 0;

void dns_test(const char *server_ip) {
	if (!arg_server || dig_not_found)
		return;

	assert(server_ip);
	if (dnscnt >= MAXDNS) {
		fprintf(stderr, "Error: maximum %d DNS servers allowed in your configuration file\n", MAXDNS);
		exit(1);
	}

	int rv = system("which dig > /dev/null");
	if (rv) {
		fprintf(stderr, "Warning: dig utility not found, Please install dnsutils package.\n");
		printf("Using default values for DNS.\n");
		dig_not_found = 1;
		return;
	}


	// dig the server
	char *cmd;
	if (asprintf(&cmd, "dig @%s +tries=1 +time=1 debian.org | grep \"Query time\" | cut -d : -f 2- | cut -d \" \" -f 2", server_ip) == -1)
		errExit("asprintf");

	char buf[MAXBUF];
	FILE *fp = popen(cmd, "r");
	if (fgets(buf, MAXBUF, fp) <= 0)
		goto doexit;

	// store the data
	storage[dnscnt].server_ip = strdup(server_ip);
	if (!storage[dnscnt].server_ip )
		errExit("strdup");
	storage[dnscnt].response_time = atoi(buf);
	printf("DNS server %s response time %d ms\n", storage[dnscnt].server_ip, storage[dnscnt].response_time);
	dnscnt++;

doexit:
	pclose(fp);
	free(cmd);
}

static char *get_fastest(void) {
	int i;
	int small = 5000;
	int id = -1;
	for (i = 0; i < dnscnt; i++) {
		if (storage[i].response_time < small) {
			small = storage[i].response_time;
			id = i;
		}
	}

	assert(id < dnscnt);
	if (id == -1)
		return NULL;
	storage[id].response_time = 5000;
	return storage[id].server_ip;
}

// using 1.1.1.1, 9.9.9.9 and 8.8.8.8 in case we don't have enough servers to populate the tunnel
void dns_set_tunnel(void) {
	if (!arg_server)
		return;

	char *name = get_fastest();
	if (name)
		atoip(name, &tunnel.overlay.dns1);
	else
		atoip("1.1.1.1", &tunnel.overlay.dns1);

	name = get_fastest();
	if (name)
		atoip(name, &tunnel.overlay.dns2);
	else
		atoip("9.9.9.9", &tunnel.overlay.dns2);

	name = get_fastest();
	if (name)
		atoip(name, &tunnel.overlay.dns3);
	else
		atoip("8.8.8.8", &tunnel.overlay.dns3);

	logmsg("Tunnel DNS %d.%d.%d.%d, %d.%d.%d.%d, %d.%d.%d.%d\n",
		PRINT_IP(tunnel.overlay.dns1), PRINT_IP(tunnel.overlay.dns2), PRINT_IP(tunnel.overlay.dns3));
}
