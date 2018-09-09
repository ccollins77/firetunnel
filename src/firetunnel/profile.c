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

uint32_t profile_netaddr = 0;
uint32_t profile_netmask = 0;
uint32_t profile_defaultgw = 0;
uint32_t profile_mtu = 0;
char *profile_child_seccomp = NULL;
char *profile_parent_seccomp = NULL;

// remove multiple spaces and return allocated memory
static char *line_remove_spaces(const char *buf) {
	assert(buf);
	if (strlen(buf) == 0)
		return NULL;

	// allocate memory for the new string
	char *rv = malloc(strlen(buf) + 1);
	if (rv == NULL)
		errExit("malloc");

	// remove space at start of line
	const char *ptr1 = buf;
	while (*ptr1 == ' ' || *ptr1 == '\t')
		ptr1++;

	// copy data and remove additional spaces
	char *ptr2 = rv;
	int state = 0;
	while (*ptr1 != '\0') {
		if (*ptr1 == '\n' || *ptr1 == '\r')
			break;

		if (state == 0) {
			if (*ptr1 != ' ' && *ptr1 != '\t')
				*ptr2++ = *ptr1++;
			else {
				*ptr2++ = ' ';
				ptr1++;
				state = 1;
			}
		}
		else {				  // state == 1
			while (*ptr1 == ' ' || *ptr1 == '\t')
				ptr1++;
			state = 0;
		}
	}

	// strip last blank character if any
	if (ptr2 > rv && *(ptr2 - 1) == ' ')
		--ptr2;
	*ptr2 = '\0';

	return rv;
}

static void profile_check_line(char *ptr, int lineno, const char *fname) {
	if (strcmp(ptr, "daemonize") == 0) {
		arg_daemonize = 1;
		return;
	}

	if (strncmp(ptr, "dns ", 4) == 0) {
		dns_test(ptr + 4);
		return;
	}

	if (strncmp(ptr, "bridge ", 7) == 0) {
		strncpy(tunnel.bridge_device_name, ptr + 7, IFNAMSIZ);
		return;
	}

	if (strncmp(ptr, "defaultgw ", 10) == 0) {
		if (atoip(ptr + 10, &profile_defaultgw)) {
			fprintf(stderr, "Error: invalid default gateway in %s line %d\n", fname, lineno);
			exit(1);
		}
		return;
	}

	if (strncmp(ptr, "mtu ", 4) == 0) {
		profile_mtu = atoi(ptr + 4);
		return;
	}

	if (strncmp(ptr, "netaddr ", 8) == 0) {
		if (atoip(ptr + 8, &profile_netaddr)) {
			fprintf(stderr, "Error: invalid network address in %s line %d\n", fname, lineno);
			exit(1);
		}
		return;
	}

	if (strncmp(ptr, "netmask ", 8) == 0) {
		if (atoip(ptr + 8, &profile_netmask)) {
			fprintf(stderr, "Error: invalid network mask in %s line %d\n", fname, lineno);
			exit(1);
		}
		return;
	}

	if (strcmp(ptr, "nonat") == 0) {
		arg_nonat = 1;
		return;
	}

	if (strcmp(ptr, "noscrambling") == 0) {
		arg_noscrambling = 1;
		return;
	}

	if (strcmp(ptr, "noseccomp") == 0) {
		arg_noseccomp = 1;
		return;
	}

	if (strncmp(ptr, "seccomp.child ", 14) == 0) {
		profile_child_seccomp = strdup(ptr + 14);
		if (!profile_child_seccomp)
			errExit("strdup");
		return;
	}

	if (strncmp(ptr, "seccomp.parent ", 15) == 0) {
		profile_parent_seccomp = strdup(ptr + 15);
		if (!profile_parent_seccomp)
			errExit("strdup");
		return;
	}

	if (strcmp(ptr, "server") == 0) {
		arg_server = 1;
		return;
	}

	// forward compatiblitiy
	fprintf(stderr, "Warning: \"%s\" profile entry not supported\n", ptr);
}

void load_profile(const char *fname) {
	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Warning: cannot access profile file %s, using default configuration\n", fname);
		return;
	}

	// read the file line by line and process it
	char buf[MAXBUF];
	int lineno = 0;
	while (fgets(buf, MAXBUF, fp)) {
		++lineno;
		// remove empty space - ptr in allocated memory
		char *ptr = line_remove_spaces(buf);
		if (ptr == NULL)
			continue;

		// comments
		if (*ptr == '#' || *ptr == '\0') {
			free(ptr);
			continue;
		}

		// verify syntax, exit in case of error
		profile_check_line(ptr, lineno, fname);
		free(ptr);
	}

	fclose(fp);
}

void save_profile(const char *fname, TOverlay *o) {
	assert(fname);
	assert(o);
	
	FILE *fp = fopen(fname, "w");
	if (!fp) {
		fprintf(stderr, "Error: cannot open runtime file\n");
		exit(1);
	}
	fprintf(fp, "net %s\n", tunnel.bridge_device_name);
	fprintf(fp, "ignore net\n");

	// copy configuration
	fprintf(fp, "netmask %d.%d.%d.%d\n", PRINT_IP(o->netmask));
	fprintf(fp, "defaultgw %d.%d.%d.%d\n", PRINT_IP(o->defaultgw));
	fprintf(fp, "mtu %d\n", o->mtu);
	fprintf(fp, "dns %d.%d.%d.%d\n", PRINT_IP(o->dns1));
	fprintf(fp, "dns %d.%d.%d.%d\n", PRINT_IP(o->dns2));
	fprintf(fp, "dns %d.%d.%d.%d\n", PRINT_IP(o->dns3));

	// tell firejail to ignore some of the network commands
	fprintf(fp, "ignore iprange\n");
	fprintf(fp, "ignore netmask\n");
	// fprintf(fp, "ignore ip\n");  -  allow ip command
	fprintf(fp, "ignore defaultgw\n");
	fprintf(fp, "ignore mtu\n");
	fprintf(fp, "ignore dns\n");
	fclose(fp);
}
