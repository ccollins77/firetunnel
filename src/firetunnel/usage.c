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

void usage(void) {
	printf("Usage:   firetunnel --server [options]\n");
	printf("         firetunnel [options] server-ip-address\n");
	printf("where\n");
	printf("    server-ip-address - the IP address of the server\n");
	printf("\n");
	printf("Options:\n");
	printf("   --bridge=device - use this Linux bridge device\n");
	printf("   --daemonize - detach from the controlling terminal and run as a Unix\n");
	printf("\tdaemon\n");
	printf("   --debug, --debug-compress - print debug information\n");
	printf("   --defaultgw=address - tunnel default gateway address, default 10.10.20.1\n");
	printf("   --dns=address - add this DNS server to the list of servers\n");
	printf("   --help, ? - this help screen\n");
	printf("   --mtu=number - maximum transmission uint for interfaces inside the tunnel\n");
	printf("\tdefault 1434\n");
	printf("   --netaddr=address - tunnel network address, default 10.10.20.0\n");
	printf("   --netmask=mask - tunnel network mask, default 255.255.255.0\n");
	printf("   --nonat - network address translation disabled\n");
	printf("   --noscrambling - scrambling disabled, the packets are sent in clear\n");
	printf("   --noseccomp - disable seccomp\n");
	printf("   --port=number - UDP server port number, default 1119\n");
	printf("   --profile=filename - load the configuration from the profile file\n");
	printf("   --server - run as a server for the tunnel; without this option the program\n");
	printf("\truns as a client\n");
	printf("   --version - software version\n");
	printf("\n");
}


