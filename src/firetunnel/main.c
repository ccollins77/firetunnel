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
#include <sys/wait.h>
#include <errno.h>
#include <linux/capability.h>
#include <sys/stat.h>

int arg_server = 0;
int arg_port = DEFAULT_PORT_NUMBER;
uint32_t arg_remote_addr = 0;
int arg_noscrambling = 0;
int arg_noseccomp = 0;
int arg_nonat = 0;
int arg_daemonize = 0;
int arg_debug = 0;
int arg_debug_compress = 0;

Tunnel tunnel;
static pid_t child_pid = 0;

static void sighdlr(int sig) {
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		if (child_pid)
			kill(child_pid, SIGKILL);
		exit(1);
		break;
	case SIGCHLD:
		while (1) {
			int wstatus;
			pid_t	pid;
			pid = wait(&wstatus);
			if (pid == 0)
				return;
			else if (pid == -1)
				return;
			else {
				fprintf (stderr, "Error: child exited with status %d; shutting down firetunnel...\n", wstatus);
				exit(1);
			}
		}
		break;
	}
}

static void parse_args(int argc, char **argv) {
	char *profile_name = DEFAULT_PROFILE;
	int i;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-?") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
			usage();
			exit(0);
		}
		else if (strcmp(argv[i], "--version") == 0) {
			printf("firetunnel version %s\n", VERSION);
			exit(0);
		}

		if (strncmp(argv[i], "--", 2) != 0)
			break;
		else if (strcmp(argv[i], "--debug") == 0)
			arg_debug = 1;
		else if (strcmp(argv[i], "--debug-compress") == 0)
			arg_debug_compress = 1;
		else if (strcmp(argv[i], "--server") == 0)
			arg_server = 1;
		else if (strncmp(argv[i], "--port=",  7) == 0) {
			arg_port = atoi(argv[i] + 7);
			if (arg_port < 1 || arg_port > 0xffff) {
				fprintf(stderr, "Error: invalid UDP port number %s\n", argv[i] + 7);
				exit(1);
			}
		}
		else if (strncmp(argv[i], "--netaddr=", 10) == 0) {
			if (atoip(argv[i] + 10, &tunnel.overlay.netaddr)) {
				fprintf(stderr, "Error: invalid IP address %s\n", argv[i] + 10);
				exit(1);
			}
		}
		else if (strncmp(argv[i], "--netmask=", 10) == 0) {
			if (atoip(argv[i] + 10, &tunnel.overlay.netmask)) {
				fprintf(stderr, "Error: invalid network mask %s\n", argv[i] + 10);
				exit(1);
			}
		}
		else if (strncmp(argv[i], "--mtu=",  6) == 0) {
			int mtu = atoi(argv[i] + 6);
			if (mtu < 576 || mtu > 1500) {
				fprintf(stderr, "Error: invalid mtu value\n");
				exit(1);
			}
			tunnel.overlay.mtu = mtu;
		}
		else if (strncmp(argv[i], "--defaultgw=", 12) == 0) {
			if (atoip(argv[i] + 12, &tunnel.overlay.defaultgw)) {
				fprintf(stderr, "Error: invalid default gateway address %s\n", argv[i] + 12);
				exit(1);
			}
		}
		else if (strcmp(argv[i], "--noscrambling") == 0)
			arg_noscrambling = 1;
		else if (strcmp(argv[i], "--nonat") == 0)
			arg_nonat = 1;
		else if (strcmp(argv[i], "--noseccomp") == 0)
			arg_noseccomp = 1;
		else if (strcmp(argv[i], "--daemonize") == 0)
			arg_daemonize = 1;
		else if (strncmp(argv[i], "--bridge=", 9) == 0)
			strncpy(tunnel.bridge_device_name, argv[i] + 9, IFNAMSIZ);
		else if (strncmp(argv[i], "--dns=", 6) == 0)
			dns_test(argv[i] + 6);
		else if (strncmp(argv[i], "--profile=", 10) == 0)
			profile_name = argv[i] + 10;
		else {
			fprintf(stderr, "Error: invalid argument %s\n", argv[i]);
			usage();
			exit(1);
		}
	}

	load_profile(profile_name);
	dns_set_tunnel();

	// when running as a client, the first argument to follow is the server IP address
	if (!arg_server && i  < argc) {
		if (atoip(argv[i], &arg_remote_addr)) {
			fprintf(stderr, "Error: invalid IP address %s\n", argv[i] + 14);
			exit(1);
		}
		i++;
	}

	// use network overlay defaults if not already configured
	if (arg_server) {
		if (tunnel.overlay.netaddr == 0)
			tunnel.overlay.netaddr = profile_netaddr;
		if (tunnel.overlay.netmask == 0)
			tunnel.overlay.netmask = profile_netmask;
		if (tunnel.overlay.defaultgw == 0)
			tunnel.overlay.defaultgw = profile_defaultgw;
	}

	logmsg("Header compression %d bytes\n", compress_l3_size());

	if (tunnel.overlay.mtu == 0)
		tunnel.overlay.mtu = profile_mtu;
	if (tunnel.overlay.mtu == 0) {  // still 0?
		// calculate the MTU based on runtime information
		// 1500 - mac - ip - udp - firetunnel - hmac - padding
		tunnel.overlay.mtu = 1500 - 14 - 20 - 8 - sizeof(PacketHeader) - KEY_LEN ;
		if (!arg_noscrambling)
			tunnel.overlay.mtu -= scramble_blocklen() - 1;
	}
	logmsg("Tunnel mtu %d\n", tunnel.overlay.mtu);

	// check ip addresses
	if ((tunnel.overlay.netaddr & tunnel.overlay.netmask) != (tunnel.overlay.defaultgw & tunnel.overlay.netmask)) {
		fprintf(stderr, "Error: invalid overlay network configuration\n");
		exit(1);
	}

	// generate bridge device name
	if (*tunnel.bridge_device_name == '\0') {
		char *type = (arg_server) ? "s" : "c";
		sprintf(tunnel.bridge_device_name, "ft%s", type);
	}
}



int main(int argc, char **argv) {
	// init
	memset(&tunnel, 0, sizeof(tunnel));
	compress_l2_init();
	compress_l3_init();

	// parse command line arguments
	parse_args(argc, argv);

	// let's make sure we are running as root
	if (getuid() != 0) {
		fprintf(stderr, "Error: you need to be root to start firetunnel\n");
		exit(1);
	}

	// create /run/firetunnel directory
	struct stat s;
	if (stat(RUN_DIR, &s) == -1) {
		if (mkdir(RUN_DIR, 0755) == -1) {
			// try again
			sleep(1);
			if (stat(RUN_DIR, &s) == -1) {
				if (mkdir(RUN_DIR, 0755) == -1) {
					fprintf(stderr, "Error: cannot create %s\n", RUN_DIR);
					exit(1);
				}
			}
		}
	}

	// initialize keys
	init_keys((uint16_t) arg_port);

	// open tap device
	tunnel.tapfd = net_tap_open(tunnel.tap_device_name);
	net_set_mtu(tunnel.tap_device_name, tunnel.overlay.mtu);
	logmsg("Device %s created\n", tunnel.tap_device_name);

	// create bridge and connect tap device to the bridge
	net_add_bridge(tunnel.bridge_device_name);
	net_set_mtu(tunnel.bridge_device_name, tunnel.overlay.mtu);
	net_if_up(tunnel.bridge_device_name);
	net_bridge_add_interface(tunnel.bridge_device_name, tunnel.tap_device_name);
	logmsg("Bridge %s created\n", tunnel.bridge_device_name);

	if (arg_server) {
		// set the bridge as our default gateway for NAT purposes
		net_if_ip(tunnel.bridge_device_name, tunnel.overlay.defaultgw,
			  tunnel.overlay.netmask, tunnel.overlay.mtu);
		net_if_up(tunnel.bridge_device_name);

		// NAT
		if (!arg_nonat) {
			//system("echo \"1\" > /proc/sys/net/ipv4/ip_forward");
			net_ipforward();
			char *ifname = net_get_nat_if();
			if (!ifname) {
				fprintf(stderr, "Error: cannot find the main Ethernet interface for this system\n");
				exit(1);
			}
			net_set_netfilter(ifname);
			logmsg("NAT configured on interface %s\n", ifname);
			free(ifname);
		}
	}

	// open udp server socket
	if (arg_server)
		tunnel.udpfd = net_udp_server(arg_port);
	else
		tunnel.udpfd = net_udp_client();


	// set firejail configuration for the server
	if (arg_server) {
		char *fname;
		if (asprintf(&fname, "%s/%s", RUN_DIR, tunnel.bridge_device_name) == -1)
			errExit("asprintf");

		// save configuration
		save_profile(fname, &tunnel.overlay);
		logmsg("%s updated\n", fname);
		free(fname);
	}

	// set remote for the client
	tunnel.state = S_DISCONNECTED;
	if (!arg_server) {
		tunnel.remote_sock_addr.sin_family    = AF_INET;
		if (arg_remote_addr)
			tunnel.remote_sock_addr.sin_addr.s_addr = htonl(arg_remote_addr);
		else
			tunnel.remote_sock_addr.sin_addr.s_addr = INADDR_ANY;
		tunnel.remote_sock_addr.sin_port = htons(arg_port);
	}

	int fd[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fd) == -1)
		errExit("setsockpair");

	if (arg_daemonize)
		daemonize();

	signal (SIGCHLD, sighdlr);
	signal(SIGTERM, sighdlr);
	signal(SIGINT, sighdlr);

	child_pid = fork();
	if (child_pid == -1)
		errExit("fork");
	if (child_pid == 0) { // child
		close(fd[0]);

		// security
		switch_user("nobody");
		if (arg_noseccomp == 0)
			seccomp("child", profile_child_seccomp);
		child(fd[1]);
		assert(0); // it should  never get here
	}
	else { // parent
		close(fd[1]);

		// security
		if (arg_noseccomp == 0)
			seccomp("parent", profile_parent_seccomp);

		// process messages sent by the child
		while (1) {
			errno = 0;
			char buf[1024];
			unsigned n = read(fd[0], buf, sizeof(buf));
			if (n == 0) {
				if (errno == ECHILD)
					break;
			}

			if (strncmp(buf, "config ", 7) == 0 && n >= (7 + sizeof(TOverlay))) {
				// prepare firejail configuration
				char *fname;
				if (asprintf(&fname, "%s/%s", RUN_DIR, tunnel.bridge_device_name) == -1)
					errExit("asprintf");
				TOverlay o;
				memcpy(&o, buf + 7, sizeof(TOverlay));
				memcpy(&tunnel.overlay, &o, sizeof(TOverlay));

				// save configuration
				save_profile(fname, &o);
				logmsg("%s updated\n", fname);
				free(fname);

				// configure mtu
				net_set_mtu(tunnel.bridge_device_name, tunnel.overlay.mtu);
				net_set_mtu(tunnel.tap_device_name, tunnel.overlay.mtu);
			}

		}

	}

	return 0;
}

