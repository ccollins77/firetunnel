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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <linux/if_bridge.h>

//*****************************************************
// Interface
//*****************************************************
static inline void check_if_name(const char *ifname) {
	if (strlen(ifname) > IFNAMSIZ) {
		fprintf(stderr, "Error: invalid device name %s\n", ifname);
		exit(1);
	}
}

// bring interface up
void net_if_up(const char *ifname) {
	check_if_name(ifname);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		errExit("socket");

	// get the existing interface flags
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	// read the existing flags
	if (ioctl(sock, SIOCGIFFLAGS, &ifr ) < 0)
		errExit("ioctl");

	ifr.ifr_flags |= IFF_UP;

	// set the new flags
	if (ioctl( sock, SIOCSIFFLAGS, &ifr ) < 0)
		errExit("ioctl");

	// checking
	// read the existing flags
	if (ioctl(sock, SIOCGIFFLAGS, &ifr ) < 0)
		errExit("ioctl");

	// wait not more than 500ms for the interface to come up
	int cnt = 0;
	while (cnt < 50) {
		usleep(10000);			  // sleep 10ms

		// read the existing flags
		if (ioctl(sock, SIOCGIFFLAGS, &ifr ) < 0)
			errExit("ioctl");
		if (ifr.ifr_flags & IFF_RUNNING)
			break;
		cnt++;
	}

	close(sock);
}

// configure interface ipv4 address
void net_if_ip(const char *ifname, uint32_t ip, uint32_t mask, int mtu) {
	check_if_name(ifname);
	int sock = socket(AF_INET,SOCK_DGRAM,0);
	if (sock < 0)
		errExit("socket");

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = htonl(ip);
	if (ioctl( sock, SIOCSIFADDR, &ifr ) < 0)
		errExit("ioctl");

	if (ip != 0) {
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr =  htonl(mask);
		if (ioctl( sock, SIOCSIFNETMASK, &ifr ) < 0)
			errExit("ioctl");
	}

	// configure mtu
	if (mtu > 0) {
		ifr.ifr_mtu = mtu;
		if (ioctl( sock, SIOCSIFMTU, &ifr ) < 0)
			errExit("ioctl");
	}

	close(sock);
	usleep(10000);				  // sleep 10ms
	return;
}

void net_set_mtu(const char *ifname, int mtu) {
	check_if_name(ifname);
	int s;
	struct ifreq ifr;

	int current_mtu = net_get_mtu(ifname);
	if (current_mtu == mtu)
		return;


	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		errExit("socket");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_mtu = mtu;
	if (ioctl(s, SIOCSIFMTU, (caddr_t)&ifr) != 0) {
		fprintf(stderr, "Warning: cannot set mtu %d for interface %s\n", mtu, ifname);
	}
	else if (!arg_server)
		logmsg("MTU %d configured for interface %s\n", mtu, ifname);
	close(s);
}

int net_get_mtu(const char *ifname) {
	check_if_name(ifname);
	int mtu = 0;
	int s;
	struct ifreq ifr;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		errExit("socket");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(s, SIOCGIFMTU, (caddr_t)&ifr) == 0)
		mtu = ifr.ifr_mtu;
	close(s);


	return mtu;
}


//*****************************************************
// Bridge
//*****************************************************
int net_add_bridge(const char *ifname) {
	int fd;
	int rv;

	errno = 0;
	if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
		errExit("socket");

#ifdef SIOCBRADDBR
	rv = ioctl(fd, SIOCBRADDBR, ifname);
	if (rv < 0)
#endif
	{
		char br[IFNAMSIZ];
		strncpy(br, ifname, IFNAMSIZ);
		unsigned long arg[3] = {BRCTL_ADD_BRIDGE, (unsigned long) br, 0};
		rv = ioctl(fd, SIOCSIFBR, arg);
	}
	close(fd);

	if (rv < 0) {
		if (errno == EEXIST)
			return 0;
		else {
			fprintf(stderr, "Error: cannot create bridge device %s\n", ifname);
			exit(1);
		}
	}

	return 0;
}

// add a veth device to a bridge
void net_bridge_add_interface(const char *bridge, const char *dev) {
	check_if_name(bridge);
	check_if_name(dev);

	// somehow adding the interface to the bridge resets MTU on bridge device!!!
	// workaround: restore MTU on the bridge device
	int mtu1 = net_get_mtu(bridge);

	struct ifreq ifr;
	int err;
	int ifindex = if_nametoindex(dev);

	if (ifindex <= 0)
		errExit("if_nametoindex");

	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
              	errExit("socket");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, bridge, IFNAMSIZ);
#ifdef SIOCBRADDIF
	ifr.ifr_ifindex = ifindex;
	err = ioctl(sock, SIOCBRADDIF, &ifr);
	if (err < 0)
#endif
	{
		unsigned long args[4] = { BRCTL_ADD_IF, ifindex, 0, 0 };

		ifr.ifr_data = (char *) args;
		err = ioctl(sock, SIOCDEVPRIVATE, &ifr);
	}
	(void) err;
	close(sock);

	int mtu2 = net_get_mtu(bridge);
	if (mtu1 != mtu2)
		net_set_mtu(bridge, mtu1);
}

//*****************************************************
// TAP interface
//*****************************************************
int net_tap_open(char *devname) {
	// open the clone device
	int fd;
	if ( (fd = open("/dev/net/tun", O_RDWR)) == -1 )
		errExit("open /dev/net/tun");

	// create a new TAP device;;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, (void *) &ifr) == -1 )
		errExit("ioctl TUNSETIFF");

	// extract device name
	memcpy(devname,  ifr.ifr_name, IFNAMSIZ);

	// persistent device
//	if(ioctl(fd, TUNSETPERSIST, 1) < 0)
//		errExit("ioctl TUNSETPERSIST");

	// bring the interface up
	net_if_up(devname);

	return fd;
}


//*****************************************************
// UDP
//*****************************************************
int net_udp_server(int port) {
	int fd;
	struct sockaddr_in addr;

	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
		errExit("socket");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family    = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
		errExit("bind");

	return fd;
}

int net_udp_client(void) {
	int fd;
	struct sockaddr_in addr;

	if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
		errExit("socket");

	return fd;
}

//*****************************************************
// netfilter
//*****************************************************
void net_ipforward(void) {
	FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "w");
	if (!fp) {
		fprintf(stderr, "Error: cannot open  /proc/sys/net/ipv4/ip_forward\n");
		exit(1);
	}

	fprintf(fp, "1");
	fclose(fp);
}

#define BUFSIZE 1024
// returns malloced memory
char *net_get_nat_if(void) {
	FILE *fp = fopen("/proc/self/net/route", "r");
	if (!fp)
		errExit("fopen");

	char buf[BUFSIZE];
	char *retval = NULL;
	while (fgets(buf, BUFSIZE, fp)) {
		if (strncmp(buf, "Iface", 5) == 0)
			continue;

		retval = buf;
		char *ptr = buf;
		while (*ptr != ' ' && *ptr != '\t')
			ptr++;
		*ptr = '\0';
		ptr++;

		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		unsigned dest;
		unsigned gw;
		int rv = sscanf(ptr, "%x %x", &dest, &gw);
		if (rv == 2 && dest == 0) // is this the default gateway?
			break;

		retval = NULL;
	}
	fclose(fp);

	if (retval)
		retval = strdup(retval);
	return retval;
}

void net_set_netfilter(char *ifname) {
	assert(ifname);
	char *cmd;

	// find iptables command
	struct stat s;
	char *iptables = NULL;
	if (stat("/sbin/iptables", &s) == 0)
		iptables = "/sbin/iptables";
	else if (stat("/usr/sbin/iptables", &s) == 0)
		iptables = "/usr/sbin/iptables";
	if (iptables == NULL) {
		fprintf(stderr, "Error: iptables command not found, cannot configure NAT\n");
		exit(1);
	}

	// delete rule
	// iptables -t nat -D POSTROUTING -o eth0 -s 10.10.20.0/24  -j MASQUERADE
	if (asprintf(&cmd, "iptables -t nat -D POSTROUTING -o %s -s %d.%d.%d.%d/%d  -j MASQUERADE",
		ifname, PRINT_IP(tunnel.overlay.netaddr), mask2bits(tunnel.overlay.netmask)) == -1)
		errExit("asprintf");
	int rv = system(cmd);	// this could fail if no shuc rule is present in the table
	(void) rv;
	free(cmd);

	// add rule
	// iptables -t nat -A POSTROUTING -o eth0 -s 10.10.20.0/24  -j MASQUERADE
	if (asprintf(&cmd, "iptables -t nat -A POSTROUTING -o %s -s %d.%d.%d.%d/%d  -j MASQUERADE",
		ifname, PRINT_IP(tunnel.overlay.netaddr), mask2bits(tunnel.overlay.netmask)) == -1)
		errExit("asprintf");
	if (system(cmd))
		goto errexit;
	free(cmd);

	return;

errexit:
	fprintf(stderr, "Error: cannot configure NAT\n");
	exit(1);

}

