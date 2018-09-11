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

#define STATS_TIMEOUT_MAX 6	// print stats every STATS_TIMEOUT_MAX * TIMEOUT
static int statscnt = 0;
#define COMPRESS_TIMEOUT_MAX (STATS_TIMEOUT_MAX)
static int compresscnt = 0;

static void send_config(int socket) {
	char msg[10 + sizeof(TOverlay)];
	strcpy(msg, "config ");
	memcpy(msg + 7, &tunnel.overlay, sizeof(TOverlay));

	// send tunnel configuration to the parent
	int rv = write(socket, msg, 7 + sizeof(TOverlay));
	if (rv == -1)
		errExit("write");
}


void child(int socket) {
	// init select loop
	struct timeval timeout;
	timeout.tv_sec = TIMEOUT;
	timeout.tv_usec = 0;

	// init packet storage
	PacketMem *pktmem = malloc(sizeof(PacketMem));
	if (!pktmem)
		errExit("malloc");
	memset(pktmem, 0, sizeof(PacketMem));
	UdpFrame *udpframe = &pktmem->f;
	int hlen = sizeof(PacketHeader);

	if (!arg_server) {
		pkt_send_hello(udpframe, tunnel.udpfd);
		printf("Connecting..."); fflush(0);
		timeout.tv_sec = 2;
	}

	// select loop
	while (1) {
		fd_set set;
		FD_ZERO (&set);
		int nfds = 0;
		FD_SET(tunnel.tapfd, &set);
		nfds = (tunnel.tapfd > nfds) ? tunnel.tapfd : nfds;
		FD_SET(tunnel.udpfd, &set);
		nfds = (tunnel.udpfd > nfds) ? tunnel.udpfd : nfds;

		int rv;
		if ((rv = select(nfds + 1, &set, NULL, NULL, &timeout)) < 0)
			errExit("select");

		if (rv == 0) {
			timeout.tv_sec = TIMEOUT;
			// a disconnected client tries every 2 seconds
			if (!arg_server && tunnel.state == S_DISCONNECTED) {
				timeout.tv_sec = 2;
				printf("."); fflush(0);
			}
			timeout.tv_usec = 0;
			logcnt = 0;

			// send HELLO packet
			// the client always sends it, regardless of the connection status
			if (tunnel.state == S_CONNECTED || !arg_server)
				pkt_send_hello(udpframe, tunnel.udpfd);

			// check connect ttl
			if (--tunnel.connect_ttl < 1) {
				tunnel.state = S_DISCONNECTED;
				tunnel.seq = 0;
				tunnel.remote_seq = 0;
				if (tunnel.connect_ttl == 0) {
					if (arg_server)
						memset(&tunnel.remote_sock_addr, 0, sizeof(tunnel.remote_sock_addr));
					compress_l2_init();
					compress_l3_init();
					logmsg("%d.%d.%d.%d:%d disconnected\n",
					       PRINT_IP(ntohl(tunnel.remote_sock_addr.sin_addr.s_addr)),
					       ntohs(tunnel.remote_sock_addr.sin_port));
				}

				tunnel.connect_ttl = 0;
			}

			// print stats
			if (++statscnt >= STATS_TIMEOUT_MAX) {
				statscnt = 0;
				pkt_print_stats(udpframe, tunnel.udpfd);
			}

			if (++compresscnt >= COMPRESS_TIMEOUT_MAX) {
				compresscnt = 0;
				if (arg_debug || arg_debug_compress) {
					int direction = (arg_server)? S2C: C2S;
					print_compress_l2_table(direction);
					print_compress_l3_table(direction);
				}
			}

			continue;
		}

		// tap
		if (FD_ISSET (tunnel.tapfd, &set)) {
			int nbytes;

			// get data from tap device
			nbytes = read(tunnel.tapfd, udpframe->eth, sizeof(UdpFrame) - hlen);
			if (nbytes == -1)
				perror("read");
			dbg_printf("tap rx %d ", nbytes);

			// eth header size of 14
			if (nbytes <=14)
				dbg_printf("error < 14\n");
			else if (tunnel.state != S_CONNECTED)
				dbg_printf("error not connected\n");
			else if (pkt_is_ipv6(udpframe->eth, nbytes))
				dbg_printf("ipv6 drop\n");
			else if (pkt_is_dns_AAAA(udpframe->eth, nbytes))
				dbg_printf("DNS AAAA drop\n");
			else {
				int compression_l2 = 0;
				int compression_l3 = 0;
				uint8_t sid;	// session id if compression is set
				if (pkt_is_dns(udpframe->eth, nbytes))
					tunnel.stats.eth_rx_dns++;

				int direction = (arg_server)? S2C: C2S;
				if (pkt_is_ip(udpframe->eth, nbytes))
					compression_l3 = classify_l3(udpframe->eth, &sid, direction);
				else
					compression_l2 = classify_l2(udpframe->eth, &sid, direction);

				// set header
				tunnel.seq++;
				PacketHeader hdr;
				memset(&hdr, 0, sizeof(hdr));
				uint8_t *ethptr = udpframe->eth;
				if (compression_l3) {
					dbg_printf("compressing L3");
					int rv = compress_l3(udpframe->eth, nbytes, sid, direction);
					nbytes -= rv;
					ethptr += rv;
					pkt_set_header(&hdr, O_DATA_COMPRESSED_L3, tunnel.seq);
					hdr.sid = sid;
				}
				else if (compression_l2) {
					dbg_printf("compressing L2 ");
					int rv = compress_l2(udpframe->eth, nbytes, sid, direction);
					nbytes -= rv;
					ethptr += rv;
					pkt_set_header(&hdr, O_DATA_COMPRESSED_L2, tunnel.seq);
					hdr.sid = sid;
				}
				else
					pkt_set_header(&hdr, O_DATA, tunnel.seq);

				scramble(ethptr, nbytes);
				hdr.pad = 0;

				memcpy(ethptr - hlen, &hdr, hlen);

				// add BLAKE2 authentication
				uint8_t *hash = get_hash(ethptr - hlen, nbytes + hlen,
							 ntohl(hdr.timestamp), tunnel.seq);
				memcpy(ethptr + nbytes, hash, KEY_LEN);

				rv = sendto(tunnel.udpfd, ethptr - hlen, nbytes + hlen + KEY_LEN, 0,
					    (const struct sockaddr *) &tunnel.remote_sock_addr,
					    sizeof(struct sockaddr_in));
				dbg_printf("sent tunnel %d\n", rv);
				if (rv == -1)
					perror("sendto");

				tunnel.stats.udp_tx_pkt++;
			}
		}

		// udp
		if (FD_ISSET (tunnel.udpfd, &set)) {
			int nbytes;
			struct sockaddr_in client_addr;
			unsigned socklen = sizeof(client_addr);

			// get data from udp socket
			nbytes = recvfrom(tunnel.udpfd, udpframe, sizeof(UdpFrame), 0,
					  (struct sockaddr *) &client_addr, &socklen);
			if (nbytes == -1)
				perror("recvfrom");

			// update stats
			tunnel.stats.udp_rx_pkt++;
			dbg_printf("tunnel rx %d ", nbytes);

			if (pkt_check_header(udpframe, nbytes, &client_addr)) { // also does BLAKE2 authentication
				// update remote seq
				if (tunnel.remote_seq < ntohs(udpframe->header.seq) ||
				    (ntohs(udpframe->header.seq) < SEQ_DELTA_MAX &&
				     tunnel.remote_seq > (0xffff - SEQ_DELTA_MAX)))
					tunnel.remote_seq = ntohs(udpframe->header.seq);

				uint8_t opcode = udpframe->header.opcode;
				if (opcode == O_DATA || opcode == O_DATA_COMPRESSED_L3 ||
				    opcode == O_DATA_COMPRESSED_L2) {
					dbg_printf("data ");

					// descramble
					descramble(udpframe->eth, nbytes - hlen - KEY_LEN);
					{
						nbytes -= hlen + KEY_LEN;
						int direction = (arg_server)? C2S: S2C;
						nbytes -= udpframe->header.pad;
						uint8_t *ethstart = udpframe->eth;
						if (opcode == O_DATA_COMPRESSED_L3) {
							dbg_printf("decompress ");
							rv = decompress_l3(ethstart, nbytes, udpframe->header.sid, direction);
							ethstart -= rv;
							nbytes += rv;
						}
						else if (opcode == O_DATA_COMPRESSED_L2) {
							dbg_printf("decompress L2 ");
							rv = decompress_l2(ethstart, nbytes, udpframe->header.sid, direction);
							ethstart -= rv;
							nbytes += rv;
						}
						if (pkt_is_ip(ethstart, nbytes) || pkt_is_udp(ethstart, nbytes))
							classify_l3(ethstart, NULL, direction);
						else
							classify_l2(ethstart, NULL, direction);

						// write to tap device
						dbg_printf("send tap ");
						rv = write(tunnel.tapfd, ethstart, nbytes);
						dbg_printf("%d\n", rv);
						if (rv == -1)
							perror("write");
					}
				}

				else if (opcode == O_HELLO) {
					dbg_printf("hello\n");
					if (tunnel.state == S_DISCONNECTED) {
						tunnel.state = S_CONNECTED;
						tunnel.seq = 0;
						// update remote data
						// force a hello out to the client
						if (arg_server) {
							memcpy(&tunnel.remote_sock_addr, &client_addr, sizeof(struct sockaddr_in));
							timeout.tv_sec = 0;
							timeout.tv_usec = 0;
						}
						else
							printf("\n");

						logmsg("%d.%d.%d.%d:%d connected\n",
						       PRINT_IP(ntohl(tunnel.remote_sock_addr.sin_addr.s_addr)),
						       ntohs(tunnel.remote_sock_addr.sin_port));
					}
					tunnel.connect_ttl = CONNECT_TTL;

					// update overlay data if we are the client
					if (!arg_server) {
						uint32_t *ptr = (uint32_t *) &udpframe->eth[0];
						TOverlay o;
						o.netaddr = ntohl(*ptr++);
						o.netmask = ntohl(*ptr++);
						o.defaultgw = ntohl(*ptr++);
						o.mtu = ntohl(*ptr++);
						o.dns1 = ntohl(*ptr++);
						o.dns2 = ntohl(*ptr++);
						o.dns3 = ntohl(*ptr++);

						if (memcmp(&tunnel.overlay, &o, sizeof(TOverlay))) {
							memcpy(&tunnel.overlay, &o, sizeof(TOverlay));
							logmsg("Tunnel: %d.%d.%d.%d/%d, default gw %d.%d.%d.%d, mtu %d\n",
							       PRINT_IP(tunnel.overlay.netaddr), mask2bits(tunnel.overlay.netmask),
							       PRINT_IP(tunnel.overlay.defaultgw), tunnel.overlay.mtu);
							logmsg("Tunnel: DNS %d.%d.%d.%d, %d.%d.%d.%d, %d.%d.%d.%d\n",
							       PRINT_IP(tunnel.overlay.dns1), PRINT_IP(tunnel.overlay.dns2), PRINT_IP(tunnel.overlay.dns3));

							// send tunnel configuration to the parent
							send_config(socket);
						}
					}
				}

				else if (opcode == O_MESSAGE) {
					dbg_printf("message\n");
					if (tunnel.state == S_DISCONNECTED || arg_server) {
						// quietly drop the packet, it could be a very old one
					}
					else {
						printf("%s\n", (char *) udpframe->eth);
					}
				}
			}
			else {
				dbg_printf("drop\n");
				tunnel.stats.udp_rx_drop_pkt++;
			}
		}
	}
}
