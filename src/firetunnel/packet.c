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
#include <time.h>
#include <arpa/inet.h>

static uint32_t scache[SEQ_DELTA_MAX];
static int scache_initialized = 0;

static void scache_init(void) {
	time_t ts = time(NULL);
	int i;
	for (i = 0; i < SEQ_DELTA_MAX; i++)
		scache[i] = ts - 1;
	scache_initialized = 1;
}

void pkt_set_header(PacketHeader *header, uint8_t opcode, uint32_t seq)  {
	assert(header);
	memset(header, 0, sizeof(PacketHeader));
	header->opcode = opcode;
	header->seq = htons(seq);
	header->timestamp = htonl(time(NULL));
}

// return 1 if header is good, 0 if bad
int pkt_check_header(UdpFrame *pkt, int len, struct sockaddr_in *client_addr) {
	assert(pkt);
	PacketHeader *header = &pkt->header;

	if (scache_initialized == 0)
		scache_init();

	// check packet length
	if (len < sizeof(PacketHeader) + KEY_LEN)
		return 0;

	// check opcode
	if (header->opcode >= O_MAX)
		return 0;

	// check ip:port
	if (tunnel.remote_sock_addr.sin_port != 0 &&
	    tunnel.remote_sock_addr.sin_addr.s_addr != 0) {
		if (tunnel.remote_sock_addr.sin_addr.s_addr != client_addr->sin_addr.s_addr ||
		    tunnel.remote_sock_addr.sin_port != client_addr->sin_port) {
		    	tunnel.stats.udp_rx_drop_addr_pkt++;

		    	logmsg("Address mismatch %d.%d.%d.%d:%d\n",
				PRINT_IP(ntohl(client_addr->sin_addr.s_addr)),
				ntohs(client_addr->sin_port));

		    	return 0;
		}
	}

	// check timestamp
	uint32_t current_timestamp = time(NULL);
	uint32_t timestamp = ntohl(header->timestamp);
	uint32_t delta = diff_uint32(current_timestamp, timestamp);
	if (delta > TIMESTAMP_DELTA_MAX) {
		tunnel.stats.udp_rx_drop_timestamp_pkt++;
		return 0;
	}

	// check seq
	uint16_t seq = ntohs(header->seq);
	// 1. accept packet if not more then +-SEQ_DELTA_MAX difference
	uint16_t delta16 = diff_uint16(tunnel.remote_seq, seq);
	if (delta16 > SEQ_DELTA_MAX) {
		tunnel.stats.udp_rx_drop_seq_pkt++;
		return 0;
	}

	// 2. accept packet if bigger timestamp than what we have stored in scache
	// this basically limits the incoming speed  to SEQ_DELTA_MAX packets per second
	uint32_t index = seq  & SEQ_BITMAP;
	if (timestamp <= scache[index]) {
		tunnel.stats.udp_rx_drop_seq_pkt++;
		return 0;
	}
	else // store timestamp
		scache[index] = timestamp;

	// check blake2
	uint8_t *hash = get_hash((uint8_t *)pkt, len - KEY_LEN,
		ntohl(header->timestamp), ntohs(header->seq));

	if (memcmp((uint8_t *) pkt + len - KEY_LEN, hash, KEY_LEN)) {
		tunnel.stats.udp_rx_drop_blake2_pkt++;
	    	logmsg("Hash mismatch %d.%d.%d.%d:%d\n",
			PRINT_IP(ntohl(client_addr->sin_addr.s_addr)),
			ntohs(client_addr->sin_port));
		return 0;
	}

	return 1;
}


void pkt_send_hello(UdpFrame *frame, int udpfd) {
	// set header
	tunnel.seq++;
	pkt_set_header(&frame->header, O_HELLO,  tunnel.seq);
	int nbytes = sizeof(PacketHeader);

	// send overlay data if we are the server
	if (arg_server) {
		uint32_t *ptr = (uint32_t *) &frame->eth;
		*ptr++ = htonl(tunnel.overlay.netaddr);
		*ptr++ = htonl(tunnel.overlay.netmask);
		*ptr++ = htonl(tunnel.overlay.defaultgw);
		*ptr++ = htonl(tunnel.overlay.mtu);
		*ptr++ = htonl(tunnel.overlay.dns1);
		*ptr++ = htonl(tunnel.overlay.dns2);
		*ptr++ = htonl(tunnel.overlay.dns3);
		nbytes += 7 * sizeof(uint32_t);
	}

	// add hash
	uint8_t *hash = get_hash((uint8_t *)frame, nbytes,
		ntohl(frame->header.timestamp), tunnel.seq);
	memcpy((uint8_t *) frame + nbytes, hash, KEY_LEN);

	// send
	int rv = sendto(udpfd, frame, nbytes + KEY_LEN, 0,
			(const struct sockaddr *) &tunnel.remote_sock_addr,
			sizeof(struct sockaddr_in));
	if (rv == -1)
		perror("sendto");
	tunnel.stats.udp_tx_pkt++;
}

void pkt_print_stats(UdpFrame *frame, int udpfd) {
	if (tunnel.state == S_DISCONNECTED)
		return;
		
	// build the stats message
	char buf[1024];
	char *ptr = buf;
	char *type = "Client";
	if (arg_server)
		type = "Server";
	int compressed = 0;
	if (tunnel.stats.udp_tx_pkt)
		compressed = (int) (100 * ((float) tunnel.stats.udp_tx_compressed_pkt / (float) tunnel.stats.udp_tx_pkt));
	sprintf(ptr, "%s: tx %u compressed %d%%; rx %u, DNS %u, drop %u: ",
		type,
		tunnel.stats.udp_tx_pkt,
		compressed,
		tunnel.stats.udp_rx_pkt,
		tunnel.stats.eth_rx_dns,
		tunnel.stats.udp_rx_drop_pkt);
	ptr += strlen(ptr);

	if (tunnel.stats.udp_rx_drop_timestamp_pkt) {
		sprintf(ptr, "tstamp %u, ", tunnel.stats.udp_rx_drop_timestamp_pkt);
		ptr += strlen(ptr);
	}
	if (tunnel.stats.udp_rx_drop_seq_pkt) {
		sprintf(ptr, "seq %u, ", tunnel.stats.udp_rx_drop_seq_pkt);
		ptr += strlen(ptr);
	}
	if (tunnel.stats.udp_rx_drop_addr_pkt) {
		sprintf(ptr, "addr %u, ", tunnel.stats.udp_rx_drop_addr_pkt);
		ptr += strlen(ptr);
	}
	if (tunnel.stats.udp_rx_drop_blake2_pkt) {
		printf(ptr, "blake2 %u, ", tunnel.stats.udp_rx_drop_blake2_pkt);
		ptr += strlen(ptr);
	}
	if (tunnel.stats.udp_rx_drop_padding_pkt) {
		sprintf(ptr, "padding %u", tunnel.stats.udp_rx_drop_padding_pkt);
		ptr += strlen(ptr);
	}

	// print stats message on console
	printf("%s\n", buf);

	// send the message to the client
	if (arg_server && tunnel.state == S_CONNECTED) {
		// set header
		tunnel.seq++;
		pkt_set_header(&frame->header, O_MESSAGE,  tunnel.seq);
		int nbytes = sizeof(PacketHeader);

		// copy the message
		strcpy(((char *) frame) + nbytes, buf);
		nbytes += strlen(buf) + 1;

		// add hash
		uint8_t *hash = get_hash((uint8_t *)frame, nbytes,
			ntohl(frame->header.timestamp), tunnel.seq);
		memcpy((uint8_t *) frame + nbytes, hash, KEY_LEN);

		// send
		int rv = sendto(udpfd, frame, nbytes + KEY_LEN, 0,
				(const struct sockaddr *) &tunnel.remote_sock_addr,
				sizeof(struct sockaddr_in));
		if (rv == -1)
			perror("sendto");
		tunnel.stats.udp_tx_pkt++;
	}
}
