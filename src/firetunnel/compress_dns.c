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

// header compression scheme based on RFC 2507
typedef struct session_t {	// offset
	uint8_t mac[14];	// 0 - ethernet header
	uint16_t ver_ihl_tos;	// 14 - ip
	uint16_t len;		// 16 - use a default value and recalculate in decompress()
//	uint16_t id;		// 18
//	uint16_t offset;	// 20
//	uint8_t ttl;		// 22
	uint8_t protocol;	// 23
	uint16_t checksum;	// 24 - use a default value and recalculate in decompress()
	uint8_t addr[8];	// 26
} __attribute__((__packed__)) Session;	// 34
#define FULL_HEADER_LEN 34

// fields not included in params above
typedef struct new_header_t {	// offset
	uint16_t id;		// 18
	uint16_t offset;	// 20
	uint8_t ttl;		// 22
} __attribute__((__packed__)) NewHeader;

int compress_dns_size(void) {
	return FULL_HEADER_LEN - sizeof(NewHeader);
}

// fill up a session structure; ptr is the start of eth packet
static void set_session(uint8_t *ptr, Session *s) {
	assert(s);
	memcpy(s->mac, ptr, 14);
	memcpy(&s->ver_ihl_tos, ptr + 14, 2);
	s->len = 0xc28a;
	s->protocol = *(ptr + 23);
	s->checksum = 0x55aa;
	memcpy(s->addr, ptr + 26, 8);
}

static void print_session(Session *s) {
	uint32_t ip;
	memcpy(&ip, s->addr, 4);
	ip = ntohl(ip);
	printf("%d.%d.%d.%d -> ", PRINT_IP(ip));

	memcpy(&ip, s->addr + 4, 4);
	ip = ntohl(ip);
	printf("%d.%d.%d.%d\n", PRINT_IP(ip));
}

static void set_new_header(uint8_t *ptr, NewHeader *h) {
	assert(h);
	memcpy(&h->id, ptr + 18, 2);
	memcpy(&h->offset, ptr + 20, 2);
	h->ttl = *(ptr + 22);
}


typedef struct tcp_connection_t {
	int active;
	int cnt;
	Session s;
} Connection;
static Connection connection_s2c[256];
static Connection connection_c2s[256];

void compress_dns_init(void) {
	memset(connection_s2c, 0, sizeof(connection_s2c));
	memset(connection_c2s, 0, sizeof(connection_c2s));
}

void print_compress_dns_table(int direction) {
	Connection *conn = (direction == S2C)? &connection_s2c[0]: &connection_c2s[0];
	printf("Compression DNS table:\n");
	int i;
	for (i = 0; i < 256; i++, conn++) {
		if (conn->active) {
			printf("   %d:%d\t", i, conn->cnt);
			print_session(&conn->s);
		}
	}
}

// record the session and return 1 if the packet can be compressed
// store the hash in sid if sid not null
int classify_dns(uint8_t *pkt, uint8_t *sid, int direction) {
	int rv = 0;
	Session s;
	set_session(pkt, &s);

	uint8_t hash = 0;
	unsigned i;
	uint8_t *ptr = (uint8_t *) &s;
	for ( i = 0; i < sizeof(s); i++, ptr++)
		hash ^= *ptr;
	if (sid)
		*sid = hash;

	Connection *conn = (direction == S2C)? &connection_s2c[hash]: &connection_c2s[hash];
	if (conn->active) {
		if (memcmp(&s, &conn->s, sizeof(Session)) == 0) {
			conn->cnt++;
			int cnt = conn->cnt;

			if (cnt > 50 && cnt % 50)
				rv = 1;
			else if (cnt > 20 && cnt % 20)
				rv = 1;
			else if (cnt > 3 && cnt % 8)
				rv = 1;
		}
		else {
			dbg_printf("replace l2 hash %d\n", hash);
			tunnel.stats.compress_hash_collision++;
			memcpy(&conn->s, &s, sizeof(Session));
			conn->cnt = 1;
		}
	}
	else {
		memcpy(&conn->s, &s, sizeof(Session));
		conn->cnt = 1;
		conn->active = 1;
	}

	return rv;
}

int compress_dns(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
//uint16_t len;
//memcpy(&len, pkt + 14 + 2, 2);
//len = ntohs(len);
//printf("compress ip len %u\n", len);

	(void) direction;
	(void) nbytes;
	(void) sid;
	tunnel.stats.udp_tx_compressed_pkt++;
	NewHeader h;
	set_new_header(pkt, &h);
	memcpy(pkt + FULL_HEADER_LEN - sizeof(h), &h, sizeof(h));

	return FULL_HEADER_LEN - sizeof(NewHeader);
}

int decompress_dns(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
	Connection *conn = (direction == S2C)? &connection_s2c[sid]: &connection_c2s[sid];
	Session *s = &conn->s;
	NewHeader h;
	memcpy(&h, pkt, sizeof(h));

	// build the real header
	pkt += sizeof(h) - FULL_HEADER_LEN;
	memcpy(pkt, s->mac, 14);
	memcpy(pkt + 14, &s->ver_ihl_tos, 2);

	// recalculate len
	uint16_t len = nbytes + FULL_HEADER_LEN - sizeof(h) - 14;
//printf("decompress nbytes %d, ip len %d\n", nbytes, len);
	len = htons(len);
	memcpy(pkt + 16, &len, 2);

	memcpy(pkt + 18, &h.id, 2);
	memcpy(pkt + 20, &h.offset, 2);
	*(pkt + 22) = h.ttl;
	*(pkt + 23) = s->protocol;
	memcpy(pkt + 26, s->addr, 8);

	// calculate ip checksum
	memset(pkt + 24, 0, 2);
	uint16_t ipptr[10];	// we could be misaligned in memory
	memcpy(&ipptr[0], pkt + 14, 20);
	uint32_t r = 0;
	int i;
	for (i = 0; i < 10; i++)
		r += ipptr[i];
	uint16_t checksum = (uint16_t) (r & 0xffff) + (uint16_t) (r >> 16);
	checksum = ~checksum;
	memcpy(pkt + 24, &checksum, 2);

	return FULL_HEADER_LEN - sizeof(NewHeader);
}
