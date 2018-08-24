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
} __attribute__((__packed__)) Session;	// 38
#define FULL_HEADER_LEN 14

int compress_l2_size(void) {
	return FULL_HEADER_LEN ;
}

// fill up a session structure; ptr is the start of eth packet
static void set_session(uint8_t *ptr, Session *s) {
	assert(s);
	memcpy(s->mac, ptr, 14);
}

static void print_session(Session *s) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x ->", PRINT_MAC(s->mac));
	printf("%02x:%02x:%02x:%02x:%02x:%02x ", PRINT_MAC(s->mac + 6));
	printf("%02x%02x\n", s->mac[12], s->mac[13]);
}

typedef struct mac_connection_t {
	int active;
	int cnt;
	Session s;
} Connection;
static Connection connection_s2c[256];
static Connection connection_c2s[256];

void compress_l2_init(void) {
	memset(connection_s2c, 0, sizeof(connection_s2c));
	memset(connection_c2s, 0, sizeof(connection_c2s));
}

void print_compress_l2_table(int direction) {
	Connection *conn = (direction == S2C)? connection_s2c: connection_c2s;
	printf("Compression L2 hash table:\n");
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
int classify_l2(uint8_t *pkt, uint8_t *sid, int direction) {
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

int compress_l2(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
	(void) pkt;
	(void) nbytes;
	(void) sid;
	(void) direction;
	tunnel.stats.udp_tx_compressed_pkt++;
	return FULL_HEADER_LEN;
}

int decompress_l2(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
	(void) nbytes;
	Connection *conn = (direction == S2C)? &connection_s2c[sid]: &connection_c2s[sid];
	Session *s = &conn->s;

	// build the real header
	pkt -= FULL_HEADER_LEN;
	memcpy(pkt, s->mac, 14);

	return FULL_HEADER_LEN;
}
