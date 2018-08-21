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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <syslog.h>

// From Wikipedia: https://en.wikipedia.org/wiki/Scytale
// Skytale was a tool used  to perform a transposition cipher, consisting of a cylinder with a
// strip of parchment wound around it on which is written a message. The ancient Greeks,
// and the Spartans in particular, are said to have used this cipher to communicate during
// military campaigns.
//
// Please don't confuse this for serious encryption. Network traffic is highly recognizable.
// Somebody who knows what he's doing will figure this out in exactly 10 minutes just by
// looking at traffic traces.

// the cipher works on blocks of 8 bytes; padding is necessary for the original packet
#define BLOCKLEN 8

// provides the scrambling block length for MTU calculation purposes
__attribute__((weak)) int scramble_blocklen(void) {
	return BLOCKLEN;
}

// transposition routine; same function is used for encoding and decoding
static void skytale(uint8_t *in) {
	uint8_t out[BLOCKLEN] = {0};
	uint8_t *ptr = in;

	int j;
	uint8_t mask_out = 1;
	for (j = 0; j < BLOCKLEN; j++, ptr++, mask_out <<= 1) {
		int i;
		uint8_t mask_in = 1;
		for (i = 0; i < BLOCKLEN; i++, mask_in <<= 1)
			out[i] |= (*ptr & mask_in) ? mask_out : 0;
		out[i] ^= 0xc5; // ancient Greek to English translation :)
	}

	memcpy(in, out, BLOCKLEN);
}



// scrambling function called for each packet;
// the scrambled stream is usually longer than the original stream due to padding;
// this function returns the length difference (pad = output - input)
__attribute__((weak)) int scramble(uint8_t *ptr, int len) {
	// no scrambling if the program was started with --noscrambling command line option
	if (arg_noscrambling)
		return 0;

	// padding: multiple of SKYTALE_BLOCKLEN
	// https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
	int pad = BLOCKLEN - (len % BLOCKLEN);
	assert(ptr);
	int i;
	for (i = 0; i < pad; i++)
		*(ptr + len + i) = pad;


	for ( i = 0; i < ((len + pad) / BLOCKLEN); i++)
		skytale(ptr + i * BLOCKLEN);
	return pad;
}

// descrambling function called for each packet;
// the length of the packet should be a multiple of the block length
// the function returns 1 if error, 0 if ok
__attribute__((weak)) int descramble(uint8_t *ptr, int len) {
	// no scrambling if the program was started with --noscrambling command line option
	if (arg_noscrambling)
		return 0;

	// check padding
	if ((len % BLOCKLEN) != 0) {
		logmsg("Padding error!!!\n");
		return 1;
	}

	assert(ptr);
	int i;
	for ( i = 0; i < (len / BLOCKLEN); i++)
		skytale(ptr + i * BLOCKLEN);
	return 0;
}



