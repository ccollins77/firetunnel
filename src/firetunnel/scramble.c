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

//**********************************************************************************
// Skytale scrambler
//**********************************************************************************
// Skytale was a tool used  to perform a transposition cipher, consisting of a cylinder with a
// strip of parchment wound around it on which is written a message. The ancient Greeks,
// and the Spartans in particular, are said to have used this cipher to communicate during
// military campaigns.
//
// More:
// 	skytale: https://en.wikipedia.org/wiki/Scytale
// 	ciphertext stealing: https://en.wikipedia.org/wiki/Ciphertext_stealing
//
// Please don't confuse this for serious encryption. Network traffic is highly recognizable.
// Somebody who knows what he's doing will figure this out in exactly 10 minutes just by
// looking at traffic traces.
//**********************************************************************************

// transposition routine; same function is used for encoding and decoding
#define BLOCKLEN 8
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
	}

	memcpy(in, out, BLOCKLEN);
}



// scrambling function called for each packet;
__attribute__((weak)) void scramble(uint8_t *ptr, int len) {
	assert(ptr);

	// no scrambling if the program was started with --noscrambling command line option
	if (arg_noscrambling)
		return;
	if (len < BLOCKLEN)
		return;

	// padding: multiple of BLOCKLEN
	int i;
	for ( i = 0; i < (len / BLOCKLEN); i++)
		skytale(ptr + i * BLOCKLEN);

	if (len % BLOCKLEN)
		skytale(ptr + len - BLOCKLEN);

}

// descrambling function called for each packet;
// the function returns 1 if error, 0 if ok
__attribute__((weak)) int descramble(uint8_t *ptr, int len) {
	assert(ptr);

	// no scrambling if the program was started with --noscrambling command line option
	if (arg_noscrambling)
		return 0;
	if (len < BLOCKLEN)
		return 1;

	if (len % BLOCKLEN)
		skytale(ptr + len - BLOCKLEN);

	int i;
	for ( i = 0; i < (len / BLOCKLEN); i++)
		skytale(ptr + i * BLOCKLEN);
	return 0;
}



