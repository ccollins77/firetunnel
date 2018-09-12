#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void process(uint8_t *a) {
	uint64_t b[16];
	int i;

	uint64_t *ptr64 = (uint64_t *) &a[21];
	for (i = 0; i < 16; i++, ptr64++)
		b[i] = *ptr64;

	uint8_t *c = (uint8_t *) &b[0];
	for (i = 0; i < 16 * 8; i++, c++)
		printf("%x ", *c);
	printf("\n");

	ptr64 = (uint64_t *) &a[21];
	for (i = 0; i < 16; i++, ptr64++)
		*ptr64 = b[i];

	printf("\n");
}

int main(void) {
	uint8_t a[265];
	int i;
	for (i = 0; i < 256; i++)
		a[i] = i;

	process(a);
	for (i = 0; i < 256; i++)
		printf("%x ", a[i]);

	return 0;
}