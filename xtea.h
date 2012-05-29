#ifndef DM_ENCRYPT_H
#define DM_ENCRYPT_H
#include <stdint.h>

#define RCM_NUM_ROUNDS  32
#define VSIZE           (sizeof(uint32_t) * 2)

/*
 * Take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3]
 * Adapted from the reference code released into the public domain.
 * Retrieved from Wikipdeia - http://en.wikipedia.org/wiki/XTEA
 *
 * @author David Wheeler
 * @author Roger Needham
 * @param num_rounds Recommended value is 32.
 * @param v 64 bits of data to be encrypted.
 * @param key The encryption key.
 */

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);
void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);

#endif
