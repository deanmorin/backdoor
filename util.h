#ifndef DM_UTIL_H
#define DM_UTIL_H
#include <stdint.h>
#include "pkthdr.h"

/* 
 * Copyright (c)1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * dupliated in all such forms and that any documentation, advertising 
 * materials, and other materials related to such distribution and use
 * acknowledge that the software was developed by the University of
 * California, Berkeley. The name of the University may not be used
 * to endorse or promote products derived from this software without
 * specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHATIBILITY AND 
 * FITNESS FOR A PARTICULAR PURPOSE
 *
 * Our algorithm is simple, using a 32-bit accumulator (sum),
 * we add sequential 16-bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */
uint16_t chksum(uint16_t *ptr, int nbytes);

uint16_t trans_chksum(uint16_t *pseudoh, uint16_t *transh, int istcp,
        uint16_t *data, size_t dlen);

void fill_pseudo_hdr(struct pseudo_header *pseudoh, struct ip_header *iph,
        uint16_t len);

uint16_t port_from_date();

void print_packet(const u_char *packet, uint32_t caplen);

void print_ascii(const u_char *packet, size_t pckidx, char *out, size_t outidx);

void reverse(char* s, size_t len);

#endif 
