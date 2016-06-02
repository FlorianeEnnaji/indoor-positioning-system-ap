/*
 * Radiotap parser
 *
 * Copyright 2007               Andy Green <andy@warmcat.com>
 * Copyright 2009               Johannes Berg <johannes@sipsolutions.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of ISC
 * license:
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __RADIOTAP_ITER_H
#define __RADIOTAP_ITER_H

#define RADIOTAP_SUPPORT_OVERRIDES

// #include <glib.h>
#include <stdint.h>
//#include "packet-ieee80211-radiotap-defs.h"

/* Radiotap header iteration
 *   implemented in radiotap.c
 */

#define guint8 uint8_t
#define guint uint32_t
#define guint16 uint16_t
#define guint32 uint32_t


struct radiotap_override {
	guint8 field;
	guint align:4, size:4;
};

struct radiotap_align_size {
	guint align:4, size:4;
};

struct ieee80211_radiotap_namespace {
	const struct radiotap_align_size *align_size;
	int n_bits;
	guint32 oui;
	guint8 subns;
};

struct ieee80211_radiotap_vendor_namespaces {
	const struct ieee80211_radiotap_namespace *ns;
	int n_ns;
};

struct ieee80211_radiotap_iterator {
	struct ieee80211_radiotap_header *_rtheader;
	const struct ieee80211_radiotap_vendor_namespaces *_vns;
	const struct ieee80211_radiotap_namespace *current_namespace;

	unsigned char *_arg, *_next_ns_data;
	guint32 *_next_bitmap;

	unsigned char *this_arg;
#ifdef RADIOTAP_SUPPORT_OVERRIDES
	const struct radiotap_override *overrides;
	int n_overrides;
#endif
	int this_arg_index;
	int this_arg_size;

	int is_radiotap_ns;

	int _max_length;
	int _arg_index;
	guint32 _bitmap_shifter;
	int _reset_on_ext;
};

extern int ieee80211_radiotap_iterator_init(
		struct ieee80211_radiotap_iterator *iterator,
		struct ieee80211_radiotap_header *radiotap_header,
		int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns);
extern int ieee80211_radiotap_iterator_next(
		struct ieee80211_radiotap_iterator *iterator);

#endif /* __RADIOTAP_ITER_H */
