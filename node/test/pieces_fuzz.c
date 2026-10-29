/*
 * A fuzz harness for a piece a peer hands over, `fzn_pieces_keep`, and the
 * rebuild that reads it, `fzn_pieces_rebuild`: sec 689's journey 3,
 * retention and logs, its erasure-coded pieces (secs 595 to 601).
 *
 * WHY THESE. A piece placed on this host arrives from another host, every
 * byte of it, and `fzn_pieces_keep` writes it to disk under the name its
 * own head gives. The claim is that a piece is kept only in a piece's
 * shape, only under its own name, and that one lying piece among the rest
 * can neither make a rebuild return other bytes than the item's nor stop
 * one while k whole pieces are there.
 *
 * THE PEER LIES BY MUTATION. Each case keeps every whole piece of an item
 * but one, then that one, bent with even odds: bits flipped, cut short,
 * grown, a head field set to a byte of its own, two bytes swapped, or the
 * item's length lowered as far as its piece length allows.
 *
 * THE PROPERTIES:
 *   1. A WHOLE PIECE IS KEPT, under its item's id and index, byte for byte.
 *   2. A BENT ONE IS REFUSED, leaving the directory as it was, or KEPT under
 *      the name its head gives, byte for byte, and nothing else changed.
 *      Neither leaves a `.new` behind.
 *   3. A REBUILD THAT ANSWERS OK ANSWERS THE ITEM, byte for byte.
 *   4. K WHOLE PIECES REBUILD IT, whatever else lies in the directory, and
 *      the item's length asked first is at least its own.
 *
 * FLOORS: a run that never kept a bent piece, never refused one, or never
 * rebuilt with a bent one beside the whole has not tested what it claims.
 *
 * HOW IT TERMINATES: no forks, fixed loops. Its scratch is
 * /tmp/fzn-pieces-fuzz-PID, two directories this process makes; each is
 * emptied entry by entry and removed at the end.
 */
#define _POSIX_C_SOURCE 200809L
#include "../pieces.h"
#include "../../chunk/erasure.h"
#include "../../session/hash_monocypher.h"
#include "../../wire/bytes.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FUZZ_DEFAULT_CASES 2000u
#define FUZZ_MIN_CASES 1000u
/* A FRESH ITEM, and fresh k and m, every this many cases. */
#define CASES_AN_ITEM 40u
#define ITEM_MAX 6000u
#define KIND 1u
#define PIECE_MAX (FZN_PIECE_HEAD_LEN + ITEM_MAX + 64u)
/* Entries a directory may hold here: k + m whole, one bent, and room. */
#define NAMES_MAX 48u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL pieces_fuzz.c: case %lu: %s\n", c, what);
}

/* ---- a generator, seeded ---------------------------------------------- */

static uint64_t state = 0x9e3779b97f4a7c15ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

/* ---- scratch ------------------------------------------------------------ */

static char top[64], src[128], dst[128];

/* Every entry of `dir`, which this process made; then `dir`, when `gone`. */
static void wipe(const char *dir, int gone)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char path[400];

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		(void)remove(path);
	}
	(void)closedir(d);
	if (gone)
		(void)rmdir(dir);
}

/* The names in `dir`, sorted, into `names`; how many, or NAMES_MAX + 1 when
 * more. */
static size_t names_in(const char *dir, char names[NAMES_MAX][256])
{
	DIR *d = opendir(dir);
	struct dirent *e;
	size_t n = 0, i, j;
	char t[256];

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (n == NAMES_MAX) {
			n++;
			break;
		}
		snprintf(names[n++], 256, "%s", e->d_name);
	}
	(void)closedir(d);
	for (i = 1; i < n && n <= NAMES_MAX; i++)
		for (j = i; j > 0 && strcmp(names[j - 1], names[j]) > 0; j--) {
			memcpy(t, names[j], sizeof(t));
			memcpy(names[j], names[j - 1], sizeof(t));
			memcpy(names[j - 1], t, sizeof(t));
		}
	return n;
}

static void piece_name(char *out, size_t cap, const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned index)
{
	static const char HEX[] = "0123456789abcdef";
	char hex[2u * FZN_BUCKETS_ID_LEN + 1u];
	size_t i;

	for (i = 0; i < FZN_BUCKETS_ID_LEN; i++) {
		hex[2u * i] = HEX[id[i] >> 4];
		hex[2u * i + 1u] = HEX[id[i] & 15u];
	}
	hex[2u * FZN_BUCKETS_ID_LEN] = '\0';
	snprintf(out, cap, "%s.%u.piece", hex, index);
}

/* `dir`/`name` read whole into `out`; its length, or 0 when it will not. */
static size_t read_file(const char *dir, const char *name, uint8_t *out, size_t cap)
{
	char path[400];
	FILE *f;
	size_t n;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "rb");
	if (!f)
		return 0;
	n = fread(out, 1, cap, f);
	(void)fclose(f);
	return n;
}

/* ---- the item ------------------------------------------------------------ */

static fzn_hash_ops_t HASH;
static uint8_t item[ITEM_MAX], id[FZN_BUCKETS_ID_LEN];
static size_t item_len;
static unsigned k, m;
static uint8_t whole[FZN_ERASURE_PIECES_MAX][PIECE_MAX];
static size_t whole_len[FZN_ERASURE_PIECES_MAX];

static int new_item(void)
{
	uint8_t host[32], keepers[FZN_ERASURE_PIECES_MAX][32];
	char name[160];
	size_t i, written = 0;

	item_len = 1u + (size_t)(next() % ITEM_MAX);
	for (i = 0; i < item_len; i++)
		item[i] = (uint8_t)next();
	k = 1u + (unsigned)(next() % 4u);
	m = 1u + (unsigned)(next() % 3u);
	memset(host, 0x5a, sizeof(host));
	for (i = 0; i < k + m; i++)
		memset(keepers[i], (int)(0x10u + i), 32u);
	wipe(src, 0);
	if (!fzn_buckets_id(&HASH, item, item_len, id)
	    || fzn_pieces_cut(src, KIND, id, host, (const uint8_t (*)[32])keepers, item, item_len, k,
	                      m, &written)
	               != FZN_PIECES_OK
	    || written != k + m)
		return 0;
	for (i = 0; i < k + m; i++) {
		piece_name(name, sizeof(name), id, (unsigned)i);
		whole_len[i] = read_file(src, name, whole[i], PIECE_MAX);
		if (whole_len[i] <= FZN_PIECE_HEAD_LEN)
			return 0;
	}
	return 1;
}

/* ---- the lie --------------------------------------------------------------- */

static size_t bend(uint8_t *p, size_t len)
{
	static const size_t fields[] = { 0u, 1u, 2u, 66u, 73u, 74u, 75u, 76u, 109u, 112u };
	size_t i, n, a, b;
	uint8_t t;

	switch (next() % 6u) {
	case 5: { /* the item's length lowered, its piece length kept */
		uint64_t was = fzn_get_be64(p + 66), plen = fzn_get_be32(p + 109);
		uint64_t least = (plen - 1u) * p[74] + 1u;

		if (len >= FZN_PIECE_HEAD_LEN && plen && least < was)
			fzn_put_be64(p + 66, least);
		else
			p[next() % len] ^= 0x01u;
		return len;
	}
	case 0: /* bits flipped */
		n = 1u + (size_t)(next() % 8u);
		for (i = 0; i < n; i++)
			p[next() % len] ^= (uint8_t)(1u << (next() % 8u));
		return len;
	case 1: /* cut short */
		return (size_t)(next() % len);
	case 2: /* grown */
		n = 1u + (size_t)(next() % 64u);
		for (i = 0; i < n; i++)
			p[len + i] = (uint8_t)next();
		return len + n;
	case 3: /* a head field, a byte of its own */
		p[fields[next() % (sizeof(fields) / sizeof(fields[0]))]] =
		        (uint8_t)(next() % 3u == 0u ? next() % 40u : next());
		return len;
	default: /* two bytes swapped */
		a = (size_t)(next() % len);
		b = (size_t)(next() % len);
		t = p[a];
		p[a] = p[b];
		p[b] = t;
		return len;
	}
}

int main(int argc, char **argv)
{
	static uint8_t cand[PIECE_MAX], back[PIECE_MAX], out[ITEM_MAX];
	static char before[NAMES_MAX][256], after[NAMES_MAX][256];
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long kept_bent = 0, refused = 0, rebuilt_beside = 0;
	char name[160];

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	fzn_hash_monocypher_init(&HASH);
	snprintf(top, sizeof(top), "/tmp/fzn-pieces-fuzz-%ld", (long)getpid());
	snprintf(src, sizeof(src), "%s/src", top);
	snprintf(dst, sizeof(dst), "%s/dst", top);
	if (mkdir(top, 0700) != 0) {
		fprintf(stderr, "pieces_fuzz: cannot make %s\n", top);
		return 1;
	}

	for (c = 0; c < cases; c++) {
		uint8_t got_id[FZN_BUCKETS_ID_LEN];
		unsigned got_index = 0, j, i, good = 0;
		size_t len, nb, na, olen = 0, x;
		int bent, r, changed = 0, extra = 0;

		if (c % CASES_AN_ITEM == 0u && !new_item()) {
			fail("fixture: an item was not cut into pieces", c);
			break;
		}
		wipe(dst, 0);
		j = (unsigned)(next() % (k + m));
		for (i = 0; i < k + m; i++)
			if (i != j
			    && fzn_pieces_keep(dst, whole[i], whole_len[i], got_id, &got_index)
			               != FZN_PIECES_OK)
				fail("fixture: a whole piece was not kept", c);
		memcpy(cand, whole[j], whole_len[j]);
		len = whole_len[j];
		bent = (int)(next() & 1u);
		if (bent)
			len = bend(cand, len);
		nb = names_in(dst, before);
		r = fzn_pieces_keep(dst, cand, len, got_id, &got_index);
		na = names_in(dst, after);
		for (x = 0; x < na && x < NAMES_MAX; x++)
			if (strstr(after[x], ".new"))
				fail("a kept or refused piece left a .new behind", c);

		if (!bent) {
			/* 1. A WHOLE PIECE IS KEPT. */
			piece_name(name, sizeof(name), id, j);
			if (r != FZN_PIECES_OK || memcmp(got_id, id, sizeof(id)) != 0 || got_index != j
			    || read_file(dst, name, back, sizeof(back)) != len
			    || memcmp(back, cand, len) != 0)
				fail("a whole piece was not kept under its own name, byte for byte", c);
		} else if (r != FZN_PIECES_OK) {
			/* 2. REFUSED, the directory as it was. */
			refused++;
			if (na != nb)
				changed = 1;
			for (x = 0; !changed && x < na && x < NAMES_MAX; x++)
				changed = strcmp(before[x], after[x]) != 0;
			if (changed)
				fail("a refused piece changed the directory", c);
		} else {
			/* 2. KEPT under the name its head gives, byte for byte. */
			kept_bent++;
			piece_name(name, sizeof(name), got_id, got_index);
			if (len < FZN_PIECE_HEAD_LEN || memcmp(cand + 2, got_id, sizeof(got_id)) != 0
			    || got_index != cand[76] || read_file(dst, name, back, sizeof(back)) != len
			    || memcmp(back, cand, len) != 0)
				fail("a bent piece was kept other than under its head's name, byte for byte",
				     c);
			/* Nothing else: every name before is there after, and at most
			 * that one is new. */
			for (x = 0; x < nb && x < NAMES_MAX; x++) {
				size_t y;
				int found = 0;

				for (y = 0; y < na && y < NAMES_MAX && !found; y++)
					found = strcmp(before[x], after[y]) == 0;
				if (!found)
					fail("keeping a bent piece removed another", c);
			}
			for (x = 0; x < na && x < NAMES_MAX; x++) {
				size_t y;
				int found = 0;

				for (y = 0; y < nb && y < NAMES_MAX && !found; y++)
					found = strcmp(after[x], before[y]) == 0;
				extra += !found && strcmp(after[x], name) != 0;
			}
			if (extra)
				fail("keeping a bent piece made a file other than its own", c);
		}

		/* 3 and 4. THE REBUILD. */
		for (i = 0; i < k + m; i++) {
			piece_name(name, sizeof(name), id, i);
			good += read_file(dst, name, back, sizeof(back)) == whole_len[i]
			        && memcmp(back, whole[i], whole_len[i]) == 0;
		}
		/* 4. AND THE ROOM IT IS GIVEN holds it: the length asked first,
		 * as the daemon sizes the rebuild's buffer by it. */
		if (good >= k && (fzn_pieces_item_len(dst, id, &olen) != FZN_PIECES_OK
		                  || olen < item_len))
			fail("k whole pieces were present and the item's length was said short", c);
		olen = 0;
		r = fzn_pieces_rebuild(dst, KIND, id, &HASH, out, sizeof(out), &olen, NULL);
		if (r == FZN_PIECES_OK && (olen != item_len || memcmp(out, item, item_len) != 0))
			fail("a rebuild answered OK with other bytes than the item's", c);
		if (good >= k && r != FZN_PIECES_OK) {
			fail("k whole pieces were present and the rebuild refused", c);
			if (failures <= 10)
				fprintf(stderr, "    k %u m %u, %u whole, the %s piece at index %u: %s\n",
				        k, m, good, bent ? "bent" : "whole", j, fzn_pieces_err_str(r));
		}
		if (bent && r == FZN_PIECES_OK && good < k + m)
			rebuilt_beside++;
	}

	wipe(src, 1);
	wipe(dst, 1);
	(void)rmdir(top);
	if (kept_bent == 0u)
		fail("no bent piece was kept: the mutations never reached the disk", cases);
	if (refused == 0u)
		fail("no bent piece was refused: the shape check was never met", cases);
	if (rebuilt_beside == 0u)
		fail("no rebuild ran with a bent piece beside the whole", cases);
	printf("pieces_fuzz: %lu cases, %lu bent kept, %lu refused, %lu rebuilt beside a bent one, "
	       "%d failure(s)\n",
	       cases, kept_bent, refused, rebuilt_beside, failures);
	return failures ? 1 : 0;
}
