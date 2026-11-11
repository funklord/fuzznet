/* See verify_memo.h. */

#include "verify_memo.h"

#include "../fault/fault.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../wire/bytes.h"

/* THE FILE, `node/verify_memo.situ`: version, count, the digests, the signature. */
#define FILE_VERSION 1u
#define FILE_HEAD_LEN 5u

/* The hash of what was signed, then of it with the key and the signature, so nothing
 * of a check's bytes is left out and two of them cannot run together. */
static int digest_of(const fzn_verify_memo_t *m, const uint8_t *pubkey, const uint8_t *msg,
                     size_t msg_len, const uint8_t *sig, uint8_t out[FZN_VERIFY_MEMO_DIGEST])
{
	uint8_t all[FZN_VERIFY_MEMO_DIGEST + FZN_PUBKEY_LEN + FZN_SIG_LEN];

	if (!m->hash->hash(m->hash->ctx, all, FZN_VERIFY_MEMO_DIGEST, msg, msg_len))
		return 0;
	memcpy(all + FZN_VERIFY_MEMO_DIGEST, pubkey, FZN_PUBKEY_LEN);
	memcpy(all + FZN_VERIFY_MEMO_DIGEST + FZN_PUBKEY_LEN, sig, FZN_SIG_LEN);
	return m->hash->hash(m->hash->ctx, out, FZN_VERIFY_MEMO_DIGEST, all, sizeof(all));
}

/* SETS OF FZN_VERIFY_MEMO_WAYS, TWO A DIGEST, sec 1007: direct-mapped, two signatures
 * a node keeps reading that fell in one slot put each other out at every walk, and at
 * 20000 contacts some 13000 slots held two -- 50000 checks a round, an Ed25519 check
 * each, though the memo had held them all once. A digest goes in the emptier of two
 * sets drawn from different bytes of it, which keeps the fullest set near the mean,
 * so at three quarters taken a set is seldom full. The first slot of the `which`th
 * set of `digest` in a table of `slots`. */
static size_t set_of(const uint8_t digest[FZN_VERIFY_MEMO_DIGEST], size_t slots, int which)
{
	const uint8_t *d = digest + (which ? 8 : 0);
	uint64_t v = (uint64_t)d[0] | ((uint64_t)d[1] << 8) | ((uint64_t)d[2] << 16)
	             | ((uint64_t)d[3] << 24) | ((uint64_t)d[4] << 32) | ((uint64_t)d[5] << 40);

	return (size_t)(v % (slots / FZN_VERIFY_MEMO_WAYS)) * FZN_VERIFY_MEMO_WAYS;
}

static int slot_empty(const uint8_t *slot);

static int table_made(fzn_verify_memo_t *m)
{
	if (!m->table && !m->no_room) {
		if (FZN_FAULT_RAM())
			m->table = calloc(FZN_VERIFY_MEMO_SLOTS, FZN_VERIFY_MEMO_DIGEST);
		m->no_room = !m->table;
		m->room = m->table ? FZN_VERIFY_MEMO_SLOTS : 0u;
		m->filled = 0;
	}
	return m->table != NULL;
}

/* 1 when `digest` is held, in either of its sets. */
static int held(const fzn_verify_memo_t *m, const uint8_t digest[FZN_VERIFY_MEMO_DIGEST])
{
	int which;
	size_t w;

	for (which = 0; which < 2; which++) {
		size_t at = set_of(digest, m->room, which);

		for (w = 0; w < FZN_VERIFY_MEMO_WAYS; w++)
			if (memcmp(m->table[at + w], digest, FZN_VERIFY_MEMO_DIGEST) == 0)
				return 1;
	}
	return 0;
}

/* The free ways of the set at `at`. */
static size_t free_ways(uint8_t (*table)[FZN_VERIFY_MEMO_DIGEST], size_t at)
{
	size_t w, n = 0;

	for (w = 0; w < FZN_VERIFY_MEMO_WAYS; w++)
		n += (size_t)slot_empty(table[at + w]);
	return n;
}

/* `digest` into a table of `slots`, in a free way of the emptier of its sets: 1 when it
 * took one; else, both full, -1 -- and with `evict`, in a way of the first its own
 * bytes name. Not asked of a digest already held. */
static int put(uint8_t (*table)[FZN_VERIFY_MEMO_DIGEST], size_t slots,
               const uint8_t digest[FZN_VERIFY_MEMO_DIGEST], int evict)
{
	size_t a = set_of(digest, slots, 0), b = set_of(digest, slots, 1);
	size_t at = free_ways(table, b) > free_ways(table, a) ? b : a, w;

	for (w = 0; w < FZN_VERIFY_MEMO_WAYS; w++)
		if (slot_empty(table[at + w])) {
			memcpy(table[at + w], digest, FZN_VERIFY_MEMO_DIGEST);
			return 1;
		}
	if (evict)
		memcpy(table[a + digest[6] % FZN_VERIFY_MEMO_WAYS], digest, FZN_VERIFY_MEMO_DIGEST);
	return -1;
}

/* GROWN, sec 1007, twice over: what a node holds grows with its contacts, and a table
 * it outgrows checks again what it has already seen. 1 when it grew; one that will not
 * keeps what it has. */
static int grow(fzn_verify_memo_t *m)
{
	uint8_t (*more)[FZN_VERIFY_MEMO_DIGEST];
	size_t slots = m->room * 2u, i;

	if (m->room > ((size_t)-1) / 4u / FZN_VERIFY_MEMO_DIGEST || !FZN_FAULT_RAM()
	    || !(more = calloc(slots, FZN_VERIFY_MEMO_DIGEST)))
		return 0;
	m->filled = 0;
	for (i = 0; i < m->room; i++)
		if (!slot_empty(m->table[i]) && put(more, slots, m->table[i], 1) > 0)
			m->filled++;
	free(m->table);
	m->table = more;
	m->room = slots;
	return 1;
}

/* KEPT: the table grown at three quarters taken, and when both of a digest's sets are
 * full -- once a quarter is, so that digests aimed at two sets cannot double it for
 * ever; below that, one is put out. */
static void keep(fzn_verify_memo_t *m, const uint8_t digest[FZN_VERIFY_MEMO_DIGEST])
{
	if (held(m, digest))
		return;
	if (m->filled + 1u > m->room / 4u * 3u)
		(void)grow(m);
	while (put(m->table, m->room, digest, 0) < 0)
		if (m->filled < m->room / 4u || !grow(m)) {
			(void)put(m->table, m->room, digest, 1);
			return;
		}
	m->filled++;
}

static int memo_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	fzn_verify_memo_t *m = ctx;
	uint8_t digest[FZN_VERIFY_MEMO_DIGEST];
	int have = 0;

	if (table_made(m) && digest_of(m, pubkey, msg, msg_len, sig, digest)) {
		have = 1;
		if (held(m, digest)) {
			m->hits++;
			return 1;
		}
	}
	m->checks++;
	if (!m->inner->verify(m->inner->ctx, pubkey, msg, msg_len, sig))
		return 0;
	if (have) {
		keep(m, digest);
		m->added++;
	}
	return 1;
}

static int memo_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	fzn_verify_memo_t *m = ctx;
	uint8_t digest[FZN_VERIFY_MEMO_DIGEST];

	if (!m->inner->sign(m->inner->ctx, sig, msg, msg_len))
		return 0;
	/* A SIGNATURE OF ANOTHER KEY'S only ever misses: the digest holds the key. */
	if (m->own && table_made(m) && digest_of(m, m->own, msg, msg_len, sig, digest)) {
		keep(m, digest);
		m->added++;
	}
	return 1;
}

void fzn_verify_memo_init(fzn_verify_memo_t *m, const fzn_sign_ops_t *inner,
                          const fzn_hash_ops_t *hash, fzn_sign_ops_t *ops)
{
	memset(m, 0, sizeof(*m));
	m->inner = inner;
	m->hash = hash;
	ops->verify = memo_verify;
	ops->sign = memo_sign;
	ops->ctx = m;
}

void fzn_verify_memo_free(fzn_verify_memo_t *m)
{
	if (!m)
		return;
	free(m->table);
	m->table = NULL;
	m->room = m->filled = 0;
}

static int slot_empty(const uint8_t *slot)
{
	static const uint8_t none[FZN_VERIFY_MEMO_DIGEST];

	return memcmp(slot, none, sizeof(none)) == 0;
}

/* `bytes` WHOLE AT `path`, by way of a temporary, synced. */
static int write_whole(const char *path, const uint8_t *bytes, size_t len)
{
	char temp[512];
	size_t at = 0;
	int fd, ok;

	if ((size_t)snprintf(temp, sizeof(temp), "%s.tmp", path) >= sizeof(temp)
	    || (fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
		return 0;
	while (at < len) {
		ssize_t n = write(fd, bytes + at, len - at);

		if (n <= 0)
			break;
		at += (size_t)n;
	}
	ok = at == len && fsync(fd) == 0;
	if (close(fd) != 0)
		ok = 0;
	if (!ok || rename(temp, path) != 0) {
		(void)unlink(temp);
		return 0;
	}
	return 1;
}

int fzn_verify_memo_save(fzn_verify_memo_t *m, const char *path)
{
	uint8_t hashed[FZN_VERIFY_MEMO_DIGEST];
	uint8_t *file;
	size_t i, n = 0, body;
	int ok;

	if (!m || !path || !m->table || !m->inner->sign)
		return 0;
	for (i = 0; i < m->room; i++)
		n += !slot_empty(m->table[i]);
	body = FILE_HEAD_LEN + n * FZN_VERIFY_MEMO_DIGEST;
	if (!(file = malloc(body + FZN_SIG_LEN)))
		return 0;
	file[0] = FILE_VERSION;
	fzn_put_be32(file + 1, (uint32_t)n);
	for (i = 0, n = 0; i < m->room; i++) {
		if (slot_empty(m->table[i]))
			continue;
		memcpy(file + FILE_HEAD_LEN + n++ * FZN_VERIFY_MEMO_DIGEST, m->table[i],
		       FZN_VERIFY_MEMO_DIGEST);
	}
	ok = m->hash->hash(m->hash->ctx, hashed, sizeof(hashed), file, body)
	     && m->inner->sign(m->inner->ctx, file + body, hashed, sizeof(hashed))
	     && write_whole(path, file, body + FZN_SIG_LEN);
	free(file);
	if (ok)
		m->added_saved = m->added;
	return ok;
}

size_t fzn_verify_memo_load(fzn_verify_memo_t *m, const char *path,
                            const uint8_t own[FZN_PUBKEY_LEN])
{
	uint8_t hashed[FZN_VERIFY_MEMO_DIGEST];
	uint8_t *file = NULL;
	FILE *f;
	long len;
	size_t i, n = 0, body;

	if (!m || !path || !own || !(f = fopen(path, "rb")))
		return 0;
	if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < (long)(FILE_HEAD_LEN + FZN_SIG_LEN)
	    || (size_t)len > FILE_HEAD_LEN + (size_t)FZN_VERIFY_MEMO_HELD_MAX * FZN_VERIFY_MEMO_DIGEST
	                             + FZN_SIG_LEN
	    || fseek(f, 0, SEEK_SET) != 0 || !(file = malloc((size_t)len))
	    || fread(file, 1u, (size_t)len, f) != (size_t)len) {
		(void)fclose(f);
		free(file);
		return 0;
	}
	(void)fclose(f);
	body = (size_t)len - FZN_SIG_LEN;
	n = fzn_get_be32(file + 1);
	/* THE SIGNATURE BEFORE ANYTHING IS BELIEVED, and then only all of it. */
	if (file[0] != FILE_VERSION || n > FZN_VERIFY_MEMO_HELD_MAX
	    || body != FILE_HEAD_LEN + n * FZN_VERIFY_MEMO_DIGEST
	    || !m->hash->hash(m->hash->ctx, hashed, sizeof(hashed), file, body)
	    || !m->inner->verify(m->inner->ctx, own, hashed, sizeof(hashed), file + body)
	    || !table_made(m)) {
		free(file);
		return 0;
	}
	for (i = 0; i < n; i++) {
		const uint8_t *digest = file + FILE_HEAD_LEN + i * FZN_VERIFY_MEMO_DIGEST;

		keep(m, digest);
	}
	free(file);
	return n;
}
