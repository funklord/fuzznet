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

static size_t slot_of(const uint8_t digest[FZN_VERIFY_MEMO_DIGEST])
{
	return ((size_t)digest[0] | ((size_t)digest[1] << 8) | ((size_t)digest[2] << 16)
	        | ((size_t)digest[3] << 24))
	       % FZN_VERIFY_MEMO_SLOTS;
}

static int table_made(fzn_verify_memo_t *m)
{
	if (!m->table && !m->no_room) {
		if (FZN_FAULT_RAM())
			m->table = calloc(FZN_VERIFY_MEMO_SLOTS, FZN_VERIFY_MEMO_DIGEST);
		m->no_room = !m->table;
	}
	return m->table != NULL;
}

static int memo_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	fzn_verify_memo_t *m = ctx;
	uint8_t digest[FZN_VERIFY_MEMO_DIGEST];
	uint8_t *slot = NULL;

	if (table_made(m) && digest_of(m, pubkey, msg, msg_len, sig, digest)) {
		slot = m->table[slot_of(digest)];
		if (memcmp(slot, digest, FZN_VERIFY_MEMO_DIGEST) == 0) {
			m->hits++;
			return 1;
		}
	}
	m->checks++;
	if (!m->inner->verify(m->inner->ctx, pubkey, msg, msg_len, sig))
		return 0;
	if (slot) {
		memcpy(slot, digest, FZN_VERIFY_MEMO_DIGEST);
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
		memcpy(m->table[slot_of(digest)], digest, FZN_VERIFY_MEMO_DIGEST);
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
	for (i = 0; i < FZN_VERIFY_MEMO_SLOTS; i++)
		n += !slot_empty(m->table[i]);
	body = FILE_HEAD_LEN + n * FZN_VERIFY_MEMO_DIGEST;
	if (!(file = malloc(body + FZN_SIG_LEN)))
		return 0;
	file[0] = FILE_VERSION;
	fzn_put_be32(file + 1, (uint32_t)n);
	for (i = 0, n = 0; i < FZN_VERIFY_MEMO_SLOTS; i++) {
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
	    || (size_t)len
	               > FILE_HEAD_LEN + (size_t)FZN_VERIFY_MEMO_SLOTS * FZN_VERIFY_MEMO_DIGEST
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
	if (file[0] != FILE_VERSION || n > FZN_VERIFY_MEMO_SLOTS
	    || body != FILE_HEAD_LEN + n * FZN_VERIFY_MEMO_DIGEST
	    || !m->hash->hash(m->hash->ctx, hashed, sizeof(hashed), file, body)
	    || !m->inner->verify(m->inner->ctx, own, hashed, sizeof(hashed), file + body)
	    || !table_made(m)) {
		free(file);
		return 0;
	}
	for (i = 0; i < n; i++) {
		const uint8_t *digest = file + FILE_HEAD_LEN + i * FZN_VERIFY_MEMO_DIGEST;

		memcpy(m->table[slot_of(digest)], digest, FZN_VERIFY_MEMO_DIGEST);
	}
	free(file);
	return n;
}
