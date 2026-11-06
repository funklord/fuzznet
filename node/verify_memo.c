/* See verify_memo.h. */

#include "verify_memo.h"

#include "../fault/fault.h"

#include <stdlib.h>
#include <string.h>

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

static int memo_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	fzn_verify_memo_t *m = ctx;
	uint8_t digest[FZN_VERIFY_MEMO_DIGEST];
	uint8_t *slot = NULL;

	if (!m->table && !m->no_room) {
		if (FZN_FAULT_RAM())
			m->table = calloc(FZN_VERIFY_MEMO_SLOTS, FZN_VERIFY_MEMO_DIGEST);
		m->no_room = !m->table;
	}
	if (m->table && digest_of(m, pubkey, msg, msg_len, sig, digest)) {
		size_t at = ((size_t)digest[0] | ((size_t)digest[1] << 8) | ((size_t)digest[2] << 16)
		             | ((size_t)digest[3] << 24))
		            % FZN_VERIFY_MEMO_SLOTS;

		slot = m->table[at];
		if (memcmp(slot, digest, FZN_VERIFY_MEMO_DIGEST) == 0) {
			m->hits++;
			return 1;
		}
	}
	m->checks++;
	if (!m->inner->verify(m->inner->ctx, pubkey, msg, msg_len, sig))
		return 0;
	if (slot)
		memcpy(slot, digest, FZN_VERIFY_MEMO_DIGEST);
	return 1;
}

static int memo_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	fzn_verify_memo_t *m = ctx;

	return m->inner->sign(m->inner->ctx, sig, msg, msg_len);
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
