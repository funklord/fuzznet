/* A HOST'S NOTES STREAM, AS A TEST CHAINS IT: what `fzn_notes_chain_fn`
 * asks, with no journal behind it. project.md sec 517.
 *
 * Since sec 517 every note record is the next of its host's stream 0, signed
 * naming the one before. The node's journal is the real chain; this numbers
 * each issuer's records from 1 and names the one before by a toy digest of
 * its bytes. What is under test is the notes model handing records to a
 * chain and indexing what comes back, not the chain itself, which
 * `node/test/node_journal_test.c` covers.
 *
 * Header-only and static inline, so each suite that includes it has its own
 * copy, takes only what it calls, and none of it reaches the library.
 */

#ifndef FZN_NOTES_TEST_CHAIN_STUB_H
#define FZN_NOTES_TEST_CHAIN_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../author.h"

#define CHAIN_STUB_ISSUERS 8u

static struct {
	uint8_t issuer[CHAIN_STUB_ISSUERS][FZN_PUBKEY_LEN];
	uint64_t seq[CHAIN_STUB_ISSUERS];
	uint8_t head[CHAIN_STUB_ISSUERS][FZN_RECORD_ID_LEN];
	size_t count;
	/* Every chaining refused while set, as a journal that will not write. */
	int refuse;
	/* How many records were chained, all issuers together. */
	size_t chained;
} chain_stub;

/* A toy digest, enough to name a record distinctly; not a hash anything
 * relies on. */
static inline void chain_stub_digest(const uint8_t *bytes, size_t len,
                                     uint8_t out[FZN_RECORD_ID_LEN])
{
	size_t i;

	memset(out, 0x3d, FZN_RECORD_ID_LEN);
	for (i = 0; i < len; i++)
		out[i % FZN_RECORD_ID_LEN] = (uint8_t)((out[i % FZN_RECORD_ID_LEN] * 31u) ^ bytes[i]);
}

static inline int chain_stub_chain(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN],
                                   const fzn_sign_ops_t *sign, uint32_t kind,
                                   const uint8_t subject[FZN_SUBJECT_LEN], const uint8_t *body,
                                   size_t body_len, uint64_t now_ms, uint8_t *record,
                                   size_t cap, size_t *record_len)
{
	size_t i;

	(void)ctx;
	if (chain_stub.refuse)
		return 0;
	for (i = 0; i < chain_stub.count; i++)
		if (memcmp(chain_stub.issuer[i], issuer, FZN_PUBKEY_LEN) == 0)
			break;
	if (i == chain_stub.count) {
		if (i >= CHAIN_STUB_ISSUERS)
			return 0;
		memcpy(chain_stub.issuer[i], issuer, FZN_PUBKEY_LEN);
		chain_stub.seq[i] = 0;
		chain_stub.count++;
	}
	if (fzn_record_sign(issuer, subject, FZN_NOTE_STREAM, kind, chain_stub.seq[i] + 1u,
	                    chain_stub.seq[i] ? chain_stub.head[i] : NULL, now_ms, body, body_len,
	                    sign, record, cap, record_len)
	    != FZN_RECORD_OK)
		return 0;
	chain_stub.seq[i]++;
	chain_stub_digest(record, *record_len, chain_stub.head[i]);
	chain_stub.chained++;
	return 1;
}

/* An author's chain onto this stub. */
static inline void chain_stub_attach(fzn_notes_author_t *a)
{
	a->chain = chain_stub_chain;
	a->chain_ctx = NULL;
}

#endif /* FZN_NOTES_TEST_CHAIN_STUB_H */
