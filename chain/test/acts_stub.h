/* A KEY'S ACTS, AS A TEST CHAINS THEM: what `fzn_act_log_ops_t` asks, with
 * no node behind it. project.md sec 509.
 *
 * Until sec 509 a chain-level test asked `chain/root_log`'s log, the one
 * implementation of these ops this library had. The node's journal answers
 * them now (sec 506) and the log is gone, but a cut is still a question the
 * revocation store, the root set and the roster ask, and their suites still
 * need something to answer it.
 *
 * So this answers it the way the journal does: an entry names its key, the
 * act it logs and the entry before it, and an act stands under a cut when it
 * is the cut or is reached from it by following `prev` within one key. A
 * second entry naming the same predecessor is a fork, and stands under
 * neither branch's cut but its own. Nothing is signed: what is under test is
 * the store asking, not the log answering.
 *
 * Header-only and static, so each suite that includes it has its own copy
 * and none of it reaches the library.
 */

#ifndef FZN_CHAIN_TEST_ACTS_STUB_H
#define FZN_CHAIN_TEST_ACTS_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../revocation.h"

#define ACTS_STUB_MAX 16u
#define ACTS_STUB_ID_LEN 32u

typedef struct acts_stub_entry {
	uint8_t key[FZN_PUBKEY_LEN];
	uint8_t id[ACTS_STUB_ID_LEN];
	uint8_t prev[ACTS_STUB_ID_LEN];
	uint8_t act[ACTS_STUB_ID_LEN];
} acts_stub_entry_t;

typedef struct acts_stub {
	acts_stub_entry_t entries[ACTS_STUB_MAX];
	size_t used;
} acts_stub_t;

/* An id no two entries share: a mix of the key, the predecessor, the act and
 * the entry's place. */
static void acts_stub_id(const acts_stub_t *s, const uint8_t *key, const uint8_t *prev,
                         const uint8_t *act, uint8_t out[ACTS_STUB_ID_LEN])
{
	uint64_t h = 0xcbf29ce484222325ull ^ (uint64_t)s->used;
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		h = (h ^ key[i]) * 0x100000001b3ull;
	for (i = 0; i < ACTS_STUB_ID_LEN; i++)
		h = (h ^ (prev ? prev[i] : 0u) ^ act[i]) * 0x100000001b3ull;
	for (i = 0; i < ACTS_STUB_ID_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

/* `key` logs `act` (the hash of the act's record) after the entry `prev`, or
 * first with NULL. The new entry's id into `id`. 1 when there was room. */
static int acts_stub_log(acts_stub_t *s, const uint8_t key[FZN_PUBKEY_LEN],
                         const uint8_t prev[ACTS_STUB_ID_LEN],
                         const uint8_t act[ACTS_STUB_ID_LEN], uint8_t id[ACTS_STUB_ID_LEN])
{
	acts_stub_entry_t *e;

	if (s->used >= ACTS_STUB_MAX)
		return 0;
	e = &s->entries[s->used];
	memcpy(e->key, key, FZN_PUBKEY_LEN);
	if (prev)
		memcpy(e->prev, prev, ACTS_STUB_ID_LEN);
	else
		memset(e->prev, 0, ACTS_STUB_ID_LEN);
	memcpy(e->act, act, ACTS_STUB_ID_LEN);
	acts_stub_id(s, key, prev, act, e->id);
	memcpy(id, e->id, ACTS_STUB_ID_LEN);
	s->used++;
	return 1;
}

static const acts_stub_entry_t *acts_stub_by_id(const acts_stub_t *s,
                                                const uint8_t key[FZN_PUBKEY_LEN],
                                                const uint8_t id[ACTS_STUB_ID_LEN])
{
	size_t i;

	for (i = 0; i < s->used; i++)
		if (memcmp(s->entries[i].key, key, FZN_PUBKEY_LEN) == 0
		    && memcmp(s->entries[i].id, id, ACTS_STUB_ID_LEN) == 0)
			return &s->entries[i];
	return NULL;
}

/* The question: the cut, or an entry `prev` reaches from it, logs `act`. */
static int acts_stub_stands(void *ctx, const uint8_t key[FZN_PUBKEY_LEN],
                            const uint8_t cut[FZN_REVOCATION_ID_LEN],
                            const uint8_t act[FZN_REVOCATION_ID_LEN])
{
	const acts_stub_t *s = (const acts_stub_t *)ctx;
	const acts_stub_entry_t *e = acts_stub_by_id(s, key, cut);
	size_t steps = 0;

	while (e && steps++ <= ACTS_STUB_MAX) {
		if (memcmp(e->act, act, ACTS_STUB_ID_LEN) == 0)
			return 1;
		e = acts_stub_by_id(s, key, e->prev);
	}
	return 0;
}

static void acts_stub_ops(acts_stub_t *s, fzn_act_log_ops_t *ops)
{
	ops->stands = acts_stub_stands;
	ops->ctx = s;
}

#endif /* FZN_CHAIN_TEST_ACTS_STUB_H */
