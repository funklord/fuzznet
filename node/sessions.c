/* The sessions a host granted. node/sessions.h says what and why. */

#include "sessions.h"

#include <stdlib.h>
#include <string.h>

#include "../wire/bytes.h"

#define HANDLE_AT FZN_SESSION_RANDOM_LEN
#define FIRST_CAP 8u

void fzn_node_sessions_drop(fzn_node_session_t *s)
{
	if (s)
		memset(s, 0, sizeof(*s));
}

/* A FREE SLOT, the table grown if there is none. Its index, or `SIZE_MAX`. */
static size_t free_slot(fzn_node_sessions_t *t)
{
	fzn_node_session_t *more;
	size_t i, cap;

	for (i = 0; i < t->cap; i++)
		if (!t->table[i].used)
			return i;
	cap = t->cap ? t->cap * 2u : FIRST_CAP;
	if (cap > (size_t)FZN_NODE_SESSION_SLOT_MASK + 1u)
		return SIZE_MAX;
	more = realloc(t->table, cap * sizeof(*more));
	if (!more)
		return SIZE_MAX;
	memset(more + t->cap, 0, (cap - t->cap) * sizeof(*more));
	t->table = more;
	i = t->cap;
	t->cap = cap;
	return i;
}

int fzn_node_sessions_grant(fzn_node_sessions_t *t, const uint8_t sender[FZN_PUBKEY_LEN],
                            const uint8_t capability[FZN_CAP_ID_LEN],
                            const uint8_t root[FZN_AEAD_KEY_LEN],
                            const uint8_t ask[FZN_SESSION_ASK_LEN], uint64_t now_ms,
                            const fzn_hash_ops_t *hash, const fzn_random_ops_t *rng,
                            uint8_t grant_out[FZN_SESSION_GRANT_LEN])
{
	fzn_node_session_t *s;
	uint32_t drawn;
	size_t i;

	if (!t || !sender || !capability || !root || !ask || !hash || !rng || !rng->fill
	    || !grant_out)
		return 0;
	for (i = 0; i < t->cap; i++) {
		s = &t->table[i];
		if (!s->used || s->confirmed || s->initiator
		    || memcmp(s->sender, sender, FZN_PUBKEY_LEN) != 0)
			continue;
		/* THE SAME ASK AGAIN: its answer was lost, and the first grant
		 * is the one it may yet hear. */
		if (memcmp(s->ask, ask, FZN_SESSION_ASK_LEN) == 0
		    && memcmp(s->root, root, FZN_AEAD_KEY_LEN) == 0) {
			memcpy(grant_out, s->grant, FZN_SESSION_GRANT_LEN);
			return 1;
		}
		/* ANOTHER: one unconfirmed a sender, the newest. */
		fzn_node_sessions_drop(s);
	}
	if ((i = free_slot(t)) == SIZE_MAX)
		return 0;
	s = &t->table[i];
	if (!rng->fill(rng->ctx, grant_out, FZN_SESSION_RANDOM_LEN)
	    || !rng->fill(rng->ctx, (uint8_t *)&drawn, sizeof(drawn)))
		return 0;
	fzn_put_be32(grant_out + HANDLE_AT,
	             (drawn & ~FZN_NODE_SESSION_SLOT_MASK) | (uint32_t)i);
	fzn_put_be64(grant_out + HANDLE_AT + 4u, now_ms);
	if (!fzn_session_end_derive(&s->end, hash, root, ask, grant_out, 0))
		return 0;
	memcpy(s->sender, sender, FZN_PUBKEY_LEN);
	memcpy(s->capability, capability, FZN_CAP_ID_LEN);
	memcpy(s->root, root, FZN_AEAD_KEY_LEN);
	memcpy(s->ask, ask, FZN_SESSION_ASK_LEN);
	memcpy(s->grant, grant_out, FZN_SESSION_GRANT_LEN);
	s->used = 1;
	s->confirmed = 0;
	return 1;
}

/* THIS HOST'S ASK OF `peer` STILL WAITING, or NULL. */
static fzn_node_session_t *asking(fzn_node_sessions_t *t, const uint8_t peer[FZN_PUBKEY_LEN])
{
	size_t i;

	for (i = 0; i < t->cap; i++)
		if (t->table[i].used && t->table[i].initiator && !t->table[i].confirmed
		    && memcmp(t->table[i].sender, peer, FZN_PUBKEY_LEN) == 0)
			return &t->table[i];
	return NULL;
}

int fzn_node_sessions_ask(fzn_node_sessions_t *t, const uint8_t peer[FZN_PUBKEY_LEN],
                          const uint8_t capability[FZN_CAP_ID_LEN],
                          const uint8_t root[FZN_AEAD_KEY_LEN], const fzn_random_ops_t *rng,
                          uint8_t ask_out[FZN_SESSION_ASK_LEN])
{
	fzn_node_session_t *s;
	uint32_t drawn;
	size_t i;

	if (!t || !peer || !capability || !root || !rng || !rng->fill || !ask_out)
		return 0;
	if ((s = asking(t, peer)) != NULL && memcmp(s->root, root, FZN_AEAD_KEY_LEN) == 0) {
		memcpy(ask_out, s->ask, FZN_SESSION_ASK_LEN);
		return 1;
	}
	if (s)
		fzn_node_sessions_drop(s);
	if ((i = free_slot(t)) == SIZE_MAX)
		return 0;
	s = &t->table[i];
	if (!rng->fill(rng->ctx, ask_out, FZN_SESSION_RANDOM_LEN)
	    || !rng->fill(rng->ctx, (uint8_t *)&drawn, sizeof(drawn)))
		return 0;
	fzn_put_be32(ask_out + HANDLE_AT, (drawn & ~FZN_NODE_SESSION_SLOT_MASK) | (uint32_t)i);
	memcpy(s->sender, peer, FZN_PUBKEY_LEN);
	memcpy(s->capability, capability, FZN_CAP_ID_LEN);
	memcpy(s->root, root, FZN_AEAD_KEY_LEN);
	memcpy(s->ask, ask_out, FZN_SESSION_ASK_LEN);
	/* FOUND BY ITS HANDLE before the grant comes, as `find` reads `hears_as`. */
	s->end.hears_as = fzn_get_be32(ask_out + HANDLE_AT);
	s->used = 1;
	s->initiator = 1;
	s->confirmed = 0;
	return 1;
}

int fzn_node_sessions_asked(fzn_node_sessions_t *t, const uint8_t peer[FZN_PUBKEY_LEN],
                            const uint8_t grant[FZN_SESSION_GRANT_LEN], const fzn_hash_ops_t *hash,
                            const uint8_t *to, unsigned to_len)
{
	fzn_node_session_t *s;

	if (!t || !peer || !grant || !hash || (to_len && !to) || to_len > sizeof(s->from)
	    || !(s = asking(t, peer)))
		return 0;
	if (!fzn_session_end_derive(&s->end, hash, s->root, s->ask, grant, 1)) {
		fzn_node_sessions_drop(s);
		return 0;
	}
	memcpy(s->grant, grant, FZN_SESSION_GRANT_LEN);
	if (to_len)
		memcpy(s->from, to, to_len);
	s->from_len = to_len;
	fzn_node_sessions_confirm(t, s);
	return 1;
}

fzn_node_session_t *fzn_node_sessions_find(fzn_node_sessions_t *t, uint32_t handle)
{
	size_t slot = handle & FZN_NODE_SESSION_SLOT_MASK;

	if (!t || slot >= t->cap || !t->table[slot].used || t->table[slot].end.hears_as != handle)
		return NULL;
	return &t->table[slot];
}

fzn_node_session_t *fzn_node_sessions_of(fzn_node_sessions_t *t,
                                         const uint8_t sender[FZN_PUBKEY_LEN])
{
	size_t i;

	if (!t || !sender)
		return NULL;
	for (i = 0; i < t->cap; i++)
		if (t->table[i].used && t->table[i].confirmed
		    && memcmp(t->table[i].sender, sender, FZN_PUBKEY_LEN) == 0)
			return &t->table[i];
	return NULL;
}

void fzn_node_sessions_confirm(fzn_node_sessions_t *t, fzn_node_session_t *s)
{
	size_t i;

	if (!t || !s || s->confirmed)
		return;
	for (i = 0; i < t->cap; i++) {
		fzn_node_session_t *other = &t->table[i];

		if (other != s && other->used
		    && memcmp(other->sender, s->sender, FZN_PUBKEY_LEN) == 0)
			fzn_node_sessions_drop(other);
	}
	s->confirmed = 1;
}

void fzn_node_sessions_release(fzn_node_sessions_t *t)
{
	if (!t)
		return;
	if (t->table)
		memset(t->table, 0, t->cap * sizeof(*t->table));
	free(t->table);
	t->table = NULL;
	t->cap = 0;
}
