/* See stage.h. */

#include "stage.h"

#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

/* HOW MANY HELD AT ONCE: each is an admin's or a root's act, so this bounds
 * what those few may leave pending, not what a stranger may. */
#define STAGE_HELD_MAX 1024u

int fzn_stage_issue(const uint8_t setter[FZN_PUBKEY_LEN], const fzn_sign_ops_t *sign, uint8_t act,
                    const uint8_t token[FZN_STAGE_TOKEN_LEN], uint64_t deadline_ms,
                    const uint8_t *revert, size_t revert_len, uint8_t *out, size_t *len)
{
	size_t at = 0;

	if (!setter || !sign || !sign->sign || !token || !out || !len
	    || (act != FZN_STAGE_ACT_STAGE && act != FZN_STAGE_ACT_CONFIRM)
	    || (act == FZN_STAGE_ACT_STAGE && (!revert || !revert_len || !deadline_ms))
	    || (act == FZN_STAGE_ACT_CONFIRM && (revert_len || deadline_ms))
	    || revert_len > FZN_STAGE_REVERT_MAX)
		return 0;
	out[at++] = (uint8_t)FZN_SIGNED_VERSION;
	out[at++] = (uint8_t)FZN_OBJECT_STAGE;
	memcpy(out + at, setter, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	out[at++] = act;
	memcpy(out + at, token, FZN_STAGE_TOKEN_LEN);
	at += FZN_STAGE_TOKEN_LEN;
	fzn_put_be64(out + at, deadline_ms);
	at += 8u;
	fzn_put_be16(out + at, (uint16_t)revert_len);
	at += 2u;
	if (revert_len)
		memcpy(out + at, revert, revert_len);
	at += revert_len;
	if (!sign->sign(sign->ctx, out + at, out, at))
		return 0;
	*len = at + (size_t)FZN_SIG_LEN;
	return 1;
}

int fzn_stage_open(const uint8_t *bytes, size_t len, const fzn_sign_ops_t *verify,
                   fzn_stage_t *out)
{
	size_t rl;

	if (!bytes || !verify || !verify->verify || !out || len < FZN_STAGE_HEAD + FZN_SIG_LEN
	    || len > FZN_STAGE_MAX || bytes[0] != (uint8_t)FZN_SIGNED_VERSION
	    || bytes[1] != (uint8_t)FZN_OBJECT_STAGE)
		return 0;
	rl = fzn_get_be16(bytes + FZN_STAGE_HEAD - 2u);
	if (len != FZN_STAGE_HEAD + rl + FZN_SIG_LEN || rl > FZN_STAGE_REVERT_MAX)
		return 0;
	out->setter = bytes + FZN_STAGE_OFF_SETTER;
	out->act = bytes[2u + FZN_PUBKEY_LEN];
	out->token = bytes + 3u + FZN_PUBKEY_LEN;
	out->deadline_ms = fzn_get_be64(bytes + 3u + FZN_PUBKEY_LEN + FZN_STAGE_TOKEN_LEN);
	out->revert = rl ? bytes + FZN_STAGE_HEAD : NULL;
	out->revert_len = rl;
	if ((out->act == FZN_STAGE_ACT_STAGE && (!rl || !out->deadline_ms))
	    || (out->act == FZN_STAGE_ACT_CONFIRM && (rl || out->deadline_ms))
	    || (out->act != FZN_STAGE_ACT_STAGE && out->act != FZN_STAGE_ACT_CONFIRM))
		return 0;
	return verify->verify(verify->ctx, out->setter, bytes, len - (size_t)FZN_SIG_LEN,
	                      bytes + len - (size_t)FZN_SIG_LEN);
}

static void key_of(const uint8_t setter[FZN_PUBKEY_LEN], const uint8_t token[FZN_STAGE_TOKEN_LEN],
                   uint8_t key[FZN_PUBKEY_LEN])
{
	memcpy(key, token, FZN_STAGE_TOKEN_LEN);
	memcpy(key + FZN_STAGE_TOKEN_LEN, setter, FZN_PUBKEY_LEN - FZN_STAGE_TOKEN_LEN);
}

int fzn_stage_hold(const fzn_persist_ops_t *store, const uint8_t *bytes, size_t len,
                   const fzn_stage_t *s)
{
	uint8_t key[FZN_PUBKEY_LEN];

	if (!store || !store->save || !bytes || !s || s->act != FZN_STAGE_ACT_STAGE)
		return 0;
	key_of(s->setter, s->token, key);
	return store->save(store->ctx, FZN_PERSIST_STAGE, key, bytes, len);
}

int fzn_stage_drop(const fzn_persist_ops_t *store, const uint8_t setter[FZN_PUBKEY_LEN],
                   const uint8_t token[FZN_STAGE_TOKEN_LEN])
{
	uint8_t key[FZN_PUBKEY_LEN];

	if (!store || !store->remove || !setter || !token)
		return 0;
	key_of(setter, token, key);
	return store->remove(store->ctx, FZN_PERSIST_STAGE, key);
}

long fzn_stage_each(const fzn_persist_ops_t *store, const fzn_sign_ops_t *verify,
                    void (*each)(void *ctx, const uint8_t *bytes, size_t len,
                                 const fzn_stage_t *s),
                    void *ctx)
{
	static uint8_t keys[STAGE_HELD_MAX * FZN_PUBKEY_LEN];
	static uint8_t bytes[FZN_STAGE_MAX];
	size_t n = 0, i, len;
	long walked = 0;

	if (!store || !store->list || !store->load || !verify || !each
	    || !store->list(store->ctx, FZN_PERSIST_STAGE, keys, STAGE_HELD_MAX, &n))
		return -1;
	for (i = 0; i < n; i++) {
		fzn_stage_t s;

		len = 0;
		if (!store->load(store->ctx, FZN_PERSIST_STAGE, keys + i * FZN_PUBKEY_LEN, bytes,
		                 sizeof(bytes), &len)
		    || !fzn_stage_open(bytes, len, verify, &s))
			continue;
		each(ctx, bytes, len, &s);
		walked++;
	}
	return walked;
}
