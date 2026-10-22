/* Groups as a host uses them: project.md sec 626, and the header. */
#include "groups.h"

#include <stdio.h>
#include <string.h>

#include "../prekey/prekey.h"
#include "../session/box.h"

/* ---- names ---------------------------------------------------------------- */

#define NAME_VERSION 1u

fzn_contact_err_t fzn_node_group_name(const fzn_persist_ops_t *store,
                                      const uint8_t id[FZN_GROUP_ID_LEN],
                                      char name[FZN_CONTACT_NAME_MAX + 1u], size_t *len)
{
	uint8_t bytes[1u + FZN_CONTACT_NAME_MAX];
	size_t n = 0;

	if (!store || !store->load || !id || !name || !len)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_GROUP_LABEL, id, bytes, sizeof(bytes), &n))
		return FZN_CONTACT_ERR_ABSENT;
	if (n < 2u || bytes[0] != NAME_VERSION || !fzn_contact_name_ok((const char *)bytes + 1, n - 1u))
		return FZN_CONTACT_ERR_SHAPE;
	memcpy(name, bytes + 1, n - 1u);
	name[n - 1u] = '\0';
	*len = n - 1u;
	return FZN_CONTACT_OK;
}

/* A hex digit's value, or -1. */
static int hex_digit(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

fzn_contact_err_t fzn_node_group_find(const fzn_persist_ops_t *store, const char *name,
                                      size_t len, uint8_t id[FZN_GROUP_ID_LEN])
{
	static uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	char held[FZN_CONTACT_NAME_MAX + 1u];
	size_t n = 0, i, held_len = 0;

	uint8_t want[FZN_GROUP_ID_LEN];
	int by_id = 0;

	if (!store || !name || !id)
		return FZN_CONTACT_ERR_MALFORMED;
	/* THE GROUP'S ID AS 64 HEX, sec 647, which no name can be: names are
	 * this host's, at most 32 characters, and a client keys on the id. */
	if (len == FZN_GROUP_ID_LEN * 2u) {
		for (i = 0; i < FZN_GROUP_ID_LEN; i++) {
			int hi = hex_digit((unsigned char)name[2u * i]);
			int lo = hex_digit((unsigned char)name[2u * i + 1u]);

			if (hi < 0 || lo < 0)
				break;
			want[i] = (uint8_t)(hi * 16 + lo);
		}
		by_id = i == FZN_GROUP_ID_LEN;
	}
	if (!by_id && !fzn_contact_name_ok(name, len))
		return FZN_CONTACT_ERR_NAME;
	if (!store->list
	    || !store->list(store->ctx, FZN_PERSIST_GROUP_LABEL, (uint8_t *)ids, FZN_GROUPS_HELD_MAX,
	                    &n))
		return FZN_CONTACT_ERR_BACKEND;
	/* THE SAME GROUPS EITHER WAY: those this host names, so a group left,
	 * its name forgotten, is no more found by its id than by its name. */
	for (i = 0; i < n; i++)
		if (by_id ? memcmp(ids[i], want, FZN_GROUP_ID_LEN) == 0
		          : fzn_node_group_name(store, ids[i], held, &held_len) == FZN_CONTACT_OK
		                    && held_len == len && memcmp(held, name, len) == 0) {
			memcpy(id, ids[i], FZN_GROUP_ID_LEN);
			return FZN_CONTACT_OK;
		}
	return FZN_CONTACT_ERR_ABSENT;
}

fzn_contact_err_t fzn_node_group_rename(const fzn_persist_ops_t *store,
                                        const uint8_t id[FZN_GROUP_ID_LEN], const char *name,
                                        size_t len)
{
	uint8_t bytes[1u + FZN_CONTACT_NAME_MAX], other[FZN_GROUP_ID_LEN];
	fzn_contact_err_t err;

	if (!store || !store->save || !id || !name)
		return FZN_CONTACT_ERR_MALFORMED;
	if (!fzn_contact_name_ok(name, len))
		return FZN_CONTACT_ERR_NAME;
	err = fzn_node_group_find(store, name, len, other);
	if (err == FZN_CONTACT_OK && memcmp(other, id, FZN_GROUP_ID_LEN) != 0)
		return FZN_CONTACT_ERR_TAKEN;
	if (err != FZN_CONTACT_OK && err != FZN_CONTACT_ERR_ABSENT)
		return err;
	bytes[0] = NAME_VERSION;
	memcpy(bytes + 1, name, len);
	return store->save(store->ctx, FZN_PERSIST_GROUP_LABEL, id, bytes, 1u + len)
	               ? FZN_CONTACT_OK
	               : FZN_CONTACT_ERR_BACKEND;
}

/* ---- membership ----------------------------------------------------------- */

fzn_contact_err_t fzn_node_group_ids_of(const fzn_persist_ops_t *store,
                                        const uint8_t root[FZN_PUBKEY_LEN],
                                        uint8_t (*ids)[FZN_GROUP_ID_LEN], size_t cap,
                                        size_t *count)
{
	static uint8_t held[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	static fzn_group_t g;
	size_t n = 0, i;

	if (!store || !root || !ids || !count)
		return FZN_CONTACT_ERR_MALFORMED;
	*count = 0;
	if (fzn_group_log_list(store, held, FZN_GROUPS_HELD_MAX, &n) != FZN_GROUP_LOG_OK)
		return FZN_CONTACT_ERR_BACKEND;
	for (i = 0; i < n && *count < cap; i++)
		if (fzn_group_log_get(store, held[i], &g) == FZN_GROUP_LOG_OK
		    && fzn_group_is_member(&g, root))
			memcpy(ids[(*count)++], held[i], FZN_GROUP_ID_LEN);
	return FZN_CONTACT_OK;
}

int fzn_node_group_host_owner(const fzn_persist_ops_t *store, const uint8_t self[FZN_PUBKEY_LEN],
                              const uint8_t host[FZN_PUBKEY_LEN], uint8_t owner[FZN_PUBKEY_LEN])
{
	static uint8_t held[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	static fzn_group_t g;
	const fzn_group_host_t *h;
	size_t n = 0, i;

	if (!store || !self || !host || !owner
	    || fzn_group_log_list(store, held, FZN_GROUPS_HELD_MAX, &n) != FZN_GROUP_LOG_OK)
		return 0;
	for (i = 0; i < n; i++)
		/* A LISTED HOST'S OWNER IS A MEMBER: the log drops a member's
		 * hosts with its removal or leave, and lists none but a
		 * member's (`node/group_log.h`). */
		if (fzn_group_log_get(store, held[i], &g) == FZN_GROUP_LOG_OK
		    && fzn_group_is_member(&g, self) && (h = fzn_group_host(&g, host)) != NULL) {
			memcpy(owner, h->owner, FZN_PUBKEY_LEN);
			return 1;
		}
	return 0;
}

/* ---- acting --------------------------------------------------------------- */

static fzn_group_log_err_t act_with(const fzn_node_groups_t *g, uint8_t kind, const uint8_t *id,
                                    const uint8_t *subject, uint8_t setting, uint64_t value,
                                    const uint8_t *payload, size_t payload_len, uint8_t *made);

fzn_group_log_err_t fzn_node_groups_act(const fzn_node_groups_t *g, uint8_t kind,
                                        const uint8_t *id, const uint8_t subject[FZN_PUBKEY_LEN],
                                        uint8_t setting, uint64_t value,
                                        uint8_t made[FZN_GROUP_ID_LEN])
{
	return act_with(g, kind, id, subject, setting, value, NULL, 0u, made);
}

static fzn_group_log_err_t act_with(const fzn_node_groups_t *g, uint8_t kind, const uint8_t *id,
                                    const uint8_t *subject, uint8_t setting, uint64_t value,
                                    const uint8_t *payload, size_t payload_len, uint8_t *made)
{
	static fzn_group_act_t a;
	static fzn_group_t held;
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	fzn_group_offer_t did;
	size_t n = 0, dropped = 0;
	fzn_group_log_err_t err;

	if (!g || !g->log.store || !g->host_sign || !g->signer || !g->clock
	    || (!id && (!g->rng || !g->rng->fill)) || (id && !subject && kind != FZN_GROUP_ACT_SET)
	    || payload_len > FZN_GROUP_ACT_PAYLOAD_MAX || (payload_len && !payload))
		return FZN_GROUP_LOG_ERR_MALFORMED;
	memset(&a, 0, sizeof(a));
	a.kind = kind;
	if (payload_len)
		memcpy(a.payload, payload, payload_len);
	a.payload_len = payload_len;
	if (id) {
		err = fzn_group_log_get(g->log.store, id, &held);
		if (err != FZN_GROUP_LOG_OK)
			return err;
		memcpy(a.group, id, FZN_GROUP_ID_LEN);
		memcpy(a.prev, held.head, 32u);
		a.seq = held.seq;
		if (subject)
			memcpy(a.subject, subject, FZN_PUBKEY_LEN);
	} else if (kind != FZN_GROUP_ACT_CREATE
	           || !g->rng->fill(g->rng->ctx, a.subject, FZN_PUBKEY_LEN)) {
		return FZN_GROUP_LOG_ERR_MALFORMED;
	}
	a.setting = setting;
	a.value = value;
	a.at = g->clock();
	if (!g->signer(g->signer_ctx, &a.signer)
	    || fzn_group_act_sign(&a, g->host_sign) != FZN_GROUP_ACT_OK
	    || fzn_group_act_encode(&a, bytes, sizeof(bytes), &n) != FZN_GROUP_ACT_OK)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	err = fzn_group_log_offer(&g->log, bytes, n, &did, &dropped);
	if (err != FZN_GROUP_LOG_OK)
		return err;
	if (made && fzn_group_act_hash(&a, g->log.hash, made) != FZN_GROUP_ACT_OK)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	if (g->acted)
		g->acted(g->acted_ctx, id ? id : made);
	return FZN_GROUP_LOG_OK;
}

/* ---- epochs, sec 627 ----------------------------------------------------- */

#define SECRET_VERSION 1u

static int epoch_subject(const fzn_node_groups_t *g, const uint8_t *id, uint32_t epoch,
                         uint8_t out[FZN_PUBKEY_LEN])
{
	uint8_t in[FZN_GROUP_ID_LEN + 4u];

	memcpy(in, id, FZN_GROUP_ID_LEN);
	in[FZN_GROUP_ID_LEN] = (uint8_t)(epoch >> 24);
	in[FZN_GROUP_ID_LEN + 1u] = (uint8_t)(epoch >> 16);
	in[FZN_GROUP_ID_LEN + 2u] = (uint8_t)(epoch >> 8);
	in[FZN_GROUP_ID_LEN + 3u] = (uint8_t)epoch;
	return g->log.hash->hash(g->log.hash->ctx, out, FZN_PUBKEY_LEN, in, sizeof(in));
}

fzn_group_log_err_t fzn_node_groups_secret(const fzn_node_groups_t *g,
                                           const uint8_t id[FZN_GROUP_ID_LEN], uint32_t epoch,
                                           uint8_t out[FZN_GROUP_SECRET_LEN])
{
	uint8_t subject[FZN_PUBKEY_LEN], bytes[1u + FZN_GROUP_SECRET_LEN];
	size_t n = 0;

	if (!g || !g->log.store || !g->log.store->load || !g->log.hash || !id || !out)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	if (!epoch_subject(g, id, epoch, subject)
	    || !g->log.store->load(g->log.store->ctx, FZN_PERSIST_GROUP_EPOCH, subject, bytes,
	                           sizeof(bytes), &n))
		return FZN_GROUP_LOG_ERR_ABSENT;
	if (n != sizeof(bytes) || bytes[0] != SECRET_VERSION)
		return FZN_GROUP_LOG_ERR_BACKEND;
	memcpy(out, bytes + 1, FZN_GROUP_SECRET_LEN);
	memset(bytes, 0, sizeof(bytes));
	return FZN_GROUP_LOG_OK;
}

static int secret_keep(const fzn_node_groups_t *g, const uint8_t *id, uint32_t epoch,
                       const uint8_t *secret)
{
	uint8_t subject[FZN_PUBKEY_LEN], bytes[1u + FZN_GROUP_SECRET_LEN];
	int ok;

	bytes[0] = SECRET_VERSION;
	memcpy(bytes + 1, secret, FZN_GROUP_SECRET_LEN);
	ok = epoch_subject(g, id, epoch, subject)
	     && g->log.store->save(g->log.store->ctx, FZN_PERSIST_GROUP_EPOCH, subject, bytes,
	                           sizeof(bytes));
	memset(bytes, 0, sizeof(bytes));
	return ok;
}

/* EPOCH `epoch`'s SECRET AS HELD HERE, AND THE ONE THE GROUP COMMITTED TO:
 * a secret this host drew for an epoch whose commitment another host's
 * act fixed -- a fork lost -- is forgotten, so this host takes the right
 * one from its box rather than sealing the wrong one to others. */
static int secret_of(const fzn_node_groups_t *g, const fzn_group_t *held, uint32_t epoch,
                     uint8_t secret[FZN_GROUP_SECRET_LEN])
{
	uint8_t subject[FZN_PUBKEY_LEN], commit[32];
	const uint8_t *want = fzn_group_commit(held, epoch);

	if (!want || fzn_node_groups_secret(g, held->id, epoch, secret) != FZN_GROUP_LOG_OK)
		return 0;
	if (fzn_group_epoch_commit(g->log.hash, held->id, epoch, secret, commit)
	    && memcmp(commit, want, 32u) == 0)
		return 1;
	memset(secret, 0, FZN_GROUP_SECRET_LEN);
	if (g->log.store->remove && epoch_subject(g, held->id, epoch, subject))
		(void)g->log.store->remove(g->log.store->ctx, FZN_PERSIST_GROUP_EPOCH, subject);
	return 0;
}

static int secret_held(const fzn_node_groups_t *g, const fzn_group_t *held, uint32_t epoch)
{
	uint8_t secret[FZN_GROUP_SECRET_LEN];
	int ok = secret_of(g, held, epoch, secret);

	memset(secret, 0, sizeof(secret));
	return ok;
}

/* THE SECRETS SEALED TO THIS HOST and not yet opened here: every KEYS act
 * in the log read, this host's box opened, and the secret kept only when
 * it is the one the epoch committed to. */
static size_t take_secrets(const fzn_node_groups_t *g, const fzn_group_t *held,
                           const uint8_t *self)
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	static fzn_group_act_t a;
	uint8_t secret[FZN_GROUP_SECRET_LEN], commit[32];
	const uint8_t *want;
	size_t n = 0, i, opened, taken = 0;
	uint32_t s;

	for (s = 0; s < held->seq; s++) {
		if (fzn_group_log_act(&g->log, held->id, s, bytes, sizeof(bytes), &n) != FZN_GROUP_LOG_OK
		    || fzn_group_act_decode(bytes, n, &a) != FZN_GROUP_ACT_OK
		    || a.kind != FZN_GROUP_ACT_KEYS || a.value > 0xffffffffu)
			continue;
		want = fzn_group_commit(held, (uint32_t)a.value);
		if (!want || secret_held(g, held, (uint32_t)a.value))
			continue;
		for (i = 0; i + FZN_GROUP_KEY_ENTRY_LEN <= a.payload_len; i += FZN_GROUP_KEY_ENTRY_LEN) {
			if (memcmp(a.payload + i, self, FZN_PUBKEY_LEN) != 0
			    || fzn_box_open(g->agree_secret, g->agree, g->log.hash, g->aead,
			                    a.payload + i + FZN_PUBKEY_LEN, FZN_GROUP_KEY_BOX_LEN, secret,
			                    sizeof(secret), &opened)
			               != FZN_BOX_OK
			    || opened != sizeof(secret))
				continue;
			if (fzn_group_epoch_commit(g->log.hash, held->id, (uint32_t)a.value, secret, commit)
			    && memcmp(commit, want, 32u) == 0 && secret_keep(g, held->id, (uint32_t)a.value, secret))
				taken++;
			break;
		}
	}
	memset(secret, 0, sizeof(secret));
	return taken;
}

/* EPOCH `epoch`'s secret sealed to `n` hosts, in one KEYS act: each box to
 * the prekey its HOST act's signer carries. */
static fzn_group_log_err_t seal_keys(const fzn_node_groups_t *g, const fzn_group_t *held,
                                     uint32_t epoch, const uint8_t *secret, const uint8_t *commit,
                                     const fzn_group_host_t *const *to, size_t n)
{
	static uint8_t payload[FZN_GROUP_KEYS_PER_ACT * FZN_GROUP_KEY_ENTRY_LEN];
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	static fzn_group_act_t a;
	size_t i, len = 0, box_len = 0;

	for (i = 0; i < n && i < FZN_GROUP_KEYS_PER_ACT; i++) {
		uint8_t *entry = payload + i * FZN_GROUP_KEY_ENTRY_LEN;

		if (fzn_group_log_act(&g->log, held->id, to[i]->seq, bytes, sizeof(bytes), &len)
		            != FZN_GROUP_LOG_OK
		    || fzn_group_act_decode(bytes, len, &a) != FZN_GROUP_ACT_OK
		    || memcmp(fzn_contact_device_key(&a.signer), to[i]->key, FZN_PUBKEY_LEN) != 0
		    || fzn_box_seal(g->agree, g->log.hash, g->aead, g->rng,
		                    a.signer.record + FZN_PREKEY_OFF_PREKEY, secret, FZN_GROUP_SECRET_LEN,
		                    entry + FZN_PUBKEY_LEN, FZN_GROUP_KEY_BOX_LEN, &box_len)
		               != FZN_BOX_OK
		    || box_len != FZN_GROUP_KEY_BOX_LEN)
			return FZN_GROUP_LOG_ERR_MALFORMED;
		memcpy(entry, to[i]->key, FZN_PUBKEY_LEN);
	}
	return act_with(g, FZN_GROUP_ACT_KEYS, held->id, commit, 0u, epoch, payload,
	                i * FZN_GROUP_KEY_ENTRY_LEN, NULL);
}

/* How many backfill acts one tend makes at most: the rest next time. */
#define BACKFILL_PER_TEND 8u

fzn_group_log_err_t fzn_node_groups_tend(const fzn_node_groups_t *g,
                                         const uint8_t id[FZN_GROUP_ID_LEN], size_t *made)
{
	static fzn_group_t held;
	static fzn_contact_device_t own;
	static const fzn_group_host_t *to[FZN_GROUP_KEYS_PER_ACT];
	uint8_t secret[FZN_GROUP_SECRET_LEN], commit[32];
	const uint8_t *self;
	fzn_group_log_err_t err;
	size_t n, i, round;
	uint32_t cur;

	if (!g || !id || !made || !g->agree || !g->aead || !g->agree_secret || !g->rng
	    || !g->signer)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	*made = 0;
	err = fzn_group_log_get(g->log.store, id, &held);
	if (err != FZN_GROUP_LOG_OK)
		return err;
	if (!g->signer(g->signer_ctx, &own) || !fzn_group_is_member(&held, own.owner))
		return FZN_GROUP_LOG_OK;
	self = fzn_contact_device_key(&own);
	/* NAMED AMONG ITS HOSTS. */
	if (!fzn_group_host(&held, self)) {
		err = fzn_node_groups_act(g, FZN_GROUP_ACT_HOST, id, own.owner, 0u, 0u, NULL);
		if (err != FZN_GROUP_LOG_OK)
			return err;
		(*made)++;
		if (fzn_group_log_get(g->log.store, id, &held) != FZN_GROUP_LOG_OK)
			return FZN_GROUP_LOG_ERR_BACKEND;
	}
	(void)take_secrets(g, &held, self);
	cur = held.epoch;
	/* THE CURRENT EPOCH: drawn here if nobody has, else sealed to whoever
	 * lacks it, when this host holds it. */
	if (!fzn_group_commit(&held, cur)) {
		if (!g->rng->fill(g->rng->ctx, secret, sizeof(secret))
		    || !fzn_group_epoch_commit(g->log.hash, id, cur, secret, commit)
		    || !secret_keep(g, id, cur, secret))
			return FZN_GROUP_LOG_ERR_BACKEND;
		for (i = 0, n = 0; i < held.n_hosts && n < FZN_GROUP_KEYS_PER_ACT; i++)
			to[n++] = &held.hosts[i];
		err = seal_keys(g, &held, cur, secret, commit, to, n);
		memset(secret, 0, sizeof(secret));
		if (err != FZN_GROUP_LOG_OK)
			return err;
		(*made)++;
		if (fzn_group_log_get(g->log.store, id, &held) != FZN_GROUP_LOG_OK)
			return FZN_GROUP_LOG_ERR_BACKEND;
	}
	if (secret_of(g, &held, cur, secret)) {
		for (i = 0, n = 0; i < held.n_hosts && n < FZN_GROUP_KEYS_PER_ACT; i++)
			if (held.hosts[i].keyed_epoch != cur)
				to[n++] = &held.hosts[i];
		err = n ? seal_keys(g, &held, cur, secret, fzn_group_commit(&held, cur), to, n)
		        : FZN_GROUP_LOG_OK;
		memset(secret, 0, sizeof(secret));
		if (err != FZN_GROUP_LOG_OK)
			return err;
		if (n) {
			(*made)++;
			if (fzn_group_log_get(g->log.store, id, &held) != FZN_GROUP_LOG_OK)
				return FZN_GROUP_LOG_ERR_BACKEND;
		}
	}
	/* BACKFILL, newest first: the epoch before the oldest a host holds,
	 * to every host at that same point, while this host holds it. */
	for (round = 0; held.backfill && round < BACKFILL_PER_TEND; round++) {
		uint32_t e = 0;

		for (i = 0; i < held.n_hosts; i++) {
			uint32_t want = held.hosts[i].backfilled_to - 1u;

			if (held.hosts[i].backfilled_to > 1u && want > e && fzn_group_commit(&held, want)
			    && secret_held(g, &held, want))
				e = want;
		}
		if (!e || !secret_of(g, &held, e, secret))
			break;
		for (i = 0, n = 0; i < held.n_hosts && n < FZN_GROUP_KEYS_PER_ACT; i++)
			if (held.hosts[i].backfilled_to == e + 1u)
				to[n++] = &held.hosts[i];
		err = seal_keys(g, &held, e, secret, fzn_group_commit(&held, e), to, n);
		memset(secret, 0, sizeof(secret));
		if (err != FZN_GROUP_LOG_OK)
			return err;
		(*made)++;
		if (fzn_group_log_get(g->log.store, id, &held) != FZN_GROUP_LOG_OK)
			return FZN_GROUP_LOG_ERR_BACKEND;
	}
	return FZN_GROUP_LOG_OK;
}

/* ---- the verbs ------------------------------------------------------------ */

static int next_word(const uint8_t **rest, size_t *rest_len, const uint8_t **w, size_t *w_len)
{
	size_t i = 0;

	while (*rest_len && **rest == ' ') {
		(*rest)++;
		(*rest_len)--;
	}
	if (!*rest_len)
		return 0;
	while (i < *rest_len && (*rest)[i] != ' ')
		i++;
	*w = *rest;
	*w_len = i;
	*rest += i;
	*rest_len -= i;
	return 1;
}

static int is_word(const uint8_t *w, size_t len, const char *want)
{
	return len == strlen(want) && memcmp(w, want, len) == 0;
}

static size_t answer(char *reply, size_t cap, fzn_reply_t kind, const char *detail,
                     size_t detail_len)
{
	size_t len = 0;

	if (fzn_reply_compose((uint8_t *)reply, cap, &len, kind, (const uint8_t *)detail,
	                      detail_len) != FZN_COMPOSE_OK)
		return 0;
	return len;
}

static size_t say(char *reply, size_t cap, fzn_reply_t kind, const char *detail)
{
	return answer(reply, cap, kind, detail, detail ? strlen(detail) : 0u);
}

static size_t log_refusal(char *reply, size_t cap, fzn_group_log_err_t err)
{
	return say(reply, cap,
	           err == FZN_GROUP_LOG_ERR_DENIED   ? FZN_REPLY_DENIED
	           : err == FZN_GROUP_LOG_ERR_MALFORMED ? FZN_REPLY_MALFORMED
	                                              : FZN_REPLY_ERROR,
	           fzn_group_log_err_str(err));
}

static size_t contact_refusal(char *reply, size_t cap, fzn_contact_err_t err)
{
	return say(reply, cap, err == FZN_CONTACT_ERR_NAME ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
	           fzn_contact_err_str(err));
}

static void hex_of(const uint8_t *in, size_t n, char *out)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2u * i] = digits[in[i] >> 4];
		out[2u * i + 1u] = digits[in[i] & 15u];
	}
}

/* `add group NAME`: a group made and named. */
static size_t make_group(const fzn_node_groups_t *g, const uint8_t *name, size_t name_len,
                         char *reply, size_t cap)
{
	uint8_t id[FZN_GROUP_ID_LEN];
	fzn_contact_err_t cerr;
	fzn_group_log_err_t err;

	if (!fzn_contact_name_ok((const char *)name, name_len))
		return contact_refusal(reply, cap, FZN_CONTACT_ERR_NAME);
	cerr = fzn_node_group_find(g->log.store, (const char *)name, name_len, id);
	if (cerr == FZN_CONTACT_OK)
		return contact_refusal(reply, cap, FZN_CONTACT_ERR_TAKEN);
	if (cerr != FZN_CONTACT_ERR_ABSENT)
		return contact_refusal(reply, cap, cerr);
	err = fzn_node_groups_act(g, FZN_GROUP_ACT_CREATE, NULL, NULL, 0u, 0u, id);
	if (err != FZN_GROUP_LOG_OK)
		return log_refusal(reply, cap, err);
	cerr = fzn_node_group_rename(g->log.store, id, (const char *)name, name_len);
	if (cerr != FZN_CONTACT_OK)
		return contact_refusal(reply, cap, cerr);
	/* ITS ID SAID, sec 648: what a client keys on from the start. */
	{
		char id_hex[FZN_GROUP_ID_LEN * 2u + 1u];

		hex_of(id, FZN_GROUP_ID_LEN, id_hex);
		id_hex[FZN_GROUP_ID_LEN * 2u] = '\0';
		return say(reply, cap, FZN_REPLY_OK, id_hex);
	}
}

/* `remove group NAME`: left, if this user is still in it, and forgotten
 * here -- its shares first, as sec 478 has it, then its name. THE LOG
 * STAYS while others are in the group: the leave is an act of this host's
 * that the others learn by asking it, so it is served on, unnamed and out
 * of `list group`. A group nobody else is in goes whole. The last admin
 * of a group others are in may not leave, and so may not forget it
 * either: another admin is made first. */
static size_t forget_group(const fzn_node_groups_t *g, const uint8_t *id, char *reply,
                           size_t cap)
{
	static fzn_group_t held;
	static fzn_contact_device_t self;
	uint8_t subject[FZN_PUBKEY_LEN], in[FZN_GROUP_ID_LEN + 4u];
	fzn_group_log_err_t err;
	uint32_t s;
	int alone;

	err = fzn_group_log_get(g->log.store, id, &held);
	if (err != FZN_GROUP_LOG_OK)
		return log_refusal(reply, cap, err);
	if (!g->signer(g->signer_ctx, &self))
		return say(reply, cap, FZN_REPLY_ERROR, "this host cannot act for its user");
	alone = held.n_members == 0u
	        || (held.n_members == 1u && fzn_group_is_member(&held, self.owner));
	if (!alone && fzn_group_is_member(&held, self.owner)) {
		err = fzn_node_groups_act(g, FZN_GROUP_ACT_LEAVE, id, self.owner, 0u, 0u, NULL);
		/* THE LAST ADMIN'S LEAVE, refused by the log's own judgement: said
		 * with the two ways out, as fuzzypickles found the bare refusal
		 * left a person with none (sec 688). */
		if (err == FZN_GROUP_LOG_ERR_DENIED && fzn_group_is_admin(&held, self.owner)
		    && held.n_admins == 1u)
			return say(reply, cap, FZN_REPLY_DENIED,
			           "the last admin may not leave while others are in the group: make "
			           "another member an admin, or remove the others, first");
		if (err != FZN_GROUP_LOG_OK)
			return log_refusal(reply, cap, err);
	}
	if (g->forget && !g->forget(g->forget_ctx, id))
		return say(reply, cap, FZN_REPLY_ERROR, "the group's shares would not all go, so it stays");
	if (!g->log.store->remove)
		return say(reply, cap, FZN_REPLY_ERROR, "this store cannot forget");
	(void)g->log.store->remove(g->log.store->ctx, FZN_PERSIST_GROUP_LABEL, id);
	if (!alone)
		return say(reply, cap, FZN_REPLY_OK, NULL);
	(void)g->log.store->remove(g->log.store->ctx, FZN_PERSIST_GROUP, id);
	for (s = 0; s < held.seq; s++) {
		memcpy(in, id, FZN_GROUP_ID_LEN);
		in[FZN_GROUP_ID_LEN] = (uint8_t)(s >> 24);
		in[FZN_GROUP_ID_LEN + 1u] = (uint8_t)(s >> 16);
		in[FZN_GROUP_ID_LEN + 2u] = (uint8_t)(s >> 8);
		in[FZN_GROUP_ID_LEN + 3u] = (uint8_t)s;
		if (g->log.hash->hash(g->log.hash->ctx, subject, FZN_PUBKEY_LEN, in, sizeof(in)))
			(void)g->log.store->remove(g->log.store->ctx, FZN_PERSIST_GROUP_ACT, subject);
	}
	return say(reply, cap, FZN_REPLY_OK, NULL);
}

/* `list group [FROM]`: `ok TOTAL FROM NAME,COUNT ...`, a page at a time, a
 * group this host has not named by its id's first 8 bytes in hex. */
static size_t list_groups(const fzn_node_groups_t *g, const uint8_t *rest, size_t rest_len,
                          char *reply, size_t cap)
{
	static uint8_t ids[FZN_GROUPS_HELD_MAX][FZN_GROUP_ID_LEN];
	static fzn_group_t held;
	static fzn_contact_device_t self;
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	size_t count = 0, from = 0, used, i, kept;
	int have_self;
	const uint8_t *w;
	size_t w_len;
	int n;

	if (next_word(&rest, &rest_len, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_GROUPS_HELD_MAX)
				return say(reply, cap, FZN_REPLY_MALFORMED, "not an index");
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	if (fzn_group_log_list(g->log.store, ids, FZN_GROUPS_HELD_MAX, &count) != FZN_GROUP_LOG_OK)
		return say(reply, cap, FZN_REPLY_ERROR, "the groups did not read");
	/* ONLY THE GROUPS THIS USER IS IN: one left is kept to serve its leave,
	 * and is no longer this user's to list. */
	have_self = g->signer && g->signer(g->signer_ctx, &self);
	for (i = 0, kept = 0; i < count; i++)
		if (fzn_group_log_get(g->log.store, ids[i], &held) == FZN_GROUP_LOG_OK
		    && (!have_self || fzn_group_is_member(&held, self.owner)))
			memmove(ids[kept++], ids[i], FZN_GROUP_ID_LEN);
	count = kept;
	if (from > count)
		return say(reply, cap, FZN_REPLY_MALFORMED, "past the last group");
	n = snprintf(detail, sizeof(detail), "%zu %zu", count, from);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = from; i < count; i++) {
		char name[FZN_CONTACT_NAME_MAX + 1u], item[FZN_CONTACT_NAME_MAX + 16u + 65u];
		char id_hex[FZN_GROUP_ID_LEN * 2u + 1u];
		size_t name_len = 0;
		int k;

		if (fzn_group_log_get(g->log.store, ids[i], &held) != FZN_GROUP_LOG_OK)
			continue;
		if (fzn_node_group_name(g->log.store, ids[i], name, &name_len) != FZN_CONTACT_OK) {
			hex_of(ids[i], 8u, name);
			name[16] = '\0';
		}
		/* ITS ID LAST, sec 647: what a client keys on, a name being this
		 * host's alone. */
		hex_of(ids[i], FZN_GROUP_ID_LEN, id_hex);
		id_hex[FZN_GROUP_ID_LEN * 2u] = '\0';
		k = snprintf(item, sizeof(item), " %s,%zu,%s", name, held.n_members, id_hex);
		if (k < 0 || limit - used < (size_t)k)
			break;
		memcpy(detail + used, item, (size_t)k);
		used += (size_t)k;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

/* `get group NAME`: `ok COUNT MEMBER ...`, by contact name -- a member this
 * host has no contact for by its root's hex, and an admin marked `*`. */
static size_t get_group(const fzn_node_groups_t *g, const uint8_t *id, char *reply, size_t cap)
{
	static fzn_group_t held;
	static char detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap), used, i;
	int n;

	if (fzn_group_log_get(g->log.store, id, &held) != FZN_GROUP_LOG_OK)
		return say(reply, cap, FZN_REPLY_ERROR, "the group did not read");
	n = snprintf(detail, sizeof(detail), "%zu", held.n_members);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = 0; i < held.n_members; i++) {
		fzn_contact_t c;
		char who[1u + (FZN_PUBKEY_LEN * 2u)];
		size_t who_len = 0;

		if (fzn_group_is_admin(&held, held.members[i]))
			who[who_len++] = '*';
		if (fzn_contact_get(g->log.store, held.members[i], &c) == FZN_CONTACT_OK) {
			memcpy(who + who_len, c.name, c.name_len);
			who_len += c.name_len;
		} else {
			hex_of(held.members[i], FZN_PUBKEY_LEN, who + who_len);
			who_len += FZN_PUBKEY_LEN * 2u;
		}
		if (limit - used < 1u + who_len)
			break;
		detail[used++] = ' ';
		memcpy(detail + used, who, who_len);
		used += who_len;
	}
	return answer(reply, cap, FZN_REPLY_OK, detail, used);
}

size_t fzn_node_groups_local(const fzn_node_groups_t *g, const fzn_request_t *request,
                             char *reply, size_t cap)
{
	const uint8_t *rest, *subject, *name = NULL, *other = NULL, *value = NULL;
	size_t rest_len, subject_len, name_len = 0, other_len = 0, value_len = 0;
	uint8_t id[FZN_GROUP_ID_LEN];
	fzn_contact_t contact;
	fzn_contact_err_t cerr;
	fzn_group_log_err_t err;
	uint8_t kind;
	int add;

	if (!g || !request || !request->arg)
		return 0;
	rest = request->arg;
	rest_len = request->arg_len;
	if (!next_word(&rest, &rest_len, &subject, &subject_len))
		return 0;
	add = request->parsed == FZN_VERB_ADD;
	if (is_word(subject, subject_len, "group")) {
		if (request->parsed == FZN_VERB_LIST)
			return list_groups(g, rest, rest_len, reply, cap);
		if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_REMOVE
		    && request->parsed != FZN_VERB_GET && request->parsed != FZN_VERB_SET)
			return 0;
	} else if (is_word(subject, subject_len, "epoch")) {
		if (request->parsed != FZN_VERB_GET)
			return 0;
	} else if (is_word(subject, subject_len, "member") || is_word(subject, subject_len, "admin")) {
		if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_REMOVE)
			return 0;
	} else {
		return 0;
	}
	(void)next_word(&rest, &rest_len, &name, &name_len);
	(void)next_word(&rest, &rest_len, &other, &other_len);
	(void)next_word(&rest, &rest_len, &value, &value_len);
	if (!name)
		return say(reply, cap, FZN_REPLY_MALFORMED, "name the group");
	if (is_word(subject, subject_len, "group") && add)
		return make_group(g, name, name_len, reply, cap);
	cerr = fzn_node_group_find(g->log.store, (const char *)name, name_len, id);
	if (cerr != FZN_CONTACT_OK)
		return contact_refusal(reply, cap, cerr);
	/* `get epoch GROUP`: `ok EPOCH held` or `ok EPOCH none` -- whether this
	 * host holds the current epoch's secret, never the secret. */
	if (is_word(subject, subject_len, "epoch")) {
		static fzn_group_t held;
		char detail[32];
		int k;

		if (fzn_group_log_get(g->log.store, id, &held) != FZN_GROUP_LOG_OK)
			return say(reply, cap, FZN_REPLY_ERROR, "the group did not read");
		k = snprintf(detail, sizeof(detail), "%lu %s", (unsigned long)held.epoch,
		             g->log.hash && secret_held(g, &held, held.epoch) ? "held" : "none");
		return answer(reply, cap, FZN_REPLY_OK, detail, k > 0 ? (size_t)k : 0u);
	}
	if (is_word(subject, subject_len, "group")) {
		if (request->parsed == FZN_VERB_GET)
			return get_group(g, id, reply, cap);
		if (request->parsed == FZN_VERB_REMOVE)
			return forget_group(g, id, reply, cap);
		/* `set group GROUP backfill 0|1`. */
		if (!other || !is_word(other, other_len, "backfill") || !value || value_len != 1u
		    || (value[0] != '0' && value[0] != '1'))
			return say(reply, cap, FZN_REPLY_MALFORMED, "set group GROUP backfill 0|1");
		err = fzn_node_groups_act(g, FZN_GROUP_ACT_SET, id, NULL, FZN_GROUP_SETTING_BACKFILL,
		                          (uint64_t)(value[0] - '0'), NULL);
		return err == FZN_GROUP_LOG_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
		                               : log_refusal(reply, cap, err);
	}
	if (!other)
		return say(reply, cap, FZN_REPLY_MALFORMED, "name the contact");
	cerr = fzn_contact_find(g->log.store, (const char *)other, other_len, &contact);
	if (cerr != FZN_CONTACT_OK)
		return contact_refusal(reply, cap, cerr);
	if (is_word(subject, subject_len, "member"))
		kind = add ? FZN_GROUP_ACT_ADD : FZN_GROUP_ACT_REMOVE;
	else
		kind = add ? FZN_GROUP_ACT_ADMIN_ADD : FZN_GROUP_ACT_ADMIN_REMOVE;
	err = fzn_node_groups_act(g, kind, id, contact.key, 0u, 0u, NULL);
	return err == FZN_GROUP_LOG_OK ? say(reply, cap, FZN_REPLY_OK, NULL)
	                               : log_refusal(reply, cap, err);
}
