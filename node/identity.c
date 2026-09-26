/* See identity.h. */

#include "identity.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* Diagnostics through flog, vendored and possibly absent. sec 209. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define IDENTITY_LOG(env, sub, sev, ...)                                                   \
	do {                                                                               \
		if ((env) && (env)->log)                                                   \
			flog_printf((env)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);      \
	} while (0)
#else
#define IDENTITY_LOG(env, sub, sev, ...) ((void)0)
#endif

const char *fzn_node_identity_err_str(fzn_node_identity_err_t err)
{
	switch (err) {
	case FZN_NODE_IDENTITY_OK:
		return "ok";
	case FZN_NODE_IDENTITY_MALFORMED:
		return "malformed";
	case FZN_NODE_IDENTITY_STORE:
		return "the store failed or could not say what it holds";
	case FZN_NODE_IDENTITY_PARTIAL:
		return "the store holds part of an identity";
	case FZN_NODE_IDENTITY_SHAPE:
		return "a stored part is not a shape this version reads";
	case FZN_NODE_IDENTITY_CRYPTO:
		return "a key would not derive, install, issue or sign";
	case FZN_NODE_IDENTITY_MISMATCH:
		return "the stored self-root is not this identity";
	}
	return "unknown";
}

static int env_ok(const fzn_node_identity_env_t *env)
{
	return env && env->store && env->store->load && env->store->save && env->rng
	       && env->rng->fill && env->seat && env->seat->install && env->sign
	       && env->sign->sign && env->sign->verify && env->hash && env->agree;
}

/* Seat the seed, check the anchor against the key it produced, issue the
 * prekey record, and fill `out`. Shared by load and create so the two paths
 * cannot come to disagree about what an identity is.
 *
 * THE PREKEY IS VERIFIED AFTER IT IS ISSUED, which looks redundant and is the
 * check on the one thing the env cannot enforce: that `sign` is the signer
 * `seat` armed. If they are two different signers, the record is signed by one
 * key and names the other, and the node would hand every device a card it
 * cannot verify. Asking the verifier over the record makes that a refusal here
 * rather than a pairing that fails somewhere else. */
static fzn_node_identity_err_t finish(const fzn_node_identity_env_t *env, uint64_t now,
                                      const uint8_t seed[FZN_SIGN_SEED_LEN],
                                      const fzn_agree_secret_t *sk, const fzn_trust_t *trust,
                                      fzn_node_identity_t *out)
{
	uint8_t pubkey[FZN_PUBKEY_LEN];
	uint8_t record_bytes[FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t record;
	const uint8_t *root;

	if (!env->seat->install(env->seat->ctx, seed, pubkey))
		return FZN_NODE_IDENTITY_CRYPTO;

	/* A SELF-ROOT IS A CLAIM ABOUT THIS KEY, so it must be this key. A
	 * pinned or adopted anchor names somebody else's root by design and is
	 * not compared. Public keys, so an ordinary comparison. */
	root = fzn_trust_root(trust);
	if (!root)
		return FZN_NODE_IDENTITY_SHAPE;
	if (fzn_trust_source_of(trust) == FZN_TRUST_SELF
	    && memcmp(root, pubkey, FZN_PUBKEY_LEN) != 0) {
		IDENTITY_LOG(env, "node/identity", FLOG_ERR,
		             "the stored anchor is a self-root for a different key, so this "
		             "store's parts belong to more than one node; nothing was loaded");
		return FZN_NODE_IDENTITY_MISMATCH;
	}

	if (!fzn_agree_secret_public(sk))
		return FZN_NODE_IDENTITY_CRYPTO;
	if (fzn_prekey_issue(pubkey, fzn_agree_secret_public(sk), now, env->sign,
	                     record_bytes) != FZN_PREKEY_OK)
		return FZN_NODE_IDENTITY_CRYPTO;
	if (fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK
	    || fzn_prekey_verify(record, env->sign) != FZN_PREKEY_OK)
		return FZN_NODE_IDENTITY_CRYPTO;

	memcpy(out->pubkey, pubkey, FZN_PUBKEY_LEN);
	memcpy(out->prekey_record, record_bytes, FZN_PREKEY_LEN_TOTAL);
	out->sign = env->sign;
	out->hash = env->hash;
	out->agree = env->agree;
	return FZN_NODE_IDENTITY_OK;
}

static fzn_node_identity_err_t from_persist(fzn_persist_err_t err)
{
	return (err == FZN_PERSIST_ERR_BACKEND) ? FZN_NODE_IDENTITY_CRYPTO
	                                        : FZN_NODE_IDENTITY_SHAPE;
}

/* The caller's two structs are written only once everything has succeeded,
 * so a refused load leaves a live secret and anchor where they were -- the
 * promise `persist.h` makes for `fzn_persist_secret_open`, one layer out. */
static void hand_over(fzn_agree_secret_t *sk_local, fzn_trust_t *trust_local,
                      fzn_agree_secret_t *agree_secret, fzn_trust_t *trust,
                      fzn_node_identity_t *out)
{
	*agree_secret = *sk_local;
	*trust = *trust_local;
	out->agree_secret = agree_secret;
}

fzn_node_identity_err_t fzn_node_identity_load(const fzn_node_identity_env_t *env,
                                               uint64_t now,
                                               fzn_agree_secret_t *agree_secret,
                                               fzn_trust_t *trust,
                                               fzn_node_identity_t *out)
{
	uint8_t blob[FZN_PERSIST_MAX];
	uint8_t seed[FZN_SIGN_SEED_LEN];
	fzn_agree_secret_t sk;
	fzn_trust_t tr;
	fzn_node_identity_err_t result;
	fzn_persist_err_t perr;
	size_t len;

	if (!env_ok(env) || !agree_secret || !trust || !out)
		return FZN_NODE_IDENTITY_MALFORMED;
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&tr);

	len = 0;
	if (!env->store->load(env->store->ctx, FZN_PERSIST_OWN_IDENTITY, NULL, blob,
	                      sizeof(blob), &len))
		return FZN_NODE_IDENTITY_STORE;
	perr = fzn_persist_identity_open(blob, len, seed);
	fzn_wipe(blob, sizeof(blob));
	if (perr != FZN_PERSIST_OK)
		return from_persist(perr);

	len = 0;
	if (!env->store->load(env->store->ctx, FZN_PERSIST_OWN_PREKEY, NULL, blob,
	                      sizeof(blob), &len)) {
		result = FZN_NODE_IDENTITY_STORE;
		goto out;
	}
	perr = fzn_persist_secret_open(blob, len, env->agree, &sk);
	fzn_wipe(blob, sizeof(blob));
	if (perr != FZN_PERSIST_OK) {
		result = from_persist(perr);
		goto out;
	}

	len = 0;
	if (!env->store->load(env->store->ctx, FZN_PERSIST_TRUST, NULL, blob, sizeof(blob),
	                      &len)) {
		result = FZN_NODE_IDENTITY_STORE;
		goto out;
	}
	perr = fzn_persist_trust_open(blob, len, &tr);
	if (perr != FZN_PERSIST_OK) {
		result = from_persist(perr);
		goto out;
	}

	result = finish(env, now, seed, &sk, &tr, out);
	if (result == FZN_NODE_IDENTITY_OK)
		hand_over(&sk, &tr, agree_secret, trust, out);
out:
	fzn_wipe(seed, sizeof(seed));
	fzn_agree_secret_wipe(&sk);
	return result;
}

static int save(const fzn_node_identity_env_t *env, fzn_persist_slot_t slot,
                const uint8_t *blob, size_t len)
{
	return env->store->save(env->store->ctx, slot, NULL, blob, len);
}

fzn_node_identity_err_t fzn_node_identity_create(const fzn_node_identity_env_t *env,
                                                 uint64_t now,
                                                 fzn_agree_secret_t *agree_secret,
                                                 fzn_trust_t *trust,
                                                 fzn_node_identity_t *out)
{
	uint8_t seed[FZN_SIGN_SEED_LEN];
	uint8_t raw[FZN_AGREE_SECRET_LEN];
	uint8_t pubkey[FZN_PUBKEY_LEN];
	uint8_t blob[FZN_PERSIST_MAX];
	fzn_agree_secret_t sk;
	fzn_trust_t tr;
	fzn_node_identity_err_t result = FZN_NODE_IDENTITY_CRYPTO;
	size_t len;

	if (!env_ok(env) || !agree_secret || !trust || !out)
		return FZN_NODE_IDENTITY_MALFORMED;
	memset(&sk, 0, sizeof(sk));
	fzn_trust_init(&tr);

	if (!env->rng->fill(env->rng->ctx, seed, sizeof(seed))
	    || !env->rng->fill(env->rng->ctx, raw, sizeof(raw)))
		goto out;
	if (fzn_agree_secret_install(&sk, env->agree, raw) != FZN_AGREE_OK)
		goto out;

	/* SEATED ONCE HERE FOR THE KEY THE ANCHOR NAMES, and again inside
	 * `finish` -- the second seating is the same seed and the same key, and
	 * it keeps one path from seed to identity rather than two. */
	if (!env->seat->install(env->seat->ctx, seed, pubkey))
		goto out;
	if (fzn_trust_self(&tr, pubkey) != FZN_TRUST_OK)
		goto out;

	/* EVERYTHING IS DERIVED AND CHECKED BEFORE ANYTHING IS WRITTEN, so a
	 * failure above leaves the store as empty as it was. */
	result = finish(env, now, seed, &sk, &tr, out);
	if (result != FZN_NODE_IDENTITY_OK)
		goto out;

	/* THE SEED FIRST AND THE ANCHOR LAST. A save that fails part way leaves
	 * a partial store, which boot refuses by name; the order makes the
	 * commonest partial state "an identity with no anchor", which is the
	 * one boot most needs to refuse rather than repair. An all-zero seed
	 * from a broken random source is refused by the pack and never
	 * written. */
	result = FZN_NODE_IDENTITY_STORE;
	if (fzn_persist_identity_pack(seed, blob, sizeof(blob), &len) != FZN_PERSIST_OK) {
		result = FZN_NODE_IDENTITY_CRYPTO;
		goto out;
	}
	if (!save(env, FZN_PERSIST_OWN_IDENTITY, blob, len))
		goto out;
	if (fzn_persist_secret_pack(&sk, blob, sizeof(blob), &len) != FZN_PERSIST_OK
	    || !save(env, FZN_PERSIST_OWN_PREKEY, blob, len))
		goto out;
	if (fzn_persist_trust_pack(&tr, blob, sizeof(blob), &len) != FZN_PERSIST_OK
	    || !save(env, FZN_PERSIST_TRUST, blob, len))
		goto out;

	hand_over(&sk, &tr, agree_secret, trust, out);
	IDENTITY_LOG(env, "node/identity", FLOG_NOTE,
	             "created a new self-rooted identity; this node is a new host to "
	             "every peer");
	result = FZN_NODE_IDENTITY_OK;
out:
	fzn_wipe(seed, sizeof(seed));
	fzn_wipe(raw, sizeof(raw));
	fzn_wipe(blob, sizeof(blob));
	fzn_agree_secret_wipe(&sk);
	return result;
}

fzn_node_identity_err_t fzn_node_identity_boot(const fzn_node_identity_env_t *env,
                                               const fzn_node_identity_found_t *found,
                                               uint64_t now,
                                               fzn_agree_secret_t *agree_secret,
                                               fzn_trust_t *trust,
                                               fzn_node_identity_t *out, int *created)
{
	fzn_persist_err_t parts[3];
	unsigned present = 0, absent = 0, i;

	if (!found || !created)
		return FZN_NODE_IDENTITY_MALFORMED;
	*created = 0;
	parts[0] = found->seed;
	parts[1] = found->prekey;
	parts[2] = found->trust;
	for (i = 0; i < 3u; i++) {
		if (parts[i] == FZN_PERSIST_OK)
			present++;
		else if (parts[i] == FZN_PERSIST_ERR_ABSENT)
			absent++;
		else {
			IDENTITY_LOG(env, "node/identity", FLOG_ERR,
			             "the store could not say whether it holds part %u of this "
			             "identity, so nothing was loaded and nothing was created",
			             i);
			return FZN_NODE_IDENTITY_STORE;
		}
	}
	if (present == 3u)
		return fzn_node_identity_load(env, now, agree_secret, trust, out);
	if (absent == 3u) {
		fzn_node_identity_err_t err =
		        fzn_node_identity_create(env, now, agree_secret, trust, out);

		if (err == FZN_NODE_IDENTITY_OK)
			*created = 1;
		return err;
	}
	IDENTITY_LOG(env, "node/identity", FLOG_ERR,
	             "the store holds part of an identity (seed %s, prekey %s, anchor %s) "
	             "and it was left as found",
	             found->seed == FZN_PERSIST_OK ? "present" : "absent",
	             found->prekey == FZN_PERSIST_OK ? "present" : "absent",
	             found->trust == FZN_PERSIST_OK ? "present" : "absent");
	return FZN_NODE_IDENTITY_PARTIAL;
}
