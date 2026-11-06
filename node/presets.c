/* See presets.h. */

#include "presets.h"

#include <string.h>

/* WHAT EACH KIND OF HOST STARTS WITH. Bump a revision when its values change,
 * which is what applies them again on an update. */
static const fzn_preset_value_t USERD[] = {
	{ "relay/enabled", "off", FZN_PRESET_HOST },
	{ "invite/confirm", "on", FZN_PRESET_HOST },
	{ "location/enabled", "off", FZN_PRESET_HOST },
};

static const fzn_preset_value_t ROOTD[] = {
	{ "relay/enabled", "off", FZN_PRESET_ADMIN },
	{ "invite/confirm", "on", FZN_PRESET_ADMIN },
	{ "location/enabled", "off", FZN_PRESET_NOBODY },
};

static const fzn_preset_value_t VAULT[] = {
	{ "relay/enabled", "on", FZN_PRESET_VOTE },
	{ "relay/quota", "0", FZN_PRESET_ADMIN },
	{ "invite/confirm", "on", FZN_PRESET_ADMIN },
	{ "location/enabled", "off", FZN_PRESET_NOBODY },
};

static const fzn_preset_value_t EMBEDDED[] = {
	{ "relay/enabled", "off", FZN_PRESET_ROOT },
	{ "location/enabled", "off", FZN_PRESET_HOST },
	{ "invite/confirm", "on", FZN_PRESET_ADMIN },
};

static const fzn_preset_value_t RELAY[] = {
	{ "relay/enabled", "on", FZN_PRESET_ROOT },
	{ "invite/confirm", "on", FZN_PRESET_ADMIN },
	{ "location/enabled", "off", FZN_PRESET_NOBODY },
};

/* A CLIENT'S, written to its own file: the app fills in what it knows. */
static const fzn_preset_value_t UI_CLIENT[] = {
	{ "client/start-on-login", "on", FZN_PRESET_HOST },
	{ "log/level", "N", FZN_PRESET_HOST },
};

static const fzn_preset_value_t ONE_SHOT_CLIENT[] = {
	{ "client/start-on-login", "off", FZN_PRESET_NOBODY },
	{ "log/level", "W", FZN_PRESET_HOST },
};

static const fzn_preset_value_t INSECURE_CLIENT[] = {
	{ "client/start-on-login", "off", FZN_PRESET_NOBODY },
	{ "log/level", "W", FZN_PRESET_NOBODY },
};

#define VALUES(t) (t), sizeof(t) / sizeof((t)[0])

static const fzn_preset_t PRESETS[] = {
	{ "userd", 1u, "full", 1, VALUES(USERD) },
	{ "vault", 1u, "full", 1, VALUES(VAULT) },
	{ "relay", 1u, "full", 1, VALUES(RELAY) },
	{ "rootd", 1u, "full", 0, VALUES(ROOTD) },
	{ "embedded-device", 1u, "small", 0, VALUES(EMBEDDED) },
	{ "ui-client", 1u, "client", 0, VALUES(UI_CLIENT) },
	{ "one-shot-client", 1u, "client", 0, VALUES(ONE_SHOT_CLIENT) },
	{ "insecure-client", 1u, "client", 0, VALUES(INSECURE_CLIENT) },
};

int fzn_preset_fits(const fzn_preset_t *p)
{
	return p && strcmp(p->build, FZN_PRESET_BUILD) == 0;
}

const fzn_preset_t *fzn_preset_at(size_t i)
{
	return i < sizeof(PRESETS) / sizeof(PRESETS[0]) ? &PRESETS[i] : NULL;
}

const fzn_preset_t *fzn_preset_find(const char *name, size_t len)
{
	size_t i;

	if (!name)
		return NULL;
	for (i = 0; fzn_preset_at(i); i++)
		if (strlen(PRESETS[i].name) == len && memcmp(PRESETS[i].name, name, len) == 0)
			return &PRESETS[i];
	return NULL;
}

static const fzn_preset_value_t *in_table(const fzn_preset_value_t *t, size_t n, const char *key,
                                          size_t key_len)
{
	size_t i;

	for (i = 0; t && i < n; i++)
		if (strlen(t[i].key) == key_len && memcmp(t[i].key, key, key_len) == 0)
			return &t[i];
	return NULL;
}

const fzn_preset_value_t *fzn_preset_value_of(const fzn_preset_t *preset,
                                              const fzn_preset_value_t *extra, size_t n_extra,
                                              const char *key, size_t key_len)
{
	const fzn_preset_value_t *v;

	if (!key)
		return NULL;
	v = in_table(extra, n_extra, key, key_len);
	if (!v && preset)
		v = in_table(preset->values, preset->n_values, key, key_len);
	return v;
}

int fzn_preset_may(const fzn_preset_t *preset, const fzn_preset_value_t *extra, size_t n_extra,
                   const char *key, size_t key_len, int rank)
{
	const fzn_preset_value_t *v = fzn_preset_value_of(preset, extra, n_extra, key, key_len);

	if (v && v->who == FZN_PRESET_VOTE)
		return rank >= FZN_PRESET_ROOT;
	return !v || (v->who != FZN_PRESET_NOBODY && rank >= v->who);
}

const char *fzn_preset_who_word(int who)
{
	return who == FZN_PRESET_HOST    ? "host"
	       : who == FZN_PRESET_ADMIN ? "admin"
	       : who == FZN_PRESET_ROOT  ? "root"
	       : who == FZN_PRESET_VOTE  ? "vote"
	                                 : "nobody";
}

static long apply_table(const fzn_preset_value_t *t, size_t n, const fzn_preset_ops_t *ops)
{
	char held[256];
	size_t i, len;
	long wrote = 0;

	for (i = 0; t && i < n; i++) {
		int has;

		len = 0;
		has = ops->get(ops->ctx, t[i].key, held, sizeof(held), &len);
		/* WHAT SOMEBODY CHOSE STANDS, however it got there. */
		if (has && t[i].who != FZN_PRESET_NOBODY)
			continue;
		if (has && len == strlen(t[i].value) && memcmp(held, t[i].value, len) == 0)
			continue;
		if (!ops->set(ops->ctx, t[i].key, t[i].value))
			return -1;
		wrote++;
	}
	return wrote;
}

long fzn_preset_apply(const fzn_preset_t *preset, const fzn_preset_value_t *extra, size_t n_extra,
                      const fzn_preset_ops_t *ops)
{
	long a = 0, b;

	if (!ops || !ops->get || !ops->set)
		return -1;
	if (preset) {
		a = apply_table(preset->values, preset->n_values, ops);
		if (a < 0)
			return -1;
	}
	b = apply_table(extra, n_extra, ops);
	return b < 0 ? -1 : a + b;
}
