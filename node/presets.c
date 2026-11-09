/* See presets.h. */

#include "presets.h"

#include <stdio.h>
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

static int same(const char *held, size_t len, const char *value)
{
	return len == strlen(value) && memcmp(held, value, len) == 0;
}

/*
 * WHAT A PRESET WROTE, sec 973, kept under FZN_PRESET_WROTE_PREFIX and the key:
 * the value it put in a configurable cell. A cell still holding it is the
 * preset's, and a revision or another preset replaces it; a cell holding
 * anything else is somebody's choice and stands. It was "a cell with a value
 * stands, however it got there", so a value a preset wrote was a choice from
 * then on, and no revision ever reached a host that had run the one before.
 * `set setting` on a key the preset names lets go of the mark (the daemon's
 * gate), so a person who sets today's value has chosen it too.
 *
 * A HOST FROM BEFORE has no marks. A value equal to the preset's now is taken
 * as the preset's; any other stays a choice, as an old preset value cannot be
 * told from a person's.
 */
static long apply_table(const fzn_preset_value_t *t, size_t n, const fzn_preset_ops_t *ops)
{
	char held[256], mark[256], mark_key[128];
	size_t i, len, mark_len;
	long wrote = 0;

	for (i = 0; t && i < n; i++) {
		int has, marked = 0, keeps_mark = t[i].who != FZN_PRESET_NOBODY;

		len = 0;
		has = ops->get(ops->ctx, t[i].key, held, sizeof(held), &len);
		if (keeps_mark) {
			int at = snprintf(mark_key, sizeof(mark_key), "%s%s", FZN_PRESET_WROTE_PREFIX,
			                  t[i].key);

			keeps_mark = at > 0 && (size_t)at < sizeof(mark_key);
			mark_len = 0;
			marked = keeps_mark
			         && ops->get(ops->ctx, mark_key, mark, sizeof(mark), &mark_len);
		}
		/* SOMEBODY'S CHOICE STANDS: a value the preset did not write. */
		if (has && t[i].who != FZN_PRESET_NOBODY
		    && !(marked && len == mark_len && memcmp(held, mark, len) == 0)) {
			if (marked || !same(held, len, t[i].value) || !keeps_mark)
				continue;
			/* FROM BEFORE THE MARKS, and the preset's value: the preset's. */
			if (!ops->set(ops->ctx, mark_key, t[i].value))
				return -1;
			continue;
		}
		if (has && same(held, len, t[i].value)) {
			if (keeps_mark && !(marked && same(mark, mark_len, t[i].value))
			    && !ops->set(ops->ctx, mark_key, t[i].value))
				return -1;
			continue;
		}
		if (!ops->set(ops->ctx, t[i].key, t[i].value))
			return -1;
		if (keeps_mark && !ops->set(ops->ctx, mark_key, t[i].value))
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
