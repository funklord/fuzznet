/* See settings.h. */

#include "settings.h"

#include "apply.h"
#include "../log/rules.h"
#include "../wire/bytes.h"

#include <stdio.h>
#include <string.h>

static const char HEX[] = "0123456789abcdef";

const char *fzn_node_settings_err_str(fzn_node_settings_err_t err)
{
	switch (err) {
	case FZN_NODE_SETTINGS_OK:
		return "ok";
	case FZN_NODE_SETTINGS_MALFORMED:
		return "malformed";
	case FZN_NODE_SETTINGS_REFUSED:
		return "this setter may not set that";
	case FZN_NODE_SETTINGS_STALE:
		return "older than the setting standing";
	case FZN_NODE_SETTINGS_BACKEND:
		return "the store refused";
	case FZN_NODE_SETTINGS_JOURNAL:
		return "the journal refused";
	}
	return "unknown";
}

static int ready(const fzn_node_settings_t *ns)
{
	return ns && ns->store && ns->store->load && ns->store->save && ns->hash && ns->hash->hash
	       && ns->verify && ns->verify->verify;
}

/* ---- rows ---------------------------------------------------------------- */

/* A row: the rank with its top bit set, when this node learned the setting
 * (seconds, 0 for not known), then the setting as its setter signed it --
 * sec 549, so a clear can be forgotten once the window has passed. A row
 * written before that is the rank and the setting, and reads as learned at
 * a time not known. */
#define ROW_STAMPED 0x80u
#define ROW_HEAD 9u
#define ROW_MAX (ROW_HEAD + FZN_SETTING_MAX)

/* A row's parts: its rank, when it was learned, and where its setting
 * starts. 0 for a row of neither shape. */
static int row_read(const uint8_t *buf, size_t len, fzn_setting_rank_t *rank, uint64_t *learned,
                    size_t *head)
{
	if (len < 2u)
		return 0;
	if (buf[0] & ROW_STAMPED) {
		if (len <= ROW_HEAD)
			return 0;
		*rank = (fzn_setting_rank_t)(buf[0] & ~ROW_STAMPED);
		*learned = fzn_get_be64(buf + 1u);
		*head = ROW_HEAD;
	} else {
		*rank = (fzn_setting_rank_t)buf[0];
		*learned = 0;
		*head = 1u;
	}
	return (unsigned)*rank < FZN_SETTING_RANKS;
}

size_t fzn_node_settings_row_setting(const uint8_t *row, size_t len)
{
	fzn_setting_rank_t rank;
	uint64_t learned;
	size_t head = 0;

	return row && row_read(row, len, &rank, &learned, &head) ? head : 0u;
}

/* Save `bytes` as `cell`'s row at `rank`, learned at `learned`. */
static int row_save(const fzn_node_settings_t *ns, const uint8_t row[FZN_PUBKEY_LEN],
                    fzn_setting_rank_t rank, uint64_t learned, const uint8_t *bytes, size_t len)
{
	static uint8_t out[ROW_MAX];

	if (len > FZN_SETTING_MAX)
		return 0;
	out[0] = (uint8_t)(ROW_STAMPED | (unsigned)rank);
	fzn_put_be64(out + 1u, learned);
	memcpy(out + ROW_HEAD, bytes, len);
	return ns->store->save(ns->store->ctx, FZN_PERSIST_SETTING, row, out, ROW_HEAD + len);
}

/* The row of `cell` at `rank`. */
static int row_of(const fzn_node_settings_t *ns, const uint8_t cell[FZN_SUBJECT_LEN],
                  fzn_setting_rank_t rank, uint8_t row[FZN_PUBKEY_LEN])
{
	static const char DOMAIN[] = "fuzznet.setting.row";
	uint8_t in[sizeof(DOMAIN) - 1u + FZN_SUBJECT_LEN + 1u];
	size_t at = sizeof(DOMAIN) - 1u;

	memcpy(in, DOMAIN, at);
	memcpy(in + at, cell, FZN_SUBJECT_LEN);
	in[at + FZN_SUBJECT_LEN] = (uint8_t)rank;
	return ns->hash->hash(ns->hash->ctx, row, FZN_PUBKEY_LEN, in, sizeof(in));
}

/* The setting standing for `cell` at `rank`, opened from `buf` (ROW_MAX);
 * where it starts in `buf` and its length in `*head` and `*obj_len` (either
 * may be NULL). */
static int standing(const fzn_node_settings_t *ns, const uint8_t cell[FZN_SUBJECT_LEN],
                    fzn_setting_rank_t rank, uint8_t *buf, fzn_setting_t *s, size_t *obj_len,
                    size_t *head)
{
	uint8_t row[FZN_PUBKEY_LEN], again[FZN_SUBJECT_LEN];
	fzn_setting_rank_t filed;
	uint64_t learned;
	size_t len = 0, at = 0;

	if (obj_len)
		*obj_len = 0;

	/* WHAT IT SAYS IT IS, where it was looked for: a row of the cell and
	 * rank it is filed under, or not this cell's. */
	if (!row_of(ns, cell, rank, row)
	    || !ns->store->load(ns->store->ctx, FZN_PERSIST_SETTING, row, buf, ROW_MAX, &len)
	    || !row_read(buf, len, &filed, &learned, &at) || filed != rank
	    || fzn_setting_open(buf + at, len - at, ns->verify, s) != FZN_SETTING_OK
	    || !fzn_setting_cell(s, ns->hash, again) || memcmp(again, cell, FZN_SUBJECT_LEN) != 0)
		return 0;
	if (obj_len)
		*obj_len = len - at;
	if (head)
		*head = at;
	return 1;
}

fzn_node_settings_err_t fzn_node_settings_learn(const fzn_node_settings_t *ns,
                                                const uint8_t *bytes, size_t len,
                                                fzn_setting_rank_t rank)
{
	static uint8_t held_buf[ROW_MAX];
	uint8_t cell[FZN_SUBJECT_LEN], row[FZN_PUBKEY_LEN];
	fzn_setting_t s, held;
	size_t held_len = 0, held_at = 0;

	if (!ready(ns) || !bytes || (unsigned)rank >= FZN_SETTING_RANKS)
		return FZN_NODE_SETTINGS_MALFORMED;
	if (fzn_setting_open(bytes, len, ns->verify, &s) != FZN_SETTING_OK
	    || !fzn_setting_cell(&s, ns->hash, cell))
		return FZN_NODE_SETTINGS_REFUSED;
	if (standing(ns, cell, rank, held_buf, &held, &held_len, &held_at)) {
		/* THE SAME SETTING AGAIN is what a journal replays: kept, no
		 * change -- and its learning time kept with it. */
		if (held_len == len && memcmp(held_buf + held_at, bytes, len) == 0)
			return FZN_NODE_SETTINGS_OK;
		if (!fzn_setting_supersedes(&s, &held))
			return FZN_NODE_SETTINGS_STALE;
	}
	if (!row_of(ns, cell, rank, row))
		return FZN_NODE_SETTINGS_BACKEND;
	return row_save(ns, row, rank, ns->now ? ns->now() : 0u, bytes, len)
	               ? FZN_NODE_SETTINGS_OK
	               : FZN_NODE_SETTINGS_BACKEND;
}

/* THE RANK IN FORCE for `cell`: the highest whose standing setting sets a
 * value, opened from `buf`; -1 when none does. */
static int in_force(const fzn_node_settings_t *ns, const uint8_t cell[FZN_SUBJECT_LEN],
                    uint8_t *buf, fzn_setting_t *s)
{
	int r;

	for (r = (int)FZN_SETTING_RANKS - 1; r >= 0; r--)
		if (standing(ns, cell, (fzn_setting_rank_t)r, buf, s, NULL, NULL) && s->set)
			return r;
	return -1;
}

int fzn_node_settings_get(const fzn_node_settings_t *ns, fzn_scope_t scope,
                          const uint8_t about[FZN_SUBJECT_LEN], const uint8_t *key,
                          size_t key_len, uint8_t *value, size_t *value_len,
                          fzn_setting_rank_t *rank)
{
	static uint8_t buf[ROW_MAX];
	uint8_t cell[FZN_SUBJECT_LEN];
	fzn_setting_t s;
	int r;

	if (!ready(ns) || !value || !value_len || !rank
	    || !fzn_setting_cell_of(scope, about, key, key_len, ns->hash, cell))
		return 0;
	r = in_force(ns, cell, buf, &s);
	if (r < 0)
		return 0;
	memcpy(value, s.value, s.value_len);
	*value_len = s.value_len;
	*rank = (fzn_setting_rank_t)r;
	return 1;
}

fzn_node_settings_err_t fzn_node_settings_each(const fzn_node_settings_t *ns,
                                               fzn_node_settings_each_fn each, void *ctx)
{
	static uint8_t rows[FZN_NODE_SETTINGS_ROWS * FZN_PUBKEY_LEN];
	static uint8_t buf[ROW_MAX], top[ROW_MAX];
	size_t n = 0, i;

	if (!ready(ns) || !ns->store->list || !each)
		return FZN_NODE_SETTINGS_MALFORMED;
	if (!ns->store->list(ns->store->ctx, FZN_PERSIST_SETTING, rows, FZN_NODE_SETTINGS_ROWS, &n))
		return FZN_NODE_SETTINGS_BACKEND;
	for (i = 0; i < n; i++) {
		uint8_t cell[FZN_SUBJECT_LEN], again[FZN_PUBKEY_LEN];
		fzn_setting_rank_t rank;
		fzn_setting_t s, t;
		uint64_t learned;
		size_t len = 0, at = 0;
		int r;

		/* EACH CELL ONCE, from the row that is in force for it: a row is
		 * reported when it is its cell's highest live rank. */
		if (!ns->store->load(ns->store->ctx, FZN_PERSIST_SETTING, rows + (i * FZN_PUBKEY_LEN), buf,
		                     sizeof(buf), &len)
		    || !row_read(buf, len, &rank, &learned, &at)
		    || fzn_setting_open(buf + at, len - at, ns->verify, &s) != FZN_SETTING_OK
		    || !s.set || !fzn_setting_cell(&s, ns->hash, cell) || !row_of(ns, cell, rank, again)
		    || memcmp(again, rows + (i * FZN_PUBKEY_LEN), FZN_PUBKEY_LEN) != 0)
			continue;
		r = in_force(ns, cell, top, &t);
		if (r == (int)rank)
			each(ctx, &s, rank);
	}
	return FZN_NODE_SETTINGS_OK;
}

fzn_node_settings_err_t fzn_node_settings_write(const fzn_node_settings_t *ns,
                                                fzn_scope_t scope,
                                                const uint8_t about[FZN_SUBJECT_LEN],
                                                const uint8_t *key, size_t key_len, int set,
                                                const uint8_t *value, size_t value_len)
{
	static uint8_t buf[ROW_MAX];
	uint8_t bytes[FZN_SETTING_MAX], cell[FZN_SUBJECT_LEN];
	fzn_setting_rank_t rank;
	uint64_t version = 0;
	size_t len = 0;
	int r;

	if (!ready(ns) || !ns->journal || !ns->id || !ns->id->sign || !ns->apply || !ns->now || !about
	    || !fzn_setting_cell_of(scope, about, key, key_len, ns->hash, cell))
		return FZN_NODE_SETTINGS_MALFORMED;
	/* JUDGED BEFORE IT IS WRITTEN, by what judges it where it is applied:
	 * a setting this node may not make is never in its stream. */
	if (fzn_node_apply_rank(ns->apply, ns->id->pubkey, scope, about, &rank) != 1)
		return FZN_NODE_SETTINGS_REFUSED;
	/* ONE PAST EVERY VERSION HELD FOR THE CELL, at any rank, AND NO LOWER
	 * THAN THE CLOCK, sec 549: a clear is forgotten here once the window
	 * has passed, and a write after that must still supersede it on a
	 * node that has not forgotten it yet. */
	version = ns->now();
	for (r = 0; r < (int)FZN_SETTING_RANKS; r++) {
		fzn_setting_t s;

		if (standing(ns, cell, (fzn_setting_rank_t)r, buf, &s, NULL, NULL)
		    && s.version >= version)
			version = s.version + 1u;
	}
	if (version == 0u)
		version = 1u;
	if (fzn_setting_issue(ns->id->pubkey, ns->id->sign, scope, about, version, key, key_len,
	                      set, value, value_len, bytes, &len)
	    != FZN_SETTING_OK)
		return FZN_NODE_SETTINGS_MALFORMED;
	/* THE RECORD IN MILLISECONDS, as every record is since sec 561; the
	 * clock here is seconds, as the version and the learning time are. */
	if (fzn_node_journal_append_object(ns->journal, ns->id->pubkey, ns->id->sign, bytes, len,
	                                   ns->now() * 1000u, NULL)
	    != FZN_NODE_JOURNAL_OK)
		return FZN_NODE_SETTINGS_JOURNAL;
	return fzn_node_settings_learn(ns, bytes, len, rank);
}

int fzn_node_settings_rule_key(const fzn_hash_ops_t *hash, const char *text, size_t len,
                               uint8_t key[FZN_NODE_SETTINGS_RULE_KEY_LEN])
{
	uint8_t h[16];
	size_t i;

	if (!hash || !hash->hash || !text || !key
	    || !hash->hash(hash->ctx, h, sizeof(h), (const uint8_t *)text, len))
		return 0;
	memcpy(key, "retention/", 10u);
	for (i = 0; i < sizeof(h); i++) {
		key[10u + (2u * i)] = (uint8_t)HEX[h[i] >> 4];
		key[11u + (2u * i)] = (uint8_t)HEX[h[i] & 15u];
	}
	return 1;
}

fzn_node_settings_err_t fzn_node_settings_forget_clears(const fzn_node_settings_t *ns,
                                                        uint64_t older_than, size_t *forgot)
{
	static uint8_t rows[FZN_NODE_SETTINGS_ROWS * FZN_PUBKEY_LEN];
	static uint8_t buf[ROW_MAX];
	size_t n = 0, i;

	if (!forgot)
		return FZN_NODE_SETTINGS_MALFORMED;
	*forgot = 0;
	if (!ready(ns) || !ns->store->list || !ns->store->remove || !ns->now)
		return FZN_NODE_SETTINGS_MALFORMED;
	if (!ns->store->list(ns->store->ctx, FZN_PERSIST_SETTING, rows, FZN_NODE_SETTINGS_ROWS, &n))
		return FZN_NODE_SETTINGS_BACKEND;
	for (i = 0; i < n; i++) {
		const uint8_t *row = rows + (i * FZN_PUBKEY_LEN);
		fzn_setting_rank_t rank;
		fzn_setting_t s;
		uint64_t learned;
		size_t len = 0, at = 0;

		if (!ns->store->load(ns->store->ctx, FZN_PERSIST_SETTING, row, buf, sizeof(buf), &len)
		    || !row_read(buf, len, &rank, &learned, &at)
		    || fzn_setting_open(buf + at, len - at, ns->verify, &s) != FZN_SETTING_OK || s.set)
			continue;
		/* A CLEAR LEARNED AT A TIME NOT KNOWN starts its window now. */
		if (learned == 0u) {
			if (!row_save(ns, row, rank, ns->now(), buf + at, len - at))
				return FZN_NODE_SETTINGS_BACKEND;
			continue;
		}
		if (learned >= older_than)
			continue;
		if (!ns->store->remove(ns->store->ctx, FZN_PERSIST_SETTING, row))
			return FZN_NODE_SETTINGS_BACKEND;
		(*forgot)++;
	}
	return FZN_NODE_SETTINGS_OK;
}

/* A COUNT FROM 1 TO `max` in `value`, or 0: digits only, and no more of them
 * than `max` has, so nothing overflows on the way. */
static unsigned count_of(const uint8_t *value, size_t len, unsigned max)
{
	unsigned n = 0, m;
	size_t i, digits = 0;

	for (m = max; m; m /= 10u)
		digits++;
	if (len == 0u || len > digits)
		return 0;
	for (i = 0; i < len; i++) {
		if (value[i] < '0' || value[i] > '9')
			return 0;
		n = (n * 10u) + (unsigned)(value[i] - '0');
	}
	return n <= max ? n : 0u;
}

uint8_t fzn_node_settings_quorum(const fzn_node_settings_t *ns, uint8_t fallback)
{
	uint8_t value[FZN_SETTING_VALUE_MAX];
	fzn_setting_rank_t rank;
	size_t len = 0;
	unsigned k;

	if (!ready(ns) || !ns->estate
	    || !fzn_node_settings_get(ns, FZN_SCOPE_ESTATE, ns->estate,
	                              (const uint8_t *)FZN_NODE_SETTINGS_K_KEY,
	                              sizeof(FZN_NODE_SETTINGS_K_KEY) - 1u, value, &len, &rank)
	    || rank != FZN_SETTING_RANK_ROOT)
		return fallback;
	k = count_of(value, len, 255u);
	return k ? (uint8_t)k : fallback;
}

unsigned fzn_node_settings_window_days(const fzn_node_settings_t *ns)
{
	uint8_t value[FZN_SETTING_VALUE_MAX];
	fzn_setting_rank_t rank;
	size_t len = 0;
	unsigned days;

	if (!ready(ns) || !ns->estate
	    || !fzn_node_settings_get(ns, FZN_SCOPE_ESTATE, ns->estate,
	                              (const uint8_t *)FZN_NODE_SETTINGS_WINDOW_KEY,
	                              sizeof(FZN_NODE_SETTINGS_WINDOW_KEY) - 1u, value, &len,
	                              &rank))
		return FZN_NODE_SETTINGS_WINDOW_DAYS;
	days = count_of(value, len, 36500u);
	return days ? days : FZN_NODE_SETTINGS_WINDOW_DAYS;
}

fzn_node_settings_err_t fzn_node_settings_take_rules(const fzn_node_settings_t *ns,
                                                     const uint8_t about[FZN_SUBJECT_LEN],
                                                     size_t *moved)
{
	static fzn_retain_rule_t held[FZN_LOG_RULES_MAX];
	size_t n = 0, i;

	if (!moved)
		return FZN_NODE_SETTINGS_MALFORMED;
	*moved = 0;
	if (!ready(ns) || !about)
		return FZN_NODE_SETTINGS_MALFORMED;
	if (fzn_log_rules_list(ns->store, held, FZN_LOG_RULES_MAX, &n) != FZN_LOG_RULES_OK)
		return FZN_NODE_SETTINGS_BACKEND;
	for (i = 0; i < n; i++) {
		char text[FZN_RETAIN_TEXT_MAX];
		uint8_t key[FZN_NODE_SETTINGS_RULE_KEY_LEN];
		size_t len = 0;

		/* WRITTEN, THEN TAKEN OUT: a crash between leaves the rule in both,
		 * which the next start finishes. */
		if (fzn_retain_text(&held[i], text, sizeof(text), &len) != FZN_RETAIN_OK
		    || len > FZN_SETTING_VALUE_MAX
		    || !fzn_node_settings_rule_key(ns->hash, text, len, key)
		    || fzn_node_settings_write(ns, FZN_SCOPE_HOST, about, key, sizeof(key), 1,
		                               (const uint8_t *)text, len)
		               != FZN_NODE_SETTINGS_OK)
			continue;
		if (fzn_log_rules_remove(ns->store, ns->hash, &held[i]) != FZN_LOG_RULES_OK)
			return FZN_NODE_SETTINGS_BACKEND;
		(*moved)++;
	}
	return FZN_NODE_SETTINGS_OK;
}

/* ---- the verbs ------------------------------------------------------------ */

static size_t answer(char *reply, size_t cap, fzn_reply_t kind, const char *detail, size_t len)
{
	size_t out = 0;

	if (fzn_reply_compose((uint8_t *)reply, cap, &out, kind, (const uint8_t *)detail, len)
	    != FZN_COMPOSE_OK)
		return 0;
	return out;
}

static size_t say(char *reply, size_t cap, fzn_reply_t kind, const char *detail)
{
	return answer(reply, cap, kind, detail, detail ? strlen(detail) : 0u);
}

static size_t refuse(char *reply, size_t cap, fzn_node_settings_err_t err)
{
	return say(reply, cap,
	           err == FZN_NODE_SETTINGS_MALFORMED ? FZN_REPLY_MALFORMED
	           : err == FZN_NODE_SETTINGS_REFUSED ? FZN_REPLY_DENIED
	                                              : FZN_REPLY_ERROR,
	           fzn_node_settings_err_str(err));
}

/* The next space-separated word, and what follows it. */
static int word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *w_len)
{
	size_t i = 0;

	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	if (!*left)
		return 0;
	while (i < *left && (*at)[i] != ' ')
		i++;
	*w = *at;
	*w_len = i;
	*at += i;
	*left -= i;
	return 1;
}

static int is_word(const uint8_t *w, size_t w_len, const char *s)
{
	return w_len == strlen(s) && memcmp(w, s, w_len) == 0;
}

static int nibble(uint8_t c)
{
	const char *h = memchr(HEX, c, 16u);

	return h ? (int)(h - HEX) : -1;
}

static int parse_hex(const uint8_t *w, size_t w_len, uint8_t *out, size_t n)
{
	size_t i;

	if (w_len != n * 2u)
		return 0;
	for (i = 0; i < n; i++) {
		int hi = nibble(w[i * 2u]), lo = nibble(w[(i * 2u) + 1u]);

		if (hi < 0 || lo < 0)
			return 0;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 1;
}

/* SCOPE: `estate`, `host` or `host=KEYHEX`, into the scope and what it is
 * about. */
static int scope_of(const fzn_node_settings_t *ns, const uint8_t *w, size_t w_len,
                    fzn_scope_t *scope, uint8_t about[FZN_SUBJECT_LEN])
{
	if (is_word(w, w_len, "estate") && ns->estate) {
		*scope = FZN_SCOPE_ESTATE;
		memcpy(about, ns->estate, FZN_SUBJECT_LEN);
		return 1;
	}
	if (is_word(w, w_len, "host") && ns->id) {
		*scope = FZN_SCOPE_HOST;
		memcpy(about, ns->id->pubkey, FZN_SUBJECT_LEN);
		return 1;
	}
	if (w_len == 5u + 2u * FZN_SUBJECT_LEN && memcmp(w, "host=", 5u) == 0) {
		*scope = FZN_SCOPE_HOST;
		return parse_hex(w + 5u, w_len - 5u, about, FZN_SUBJECT_LEN);
	}
	return 0;
}

/* `n` bytes with %XX undone into `out` (at most `cap`). */
static int unescape(const uint8_t *in, size_t n, uint8_t *out, size_t cap, size_t *len)
{
	size_t i, w = 0;

	for (i = 0; i < n; i++) {
		uint8_t c = in[i];

		if (c == '%') {
			int hi, lo;

			if (i + 2u >= n)
				return 0;
			hi = nibble(in[i + 1u]);
			lo = nibble(in[i + 2u]);
			if (hi < 0 || lo < 0)
				return 0;
			c = (uint8_t)((hi << 4) | lo);
			i += 2u;
		}
		if (w == cap)
			return 0;
		out[w++] = c;
	}
	*len = w;
	return 1;
}

/* `n` bytes escaped, as notes' listing does: a byte below 0x21, `%` and `,`
 * as %XX. How many bytes were written into `out`, at most `cap`; 0 and
 * nothing promised when it did not all fit. */
static size_t escape(const uint8_t *b, size_t n, char *out, size_t cap, int *whole)
{
	size_t i, w = 0;

	*whole = 0;
	for (i = 0; i < n; i++) {
		uint8_t c = b[i];

		if (c <= 0x20u || c == '%' || c == ',' || c == 0x7fu) {
			if (cap - w < 3u)
				return w;
			out[w++] = '%';
			out[w++] = HEX[c >> 4];
			out[w++] = HEX[c & 15u];
		} else {
			if (cap == w)
				return w;
			out[w++] = (char)c;
		}
	}
	*whole = 1;
	return w;
}

static const char *const RANKS[FZN_SETTING_RANKS] = { "host", "admin", "root" };

static size_t set_setting(const fzn_node_settings_t *ns, int set, const uint8_t *at, size_t left,
                          char *reply, size_t cap)
{
	static const char USAGE[] = "set setting SCOPE KEY VALUE, or remove setting SCOPE KEY";
	uint8_t about[FZN_SUBJECT_LEN], value[FZN_SETTING_VALUE_MAX];
	const uint8_t *w, *key;
	size_t w_len, key_len, value_len = 0;
	fzn_scope_t scope;
	fzn_node_settings_err_t err;

	if (!word(&at, &left, &w, &w_len) || !scope_of(ns, w, w_len, &scope, about)
	    || !word(&at, &left, &key, &key_len) || !fzn_setting_key_ok(key, key_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	while (left && *at == ' ') {
		at++;
		left--;
	}
	if (set ? (!left || !unescape(at, left, value, sizeof(value), &value_len)) : left != 0u)
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	err = fzn_node_settings_write(ns, scope, about, key, key_len, set, value, value_len);
	if (err != FZN_NODE_SETTINGS_OK)
		return refuse(reply, cap, err);
	return say(reply, cap, FZN_REPLY_OK, NULL);
}

static size_t get_setting(const fzn_node_settings_t *ns, const uint8_t *at, size_t left,
                          char *reply, size_t cap)
{
	static const char USAGE[] = "get setting SCOPE KEY";
	uint8_t about[FZN_SUBJECT_LEN], value[FZN_SETTING_VALUE_MAX];
	char detail[8u + 3u * FZN_SETTING_VALUE_MAX];
	const uint8_t *w, *key;
	size_t w_len, key_len, value_len = 0, n;
	fzn_setting_rank_t rank;
	fzn_scope_t scope;
	int whole = 0, k;

	if (!word(&at, &left, &w, &w_len) || !scope_of(ns, w, w_len, &scope, about)
	    || !word(&at, &left, &key, &key_len) || !fzn_setting_key_ok(key, key_len) || left)
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (!fzn_node_settings_get(ns, scope, about, key, key_len, value, &value_len, &rank))
		return say(reply, cap, FZN_REPLY_OK, "absent");
	k = snprintf(detail, sizeof(detail), "%s ", RANKS[rank]);
	if (k < 0)
		return 0;
	n = (size_t)k + escape(value, value_len, detail + k, sizeof(detail) - (size_t)k, &whole);
	if (!whole)
		return 0;
	return answer(reply, cap, FZN_REPLY_OK, detail, n);
}

/* THE LISTING'S WALK: every value in force, the ones past `from` written. */
struct listing {
	size_t from, seen, shown, used, limit;
	int more;
	char *items;
	size_t cap;
};

static void list_one(void *ctx, const fzn_setting_t *s, fzn_setting_rank_t rank)
{
	struct listing *l = (struct listing *)ctx;
	char item[8u + 2u * FZN_SUBJECT_LEN + FZN_SETTING_KEY_MAX + 48u + 3u * FZN_SETTING_VALUE_MAX];
	size_t n, i;
	int k, whole = 0;

	if (l->more || l->seen++ < l->from)
		return;
	k = snprintf(item, sizeof(item), " %s,", fzn_scope_name(s->scope));
	if (k < 0)
		return;
	n = (size_t)k;
	for (i = 0; i < FZN_SUBJECT_LEN; i++) {
		item[n++] = HEX[s->about[i] >> 4];
		item[n++] = HEX[s->about[i] & 15u];
	}
	item[n++] = ',';
	memcpy(item + n, s->key, s->key_len);
	n += s->key_len;
	k = snprintf(item + n, sizeof(item) - n, ",%s,%llu,", RANKS[rank],
	             (unsigned long long)s->version);
	if (k < 0)
		return;
	n += (size_t)k;
	n += escape(s->value, s->value_len, item + n, sizeof(item) - n, &whole);
	/* A VALUE GOES IN WHOLE OR NOT AT ALL: the page ends where the next
	 * does not fit, and the caller asks from FROM + SHOWN. */
	if (!whole || l->used + n > l->limit) {
		l->more = 1;
		return;
	}
	memcpy(l->items + l->used, item, n);
	l->used += n;
	l->shown++;
}

static size_t list_settings(const fzn_node_settings_t *ns, const uint8_t *at, size_t left,
                            char *reply, size_t cap)
{
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	const uint8_t *w;
	size_t w_len, i;
	struct listing l;
	fzn_node_settings_err_t err;
	int k;

	memset(&l, 0, sizeof(l));
	if (word(&at, &left, &w, &w_len)) {
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || l.from > FZN_NODE_SETTINGS_ROWS)
				return say(reply, cap, FZN_REPLY_MALFORMED, "list setting [FROM]");
			l.from = (l.from * 10u) + (size_t)(w[i] - '0');
		}
	}
	l.items = items;
	l.cap = sizeof(items);
	/* ROOM FOR THE HEAD, `FROM SHOWN MORE`, beside the items. */
	l.limit = fzn_reply_ok_room(cap) > 24u ? fzn_reply_ok_room(cap) - 24u : 0u;
	if (l.limit > sizeof(items))
		l.limit = sizeof(items);
	err = fzn_node_settings_each(ns, list_one, &l);
	if (err != FZN_NODE_SETTINGS_OK)
		return refuse(reply, cap, err);
	k = snprintf(detail, sizeof(detail), "%zu %zu %d", l.from, l.shown, l.more);
	if (k < 0 || (size_t)k + l.used > sizeof(detail))
		return 0;
	memcpy(detail + k, items, l.used);
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)k + l.used);
}

size_t fzn_node_settings_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t reply_cap)
{
	const fzn_node_settings_t *ns = (const fzn_node_settings_t *)ctx;
	const uint8_t *at, *subject;
	size_t left, subject_len;

	if (!ns || !request || !reply || !request->arg)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &subject, &subject_len) || !is_word(subject, subject_len, "setting"))
		return 0;
	if (request->parsed != FZN_VERB_SET && request->parsed != FZN_VERB_REMOVE
	    && request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return say(reply, reply_cap, FZN_REPLY_DENIED, "settings need this node's own user");
	if (!ready(ns))
		return say(reply, reply_cap, FZN_REPLY_UNSUPPORTED, "no store for settings");
	if (request->parsed == FZN_VERB_SET)
		return set_setting(ns, 1, at, left, reply, reply_cap);
	if (request->parsed == FZN_VERB_REMOVE)
		return set_setting(ns, 0, at, left, reply, reply_cap);
	if (request->parsed == FZN_VERB_GET)
		return get_setting(ns, at, left, reply, reply_cap);
	return list_settings(ns, at, left, reply, reply_cap);
}
