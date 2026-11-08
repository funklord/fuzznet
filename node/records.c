/* See records.h. */

#include "records.h"

#include "../local/escape.h"
#include "../messages/line.h"
#include "../state/setting.h"
#include "../constant_time/constant_time.h"
#include "../log/retain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char HEX[] = "0123456789abcdef";

int fzn_node_records_place(const fzn_node_records_t *nr, const uint8_t *item, size_t len,
                           uint8_t subject[FZN_PUBKEY_LEN], uint32_t *month,
                           struct fzn_setting *out)
{
	fzn_setting_t s;

	if (!nr || !nr->verify || !item || !subject || !month
	    || fzn_setting_open(item, len, nr->verify, &s) != FZN_SETTING_OK
	    || s.scope != FZN_SCOPE_HOST || !fzn_ct_memeq(s.about, s.setter, FZN_PUBKEY_LEN))
		return 0;
	memcpy(subject, s.setter, FZN_PUBKEY_LEN);
	*month = fzn_message_epoch_of(s.version);
	if (out)
		*out = s;
	return 1;
}

static void note_listed(const fzn_node_records_t *nr, const uint8_t subject[FZN_PUBKEY_LEN],
                        const fzn_setting_t *s);

/* A RECORD LET GO, OR A WRITE THAT FAILED: no list resolved before holds. */
static void forget_lists(const fzn_node_records_t *nr)
{
	size_t i;

	if (nr->cache)
		for (i = 0; i < FZN_NODE_RECORDS_CACHED; i++)
			nr->cache->lists[i].held = 0;
}

void fzn_node_records_cache_free(fzn_node_records_cache_t *cache)
{
	size_t i;

	if (!cache)
		return;
	for (i = 0; i < FZN_NODE_RECORDS_CACHED; i++)
		free(cache->lists[i].rows);
	memset(cache, 0, sizeof(*cache));
}

fzn_node_apply_outcome_t fzn_node_records_file(const fzn_node_records_t *nr,
                                               const uint8_t subject[FZN_PUBKEY_LEN],
                                               uint32_t month, const uint8_t *item, size_t len)
{
	uint8_t setter[FZN_PUBKEY_LEN];
	uint32_t at = 0;
	fzn_buckets_err_t err;
	fzn_setting_t s;

	if (!nr || !nr->b || !subject || !fzn_node_records_place(nr, item, len, setter, &at, &s)
	    || at != month || !fzn_ct_memeq(setter, subject, FZN_PUBKEY_LEN))
		return FZN_NODE_APPLY_REFUSED;
	err = fzn_buckets_add(nr->b, FZN_BUCKETS_RECORDS, subject, month, item, len, NULL);
	/* A MONTH LET GO HERE is not taken back for a peer's holding it. */
	if (err == FZN_BUCKETS_GONE)
		return FZN_NODE_APPLY_APPLIED;
	if (err != FZN_BUCKETS_OK)
		return FZN_NODE_APPLY_NOT_SAVED;
	note_listed(nr, subject, &s);
	if (nr->filed)
		nr->filed(nr->filed_ctx, &s);
	return FZN_NODE_APPLY_APPLIED;
}

static fzn_node_records_err_t write_record(const fzn_node_records_t *nr, const uint8_t *key,
                                           size_t key_len, int set, const uint8_t *value,
                                           size_t value_len);

fzn_node_records_err_t fzn_node_records_write(const fzn_node_records_t *nr, const uint8_t *key,
                                              size_t key_len, const uint8_t *value,
                                              size_t value_len)
{
	return write_record(nr, key, key_len, 1, value, value_len);
}

static fzn_node_records_err_t write_record(const fzn_node_records_t *nr, const uint8_t *key,
                                           size_t key_len, int set, const uint8_t *value,
                                           size_t value_len)
{
	uint8_t bytes[FZN_SETTING_MAX];
	size_t len = 0;
	uint64_t now;
	fzn_buckets_err_t err;

	if (!nr || !nr->b || !nr->id || !nr->id->sign || !nr->now_ms || !key
	    || !fzn_setting_key_ok(key, key_len))
		return FZN_NODE_RECORDS_MALFORMED;
	now = nr->now_ms();
	/* HOST SCOPE ABOUT ITSELF, at the host's own rank: what a host may
	 * always say of itself, and all a record ever is. */
	switch (fzn_setting_issue_ranked(nr->id->pubkey, nr->id->sign, FZN_SCOPE_HOST,
	                                 nr->id->pubkey, now, key, key_len, set, value, value_len,
	                                 FZN_SETTING_RANK_HOST, bytes, &len)) {
	case FZN_SETTING_OK:
		break;
	case FZN_SETTING_ERR_MALFORMED:
		return FZN_NODE_RECORDS_MALFORMED;
	default:
		return FZN_NODE_RECORDS_BACKEND;
	}
	err = fzn_buckets_add(nr->b, FZN_BUCKETS_RECORDS, nr->id->pubkey,
	                      fzn_message_epoch_of(now), bytes, len, NULL);
	if (err == FZN_BUCKETS_GONE)
		return FZN_NODE_RECORDS_GONE;
	if (err == FZN_BUCKETS_OK) {
		fzn_setting_t s;

		memset(&s, 0, sizeof(s));
		s.version = now;
		s.key = key;
		s.key_len = key_len;
		s.set = set;
		s.value = value;
		s.value_len = set ? value_len : 0u;
		note_listed(nr, nr->id->pubkey, &s);
	} else {
		/* A FAILED ADD MAY HAVE WRITTEN. */
		forget_lists(nr);
	}
	return err == FZN_BUCKETS_OK ? FZN_NODE_RECORDS_OK : FZN_NODE_RECORDS_BACKEND;
}

/* ---- trimmed by the rules, sec 815 ------------------------------------- */

struct held {
	uint8_t id[FZN_BUCKETS_ID_LEN];
	uint8_t host[FZN_PUBKEY_LEN];
	uint8_t key[FZN_SETTING_KEY_MAX];
	size_t key_len;
	uint64_t version;
	uint64_t place; /* among its key and host's, newest first, from 0 */
	/* A LIST'S RECORD that decides its member, sec 854: the newest of its
	 * key of every host's, ties by the greater host. Never let go. */
	int resolves;
};

/* BY KEY, newest first of every host's, ties by the greater host, then
 * id: the order a list's member is resolved in, sec 854. */
static int by_key_resolving(const void *a, const void *b)
{
	const struct held *x = a, *y = b;
	size_t n = x->key_len < y->key_len ? x->key_len : y->key_len;
	int c;

	if ((c = memcmp(x->key, y->key, n)) != 0)
		return c;
	if (x->key_len != y->key_len)
		return x->key_len < y->key_len ? -1 : 1;
	if (x->version != y->version)
		return x->version > y->version ? -1 : 1;
	if ((c = memcmp(x->host, y->host, FZN_PUBKEY_LEN)) != 0)
		return -c;
	return memcmp(x->id, y->id, FZN_BUCKETS_ID_LEN);
}

static int by_member(const void *a, const void *b)
{
	const fzn_node_list_member_t *x = a, *y = b;
	size_t n = x->member_len < y->member_len ? x->member_len : y->member_len;
	int c = memcmp(x->member, y->member, n);

	if (c)
		return c;
	return x->member_len < y->member_len ? -1 : x->member_len > y->member_len;
}

static int is_list_key(const uint8_t *key, size_t len)
{
	return len > FZN_NODE_LIST_PREFIX_LEN
	       && memcmp(key, FZN_NODE_LIST_PREFIX, FZN_NODE_LIST_PREFIX_LEN) == 0;
}

/* BY HOST AND KEY, newest first within them, ties by id: a total order. */
static int by_key_newest(const void *a, const void *b)
{
	const struct held *x = a, *y = b;
	int c = memcmp(x->host, y->host, FZN_PUBKEY_LEN);
	size_t n = x->key_len < y->key_len ? x->key_len : y->key_len;

	if (c)
		return c;
	if ((c = memcmp(x->key, y->key, n)) != 0)
		return c;
	if (x->key_len != y->key_len)
		return x->key_len < y->key_len ? -1 : 1;
	if (x->version != y->version)
		return x->version > y->version ? -1 : 1;
	return memcmp(x->id, y->id, FZN_BUCKETS_ID_LEN);
}

static int holds_text(const struct held *h, const fzn_retain_rule_t *r)
{
	size_t i;

	if (!r->match_len)
		return 1;
	for (i = 0; i + r->match_len <= h->key_len; i++)
		if (memcmp(h->key + i, r->match, r->match_len) == 0)
			return 1;
	return 0;
}

/* A LIST'S MEMBERS IN, sorted, for a rule's `list=`, sec 855. */
struct members {
	char (*m)[FZN_SETTING_KEY_MAX + 1u];
	size_t n, cap;
	int failed;
};

static void member_in(void *ctx, const fzn_node_list_member_t *m)
{
	struct members *ms = ctx;

	if (!m->in || ms->failed)
		return;
	if (ms->n == ms->cap) {
		size_t cap = ms->cap ? ms->cap * 2u : 32u;
		char (*more)[FZN_SETTING_KEY_MAX + 1u] = realloc(ms->m, cap * sizeof(*more));

		if (!more) {
			ms->failed = 1;
			return;
		}
		ms->m = more;
		ms->cap = cap;
	}
	memcpy(ms->m[ms->n++], m->member, m->member_len + 1u);
}

static int by_text(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b);
}

/* Whether one of `h`'s key's `/` words is a member of `ms`. */
static int holds_member(const struct held *h, const struct members *ms)
{
	size_t at = 0;

	while (at < h->key_len) {
		char w[FZN_SETTING_KEY_MAX + 1u];
		size_t end = at;

		while (end < h->key_len && h->key[end] != '/')
			end++;
		if (end > at) {
			memcpy(w, h->key + at, end - at);
			w[end - at] = '\0';
			if (ms->n && bsearch(w, ms->m, ms->n, sizeof(ms->m[0]), by_text))
				return 1;
		}
		at = end + 1u;
	}
	return 0;
}

/* Whether `r` reaches `h`, and if it does, whether `h` is within it. `ms`
 * the members of `r`'s list, where it names one. */
static int reaches(const fzn_retain_rule_t *r, const struct held *h, const struct members *ms)
{
	return r->kind != FZN_RETAIN_POLICY && r->data == FZN_RETAIN_RECORDS
	       && (!r->has_source || memcmp(r->source, h->host, FZN_PUBKEY_LEN) == 0)
	       && holds_text(h, r) && (!r->list[0] || holds_member(h, ms));
}

static int within(const fzn_retain_rule_t *r, const struct held *h, uint64_t now_ms)
{
	if (r->limit == FZN_RETAIN_COUNT)
		return h->place < r->value;
	/* AN AGE in microseconds, a record's in ms: one written ahead of this
	 * clock is within any age. */
	return h->version >= now_ms || (now_ms - h->version) <= r->value / 1000u;
}

fzn_node_records_err_t fzn_node_records_trim(const fzn_node_records_t *nr,
                                             const fzn_retain_rule_t *rules, size_t n,
                                             uint64_t now_ms, size_t *gone)
{
	static uint8_t ids[FZN_BUCKETS_CHUNK][FZN_BUCKETS_ID_LEN];
	static uint8_t item[FZN_BUCKETS_ITEM_MAX];
	static struct members ms[FZN_RETAIN_RULES_MAX];
	fzn_bucket_t *list = NULL;
	struct held *all = NULL;
	size_t room = 0, n_buckets = 0, n_all = 0, cap_all = 0, i, j, r, went = 0;
	int drops;
	fzn_node_records_err_t err = FZN_NODE_RECORDS_OK;

	if (gone)
		*gone = 0;
	if (!nr || !nr->b || !nr->verify || (n && !rules))
		return FZN_NODE_RECORDS_MALFORMED;
	if (!n)
		return FZN_NODE_RECORDS_OK;
	if (n > FZN_RETAIN_RULES_MAX)
		return FZN_NODE_RECORDS_MALFORMED;
	drops = fzn_retain_policy_drops(rules, n, FZN_RETAIN_RECORDS);
	/* EACH LIST A RULE NAMES, read as it resolves now, sec 855. A list that
	 * cannot be read fails the trim, rather than weighing its rule as if
	 * the list were empty: a keep reaching nothing would let go what it
	 * was written to protect. */
	memset(ms, 0, sizeof(ms));
	for (r = 0; r < n; r++)
		if (rules[r].data == FZN_RETAIN_RECORDS && rules[r].list[0]
		    && (!fzn_node_records_list_each(nr, (const uint8_t *)rules[r].list,
		                                    strlen(rules[r].list), member_in, &ms[r])
		        || ms[r].failed)) {
			for (i = 0; i <= r; i++)
				free(ms[i].m);
			return FZN_NODE_RECORDS_BACKEND;
		}
	if (fzn_buckets_list_all(nr->b, FZN_BUCKETS_RECORDS, &list, &room, &n_buckets)
	    != FZN_BUCKETS_OK) {
		free(list);
		for (r = 0; r < n; r++)
			free(ms[r].m);
		return FZN_NODE_RECORDS_BACKEND;
	}
	/* EVERY RECORD HELD, grown to fit (sec 704). */
	for (i = 0; i < n_buckets && err == FZN_NODE_RECORDS_OK; i++) {
		uint64_t pos = 0, total = 0;

		do {
			size_t got = 0;

			if (fzn_buckets_ids(nr->b, FZN_BUCKETS_RECORDS, list[i].subject, list[i].month,
			                    pos, ids, FZN_BUCKETS_CHUNK, &got, &total)
			    != FZN_BUCKETS_OK) {
				err = FZN_NODE_RECORDS_BACKEND;
				break;
			}
			for (j = 0; j < got; j++) {
				uint8_t subject[FZN_PUBKEY_LEN];
				uint32_t month = 0;
				size_t len = 0;
				fzn_setting_t s;

				/* A RECORD ALREADY LET GO reads as not held, and is passed. */
				if (fzn_buckets_item(nr->b, FZN_BUCKETS_RECORDS, ids[j], item, sizeof(item),
				                     &len, NULL, NULL)
				            != FZN_BUCKETS_OK
				    || !fzn_node_records_place(nr, item, len, subject, &month, &s))
					continue;
				if (n_all == cap_all) {
					size_t cap = cap_all ? cap_all * 2u : 64u;
					struct held *more = realloc(all, cap * sizeof(*more));

					if (!more) {
						err = FZN_NODE_RECORDS_BACKEND;
						break;
					}
					all = more;
					cap_all = cap;
				}
				memcpy(all[n_all].id, ids[j], FZN_BUCKETS_ID_LEN);
				memcpy(all[n_all].host, subject, FZN_PUBKEY_LEN);
				memcpy(all[n_all].key, s.key, s.key_len);
				all[n_all].key_len = s.key_len;
				all[n_all].version = s.version;
				all[n_all].resolves = 0;
				n_all++;
			}
			pos += got;
			if (!got)
				break;
		} while (pos < total && err == FZN_NODE_RECORDS_OK);
	}
	free(list);
	if (err != FZN_NODE_RECORDS_OK) {
		free(all);
		for (r = 0; r < n; r++)
			free(ms[r].m);
		return err;
	}
	/* EACH LIST MEMBER'S DECIDING RECORD, sec 854: kept whatever the rules
	 * say, so no host's trim changes what a list resolves to. The records
	 * it supersedes are weighed as any. */
	qsort(all, n_all, sizeof(*all), by_key_resolving);
	for (i = 0; i < n_all; i++)
		all[i].resolves = is_list_key(all[i].key, all[i].key_len)
		                  && (i == 0 || all[i].key_len != all[i - 1u].key_len
		                      || memcmp(all[i].key, all[i - 1u].key, all[i].key_len) != 0);
	qsort(all, n_all, sizeof(*all), by_key_newest);
	for (i = 0; i < n_all; i++)
		all[i].place = i && memcmp(all[i].host, all[i - 1u].host, FZN_PUBKEY_LEN) == 0
		                               && all[i].key_len == all[i - 1u].key_len
		                               && memcmp(all[i].key, all[i - 1u].key, all[i].key_len) == 0
		                       ? all[i - 1u].place + 1u
		                       : 0u;
	for (i = 0; i < n_all; i++) {
		int pruned = 0, kept = all[i].resolves;

		for (r = 0; r < n && !kept; r++) {
			if (!reaches(&rules[r], &all[i], &ms[r]))
				continue;
			if (rules[r].kind == FZN_RETAIN_KEEP && within(&rules[r], &all[i], now_ms))
				kept = 1;
			if (rules[r].kind == FZN_RETAIN_PRUNE && !within(&rules[r], &all[i], now_ms))
				pruned = 1;
		}
		if (kept || (!pruned && !drops))
			continue;
		if (fzn_buckets_let_go(nr->b, FZN_BUCKETS_RECORDS, all[i].id) != FZN_BUCKETS_OK) {
			err = FZN_NODE_RECORDS_BACKEND;
			break;
		}
		went++;
	}
	/* NOT NEEDED, as a trim keeps what decides each member: emptied all
	 * the same, once in a pass, so the cache never depends on that. */
	if (went || err != FZN_NODE_RECORDS_OK)
		forget_lists(nr);
	free(all);
	for (r = 0; r < n; r++)
		free(ms[r].m);
	if (gone)
		*gone = went;
	return err;
}

/* ---- the verbs ----------------------------------------------------------- */

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

static int hex_key(const uint8_t *w, size_t w_len, uint8_t out[FZN_PUBKEY_LEN])
{
	size_t i;

	if (w_len != 2u * FZN_PUBKEY_LEN)
		return 0;
	for (i = 0; i < 2u * FZN_PUBKEY_LEN; i++) {
		const char *h = memchr(HEX, w[i] >= 'A' && w[i] <= 'F' ? w[i] + ('a' - 'A') : w[i], 16u);

		if (!h || !w[i])
			return 0;
		out[i / 2u] = (uint8_t)((out[i / 2u] << 4) | (uint8_t)(h - HEX));
	}
	return 1;
}

static size_t add_record(const fzn_node_records_t *nr, const uint8_t *at, size_t left,
                         char *reply, size_t cap)
{
	static const char USAGE[] = "add record KEY VALUE";
	uint8_t value[FZN_SETTING_VALUE_MAX];
	const uint8_t *key;
	size_t key_len, value_len = 0;
	fzn_node_records_err_t err;

	if (!word(&at, &left, &key, &key_len) || !fzn_setting_key_ok(key, key_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	while (left && *at == ' ') {
		at++;
		left--;
	}
	if (!left || !fzn_unescape(at, left, value, sizeof(value), &value_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (!nr->id)
		return say(reply, cap, FZN_REPLY_UNSUPPORTED, "this node writes no records");
	err = fzn_node_records_write(nr, key, key_len, value, value_len);
	if (err == FZN_NODE_RECORDS_MALFORMED)
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (err == FZN_NODE_RECORDS_GONE)
		return say(reply, cap, FZN_REPLY_DENIED, "this month's records were let go here");
	if (err != FZN_NODE_RECORDS_OK)
		return say(reply, cap, FZN_REPLY_ERROR, "the record was not kept");
	return say(reply, cap, FZN_REPLY_OK, NULL);
}

/* THE LISTING: every record held of one host, or of every host, each
 * bucket in the order the store lists them, each record in the order it
 * was taken; the ones past FROM written while they fit whole. */
static size_t list_records(const fzn_node_records_t *nr, const uint8_t *at, size_t left,
                           char *reply, size_t cap)
{
	static const char USAGE[] = "list record [HOST] [under PREFIX] [FROM]";
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	static uint8_t ids[FZN_BUCKETS_CHUNK][FZN_BUCKETS_ID_LEN];
	static uint8_t item[FZN_BUCKETS_ITEM_MAX];
	fzn_bucket_t *list = NULL;
	size_t room = 0, n_buckets = 0, from = 0, seen = 0, shown = 0, used = 0, limit, i, j, k;
	uint8_t host[FZN_PUBKEY_LEN];
	const uint8_t *w, *prefix = NULL;
	size_t w_len, prefix_len = 0;
	int one = 0, more = 0;

	if (word(&at, &left, &w, &w_len)) {
		if (is_word(w, w_len, "self") && nr->id) {
			memcpy(host, nr->id->pubkey, FZN_PUBKEY_LEN);
			one = 1;
		} else if (hex_key(w, w_len, host)) {
			one = 1;
		} else {
			left += w_len;
			at -= w_len;
		}
		/* UNDER A KEY'S PREFIX, sec 861: the records whose key opens with
		 * it -- `seen/wlan0/` for one interface's stations -- so a reader
		 * pages its own and not every record held. */
		if (word(&at, &left, &w, &w_len)) {
			if (is_word(w, w_len, "under")) {
				if (!word(&at, &left, &prefix, &prefix_len)
				    || !fzn_setting_key_ok(prefix, prefix_len))
					return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
			} else {
				left += w_len;
				at -= w_len;
			}
		}
		if (word(&at, &left, &w, &w_len)) {
			for (i = 0; i < w_len; i++) {
				if (w[i] < '0' || w[i] > '9' || from > ((size_t)1 << 30))
					return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
				from = (from * 10u) + (size_t)(w[i] - '0');
			}
		}
	}
	if (left)
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (fzn_buckets_list_all(nr->b, FZN_BUCKETS_RECORDS, &list, &room, &n_buckets)
	    != FZN_BUCKETS_OK) {
		free(list);
		return say(reply, cap, FZN_REPLY_ERROR, "the records could not be listed");
	}
	limit = fzn_reply_ok_room(cap) > 32u ? fzn_reply_ok_room(cap) - 32u : 0u;
	if (limit > sizeof(items))
		limit = sizeof(items);
	for (i = 0; i < n_buckets && !more; i++) {
		uint64_t pos = 0, total = 0;

		if (one && memcmp(list[i].subject, host, FZN_PUBKEY_LEN) != 0)
			continue;
		do {
			size_t got = 0;

			if (fzn_buckets_ids(nr->b, FZN_BUCKETS_RECORDS, list[i].subject, list[i].month,
			                    pos, ids, FZN_BUCKETS_CHUNK, &got, &total)
			    != FZN_BUCKETS_OK)
				break;
			for (j = 0; j < got && !more; j++) {
				char line[2u + 2u * FZN_PUBKEY_LEN + FZN_SETTING_KEY_MAX + 24u
				          + 3u * FZN_SETTING_VALUE_MAX];
				uint8_t subject[FZN_PUBKEY_LEN];
				uint32_t month = 0;
				size_t len = 0, n = 0, wrote = 0;
				fzn_setting_t s;
				int c;

				if (fzn_buckets_item(nr->b, FZN_BUCKETS_RECORDS, ids[j], item, sizeof(item),
				                     &len, NULL, NULL)
				            != FZN_BUCKETS_OK
				    || !fzn_node_records_place(nr, item, len, subject, &month, &s)
				    || (prefix && (s.key_len < prefix_len
				                   || memcmp(s.key, prefix, prefix_len) != 0)))
					continue;
				if (seen++ < from)
					continue;
				line[n++] = ' ';
				for (k = 0; k < FZN_PUBKEY_LEN; k++) {
					line[n++] = HEX[subject[k] >> 4];
					line[n++] = HEX[subject[k] & 15u];
				}
				line[n++] = ',';
				memcpy(line + n, s.key, s.key_len);
				n += s.key_len;
				c = snprintf(line + n, sizeof(line) - n, ",%llu,",
				             (unsigned long long)s.version);
				if (c < 0)
					continue;
				n += (size_t)c;
				if (fzn_escape(s.value, s.value_len, line + n, sizeof(line) - n, &wrote)
				    != s.value_len)
					continue;
				n += wrote;
				/* A RECORD GOES IN WHOLE OR NOT AT ALL: the page ends where
				 * the next does not fit. */
				if (used + n > limit) {
					more = 1;
					break;
				}
				memcpy(items + used, line, n);
				used += n;
				shown++;
			}
			pos += got;
			if (!got)
				break;
		} while (pos < total && !more);
	}
	free(list);
	{
		int c = snprintf(detail, sizeof(detail), "%zu %zu %d", from, shown, more);

		if (c < 0 || (size_t)c + used > sizeof(detail))
			return 0;
		memcpy(detail + c, items, used);
		return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)c + used);
	}
}

/* THE NEWEST RECORD OF `KEY`, sec 816: of any host, or of HOST's; ties by
 * the greater host key, so every node holding the same records answers
 * the same. */
static size_t get_record(const fzn_node_records_t *nr, const uint8_t *at, size_t left,
                         char *reply, size_t cap)
{
	static const char USAGE[] = "get record KEY [HOST]";
	static uint8_t ids[FZN_BUCKETS_CHUNK][FZN_BUCKETS_ID_LEN];
	static uint8_t item[FZN_BUCKETS_ITEM_MAX], best[FZN_BUCKETS_ITEM_MAX];
	fzn_bucket_t *list = NULL;
	size_t room = 0, n_buckets = 0, i, j, k, key_len, w_len, best_len = 0, n = 0, wrote = 0;
	uint8_t host[FZN_PUBKEY_LEN], best_host[FZN_PUBKEY_LEN] = { 0 };
	const uint8_t *key, *w;
	uint64_t best_at = 0;
	int one = 0, found = 0, c;
	char detail[2u * FZN_PUBKEY_LEN + FZN_SETTING_KEY_MAX + 24u + 3u * FZN_SETTING_VALUE_MAX];
	fzn_setting_t s;

	if (!word(&at, &left, &key, &key_len) || !fzn_setting_key_ok(key, key_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (word(&at, &left, &w, &w_len)) {
		if (is_word(w, w_len, "self") && nr->id)
			memcpy(host, nr->id->pubkey, FZN_PUBKEY_LEN);
		else if (!hex_key(w, w_len, host))
			return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
		one = 1;
	}
	if (left)
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (fzn_buckets_list_all(nr->b, FZN_BUCKETS_RECORDS, &list, &room, &n_buckets)
	    != FZN_BUCKETS_OK) {
		free(list);
		return say(reply, cap, FZN_REPLY_ERROR, "the records could not be listed");
	}
	for (i = 0; i < n_buckets; i++) {
		uint64_t pos = 0, total = 0;

		if (one && memcmp(list[i].subject, host, FZN_PUBKEY_LEN) != 0)
			continue;
		do {
			size_t got = 0;

			if (fzn_buckets_ids(nr->b, FZN_BUCKETS_RECORDS, list[i].subject, list[i].month,
			                    pos, ids, FZN_BUCKETS_CHUNK, &got, &total)
			    != FZN_BUCKETS_OK)
				break;
			for (j = 0; j < got; j++) {
				uint8_t subject[FZN_PUBKEY_LEN];
				uint32_t month = 0;
				size_t len = 0;

				if (fzn_buckets_item(nr->b, FZN_BUCKETS_RECORDS, ids[j], item, sizeof(item),
				                     &len, NULL, NULL)
				            != FZN_BUCKETS_OK
				    || !fzn_node_records_place(nr, item, len, subject, &month, &s)
				    || s.key_len != key_len || memcmp(s.key, key, key_len) != 0)
					continue;
				if (found && (s.version < best_at
				              || (s.version == best_at
				                  && memcmp(subject, best_host, FZN_PUBKEY_LEN) <= 0)))
					continue;
				found = 1;
				best_at = s.version;
				memcpy(best_host, subject, FZN_PUBKEY_LEN);
				memcpy(best, item, len);
				best_len = len;
			}
			pos += got;
			if (!got)
				break;
		} while (pos < total);
	}
	free(list);
	if (!found)
		return say(reply, cap, FZN_REPLY_OK, "absent");
	if (!fzn_node_records_place(nr, best, best_len, host, &(uint32_t){ 0 }, &s))
		return say(reply, cap, FZN_REPLY_ERROR, "the record could not be read");
	for (k = 0; k < FZN_PUBKEY_LEN; k++) {
		detail[n++] = HEX[host[k] >> 4];
		detail[n++] = HEX[host[k] & 15u];
	}
	detail[n++] = ',';
	memcpy(detail + n, s.key, s.key_len);
	n += s.key_len;
	c = snprintf(detail + n, sizeof(detail) - n, ",%llu,", (unsigned long long)s.version);
	if (c < 0)
		return 0;
	n += (size_t)c;
	if (fzn_escape(s.value, s.value_len, detail + n, sizeof(detail) - n, &wrote) != s.value_len)
		return 0;
	return answer(reply, cap, FZN_REPLY_OK, detail, n + wrote);
}

/* ---- lists, sec 854 ---------------------------------------------------- */

/* A LIST'S NAME OR MEMBER: a key's word, without the `/` that separates
 * them. */
static int list_word_ok(const uint8_t *w, size_t n)
{
	return n && !memchr(w, '/', n) && fzn_setting_key_ok(w, n);
}

/* `list/NAME/MEMBER` into `key`: its length, or 0 when it is longer than a
 * key. */
static size_t list_key(const uint8_t *name, size_t name_len, const uint8_t *member,
                       size_t member_len, uint8_t key[FZN_SETTING_KEY_MAX])
{
	size_t n = FZN_NODE_LIST_PREFIX_LEN + name_len + 1u + member_len;

	if (n > FZN_SETTING_KEY_MAX)
		return 0;
	memcpy(key, FZN_NODE_LIST_PREFIX, FZN_NODE_LIST_PREFIX_LEN);
	memcpy(key + FZN_NODE_LIST_PREFIX_LEN, name, name_len);
	key[FZN_NODE_LIST_PREFIX_LEN + name_len] = '/';
	memcpy(key + FZN_NODE_LIST_PREFIX_LEN + name_len + 1u, member, member_len);
	return n;
}

fzn_node_records_err_t fzn_node_records_list_change(const fzn_node_records_t *nr,
                                                    const uint8_t *name, size_t name_len,
                                                    const uint8_t *member, size_t member_len,
                                                    int in, const uint8_t *value,
                                                    size_t value_len)
{
	uint8_t key[FZN_SETTING_KEY_MAX];
	size_t key_len;

	if (!name || !member || !list_word_ok(name, name_len) || !list_word_ok(member, member_len)
	    || (!in && value_len)
	    || !(key_len = list_key(name, name_len, member, member_len, key)))
		return FZN_NODE_RECORDS_MALFORMED;
	return write_record(nr, key, key_len, in ? 1 : 0, value, value_len);
}

/* ONE ROW A MEMBER, the newest of every host's, ties by the greater host:
 * every node holding the same records resolves the same. `s` a record of
 * the list, `subject` its setter, into `rows` unordered: 1 for a row added,
 * 0 for one changed or left, -1 for no room. */
static int take(fzn_node_list_member_t **rows, size_t *n_rows, size_t *cap_rows,
                const uint8_t subject[FZN_PUBKEY_LEN], const fzn_setting_t *s, size_t prefix_len)
{
	fzn_node_list_member_t *m;
	size_t k;
	int added = 0;

	for (k = 0; k < *n_rows; k++)
		if ((*rows)[k].member_len == s->key_len - prefix_len
		    && memcmp((*rows)[k].member, s->key + prefix_len, (*rows)[k].member_len) == 0)
			break;
	if (k < *n_rows
	    && (s->version < (*rows)[k].at
	        || (s->version == (*rows)[k].at
	            && memcmp(subject, (*rows)[k].host, FZN_PUBKEY_LEN) <= 0)))
		return 0;
	if (k == *n_rows) {
		if (*n_rows == *cap_rows) {
			size_t cap = *cap_rows ? *cap_rows * 2u : 32u;
			fzn_node_list_member_t *more = realloc(*rows, cap * sizeof(*more));

			if (!more)
				return -1;
			*rows = more;
			*cap_rows = cap;
		}
		(*n_rows)++;
		added = 1;
	}
	m = &(*rows)[k];
	m->member_len = s->key_len - prefix_len;
	memcpy(m->member, s->key + prefix_len, m->member_len);
	m->member[m->member_len] = '\0';
	memcpy(m->host, subject, FZN_PUBKEY_LEN);
	m->at = s->version;
	m->in = s->set;
	m->value_len = s->set ? s->value_len : 0u;
	if (m->value_len)
		memcpy(m->value, s->value, m->value_len);
	return added;
}

/* A RECORD KEPT, into each list the cache holds that it is a member of, as
 * resolving every record again would: so a host that sets an object often
 * does not read all it holds for each set (sec 950). A record of no list
 * held changes nothing held. */
static void note_listed(const fzn_node_records_t *nr, const uint8_t subject[FZN_PUBKEY_LEN],
                        const fzn_setting_t *s)
{
	size_t i, prefix_len;

	if (!nr->cache || s->key_len <= FZN_NODE_LIST_PREFIX_LEN
	    || memcmp(s->key, FZN_NODE_LIST_PREFIX, FZN_NODE_LIST_PREFIX_LEN) != 0)
		return;
	for (i = 0; i < FZN_NODE_RECORDS_CACHED; i++) {
		fzn_node_records_cached_t *l = &nr->cache->lists[i];
		int added;

		prefix_len = FZN_NODE_LIST_PREFIX_LEN + l->name_len + 1u;
		if (!l->held || s->key_len <= prefix_len
		    || memcmp(s->key + FZN_NODE_LIST_PREFIX_LEN, l->name, l->name_len) != 0
		    || s->key[prefix_len - 1u] != '/'
		    || !list_word_ok(s->key + prefix_len, s->key_len - prefix_len))
			continue;
		added = take(&l->rows, &l->n, &l->cap, subject, s, prefix_len);
		if (added < 0)
			l->held = 0;
		else if (added)
			qsort(l->rows, l->n, sizeof(*l->rows), by_member);
	}
}

int fzn_node_records_list_each(const fzn_node_records_t *nr, const uint8_t *name,
                               size_t name_len,
                               void (*each)(void *ctx, const fzn_node_list_member_t *m),
                               void *ctx)
{
	static uint8_t ids[FZN_BUCKETS_CHUNK][FZN_BUCKETS_ID_LEN];
	static uint8_t item[FZN_BUCKETS_ITEM_MAX];
	uint8_t prefix[FZN_SETTING_KEY_MAX];
	fzn_node_list_member_t *rows = NULL;
	fzn_bucket_t *list = NULL;
	size_t room = 0, n_buckets = 0, n_rows = 0, cap_rows = 0, prefix_len, i, j;
	int ok = 1;

	if (!nr || !nr->b || !nr->verify || !each || !name || !list_word_ok(name, name_len)
	    || FZN_NODE_LIST_PREFIX_LEN + name_len + 1u >= FZN_SETTING_KEY_MAX)
		return 0;
	memcpy(prefix, FZN_NODE_LIST_PREFIX, FZN_NODE_LIST_PREFIX_LEN);
	memcpy(prefix + FZN_NODE_LIST_PREFIX_LEN, name, name_len);
	prefix[FZN_NODE_LIST_PREFIX_LEN + name_len] = '/';
	prefix_len = FZN_NODE_LIST_PREFIX_LEN + name_len + 1u;
	if (nr->cache)
		for (i = 0; i < FZN_NODE_RECORDS_CACHED; i++) {
			size_t at = nr->cache->lists[i].n;

			if (!nr->cache->lists[i].held || nr->cache->lists[i].name_len != name_len
			    || memcmp(nr->cache->lists[i].name, name, name_len) != 0)
				continue;
			for (j = 0; j < at; j++)
				each(ctx, &nr->cache->lists[i].rows[j]);
			return 1;
		}
	if (fzn_buckets_list_all(nr->b, FZN_BUCKETS_RECORDS, &list, &room, &n_buckets)
	    != FZN_BUCKETS_OK) {
		free(list);
		return 0;
	}
	for (i = 0; i < n_buckets && ok; i++) {
		uint64_t pos = 0, total = 0;

		do {
			size_t got = 0;

			if (fzn_buckets_ids(nr->b, FZN_BUCKETS_RECORDS, list[i].subject, list[i].month,
			                    pos, ids, FZN_BUCKETS_CHUNK, &got, &total)
			    != FZN_BUCKETS_OK) {
				ok = 0;
				break;
			}
			for (j = 0; j < got; j++) {
				uint8_t subject[FZN_PUBKEY_LEN];
				uint32_t month = 0;
				size_t len = 0;
				fzn_setting_t s;

				if (fzn_buckets_item(nr->b, FZN_BUCKETS_RECORDS, ids[j], item, sizeof(item),
				                     &len, NULL, NULL)
				            != FZN_BUCKETS_OK
				    || !fzn_node_records_place(nr, item, len, subject, &month, &s)
				    || s.key_len <= prefix_len || memcmp(s.key, prefix, prefix_len) != 0
				    || !list_word_ok(s.key + prefix_len, s.key_len - prefix_len))
					continue;
				if (take(&rows, &n_rows, &cap_rows, subject, &s, prefix_len) < 0) {
					ok = 0;
					break;
				}
			}
			pos += got;
			if (!got)
				break;
		} while (pos < total && ok);
	}
	free(list);
	if (!ok) {
		free(rows);
		return 0;
	}
	qsort(rows, n_rows, sizeof(*rows), by_member);
	if (nr->cache) {
		fzn_node_records_cache_t *c = nr->cache;
		size_t k = c->next++ % FZN_NODE_RECORDS_CACHED;

		free(c->lists[k].rows);
		memcpy(c->lists[k].name, name, name_len);
		c->lists[k].name_len = name_len;
		c->lists[k].rows = rows;
		c->lists[k].n = n_rows;
		c->lists[k].cap = cap_rows;
		c->lists[k].held = 1;
		for (i = 0; i < n_rows; i++)
			each(ctx, &rows[i]);
		return 1;
	}
	for (i = 0; i < n_rows; i++)
		each(ctx, &rows[i]);
	free(rows);
	return 1;
}

int fzn_node_records_under(const fzn_node_records_t *nr, const uint8_t *prefix, size_t prefix_len,
                           void (*each)(void *ctx, const struct fzn_setting *s), void *ctx)
{
	static uint8_t ids[FZN_BUCKETS_CHUNK][FZN_BUCKETS_ID_LEN];
	static uint8_t item[FZN_BUCKETS_ITEM_MAX];
	fzn_bucket_t *list = NULL;
	size_t room = 0, n_buckets = 0, i, j;
	int ok = 1;

	if (!nr || !nr->b || !nr->verify || !each || (prefix_len && !prefix))
		return 0;
	if (fzn_buckets_list_all(nr->b, FZN_BUCKETS_RECORDS, &list, &room, &n_buckets)
	    != FZN_BUCKETS_OK) {
		free(list);
		return 0;
	}
	for (i = 0; i < n_buckets && ok; i++) {
		uint64_t pos = 0, total = 0;

		do {
			size_t got = 0;

			if (fzn_buckets_ids(nr->b, FZN_BUCKETS_RECORDS, list[i].subject, list[i].month,
			                    pos, ids, FZN_BUCKETS_CHUNK, &got, &total)
			    != FZN_BUCKETS_OK) {
				ok = 0;
				break;
			}
			for (j = 0; j < got; j++) {
				uint8_t subject[FZN_PUBKEY_LEN];
				uint32_t month = 0;
				size_t len = 0;
				fzn_setting_t s;

				if (fzn_buckets_item(nr->b, FZN_BUCKETS_RECORDS, ids[j], item, sizeof(item),
				                     &len, NULL, NULL)
				            != FZN_BUCKETS_OK
				    || !fzn_node_records_place(nr, item, len, subject, &month, &s)
				    || s.key_len < prefix_len || memcmp(s.key, prefix, prefix_len) != 0)
					continue;
				each(ctx, &s);
			}
			pos += got;
			if (!got)
				break;
		} while (pos < total && ok);
	}
	free(list);
	return ok;
}

struct listing {
	const uint8_t *member; /* `get`'s one, or NULL for every one */
	size_t member_len;
	size_t from, seen, shown, used, limit;
	int more, found;
	fzn_node_list_member_t one;
	char *items;
};

static void list_one(void *ctx, const fzn_node_list_member_t *m)
{
	struct listing *l = ctx;
	char line[2u + FZN_SETTING_KEY_MAX + 3u * FZN_SETTING_VALUE_MAX];
	size_t n = 0, wrote = 0;

	if (l->member) {
		if (m->member_len == l->member_len && memcmp(m->member, l->member, m->member_len) == 0) {
			l->one = *m;
			l->found = 1;
		}
		return;
	}
	if (!m->in || l->more || l->seen++ < l->from)
		return;
	line[n++] = ' ';
	memcpy(line + n, m->member, m->member_len);
	n += m->member_len;
	line[n++] = ',';
	if (fzn_escape(m->value, m->value_len, line + n, sizeof(line) - n, &wrote) != m->value_len)
		return;
	n += wrote;
	/* A MEMBER GOES IN WHOLE OR NOT AT ALL. */
	if (l->used + n > l->limit) {
		l->more = 1;
		return;
	}
	memcpy(l->items + l->used, line, n);
	l->used += n;
	l->shown++;
}

/* `add listed NAME MEMBER [VALUE]`, `remove listed NAME MEMBER`,
 * `get listed NAME MEMBER` and `list listed NAME [FROM]`. */
static size_t listed(const fzn_node_records_t *nr, fzn_verb_t verb, const uint8_t *at,
                     size_t left, char *reply, size_t cap)
{
	static const char USAGE[] = "add listed NAME MEMBER [VALUE], remove listed NAME MEMBER, "
	                            "get listed NAME MEMBER, list listed NAME [FROM]";
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	uint8_t value[FZN_SETTING_VALUE_MAX];
	const uint8_t *name, *member = NULL, *w;
	size_t name_len, member_len = 0, value_len = 0, w_len, i;
	struct listing l;

	memset(&l, 0, sizeof(l));
	if (!word(&at, &left, &name, &name_len) || !list_word_ok(name, name_len))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	/* AN OBJECT'S LISTS, sec 948: read here, and written by `set object` alone,
	 * which checks a value and which a `listed` grant is not. */
	if ((verb == FZN_VERB_ADD || verb == FZN_VERB_REMOVE)
	    && (is_word(name, name_len, "object") || is_word(name, name_len, "object-value")))
		return say(reply, cap, FZN_REPLY_DENIED, "that list is the object verbs'");
	if (verb != FZN_VERB_LIST
	    && (!word(&at, &left, &member, &member_len) || !list_word_ok(member, member_len)))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (verb == FZN_VERB_ADD) {
		while (left && *at == ' ') {
			at++;
			left--;
		}
		if (left && !fzn_unescape(at, left, value, sizeof(value), &value_len))
			return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
		left = 0;
	}
	if (verb == FZN_VERB_LIST && word(&at, &left, &w, &w_len))
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || l.from > ((size_t)1 << 30))
				return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
			l.from = (l.from * 10u) + (size_t)(w[i] - '0');
		}
	if (left)
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	if (verb == FZN_VERB_ADD || verb == FZN_VERB_REMOVE) {
		fzn_node_records_err_t err;

		if (!nr->id)
			return say(reply, cap, FZN_REPLY_UNSUPPORTED, "this node writes no records");
		err = fzn_node_records_list_change(nr, name, name_len, member, member_len,
		                                   verb == FZN_VERB_ADD, value, value_len);
		if (err == FZN_NODE_RECORDS_MALFORMED)
			return say(reply, cap, FZN_REPLY_MALFORMED, "a list's name and member are one "
			                                            "key together, at most 64 bytes");
		if (err == FZN_NODE_RECORDS_GONE)
			return say(reply, cap, FZN_REPLY_DENIED, "this month's records were let go here");
		if (err != FZN_NODE_RECORDS_OK)
			return say(reply, cap, FZN_REPLY_ERROR, "the record was not kept");
		return say(reply, cap, FZN_REPLY_OK, NULL);
	}
	l.member = member;
	l.member_len = member_len;
	l.items = items;
	l.limit = fzn_reply_ok_room(cap) > 32u ? fzn_reply_ok_room(cap) - 32u : 0u;
	if (l.limit > sizeof(items))
		l.limit = sizeof(items);
	if (!fzn_node_records_list_each(nr, name, name_len, list_one, &l))
		return say(reply, cap, FZN_REPLY_ERROR, "the list could not be read");
	if (verb == FZN_VERB_GET) {
		size_t wrote = 0;

		if (!l.found)
			return say(reply, cap, FZN_REPLY_OK, "absent");
		if (!l.one.in)
			return say(reply, cap, FZN_REPLY_OK, "out");
		if (!l.one.value_len)
			return say(reply, cap, FZN_REPLY_OK, "in");
		memcpy(detail, "in ", 3u);
		if (fzn_escape(l.one.value, l.one.value_len, detail + 3, sizeof(detail) - 3u, &wrote)
		    != l.one.value_len)
			return 0;
		return answer(reply, cap, FZN_REPLY_OK, detail, 3u + wrote);
	}
	{
		int c = snprintf(detail, sizeof(detail), "%zu %zu %d", l.from, l.shown, l.more);

		if (c < 0 || (size_t)c + l.used > sizeof(detail))
			return 0;
		memcpy(detail + c, items, l.used);
		return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)c + l.used);
	}
}

size_t fzn_node_records_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                              char *reply, size_t reply_cap)
{
	const fzn_node_records_t *nr = (const fzn_node_records_t *)ctx;
	const uint8_t *at, *subject;
	size_t left, subject_len;

	if (!nr || !request || !reply || !request->arg)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &subject, &subject_len))
		return 0;
	if (is_word(subject, subject_len, "listed")) {
		if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_REMOVE
		    && request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET)
			return 0;
		if (origin != FZN_ORIGIN_SAME_USER)
			return say(reply, reply_cap, FZN_REPLY_DENIED, "lists need this node's own user");
		if (!nr->b || !nr->verify)
			return say(reply, reply_cap, FZN_REPLY_UNSUPPORTED, "no store for records");
		return listed(nr, request->parsed, at, left, reply, reply_cap);
	}
	if (!is_word(subject, subject_len, "record"))
		return 0;
	if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_LIST
	    && request->parsed != FZN_VERB_GET)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return say(reply, reply_cap, FZN_REPLY_DENIED, "records need this node's own user");
	if (!nr->b || !nr->verify)
		return say(reply, reply_cap, FZN_REPLY_UNSUPPORTED, "no store for records");
	if (request->parsed == FZN_VERB_ADD)
		return add_record(nr, at, left, reply, reply_cap);
	if (request->parsed == FZN_VERB_GET)
		return get_record(nr, at, left, reply, reply_cap);
	return list_records(nr, at, left, reply, reply_cap);
}
