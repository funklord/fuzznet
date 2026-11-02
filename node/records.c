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

fzn_node_apply_outcome_t fzn_node_records_file(const fzn_node_records_t *nr,
                                               const uint8_t subject[FZN_PUBKEY_LEN],
                                               uint32_t month, const uint8_t *item, size_t len)
{
	uint8_t setter[FZN_PUBKEY_LEN];
	uint32_t at = 0;
	fzn_buckets_err_t err;

	if (!nr || !nr->b || !subject || !fzn_node_records_place(nr, item, len, setter, &at, NULL)
	    || at != month || !fzn_ct_memeq(setter, subject, FZN_PUBKEY_LEN))
		return FZN_NODE_APPLY_REFUSED;
	err = fzn_buckets_add(nr->b, FZN_BUCKETS_RECORDS, subject, month, item, len, NULL);
	/* A MONTH LET GO HERE is not taken back for a peer's holding it. */
	if (err == FZN_BUCKETS_GONE)
		return FZN_NODE_APPLY_APPLIED;
	return err == FZN_BUCKETS_OK ? FZN_NODE_APPLY_APPLIED : FZN_NODE_APPLY_NOT_SAVED;
}

fzn_node_records_err_t fzn_node_records_write(const fzn_node_records_t *nr, const uint8_t *key,
                                              size_t key_len, const uint8_t *value,
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
	                                 nr->id->pubkey, now, key, key_len, 1, value, value_len,
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
};

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

/* Whether `r` reaches `h`, and if it does, whether `h` is within it. */
static int reaches(const fzn_retain_rule_t *r, const struct held *h)
{
	return r->kind != FZN_RETAIN_POLICY && r->data == FZN_RETAIN_RECORDS
	       && (!r->has_source || memcmp(r->source, h->host, FZN_PUBKEY_LEN) == 0)
	       && holds_text(h, r);
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
	drops = fzn_retain_policy_drops(rules, n, FZN_RETAIN_RECORDS);
	if (fzn_buckets_list_all(nr->b, FZN_BUCKETS_RECORDS, &list, &room, &n_buckets)
	    != FZN_BUCKETS_OK) {
		free(list);
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
		return err;
	}
	qsort(all, n_all, sizeof(*all), by_key_newest);
	for (i = 0; i < n_all; i++)
		all[i].place = i && memcmp(all[i].host, all[i - 1u].host, FZN_PUBKEY_LEN) == 0
		                               && all[i].key_len == all[i - 1u].key_len
		                               && memcmp(all[i].key, all[i - 1u].key, all[i].key_len) == 0
		                       ? all[i - 1u].place + 1u
		                       : 0u;
	for (i = 0; i < n_all; i++) {
		int pruned = 0, kept = 0;

		for (r = 0; r < n; r++) {
			if (!reaches(&rules[r], &all[i]))
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
	free(all);
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
	static const char USAGE[] = "list record [HOST] [FROM]";
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	static uint8_t ids[FZN_BUCKETS_CHUNK][FZN_BUCKETS_ID_LEN];
	static uint8_t item[FZN_BUCKETS_ITEM_MAX];
	fzn_bucket_t *list = NULL;
	size_t room = 0, n_buckets = 0, from = 0, seen = 0, shown = 0, used = 0, limit, i, j, k;
	uint8_t host[FZN_PUBKEY_LEN];
	const uint8_t *w;
	size_t w_len;
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
				    || !fzn_node_records_place(nr, item, len, subject, &month, &s))
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
	uint8_t host[FZN_PUBKEY_LEN], best_host[FZN_PUBKEY_LEN];
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
	if (!word(&at, &left, &subject, &subject_len) || !is_word(subject, subject_len, "record"))
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
