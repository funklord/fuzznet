#include "clocks.h"
#include "types.h"

#include <stdio.h>
#include <string.h>

void fzn_node_clocks_init(fzn_node_clocks_t *c, fzn_node_clock_t *rows, size_t cap)
{
	if (!c)
		return;
	c->rows = rows;
	c->used = 0;
	c->cap = rows ? cap : 0u;
}

int fzn_node_clocks_use(fzn_node_clocks_t *c, fzn_node_clock_t *rows, size_t cap)
{
	if (!c || !rows || cap < c->used)
		return 0;
	if (c->used && rows != c->rows)
		memmove(rows, c->rows, c->used * sizeof(*rows));
	c->rows = rows;
	c->cap = cap;
	return 1;
}

/* ROWS PAST THEIR KEEPING forgotten, the rest kept in order. */
static void forget_old(fzn_node_clocks_t *c, uint64_t now)
{
	size_t i, kept = 0;

	for (i = 0; i < c->used; i++)
		if (c->rows[i].at + FZN_NODE_CLOCKS_KEEP_S > now) {
			if (kept != i)
				c->rows[kept] = c->rows[i];
			kept++;
		}
	c->used = kept;
}

fzn_node_clocks_err_t fzn_node_clocks_note(fzn_node_clocks_t *c,
                                           const uint8_t peer[FZN_PUBKEY_LEN], int ahead,
                                           uint64_t seconds, uint64_t now)
{
	fzn_node_clock_t *r;
	size_t i;

	if (!c || !peer || (!c->rows && c->cap))
		return FZN_NODE_CLOCKS_MALFORMED;
	forget_old(c, now);
	for (i = 0; i < c->used; i++)
		if (memcmp(c->rows[i].peer, peer, FZN_PUBKEY_LEN) == 0) {
			r = &c->rows[i];
			r->seconds = seconds;
			r->at = now;
			if (r->ahead == (ahead != 0))
				return FZN_NODE_CLOCKS_OK;
			r->ahead = ahead != 0;
			return FZN_NODE_CLOCKS_NEW;
		}
	if (c->used == c->cap)
		return FZN_NODE_CLOCKS_ROOM;
	r = &c->rows[c->used++];
	memcpy(r->peer, peer, FZN_PUBKEY_LEN);
	r->ahead = ahead != 0;
	r->seconds = seconds;
	r->at = now;
	return FZN_NODE_CLOCKS_NEW;
}

static int next_word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *n)
{
	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	if (!*left)
		return 0;
	*w = *at;
	while (*left && **at != ' ') {
		(*at)++;
		(*left)--;
	}
	*n = (size_t)(*at - *w);
	return 1;
}

static int from_of(const uint8_t *w, size_t n, size_t *from)
{
	size_t i;

	if (!n || n > 10u)
		return 0;
	*from = 0;
	for (i = 0; i < n; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		*from = *from * 10u + (size_t)(w[i] - '0');
	}
	return 1;
}

#define REPLY(...) ((size_t)snprintf(reply, cap, __VA_ARGS__))

size_t fzn_node_clocks_local(fzn_node_clocks_t *c, fzn_origin_t origin,
                             const fzn_request_t *request, uint64_t now, char *reply,
                             size_t cap)
{
	static const char HEX[] = "0123456789abcdef";
	const uint8_t *at = request ? request->arg : NULL, *w;
	size_t left = request ? request->arg_len : 0u, n, from = 0, out, i, k;

	if (!at || request->parsed != FZN_VERB_LIST || !next_word(&at, &left, &w, &n) || n != 5u
	    || memcmp(w, "clock", 5u) != 0)
		return 0;
	if (!reply || cap < 2u)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return REPLY("denied clocks are this node's own user's\n");
	if (next_word(&at, &left, &w, &n) && (left || !from_of(w, n, &from)))
		return REPLY("malformed list clock [FROM]\n");
	if (!c)
		return REPLY("error this node keeps no clocks\n");
	forget_old(c, now);
	if (from > c->used)
		from = c->used;
	out = (size_t)snprintf(reply, cap, "ok %zu %zu", c->used, from);
	for (i = from; i < c->used; i++) {
		char row[2u * FZN_PUBKEY_LEN + 64u];
		int m;

		for (k = 0; k < FZN_PUBKEY_LEN; k++) {
			row[2u * k] = HEX[c->rows[i].peer[k] >> 4];
			row[2u * k + 1u] = HEX[c->rows[i].peer[k] & 15u];
		}
		m = snprintf(row + 2u * FZN_PUBKEY_LEN, sizeof(row) - 2u * FZN_PUBKEY_LEN,
		             ",%s,%llu,%llu", c->rows[i].ahead ? "ahead" : "behind",
		             (unsigned long long)c->rows[i].seconds,
		             (unsigned long long)c->rows[i].at);
		if (m < 0 || out + 1u + 2u * FZN_PUBKEY_LEN + (size_t)m + 1u >= cap)
			break;
		out += (size_t)snprintf(reply + out, cap - out, " %s", row);
	}
	return out + (size_t)snprintf(reply + out, cap - out, "\n");
}

/* ---- the time probe and offsets per peer, sec 719 stage 1 -------------- */

int fzn_node_time_is_ask(const uint8_t *payload, size_t len)
{
	return payload && len == FZN_NODE_TIME_ASK_LEN && payload[0] == FZN_TYPES_VERSION_SHARED
	       && payload[1] == FZN_TYPE_TIME_ASK;
}

size_t fzn_node_time_ask(const uint8_t nonce[FZN_NODE_TIME_NONCE_LEN], uint8_t *out, size_t cap)
{
	if (!nonce || !out || cap < FZN_NODE_TIME_ASK_LEN)
		return 0;
	out[0] = FZN_TYPES_VERSION_SHARED;
	out[1] = FZN_TYPE_TIME_ASK;
	memcpy(out + 2, nonce, FZN_NODE_TIME_NONCE_LEN);
	return FZN_NODE_TIME_ASK_LEN;
}

size_t fzn_node_time_answer(const uint8_t *ask, size_t ask_len, uint64_t now_ms, uint8_t *out,
                            size_t cap)
{
	size_t i;

	if (!fzn_node_time_is_ask(ask, ask_len) || !out || cap < FZN_NODE_TIME_ANSWER_LEN)
		return 0;
	out[0] = FZN_TYPES_VERSION_SHARED;
	out[1] = FZN_TYPE_TIME;
	memcpy(out + 2, ask + 2, FZN_NODE_TIME_NONCE_LEN);
	for (i = 0; i < 8u; i++)
		out[2u + FZN_NODE_TIME_NONCE_LEN + i] = (uint8_t)(now_ms >> (56u - 8u * i));
	return FZN_NODE_TIME_ANSWER_LEN;
}

int fzn_node_time_take(const uint8_t *answer, size_t len,
                       const uint8_t nonce[FZN_NODE_TIME_NONCE_LEN], uint64_t sent_ms,
                       uint64_t got_ms, int64_t *offset_ms, uint64_t *rtt_ms)
{
	uint64_t theirs = 0, mid;
	size_t i;

	if (!answer || len != FZN_NODE_TIME_ANSWER_LEN || !nonce || !offset_ms || !rtt_ms
	    || answer[0] != FZN_TYPES_VERSION_SHARED || answer[1] != FZN_TYPE_TIME
	    || memcmp(answer + 2, nonce, FZN_NODE_TIME_NONCE_LEN) != 0 || got_ms < sent_ms)
		return 0;
	for (i = 0; i < 8u; i++)
		theirs = (theirs << 8) | answer[2u + FZN_NODE_TIME_NONCE_LEN + i];
	/* THE MIDPOINT, the moment the answer was most likely made: half the
	 * round trip each way is the assumption, and half the round trip the
	 * error bound. */
	mid = sent_ms + (got_ms - sent_ms) / 2u;
	/* A TIME NO CLOCK KEEPS is refused: past FZN_NODE_TIME_SPAN_MS either
	 * way the offset would not fit a signed sum of two, which the median of
	 * an even vote takes. A peer answering UINT64_MAX is lying, not slow. */
	if ((theirs >= mid ? theirs - mid : mid - theirs) > FZN_NODE_TIME_SPAN_MS)
		return 0;
	*rtt_ms = got_ms - sent_ms;
	*offset_ms = theirs >= mid ? (int64_t)(theirs - mid) : -(int64_t)(mid - theirs);
	return 1;
}

void fzn_node_offsets_init(fzn_node_offsets_t *o, fzn_node_offset_t *rows, size_t cap)
{
	if (!o)
		return;
	o->rows = rows;
	o->used = 0;
	o->cap = rows ? cap : 0u;
}

int fzn_node_offsets_use(fzn_node_offsets_t *o, fzn_node_offset_t *rows, size_t cap)
{
	if (!o || !rows || cap < o->used)
		return 0;
	if (o->used && rows != o->rows)
		memmove(rows, o->rows, o->used * sizeof(*rows));
	o->rows = rows;
	o->cap = cap;
	return 1;
}

static void offsets_forget_old(fzn_node_offsets_t *o, uint64_t now)
{
	size_t i, kept = 0;

	for (i = 0; i < o->used; i++)
		if (o->rows[i].at + FZN_NODE_CLOCKS_KEEP_S > now) {
			if (kept != i)
				o->rows[kept] = o->rows[i];
			kept++;
		}
	o->used = kept;
}

fzn_node_clocks_err_t fzn_node_offsets_note(fzn_node_offsets_t *o,
                                            const uint8_t peer[FZN_PUBKEY_LEN], int estate,
                                            int64_t offset_ms, uint64_t rtt_ms, uint64_t now)
{
	fzn_node_offset_t *r = NULL;
	fzn_node_clocks_err_t made = FZN_NODE_CLOCKS_OK;
	size_t i;

	if (!o || !peer || (!o->rows && o->cap))
		return FZN_NODE_CLOCKS_MALFORMED;
	offsets_forget_old(o, now);
	for (i = 0; i < o->used && !r; i++)
		if (memcmp(o->rows[i].peer, peer, FZN_PUBKEY_LEN) == 0)
			r = &o->rows[i];
	if (!r) {
		if (o->used == o->cap)
			return FZN_NODE_CLOCKS_ROOM;
		r = &o->rows[o->used++];
		memset(r, 0, sizeof(*r));
		memcpy(r->peer, peer, FZN_PUBKEY_LEN);
		made = FZN_NODE_CLOCKS_NEW;
	}
	r->offset_ms[r->next] = offset_ms;
	r->rtt_ms[r->next] = rtt_ms;
	r->next = (r->next + 1u) % FZN_NODE_OFFSET_SAMPLES;
	if (r->n < FZN_NODE_OFFSET_SAMPLES)
		r->n++;
	r->at = now;
	r->estate = estate != 0;
	return made;
}

static const fzn_node_offset_t *offset_row(const fzn_node_offsets_t *o,
                                           const uint8_t peer[FZN_PUBKEY_LEN])
{
	size_t i;

	if (!o || !peer)
		return NULL;
	for (i = 0; i < o->used; i++)
		if (memcmp(o->rows[i].peer, peer, FZN_PUBKEY_LEN) == 0)
			return &o->rows[i];
	return NULL;
}

/* THE FILTER: the sample with the least round trip, the newest of equals,
 * since a clock drifts. Walked newest first: the window is circular, so an
 * array index says nothing of age. */
static size_t best_sample(const fzn_node_offset_t *r)
{
	size_t k, i, best = (r->next + FZN_NODE_OFFSET_SAMPLES - 1u) % FZN_NODE_OFFSET_SAMPLES;

	for (k = 1; k < r->n; k++) {
		i = (r->next + FZN_NODE_OFFSET_SAMPLES - 1u - k) % FZN_NODE_OFFSET_SAMPLES;
		if (r->rtt_ms[i] < r->rtt_ms[best])
			best = i;
	}
	return best;
}

int fzn_node_offsets_of(const fzn_node_offsets_t *o, const uint8_t peer[FZN_PUBKEY_LEN],
                        int64_t *offset_ms, uint64_t *rtt_ms)
{
	const fzn_node_offset_t *r = offset_row(o, peer);
	size_t b;

	if (!r || !r->n)
		return 0;
	b = best_sample(r);
	if (offset_ms)
		*offset_ms = r->offset_ms[b];
	if (rtt_ms)
		*rtt_ms = r->rtt_ms[b];
	return 1;
}

uint64_t fzn_node_offsets_at(const fzn_node_offsets_t *o, const uint8_t peer[FZN_PUBKEY_LEN])
{
	const fzn_node_offset_t *r = offset_row(o, peer);

	return r ? r->at : 0u;
}

size_t fzn_node_offsets_local(fzn_node_offsets_t *o, fzn_origin_t origin,
                              const fzn_request_t *request, uint64_t now, char *reply,
                              size_t cap)
{
	static const char HEX[] = "0123456789abcdef";
	const uint8_t *at = request ? request->arg : NULL, *w;
	size_t left = request ? request->arg_len : 0u, n, from = 0, out, i, k;

	if (!at || request->parsed != FZN_VERB_LIST || !next_word(&at, &left, &w, &n) || n != 6u
	    || memcmp(w, "offset", 6u) != 0)
		return 0;
	if (!reply || cap < 2u)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return REPLY("denied clocks are this node's own user's\n");
	if (next_word(&at, &left, &w, &n) && (left || !from_of(w, n, &from)))
		return REPLY("malformed list offset [FROM]\n");
	if (!o)
		return REPLY("error this node keeps no offsets\n");
	offsets_forget_old(o, now);
	if (from > o->used)
		from = o->used;
	out = (size_t)snprintf(reply, cap, "ok %zu %zu", o->used, from);
	for (i = from; i < o->used; i++) {
		const fzn_node_offset_t *r = &o->rows[i];
		char row[2u * FZN_PUBKEY_LEN + 72u];
		size_t b = best_sample(r);
		int m;

		for (k = 0; k < FZN_PUBKEY_LEN; k++) {
			row[2u * k] = HEX[r->peer[k] >> 4];
			row[2u * k + 1u] = HEX[r->peer[k] & 15u];
		}
		m = snprintf(row + 2u * FZN_PUBKEY_LEN, sizeof(row) - 2u * FZN_PUBKEY_LEN,
		             ",%lld,%llu,%llu", (long long)r->offset_ms[b],
		             (unsigned long long)r->rtt_ms[b], (unsigned long long)r->at);
		if (m < 0 || out + 1u + 2u * FZN_PUBKEY_LEN + (size_t)m + 1u >= cap)
			break;
		out += (size_t)snprintf(reply + out, cap - out, " %s", row);
	}
	return out + (size_t)snprintf(reply + out, cap - out, "\n");
}

/* ---- estate time, sec 719 stage 2 --------------------------------------- */

/* THE ESTATE'S VOTES: this node's zero, then each estate device's filtered
 * offset sampled within the keeping. `i` 0 is this node. */
static int vote(const fzn_node_offsets_t *o, uint64_t now, size_t i, int64_t *v)
{
	const fzn_node_offset_t *r;

	if (i == 0u) {
		*v = 0;
		return 1;
	}
	r = &o->rows[i - 1u];
	if (!r->estate || !r->n || r->at + FZN_NODE_CLOCKS_KEEP_S <= now)
		return 0;
	*v = r->offset_ms[best_sample(r)];
	return 1;
}

/* THE K-TH SMALLEST VOTE, by counting: an estate's devices are few, so a
 * pass a candidate costs nothing worth a buffer. */
static int64_t kth_vote(const fzn_node_offsets_t *o, uint64_t now, size_t votes, size_t k)
{
	size_t i, j, below, at_or_below;
	int64_t v, w;

	for (i = 0; i <= o->used; i++) {
		if (!vote(o, now, i, &v))
			continue;
		below = at_or_below = 0;
		for (j = 0; j <= o->used; j++)
			if (vote(o, now, j, &w)) {
				below += w < v;
				at_or_below += w <= v;
			}
		if (below <= k && k < at_or_below)
			return v;
	}
	(void)votes;
	return 0;
}

fzn_node_clock_state_t fzn_node_clock_estate(const fzn_node_offsets_t *o, uint64_t now,
                                             int64_t *offset_ms, size_t *devices)
{
	size_t i, votes = 0;
	int64_t v, median;

	if (offset_ms)
		*offset_ms = 0;
	if (devices)
		*devices = 0;
	if (!o)
		return FZN_NODE_CLOCK_UNSURE;
	for (i = 0; i <= o->used; i++)
		votes += (size_t)vote(o, now, i, &v);
	/* THE MEDIAN, the mean of the middle two of an even count. */
	if (votes % 2u)
		median = kth_vote(o, now, votes, votes / 2u);
	else
		median = (kth_vote(o, now, votes, votes / 2u - 1u) + kth_vote(o, now, votes, votes / 2u))
		         / 2;
	if (offset_ms)
		*offset_ms = median;
	if (devices)
		*devices = votes - 1u;
	if (votes - 1u < FZN_NODE_CLOCK_DEVICES_MIN)
		return FZN_NODE_CLOCK_UNSURE;
	return median > FZN_NODE_CLOCK_WRONG_MS || median < -FZN_NODE_CLOCK_WRONG_MS
	               ? FZN_NODE_CLOCK_WRONG
	               : FZN_NODE_CLOCK_RIGHT;
}

const char *fzn_node_clock_state_str(fzn_node_clock_state_t state)
{
	switch (state) {
	case FZN_NODE_CLOCK_RIGHT:
		return "right";
	case FZN_NODE_CLOCK_WRONG:
		return "wrong";
	case FZN_NODE_CLOCK_UNSURE:
		break;
	}
	return "unsure";
}

size_t fzn_node_clock_local(const fzn_node_offsets_t *o, fzn_origin_t origin,
                            const fzn_request_t *request, uint64_t now, char *reply, size_t cap)
{
	const uint8_t *at = request ? request->arg : NULL, *w;
	size_t left = request ? request->arg_len : 0u, n, devices = 0;
	fzn_node_clock_state_t state;
	int64_t offset = 0;

	if (!at || request->parsed != FZN_VERB_GET || !next_word(&at, &left, &w, &n) || n != 5u
	    || memcmp(w, "clock", 5u) != 0)
		return 0;
	if (!reply || cap < 2u)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return REPLY("denied clocks are this node's own user's\n");
	if (next_word(&at, &left, &w, &n))
		return REPLY("malformed get clock\n");
	state = fzn_node_clock_estate(o, now, &offset, &devices);
	return REPLY("ok %lld %zu %s\n", (long long)offset, devices, fzn_node_clock_state_str(state));
}
