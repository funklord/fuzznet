/* See messages.h. */

#define _POSIX_C_SOURCE 200809L

#include "messages.h"

#include "../contact/contact.h"
#include "../wire/bytes.h"

#include <stdio.h>
#include <string.h>

static const char HEX[] = "0123456789abcdef";

/* ---- replies and words -------------------------------------------------- */

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

static size_t refuse(char *reply, size_t cap, fzn_messages_err_t err)
{
	return say(reply, cap,
	           err == FZN_MESSAGES_ERR_MALFORMED || err == FZN_MESSAGES_ERR_TEXT
	                   ? FZN_REPLY_MALFORMED
	                   : FZN_REPLY_ERROR,
	           fzn_messages_err_str(err));
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
	if (*left) {
		(*at)++;
		(*left)--;
	}
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

static void hex_of(const uint8_t *b, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		out[i * 2u] = HEX[b[i] >> 4];
		out[(i * 2u) + 1u] = HEX[b[i] & 15u];
	}
}

/* Escape `n` bytes into `out`, at most `cap`, as notes' listing does; how
 * many input bytes went in. */
static size_t escape(const uint8_t *b, size_t n, char *out, size_t cap, size_t *written)
{
	size_t i, w = 0;

	for (i = 0; i < n; i++) {
		uint8_t c = b[i];

		if (c <= 0x20u || c == '%' || c == ',' || c == 0x7fu) {
			if (cap - w < 3u)
				break;
			out[w++] = '%';
			out[w++] = HEX[c >> 4];
			out[w++] = HEX[c & 15u];
		} else {
			if (cap - w < 1u)
				break;
			out[w++] = (char)c;
		}
	}
	*written = w;
	return i;
}

/* Undo %XX into `out`, at most `cap`: 0 for a malformed escape or a text
 * past `cap`. */
static int unescape(const uint8_t *in, size_t n, char *out, size_t cap, size_t *len)
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
		if (w >= cap)
			return 0;
		out[w++] = (char)c;
	}
	*len = w;
	return 1;
}

static int same_key(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, FZN_PUBKEY_LEN) == 0;
}

/* ---- the devices and their streams -------------------------------------- */

/* THE STORE'S ITEMS, IN BUCKETS (sec 564): a month let go here takes
 * none, which is what the store asked. */
static int item_add(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                    const uint8_t *item, size_t len)
{
	fzn_node_messages_t *nm = (fzn_node_messages_t *)ctx;
	fzn_buckets_err_t err = fzn_buckets_add(&nm->buckets, FZN_BUCKETS_MESSAGES, contact, epoch,
	                                        item, len, NULL);

	return err == FZN_BUCKETS_OK || err == FZN_BUCKETS_GONE;
}

static int item_drop(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch)
{
	fzn_node_messages_t *nm = (fzn_node_messages_t *)ctx;

	return fzn_buckets_drop(&nm->buckets, FZN_BUCKETS_MESSAGES, contact, epoch)
	       == FZN_BUCKETS_OK;
}

fzn_messages_err_t fzn_node_messages_init(fzn_node_messages_t *nm,
                                          const fzn_persist_ops_t *store,
                                          fzn_node_journal_t *journal, const uint8_t *issuer,
                                          const fzn_sign_ops_t *sign,
                                          const fzn_random_ops_t *rng,
                                          const fzn_aead_ops_t *aead,
                                          const fzn_hash_ops_t *hash, uint64_t (*now)(void))
{
	if (!nm || !store || !journal || !issuer || !sign || !rng || !aead || !hash || !now)
		return FZN_MESSAGES_ERR_MALFORMED;
	memset(nm, 0, sizeof(*nm));
	nm->m.store = store;
	nm->m.journal = journal;
	nm->m.issuer = issuer;
	nm->m.sign = sign;
	nm->m.rng = rng;
	nm->m.aead = aead;
	nm->m.hash = hash;
	nm->m.now = now;
	nm->m.devices = (const uint8_t(*)[FZN_PUBKEY_LEN])nm->devices;
	nm->buckets.store = store;
	nm->buckets.hash = hash;
	nm->items.add = item_add;
	nm->items.drop = item_drop;
	nm->items.ctx = nm;
	nm->m.items = &nm->items;
	return fzn_node_messages_devices(nm, NULL, 0u) == 1u ? FZN_MESSAGES_OK
	                                                     : FZN_MESSAGES_ERR_JOURNAL;
}

size_t fzn_node_messages_devices(fzn_node_messages_t *nm, const uint8_t (*keys)[FZN_PUBKEY_LEN],
                                 size_t n)
{
	size_t i, j, count = 0;

	if (!nm || (!keys && n))
		return 0;
	for (i = 0; i <= n && count < FZN_MESSAGES_DEVICES_MAX; i++) {
		const uint8_t *key = i == 0u ? nm->m.issuer : keys[i - 1u];
		int listed = 0;

		for (j = 0; j < count && !listed; j++)
			listed = same_key(nm->devices[j], key);
		if (listed
		    || fzn_node_journal_follow_stream(nm->m.journal, key, FZN_MESSAGE_STREAM, NULL)
		               != FZN_NODE_JOURNAL_OK)
			continue;
		memcpy(nm->devices[count++], key, FZN_PUBKEY_LEN);
	}
	nm->m.device_count = count;
	return count;
}

/* Whether `device`'s record at `seq` is a line's part with more to follow. */
static int line_continues(fzn_node_messages_t *nm, const uint8_t device[FZN_PUBKEY_LEN],
                          uint64_t seq)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_message_part_t p;
	fzn_record_t rec;

	return fzn_record_store_get(&nm->m.journal->store, device, FZN_MESSAGE_STREAM, seq, buf,
	                            sizeof(buf), &rec) == FZN_RECORD_STORE_OK
	       && fzn_record_kind(rec) == FZN_MESSAGE_LINE_KIND
	       && fzn_message_line_read(fzn_record_body(rec), fzn_record_body_len(rec), &p)
	       && p.part + 1u < p.parts;
}

void fzn_node_messages_skip(fzn_node_messages_t *nm, const uint8_t device[FZN_PUBKEY_LEN],
                            uint64_t to)
{
	size_t k;

	if (!nm || !device)
		return;
	for (k = 0; k < nm->n_cursors; k++)
		if (same_key(nm->cursors[k].key, device) && nm->cursors[k].at < to)
			nm->cursors[k].at = to;
}

uint64_t fzn_node_messages_cut_point(fzn_node_messages_t *nm, const uint8_t device[FZN_PUBKEY_LEN],
                                     uint64_t older_than_ms)
{
	uint64_t base, below, absorbed = 0;
	size_t k;

	if (!nm || !nm->m.journal || !device)
		return 1u;
	base = fzn_node_journal_base(nm->m.journal, device, FZN_MESSAGE_STREAM);
	for (k = 0; k < nm->n_cursors; k++)
		if (same_key(nm->cursors[k].key, device))
			absorbed = nm->cursors[k].at;
	below = fzn_node_journal_cut_point(nm->m.journal, device, FZN_MESSAGE_STREAM, absorbed,
	                                   older_than_ms);
	/* THE LAST RECORD CUT ENDS A LINE. */
	while (below > base && line_continues(nm, device, below - 1u))
		below--;
	return below;
}

static int key_place_is(const fzn_node_message_key_t *k, const uint8_t contact[FZN_PUBKEY_LEN],
                        uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN])
{
	return k->epoch == epoch && same_key(k->contact, contact) && same_key(k->device, device);
}

/* Add a key's place to `list`, once; the room past is counted dropped. */
static void note_key(fzn_node_messages_t *nm, fzn_node_message_key_t *list, size_t *n,
                     const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                     const uint8_t device[FZN_PUBKEY_LEN])
{
	size_t i;

	for (i = 0; i < *n; i++)
		if (key_place_is(&list[i], contact, epoch, device))
			return;
	if (*n >= FZN_NODE_MESSAGES_KEYS_MAX) {
		nm->dropped++;
		return;
	}
	memcpy(list[*n].contact, contact, FZN_PUBKEY_LEN);
	list[*n].epoch = epoch;
	memcpy(list[*n].device, device, FZN_PUBKEY_LEN);
	(*n)++;
}

static void drop_key(fzn_node_message_key_t *list, size_t *n,
                     const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                     const uint8_t device[FZN_PUBKEY_LEN])
{
	size_t i;

	for (i = 0; i < *n; i++)
		if (key_place_is(&list[i], contact, epoch, device)) {
			list[i] = list[--(*n)];
			return;
		}
}

/* A LINE'S KEY, SEEN: this node's own to give, another's to ask for, or one
 * that arrived since and is lacked no more. */
static void seen(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                 const uint8_t device[FZN_PUBKEY_LEN], int held)
{
	fzn_node_messages_t *nm = (fzn_node_messages_t *)ctx;

	if (same_key(device, nm->m.issuer)) {
		if (held)
			note_key(nm, nm->gives, &nm->n_gives, contact, epoch, device);
	} else if (held) {
		drop_key(nm->lacks, &nm->n_lacks, contact, epoch, device);
	} else {
		note_key(nm, nm->lacks, &nm->n_lacks, contact, epoch, device);
	}
}

fzn_messages_err_t fzn_node_messages_absorb(fzn_node_messages_t *nm,
                                            fzn_node_messages_tally_t *tally)
{
	size_t d, k;

	if (!nm || !tally)
		return FZN_MESSAGES_ERR_MALFORMED;
	uint64_t at[FZN_MESSAGES_DEVICES_MAX];
	uint64_t *where[FZN_MESSAGES_DEVICES_MAX];
	size_t marks = 0;
	fzn_messages_err_t err;

	memset(tally, 0, sizeof(*tally));
	/* EACH DEVICE FROM WHERE THIS RUN LAST READ IT, from its base at start
	 * (sec 547): what was taken in before is not taken in again, but its
	 * keys are noted again. */
	for (d = 0; d < nm->m.device_count; d++) {
		where[d] = NULL;
		for (k = 0; k < nm->n_cursors && !where[d]; k++)
			if (same_key(nm->cursors[k].key, nm->devices[d]))
				where[d] = &nm->cursors[k].at;
		if (!where[d] && nm->n_cursors < FZN_MESSAGES_DEVICES_MAX) {
			memcpy(nm->cursors[nm->n_cursors].key, nm->devices[d], FZN_PUBKEY_LEN);
			nm->cursors[nm->n_cursors].at =
			        fzn_node_journal_base(nm->m.journal, nm->devices[d], FZN_MESSAGE_STREAM)
			        - 1u;
			where[d] = &nm->cursors[nm->n_cursors++].at;
		}
		at[d] = where[d] ? *where[d] : 0u;
	}
	err = fzn_messages_absorb(&nm->m, at, seen, nm, &marks);
	if (err != FZN_MESSAGES_OK)
		return err;
	for (d = 0; d < nm->m.device_count; d++)
		if (where[d])
			*where[d] = at[d];
	tally->marks = marks;
	tally->lacking = nm->n_lacks;
	return FZN_MESSAGES_OK;
}

fzn_messages_err_t fzn_node_messages_file(fzn_node_messages_t *nm,
                                          const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                                          const uint8_t *item, size_t len, int *waiting)
{
	uint8_t its_contact[FZN_PUBKEY_LEN];
	uint32_t its_epoch = 0;
	int wait = 0;
	fzn_messages_err_t err;

	if (waiting)
		*waiting = 0;
	if (!nm || !contact || !item)
		return FZN_MESSAGES_ERR_MALFORMED;
	/* A MONTH LET GO HERE takes nothing back, its key wanted least of all:
	 * the bucket is the mark, whichever way the month went. */
	if (fzn_buckets_gone(&nm->buckets, FZN_BUCKETS_MESSAGES, contact, epoch))
		return FZN_MESSAGES_ERR_GONE;
	err = fzn_messages_file(&nm->m, item, len, its_contact, &its_epoch, &wait);
	/* ONE CONVERSATION'S MONTH, WHERE IT CAME FROM: an item filed under
	 * another bucket would leave the two buckets' digests apart for good.
	 * Checked after filing, since only the store reads an item; one that
	 * was kept under its own bucket and offered under another is refused
	 * here and kept there, which is where it belongs. */
	if (err == FZN_MESSAGES_OK
	    && (!same_key(its_contact, contact) || its_epoch != epoch))
		return FZN_MESSAGES_ERR_REFUSED;
	if (err == FZN_MESSAGES_OK && wait) {
		const uint8_t *device = item + 3u + FZN_RECORD_OFF_ISSUER;

		note_key(nm, nm->lacks, &nm->n_lacks, contact, epoch, device);
		if (waiting)
			*waiting = 1;
	}
	return err;
}

void fzn_node_messages_pushed(fzn_node_messages_t *nm, const uint8_t contact[FZN_PUBKEY_LEN],
                              uint32_t epoch, const uint8_t *item, size_t len)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	const uint8_t *device;

	if (!nm || !contact || !item || len < 3u + FZN_RECORD_OFF_ISSUER + FZN_PUBKEY_LEN)
		return;
	device = item + 3u + FZN_RECORD_OFF_ISSUER;
	if (!same_key(device, nm->m.issuer) || !fzn_messages_key_get(&nm->m, contact, epoch, device, key))
		return;
	memset(key, 0, sizeof(key));
	note_key(nm, nm->gives, &nm->n_gives, contact, epoch, device);
}

/* ---- keys between members ------------------------------------------------ */

static void put_place(uint8_t *at, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch)
{
	memcpy(at, contact, FZN_PUBKEY_LEN);
	fzn_put_be32(at + FZN_PUBKEY_LEN, epoch);
}

/* ONE WANT: `n` places asked for, and each key the answer carries taken
 * only for a place among them. 0 when the member would not answer. */
static int want_batch(fzn_node_messages_t *nm, fzn_node_messages_ask_t ask, void *ctx,
                      const fzn_node_message_key_t *asked, size_t n,
                      fzn_node_messages_tally_t *tally)
{
	uint8_t request[FZN_NODE_MESSAGES_REQUEST_MAX], reply[FZN_NODE_MESSAGES_REPLY_MAX];
	size_t at = FZN_NODE_MESSAGES_HEAD_LEN, reply_len, j, k;

	request[0] = FZN_NODE_MESSAGES_VERSION;
	request[1] = FZN_NODE_MESSAGES_WANT;
	request[2] = (uint8_t)n;
	for (j = 0; j < n; j++) {
		put_place(request + at, asked[j].contact, asked[j].epoch);
		memcpy(request + at + FZN_PUBKEY_LEN + 4u, asked[j].device, FZN_PUBKEY_LEN);
		at += FZN_NODE_MESSAGES_ENTRY_LEN;
	}
	if (!ask(ctx, request, at, reply, sizeof(reply), &reply_len))
		return 0;
	if (reply_len < FZN_NODE_MESSAGES_HEAD_LEN || reply[0] != FZN_NODE_MESSAGES_VERSION
	    || reply[1] != FZN_NODE_MESSAGES_KEYS || reply[2] > n
	    || reply_len != FZN_NODE_MESSAGES_HEAD_LEN
	                            + (size_t)reply[2] * FZN_NODE_MESSAGES_HELD_LEN)
		return 0;
	for (k = 0; k < reply[2]; k++) {
		const uint8_t *e = reply + FZN_NODE_MESSAGES_HEAD_LEN + (k * FZN_NODE_MESSAGES_HELD_LEN);
		uint32_t epoch = fzn_get_be32(e + FZN_PUBKEY_LEN);
		const uint8_t *device = e + FZN_PUBKEY_LEN + 4u;
		int was_asked = 0;

		for (j = 0; j < n && !was_asked; j++)
			was_asked = key_place_is(&asked[j], e, epoch, device);
		if (was_asked
		    && fzn_messages_key_take(&nm->m, e, epoch, device, e + FZN_NODE_MESSAGES_ENTRY_LEN)
		               == FZN_MESSAGES_OK) {
			drop_key(nm->lacks, &nm->n_lacks, e, epoch, device);
			tally->taken++;
		}
	}
	memset(reply, 0, sizeof(reply));
	return 1;
}

int fzn_node_messages_round(fzn_node_messages_t *nm, fzn_node_messages_ask_t ask, void *ctx,
                            fzn_node_messages_tally_t *tally)
{
	uint8_t request[FZN_NODE_MESSAGES_REQUEST_MAX], reply[FZN_NODE_MESSAGES_REPLY_MAX];
	size_t reply_len, i, n;

	if (!nm || !ask || !tally)
		return 0;
	/* GIVE THIS NODE'S OWN, eight at a time. A key the peer took, or
	 * refused for holding another, is given no more: one member holding it
	 * is enough for the rest to ask it there. */
	while (nm->n_gives) {
		uint8_t key[FZN_CONVERSATION_KEY_LEN];
		size_t at = FZN_NODE_MESSAGES_HEAD_LEN;

		n = nm->n_gives < FZN_NODE_MESSAGES_PER ? nm->n_gives : FZN_NODE_MESSAGES_PER;
		request[0] = FZN_NODE_MESSAGES_VERSION;
		request[1] = FZN_NODE_MESSAGES_GIVE;
		for (i = 0; i < n; i++) {
			const fzn_node_message_key_t *g = &nm->gives[nm->n_gives - 1u - i];

			if (!fzn_messages_key_get(&nm->m, g->contact, g->epoch, g->device, key))
				memset(key, 0, sizeof(key));
			put_place(request + at, g->contact, g->epoch);
			memcpy(request + at + FZN_PUBKEY_LEN + 4u, key, sizeof(key));
			at += FZN_PUBKEY_LEN + 4u + FZN_CONVERSATION_KEY_LEN;
		}
		request[2] = (uint8_t)n;
		memset(key, 0, sizeof(key));
		if (!ask(ctx, request, at, reply, sizeof(reply), &reply_len)) {
			memset(request, 0, sizeof(request));
			return 0;
		}
		memset(request, 0, sizeof(request));
		if (reply_len != FZN_NODE_MESSAGES_GIVEN_LEN || reply[0] != FZN_NODE_MESSAGES_VERSION
		    || reply[1] != FZN_NODE_MESSAGES_GIVEN || (size_t)reply[2] + reply[3] > n)
			return 0;
		tally->given += reply[2];
		tally->refused += reply[3];
		nm->n_gives -= n;
	}
	/* ASK FOR WHAT THIS NODE LACKS, eight at a time, from a copy of the
	 * list, since taking a key reorders it. */
	{
		static fzn_node_message_key_t asked[FZN_NODE_MESSAGES_KEYS_MAX];
		size_t total = nm->n_lacks;

		memcpy(asked, nm->lacks, total * sizeof(asked[0]));
		for (i = 0; i < total; i += n) {
			n = total - i < FZN_NODE_MESSAGES_PER ? total - i : FZN_NODE_MESSAGES_PER;
			if (!want_batch(nm, ask, ctx, asked + i, n, tally))
				return 0;
		}
	}
	tally->lacking = nm->n_lacks;
	return 1;
}

static size_t answer_give(fzn_node_messages_t *nm, const uint8_t *sender, const uint8_t *request,
                          size_t request_len, uint8_t *reply, size_t reply_cap)
{
	size_t n = request[2], i, taken = 0, refused = 0;

	if (n == 0u || n > FZN_NODE_MESSAGES_PER
	    || request_len != FZN_NODE_MESSAGES_HEAD_LEN
	                              + n * (FZN_PUBKEY_LEN + 4u + FZN_CONVERSATION_KEY_LEN)
	    || reply_cap < FZN_NODE_MESSAGES_GIVEN_LEN)
		return 0;
	/* AS THE GIVER'S OWN: a member gives the keys it drew, so the device a
	 * key is kept under is the sender, whatever else it might claim. */
	for (i = 0; i < n; i++) {
		const uint8_t *e = request + FZN_NODE_MESSAGES_HEAD_LEN
		                   + i * (FZN_PUBKEY_LEN + 4u + FZN_CONVERSATION_KEY_LEN);

		if (fzn_messages_key_take(&nm->m, e, fzn_get_be32(e + FZN_PUBKEY_LEN), sender,
		                          e + FZN_PUBKEY_LEN + 4u)
		    == FZN_MESSAGES_OK)
			taken++;
		else
			refused++;
	}
	reply[0] = FZN_NODE_MESSAGES_VERSION;
	reply[1] = FZN_NODE_MESSAGES_GIVEN;
	reply[2] = (uint8_t)taken;
	reply[3] = (uint8_t)refused;
	return FZN_NODE_MESSAGES_GIVEN_LEN;
}

static size_t answer_want(fzn_node_messages_t *nm, const uint8_t *request, size_t request_len,
                          uint8_t *reply, size_t reply_cap)
{
	size_t n = request[2], i, held = 0, at = FZN_NODE_MESSAGES_HEAD_LEN;

	if (n == 0u || n > FZN_NODE_MESSAGES_PER
	    || request_len != FZN_NODE_MESSAGES_HEAD_LEN + n * FZN_NODE_MESSAGES_ENTRY_LEN
	    || reply_cap < FZN_NODE_MESSAGES_HEAD_LEN + n * FZN_NODE_MESSAGES_HELD_LEN)
		return 0;
	for (i = 0; i < n; i++) {
		const uint8_t *e = request + FZN_NODE_MESSAGES_HEAD_LEN + i * FZN_NODE_MESSAGES_ENTRY_LEN;

		if (!fzn_messages_key_get(&nm->m, e, fzn_get_be32(e + FZN_PUBKEY_LEN),
		                          e + FZN_PUBKEY_LEN + 4u, reply + at + FZN_NODE_MESSAGES_ENTRY_LEN))
			continue;
		memcpy(reply + at, e, FZN_NODE_MESSAGES_ENTRY_LEN);
		at += FZN_NODE_MESSAGES_HELD_LEN;
		held++;
	}
	reply[0] = FZN_NODE_MESSAGES_VERSION;
	reply[1] = FZN_NODE_MESSAGES_KEYS;
	reply[2] = (uint8_t)held;
	return at;
}

size_t fzn_node_messages_remote(void *ctx, const uint8_t *sender, const uint8_t *request,
                                size_t request_len, uint8_t *reply, size_t reply_cap)
{
	fzn_node_messages_t *nm = (fzn_node_messages_t *)ctx;

	if (!nm || !sender || !request || !reply || request_len < FZN_NODE_MESSAGES_HEAD_LEN
	    || request[0] != FZN_NODE_MESSAGES_VERSION)
		return 0;
	if (request[1] == FZN_NODE_MESSAGES_GIVE)
		return answer_give(nm, sender, request, request_len, reply, reply_cap);
	if (request[1] == FZN_NODE_MESSAGES_WANT)
		return answer_want(nm, request, request_len, reply, reply_cap);
	return 0;
}

/* ---- the verbs ------------------------------------------------------------ */

/* WHO: a contact's name, or a key in hex. */
static int who(const fzn_node_messages_t *nm, const uint8_t *w, size_t w_len,
               uint8_t key[FZN_PUBKEY_LEN])
{
	fzn_contact_t c;

	if (parse_hex(w, w_len, key, FZN_PUBKEY_LEN))
		return 1;
	if (fzn_contact_find(nm->m.store, (const char *)w, w_len, &c) != FZN_CONTACT_OK)
		return 0;
	memcpy(key, c.key, FZN_PUBKEY_LEN);
	return 1;
}

static int direction_of(const uint8_t *w, size_t w_len, uint8_t *d)
{
	if (is_word(w, w_len, "out"))
		*d = FZN_MESSAGE_OUT;
	else if (is_word(w, w_len, "in"))
		*d = FZN_MESSAGE_IN;
	else
		return 0;
	return 1;
}

static const char *const STATES[] = { "-", "delivered", "settled", "handed-over",
	                              "not-delivered" };

static int state_of(const uint8_t *w, size_t w_len, uint8_t *s)
{
	uint8_t i;

	for (i = FZN_MESSAGE_DELIVERED; i <= FZN_MESSAGE_NOT_DELIVERED; i++)
		if (is_word(w, w_len, STATES[i])) {
			*s = i;
			return 1;
		}
	return 0;
}

/* `WHO out|in ID`, common to add and set. */
static int line_of(const fzn_node_messages_t *nm, const uint8_t **at, size_t *left,
                   uint8_t contact[FZN_PUBKEY_LEN], uint8_t *direction,
                   uint8_t id[FZN_MESSAGE_ID_LEN])
{
	const uint8_t *w;
	size_t w_len;

	return word(at, left, &w, &w_len) && who(nm, w, w_len, contact)
	       && word(at, left, &w, &w_len) && direction_of(w, w_len, direction)
	       && word(at, left, &w, &w_len) && parse_hex(w, w_len, id, FZN_MESSAGE_ID_LEN);
}

static size_t add(fzn_node_messages_t *nm, const uint8_t *at, size_t left, char *reply,
                  size_t cap)
{
	static const char USAGE[] = "add message WHO out|in ID [at MS] TEXT | file PATH";
	static char text[FZN_MESSAGE_TEXT_MAX + 1u];
	uint8_t contact[FZN_PUBKEY_LEN], id[FZN_MESSAGE_ID_LEN], direction = 0;
	uint64_t stime = nm->m.now();
	const uint8_t *w, *rest;
	size_t w_len, rest_left, len = 0, i;
	fzn_messages_err_t err;

	if (!line_of(nm, &at, &left, contact, &direction, id))
		return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
	rest = at;
	rest_left = left;
	if (word(&rest, &rest_left, &w, &w_len) && is_word(w, w_len, "at")) {
		if (!word(&rest, &rest_left, &w, &w_len) || w_len == 0u || w_len > 19u)
			return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
		for (stime = 0, i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9')
				return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
			stime = (stime * 10u) + (uint64_t)(w[i] - '0');
		}
		at = rest;
		left = rest_left;
	}
	rest = at;
	rest_left = left;
	if (word(&rest, &rest_left, &w, &w_len) && is_word(w, w_len, "file")) {
		char name[512];
		FILE *f;

		if (rest_left == 0u || rest_left >= sizeof(name) || memchr(rest, '\0', rest_left))
			return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
		memcpy(name, rest, rest_left);
		name[rest_left] = '\0';
		f = fopen(name, "rb");
		if (!f)
			return say(reply, cap, FZN_REPLY_ERROR, "the file would not open");
		/* ONE BYTE PAST THE MOST, so a text too long is refused whole
		 * rather than cut. */
		len = fread(text, 1u, sizeof(text), f);
		(void)fclose(f);
		if (len > FZN_MESSAGE_TEXT_MAX)
			return refuse(reply, cap, FZN_MESSAGES_ERR_TEXT);
	} else if (!unescape(at, left, text, FZN_MESSAGE_TEXT_MAX, &len)) {
		return say(reply, cap, FZN_REPLY_MALFORMED, "a text past 512 bytes, or a bad escape");
	}
	err = fzn_messages_write(&nm->m, contact, direction, id, stime, text, len);
	memset(text, 0, sizeof(text));
	if (err != FZN_MESSAGES_OK)
		return refuse(reply, cap, err);
	nm->fresh = 1;
	return say(reply, cap, FZN_REPLY_OK, NULL);
}

static size_t set(fzn_node_messages_t *nm, const uint8_t *at, size_t left, char *reply,
                  size_t cap)
{
	static const char USAGE[] = "set message WHO out|in ID "
	                            "delivered|settled|handed-over|not-delivered, "
	                            "or set message WHO read ID";
	uint8_t contact[FZN_PUBKEY_LEN], id[FZN_MESSAGE_ID_LEN], direction = 0, state = 0;
	const uint8_t *w, *rest = at;
	size_t w_len, rest_left = left;
	fzn_messages_err_t err;

	/* `WHO read ID`: the conversation read up to that line. sec 528. */
	if (word(&rest, &rest_left, &w, &w_len) && who(nm, w, w_len, contact)
	    && word(&rest, &rest_left, &w, &w_len) && is_word(w, w_len, "read")) {
		if (!word(&rest, &rest_left, &w, &w_len)
		    || !parse_hex(w, w_len, id, FZN_MESSAGE_ID_LEN) || rest_left)
			return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
		err = fzn_messages_read_up_to(&nm->m, contact, id);
	} else {
		if (!line_of(nm, &at, &left, contact, &direction, id)
		    || !word(&at, &left, &w, &w_len) || !state_of(w, w_len, &state) || left)
			return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
		err = fzn_messages_mark(&nm->m, contact, direction, id, state);
	}
	if (err != FZN_MESSAGES_OK)
		return refuse(reply, cap, err);
	nm->fresh = 1;
	return say(reply, cap, FZN_REPLY_OK, NULL);
}

/* `get message WHO unread`: `ok COUNT MORE`, MORE 1 when the count is a
 * floor. sec 528. */
static size_t get(fzn_node_messages_t *nm, const uint8_t *at, size_t left, char *reply,
                  size_t cap)
{
	uint8_t contact[FZN_PUBKEY_LEN];
	const uint8_t *w;
	size_t w_len, count = 0;
	char detail[48];
	int more = 0, k;
	fzn_messages_err_t err;

	if (!word(&at, &left, &w, &w_len) || !who(nm, w, w_len, contact)
	    || !word(&at, &left, &w, &w_len) || !is_word(w, w_len, "unread") || left)
		return say(reply, cap, FZN_REPLY_MALFORMED, "get message WHO unread");
	err = fzn_messages_unread(&nm->m, contact, &count, &more);
	if (err != FZN_MESSAGES_OK)
		return refuse(reply, cap, err);
	k = snprintf(detail, sizeof(detail), "%zu %d", count, more);
	if (k < 0 || (size_t)k >= sizeof(detail))
		return 0;
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)k);
}

/* `FROM SHOWN MORE`: two numbers of at most four digits and a flag. */
#define LIST_HEAD_MAX 16u

static int all_digits(const uint8_t *w, size_t w_len)
{
	size_t i;

	for (i = 0; i < w_len; i++)
		if (w[i] < '0' || w[i] > '9')
			return 0;
	return w_len > 0u;
}

static size_t list(fzn_node_messages_t *nm, const uint8_t *at, size_t left, char *reply,
                   size_t cap)
{
	static const char USAGE[] = "list message [WHO] [FROM]";
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	static char items[FZN_REPLY_MAX], detail[FZN_REPLY_MAX];
	size_t limit = fzn_reply_ok_room(cap);
	uint8_t contact[FZN_PUBKEY_LEN];
	const uint8_t *w, *filter = NULL;
	size_t w_len, from = 0, count = 0, shown = 0, used = 0, i;
	int more = 0, k;
	fzn_messages_err_t err;

	/* AN ALL-DIGIT WORD IS FROM: a contact named so is reached by its key.
	 * But a word as long as a key is a key, digits or not -- a key's hex
	 * can be all decimal digits, and was read as a page offset, refused as
	 * past the walk. A FROM is at most four digits, so the two never meet. */
	if (word(&at, &left, &w, &w_len)) {
		if (!all_digits(w, w_len) || w_len == 2u * FZN_PUBKEY_LEN) {
			if (!who(nm, w, w_len, contact))
				return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
			filter = contact;
			if (!word(&at, &left, &w, &w_len))
				w_len = 0;
		}
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > FZN_MESSAGES_WALK_MAX)
				return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	}
	if (from > FZN_MESSAGES_WALK_MAX - FZN_MESSAGES_PAGE_MAX)
		return refuse(reply, cap, FZN_MESSAGES_ERR_DEEP);
	err = fzn_messages_page(&nm->m, filter, from, page, FZN_MESSAGES_PAGE_MAX, &count, &more);
	if (err != FZN_MESSAGES_OK)
		return refuse(reply, cap, err);
	for (i = 0; i < count; i++) {
		const fzn_message_t *p = &page[i];
		char head[2u * FZN_PUBKEY_LEN + FZN_CONTACT_NAME_MAX + 2u * FZN_MESSAGE_ID_LEN + 96u];
		size_t h = 0, wrote = 0;
		fzn_contact_t c;

		hex_of(p->contact, FZN_PUBKEY_LEN, head);
		h = 2u * FZN_PUBKEY_LEN;
		head[h++] = ',';
		if (fzn_contact_get(nm->m.store, p->contact, &c) == FZN_CONTACT_OK) {
			memcpy(head + h, c.name, c.name_len);
			h += c.name_len;
		} else {
			head[h++] = '-';
		}
		head[h++] = ',';
		hex_of(p->id, FZN_MESSAGE_ID_LEN, head + h);
		h += 2u * FZN_MESSAGE_ID_LEN;
		k = snprintf(head + h, sizeof(head) - h, ",%s,%s,%llu,%llu,%d,",
		             p->direction == FZN_MESSAGE_OUT ? "out" : "in",
		             p->state <= FZN_MESSAGE_NOT_DELIVERED ? STATES[p->state] : "-",
		             (unsigned long long)p->stime, (unsigned long long)p->written_at,
		             p->readable);
		if (k < 0 || (size_t)k >= sizeof(head) - h)
			return 0;
		h += (size_t)k;
		/* A LINE GOES IN WHOLE OR NOT AT ALL: a page ends where the next
		 * does not fit, and the caller asks from FROM + SHOWN. */
		if (sizeof(items) - used < 1u + h)
			break;
		items[used] = ' ';
		memcpy(items + used + 1u, head, h);
		if (escape((const uint8_t *)p->text, p->text_len, items + used + 1u + h,
		           sizeof(items) - used - 1u - h, &wrote)
		    < p->text_len)
			break;
		/* AND ROOM LEFT FOR THE HEAD, `FROM SHOWN MORE`. */
		if (LIST_HEAD_MAX + used + 1u + h + wrote > limit)
			break;
		used += 1u + h + wrote;
		shown++;
	}
	if (shown < count)
		more = 1;
	k = snprintf(detail, sizeof(detail), "%zu %zu %d", from, shown, more);
	if (k < 0 || (size_t)k + used > limit)
		return 0;
	memcpy(detail + k, items, used);
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)k + used);
}

size_t fzn_node_messages_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t reply_cap)
{
	fzn_node_messages_t *nm = (fzn_node_messages_t *)ctx;
	const uint8_t *at, *subject;
	size_t left, subject_len;

	if (!nm || !request || !reply || !request->arg)
		return 0;
	at = request->arg;
	left = request->arg_len;
	if (!word(&at, &left, &subject, &subject_len) || !is_word(subject, subject_len, "message"))
		return 0;
	if (request->parsed != FZN_VERB_ADD && request->parsed != FZN_VERB_SET
	    && request->parsed != FZN_VERB_LIST && request->parsed != FZN_VERB_GET)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return say(reply, reply_cap, FZN_REPLY_DENIED, "messages need this node's own user");
	if (request->parsed == FZN_VERB_ADD)
		return add(nm, at, left, reply, reply_cap);
	if (request->parsed == FZN_VERB_SET)
		return set(nm, at, left, reply, reply_cap);
	if (request->parsed == FZN_VERB_GET)
		return get(nm, at, left, reply, reply_cap);
	return list(nm, at, left, reply, reply_cap);
}
