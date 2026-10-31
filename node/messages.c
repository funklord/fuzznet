/* See messages.h. */

#define _POSIX_C_SOURCE 200809L

#include "messages.h"

#include "../contact/contact.h"
#include "../local/escape.h"
#include "group_lines.h"
#include "groups.h"
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
	/* EITHER CASE, as a %XX escape is read anywhere (sec 654): a value
	 * written by another escaper is not refused for its case. */
	const char *h = memchr(HEX, c >= 'A' && c <= 'F' ? c + ('a' - 'A') : c, 16u);

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
	return fzn_escape(b, n, out, cap, written); /* local/escape.h, sec 668 */
}

/* Undo %XX into `out`, at most `cap`: 0 for a malformed escape or a text
 * past `cap`. */
static int unescape(const uint8_t *in, size_t n, char *out, size_t cap, size_t *len)
{
	return fzn_unescape(in, n, (uint8_t *)out, cap, len); /* sec 668 */
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
	/* THE OWN ROOM FIRST, sec 704. */
	nm->devices = nm->own_devices;
	nm->cursors = nm->own_cursors;
	nm->at = nm->own_at;
	nm->work = nm->own_work;
	nm->devices_cap = FZN_MESSAGES_DEVICES_MAX;
	nm->lacks = nm->own_lacks;
	nm->gives = nm->own_gives;
	nm->keys_cap = FZN_NODE_MESSAGES_KEYS_MAX;
	nm->m.devices = (const uint8_t(*)[FZN_PUBKEY_LEN])nm->devices;
	nm->m.work = nm->work;
	nm->m.work_at = nm->at;
	nm->m.work_cap = nm->devices_cap;
	nm->buckets.store = store;
	nm->buckets.hash = hash;
	nm->items.add = item_add;
	nm->items.drop = item_drop;
	nm->items.ctx = nm;
	nm->m.items = &nm->items;
	return fzn_node_messages_devices(nm, NULL, 0u) == 1u ? FZN_MESSAGES_OK
	                                                     : FZN_MESSAGES_ERR_JOURNAL;
}

int fzn_node_messages_use_devices(fzn_node_messages_t *nm, uint8_t (*devices)[FZN_PUBKEY_LEN],
                                  fzn_node_message_cursor_t *cursors, uint64_t *at,
                                  fzn_messages_work_t *work, size_t cap)
{
	if (!nm || !devices || !cursors || !at || !work || cap < nm->m.device_count
	    || cap < nm->n_cursors || cap == 0u)
		return 0;
	memmove(devices, nm->devices, nm->m.device_count * sizeof(*devices));
	memmove(cursors, nm->cursors, nm->n_cursors * sizeof(*cursors));
	nm->devices = devices;
	nm->cursors = cursors;
	nm->at = at;
	nm->work = work;
	nm->devices_cap = cap;
	nm->devices_wanted = 0;
	nm->m.devices = (const uint8_t(*)[FZN_PUBKEY_LEN])devices;
	nm->m.work = work;
	nm->m.work_at = at;
	nm->m.work_cap = cap;
	return 1;
}

int fzn_node_messages_use_keys(fzn_node_messages_t *nm, fzn_node_message_key_t *lacks,
                               fzn_node_message_key_t *gives, size_t cap)
{
	if (!nm || !lacks || !gives || cap < nm->n_lacks || cap < nm->n_gives || cap == 0u)
		return 0;
	memmove(lacks, nm->lacks, nm->n_lacks * sizeof(*lacks));
	memmove(gives, nm->gives, nm->n_gives * sizeof(*gives));
	nm->lacks = lacks;
	nm->gives = gives;
	nm->keys_cap = cap;
	nm->keys_wanted = 0;
	/* KEYS DROPPED FOR WANT OF ROOM are noted again only by an absorb from
	 * each stream's base, which a start makes: so the cursors go back
	 * there, and the next absorb notes every key as a start would. Taking a
	 * line in again is what a start does already. */
	if (nm->dropped) {
		size_t k;

		for (k = 0; k < nm->n_cursors; k++)
			nm->cursors[k].at = fzn_node_journal_base(nm->m.journal, nm->cursors[k].key,
			                                          FZN_MESSAGE_STREAM)
			                    - 1u;
		nm->dropped = 0;
	}
	return 1;
}

size_t fzn_node_messages_devices(fzn_node_messages_t *nm, const uint8_t (*keys)[FZN_PUBKEY_LEN],
                                 size_t n)
{
	size_t i, j, count = 0;

	if (!nm || (!keys && n))
		return 0;
	/* MORE THAN THE ROOM, sec 704: said, for the caller to give it. */
	if (n + 1u > nm->devices_cap)
		nm->devices_wanted = n + 1u;
	for (i = 0; i <= n && count < nm->devices_cap; i++) {
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

/* EVERY CONVERSATION'S BUCKETS, a month each, ascending by contact, in a
 * list grown to fit and kept between calls (sec 791): a user keeps a
 * bucket per contact a month for ever, past any fixed room. */
static fzn_bucket_t *buckets;
static size_t buckets_room;

static int conversations_listed(fzn_node_messages_t *nm, size_t *n)
{
	return fzn_buckets_list_all(&nm->buckets, FZN_BUCKETS_MESSAGES, &buckets, &buckets_room, n)
	       == FZN_BUCKETS_OK;
}

fzn_messages_err_t fzn_node_messages_give_up(fzn_node_messages_t *nm,
                                             int (*stands)(void *ctx,
                                                           const uint8_t contact[FZN_PUBKEY_LEN]),
                                             int (*removed)(void *ctx,
                                                            const uint8_t contact[FZN_PUBKEY_LEN]),
                                             void *ctx, size_t *marked)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	size_t n = 0, b, count, i;
	uint64_t at;
	fzn_messages_err_t err;
	int more;

	if (marked)
		*marked = 0;
	if (!nm || !stands || !marked)
		return FZN_MESSAGES_ERR_MALFORMED;
	/* EVERY CONVERSATION BY ITS BUCKETS, a month each, ascending by
	 * contact: one contact's months sit together, and are walked once. */
	if (!conversations_listed(nm, &n))
		return FZN_MESSAGES_ERR_BACKEND;
	for (b = 0; b < n; b++) {
		const uint8_t *contact = buckets[b].subject;
		int gone;

		if ((b > 0 && memcmp(buckets[b - 1u].subject, contact, FZN_PUBKEY_LEN) == 0)
		    || stands(ctx, contact))
			continue;
		/* A LINE STILL BEING SENT is given up only when its contact was
		 * removed: a key never a contact may be one the caller does not
		 * list yet, and its lines wait (sec 616). */
		gone = removed && removed(ctx, contact);
		for (at = 0, more = 1; more;) {
			count = 0;
			err = fzn_messages_owed(&nm->m, contact, &at, page, FZN_MESSAGES_PAGE_MAX, &count,
			                        &more);
			if (err != FZN_MESSAGES_OK)
				return err;
			for (i = 0; i < count; i++) {
				if (page[i].direction != FZN_MESSAGE_OUT
				    || (page[i].state != FZN_MESSAGE_HANDED_OVER
				        && !(page[i].state == 0u && gone)))
					continue;
				err = fzn_messages_mark(&nm->m, contact, FZN_MESSAGE_OUT, page[i].id,
				                        FZN_MESSAGE_NOT_DELIVERED);
				if (err != FZN_MESSAGES_OK)
					return err;
				(*marked)++;
			}
		}
	}
	return FZN_MESSAGES_OK;
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
	if (*n >= nm->keys_cap) {
		nm->dropped++;
		if (nm->keys_wanted < *n + 1u)
			nm->keys_wanted = *n + 1u;
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

/* WHERE `device` WAS LAST ABSORBED TO, or -- `make` -- a cursor made at its
 * base. NULL with no room, `devices_wanted` then set. */
static uint64_t *cursor_at(fzn_node_messages_t *nm, const uint8_t device[FZN_PUBKEY_LEN], int make)
{
	size_t k;

	for (k = 0; k < nm->n_cursors; k++)
		if (same_key(nm->cursors[k].key, device))
			return &nm->cursors[k].at;
	if (!make)
		return NULL;
	if (nm->n_cursors >= nm->devices_cap) {
		if (nm->devices_wanted < nm->n_cursors + 1u)
			nm->devices_wanted = nm->n_cursors + 1u;
		return NULL;
	}
	memcpy(nm->cursors[nm->n_cursors].key, device, FZN_PUBKEY_LEN);
	nm->cursors[nm->n_cursors].at =
	        fzn_node_journal_base(nm->m.journal, device, FZN_MESSAGE_STREAM) - 1u;
	return &nm->cursors[nm->n_cursors++].at;
}

fzn_messages_err_t fzn_node_messages_absorb(fzn_node_messages_t *nm,
                                            fzn_node_messages_tally_t *tally)
{
	size_t d, marks = 0;
	fzn_messages_err_t err;

	if (!nm || !tally)
		return FZN_MESSAGES_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	/* EACH DEVICE FROM WHERE THIS RUN LAST READ IT, from its base at start
	 * (sec 547): what was taken in before is not taken in again, but its
	 * keys are noted again. */
	for (d = 0; d < nm->m.device_count; d++) {
		const uint64_t *was = cursor_at(nm, nm->devices[d], 1);

		nm->at[d] = was ? *was : 0u;
	}
	err = fzn_messages_absorb(&nm->m, nm->at, seen, nm, &marks);
	if (err != FZN_MESSAGES_OK)
		return err;
	for (d = 0; d < nm->m.device_count; d++) {
		uint64_t *was = cursor_at(nm, nm->devices[d], 0);

		if (was) {
			tally->read += *was != nm->at[d];
			*was = nm->at[d];
		}
	}
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

/* ONE WANT's request: `n` places asked for. Its length. */
static size_t want_request(const fzn_node_message_key_t *asked, size_t n, uint8_t *request)
{
	size_t at = FZN_NODE_MESSAGES_HEAD_LEN, j;

	request[0] = FZN_NODE_MESSAGES_VERSION;
	request[1] = FZN_NODE_MESSAGES_WANT;
	request[2] = (uint8_t)n;
	for (j = 0; j < n; j++) {
		put_place(request + at, asked[j].contact, asked[j].epoch);
		memcpy(request + at + FZN_PUBKEY_LEN + 4u, asked[j].device, FZN_PUBKEY_LEN);
		at += FZN_NODE_MESSAGES_ENTRY_LEN;
	}
	return at;
}

/* ITS ANSWER: each key it carries taken only for a place among the `n`
 * asked. 0 when it is not one. */
static int want_take(fzn_node_messages_t *nm, const fzn_node_message_key_t *asked, size_t n,
                     const uint8_t *reply, size_t reply_len, fzn_node_messages_tally_t *tally)
{
	size_t j, k;

	if (!reply || reply_len < FZN_NODE_MESSAGES_HEAD_LEN || reply[0] != FZN_NODE_MESSAGES_VERSION
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
	return 1;
}

/* ONE GIVE's request: this node's own keys, the last `n` of the gives. Its
 * length; the keys in it are the caller's to wipe. */
static size_t give_request(fzn_node_messages_t *nm, size_t n, uint8_t *request)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	size_t at = FZN_NODE_MESSAGES_HEAD_LEN, i;

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
	return at;
}

/* ---- the round with a member as steps, sec 636 ---------------------------- */

enum { KEYS_GIVE = 1, KEYS_WANT = 2, KEYS_DONE = 3 };

static int keys_end(fzn_node_messages_rounding_t *r, int *done, int ok)
{
	r->phase = KEYS_DONE;
	*done = 1;
	r->tally.lacking = r->nm->n_lacks;
	return ok;
}

/* THE NEXT REQUEST: GIVE THIS NODE'S OWN, eight at a time -- a key the peer
 * took, or refused for holding another, is given no more: one member
 * holding it is enough for the rest to ask it there -- then ASK FOR WHAT
 * THIS NODE LACKS, eight at a time, from a copy of the list, since taking
 * a key reorders it. */
static int keys_next(fzn_node_messages_rounding_t *r, uint8_t *request, size_t *request_len,
                     int *done)
{
	fzn_node_messages_t *nm = r->nm;

	/* AT MOST A REQUEST A BATCH of what can be given and lacked: a round
	 * past it is one whose list does not shrink, and ends as failed rather
	 * than asking for ever. */
	if (++r->asks > 2u * (FZN_NODE_MESSAGES_KEYS_MAX / FZN_NODE_MESSAGES_PER + 1u))
		return keys_end(r, done, 0);

	if (r->phase == KEYS_GIVE && nm->n_gives) {
		r->n = nm->n_gives < FZN_NODE_MESSAGES_PER ? nm->n_gives : FZN_NODE_MESSAGES_PER;
		r->sent = *request_len = give_request(nm, r->n, request);
		return 1;
	}
	if (r->phase == KEYS_GIVE) {
		r->phase = KEYS_WANT;
		/* THE FIRST FZN_NODE_MESSAGES_KEYS_MAX LACKED, sec 704: those
		 * answered are lacked no more, and the rest come in the rounds
		 * after. */
		r->total = nm->n_lacks < FZN_NODE_MESSAGES_KEYS_MAX ? nm->n_lacks
		                                                     : FZN_NODE_MESSAGES_KEYS_MAX;
		memcpy(r->asked, nm->lacks, r->total * sizeof(r->asked[0]));
		r->i = 0;
	}
	if (r->i < r->total) {
		r->n = r->total - r->i < FZN_NODE_MESSAGES_PER ? r->total - r->i : FZN_NODE_MESSAGES_PER;
		*request_len = want_request(r->asked + r->i, r->n, request);
		return 1;
	}
	return keys_end(r, done, 1);
}

int fzn_node_messages_round_begin(fzn_node_messages_rounding_t *r, fzn_node_messages_t *nm,
                                  uint8_t *request, size_t cap, size_t *request_len, int *done)
{
	if (!r || !nm || !request || cap < FZN_NODE_MESSAGES_REQUEST_MAX || !request_len || !done)
		return 0;
	memset(&r->tally, 0, sizeof(r->tally));
	r->nm = nm;
	r->phase = KEYS_GIVE;
	r->sent = 0;
	r->asks = 0;
	*done = 0;
	return keys_next(r, request, request_len, done);
}

int fzn_node_messages_round_step(fzn_node_messages_rounding_t *r, const uint8_t *reply,
                                 size_t reply_len, uint8_t *request, size_t cap,
                                 size_t *request_len, int *done)
{
	if (!r || (r->phase != KEYS_GIVE && r->phase != KEYS_WANT) || !request
	    || cap < FZN_NODE_MESSAGES_REQUEST_MAX || !request_len || !done)
		return 0;
	*done = 0;
	if (r->phase == KEYS_GIVE) {
		/* A GIVE'S KEYS, wiped once it is answered or is not. */
		memset(request, 0, r->sent);
		if (!reply || reply_len != FZN_NODE_MESSAGES_GIVEN_LEN
		    || reply[0] != FZN_NODE_MESSAGES_VERSION || reply[1] != FZN_NODE_MESSAGES_GIVEN
		    || (size_t)reply[2] + reply[3] > r->n)
			return keys_end(r, done, 0);
		r->tally.given += reply[2];
		r->tally.refused += reply[3];
		r->nm->n_gives -= r->n;
		return keys_next(r, request, request_len, done);
	}
	if (!want_take(r->nm, r->asked + r->i, r->n, reply, reply_len, &r->tally))
		return keys_end(r, done, 0);
	r->i += r->n;
	return keys_next(r, request, request_len, done);
}

int fzn_node_messages_round(fzn_node_messages_t *nm, fzn_node_messages_ask_t ask, void *ctx,
                            fzn_node_messages_tally_t *tally)
{
	static fzn_node_messages_rounding_t r;
	static uint8_t reply[FZN_NODE_MESSAGES_REPLY_MAX];
	uint8_t request[FZN_NODE_MESSAGES_REQUEST_MAX];
	size_t request_len = 0, reply_len;
	int ok, done = 0, answered;

	if (!nm || !ask || !tally)
		return 0;
	ok = fzn_node_messages_round_begin(&r, nm, request, sizeof(request), &request_len, &done);
	while (ok && !done) {
		/* Asked first, apart from the step: see `record/exchange.c`. */
		reply_len = 0;
		answered = ask(ctx, request, request_len, reply, sizeof(reply), &reply_len);
		ok = fzn_node_messages_round_step(&r, answered ? reply : NULL, reply_len, request,
		                                  sizeof(request), &request_len, &done);
		/* AN ANSWER'S KEYS, wiped once taken. */
		memset(reply, 0, sizeof(reply));
	}
	/* THE CALLER'S TALLY GAINS what this round did. */
	tally->given += r.tally.given;
	tally->refused += r.tally.refused;
	tally->taken += r.tally.taken;
	tally->lacking = nm->n_lacks;
	return ok;
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

static size_t answer_holds(fzn_node_messages_t *nm, const uint8_t *request, size_t request_len,
                           uint8_t *reply, size_t reply_cap);

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
	if (request[1] == FZN_NODE_MESSAGES_HOLDS)
		return answer_holds(nm, request, request_len, reply, reply_cap);
	return 0;
}

/* ---- delivery to a contact, sec 613 --------------------------------------- */

/* ONE LINE'S OFFER, into `request`: its length. */
static size_t offer_request(const fzn_message_t *line, uint8_t *request)
{
	request[0] = FZN_NODE_MESSAGES_VERSION;
	request[1] = FZN_NODE_MESSAGES_DELIVER;
	memcpy(request + 2, line->id, FZN_MESSAGE_ID_LEN);
	fzn_put_be64(request + 2 + FZN_MESSAGE_ID_LEN, line->stime);
	fzn_put_be16(request + 2 + FZN_MESSAGE_ID_LEN + 8, (uint16_t)line->text_len);
	memcpy(request + FZN_NODE_MESSAGES_DELIVER_HEAD_LEN, line->text, line->text_len);
	return FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + line->text_len;
}

/* ITS OUTCOME: 2 settled, 1 held, 0 refused, -1 unanswered (`reply` NULL)
 * or answered with anything but line `id`'s DELIVERED. */
static int offer_outcome(const uint8_t *reply, size_t reply_len, const uint8_t *id)
{
	if (!reply || reply_len != FZN_NODE_MESSAGES_DELIVERED_LEN
	    || reply[0] != FZN_NODE_MESSAGES_VERSION || reply[1] != FZN_NODE_MESSAGES_DELIVERED
	    || memcmp(reply + 2, id, FZN_MESSAGE_ID_LEN) != 0)
		return -1;
	switch (reply[2 + FZN_MESSAGE_ID_LEN]) {
	case FZN_NODE_MESSAGES_SETTLED:
		return 2;
	case FZN_NODE_MESSAGES_HELD:
		return 1;
	case FZN_NODE_MESSAGES_REFUSED:
		return 0;
	}
	return -1;
}

/* ---- delivery as steps, sec 636 ------------------------------------------ */

static fzn_messages_err_t deliver_end(fzn_node_messages_delivering_t *d, int *done,
                                      fzn_messages_err_t err)
{
	d->live = 0;
	*done = 1;
	return err;
}

/* THE NEXT LINE TO OFFER, from the index place `d->at` on, its offer
 * written; or the end. One line is read at a time, by place, and the place
 * moves past it: a line marked since is passed by its place, not counted
 * out of a page that has changed. Every line still owed is reached, however
 * deep (sec 613). */
static fzn_messages_err_t deliver_next(fzn_node_messages_delivering_t *d, uint8_t *request,
                                       size_t *request_len, int *done)
{
	static fzn_message_t line;
	fzn_node_messages_t *nm = d->nm;
	size_t count;
	fzn_messages_err_t err;
	int more;

	for (;;) {
		count = 0;
		more = 0;
		err = fzn_messages_owed(&nm->m, d->contact, &d->at, &line, 1u, &count, &more);
		if (err != FZN_MESSAGES_OK)
			return deliver_end(d, done, err);
		if (!count)
			return deliver_end(d, done, FZN_MESSAGES_OK);
		/* STILL BEING SENT, or delivered and due for settlement. */
		if (line.direction != FZN_MESSAGE_OUT
		    || (line.state != 0u && !(d->settle && line.state == FZN_MESSAGE_DELIVERED))
		    || !line.readable)
			continue;
		/* THIS DEVICE'S, OR ONE IT TAKES OVER: the writer gone, sec 616. */
		if (!same_key(line.device, nm->m.issuer)
		    && !(nm->takes_over && nm->takes_over(nm->takes_over_ctx, line.device, line.id)))
			continue;
		d->tally.sent++;
		memcpy(d->id, line.id, FZN_MESSAGE_ID_LEN);
		d->state = line.state;
		*request_len = offer_request(&line, request);
		return FZN_MESSAGES_OK;
	}
}

fzn_messages_err_t fzn_node_messages_deliver_begin(fzn_node_messages_delivering_t *d,
                                                   fzn_node_messages_t *nm,
                                                   const uint8_t contact[FZN_PUBKEY_LEN],
                                                   int settle, uint8_t *request, size_t cap,
                                                   size_t *request_len, int *done)
{
	if (!d || !nm || !contact || !request || cap < FZN_NODE_MESSAGES_DELIVER_MAX
	    || !request_len || !done)
		return FZN_MESSAGES_ERR_MALFORMED;
	memset(d, 0, sizeof(*d));
	d->nm = nm;
	memcpy(d->contact, contact, FZN_PUBKEY_LEN);
	d->settle = settle;
	d->live = 1;
	*done = 0;
	return deliver_next(d, request, request_len, done);
}

fzn_messages_err_t fzn_node_messages_deliver_step(fzn_node_messages_delivering_t *d,
                                                  const uint8_t *reply, size_t reply_len,
                                                  uint8_t *request, size_t cap,
                                                  size_t *request_len, int *done)
{
	fzn_messages_err_t err;
	int got;

	if (!d || !d->live || !request || cap < FZN_NODE_MESSAGES_DELIVER_MAX || !request_len
	    || !done)
		return FZN_MESSAGES_ERR_MALFORMED;
	*done = 0;
	got = offer_outcome(reply, reply_len, d->id);
	if (got < 0) {
		d->tally.unanswered++;
		return deliver_end(d, done, FZN_MESSAGES_OK);
	}
	if (got == 0) {
		d->tally.refused++;
		return deliver_end(d, done, FZN_MESSAGES_OK);
	}
	/* HELD AGAIN of a line delivered already changes nothing. */
	if (got == 2 || d->state != FZN_MESSAGE_DELIVERED) {
		err = fzn_messages_mark(&d->nm->m, d->contact, FZN_MESSAGE_OUT, d->id,
		                        got == 2 ? FZN_MESSAGE_SETTLED : FZN_MESSAGE_DELIVERED);
		if (err != FZN_MESSAGES_OK)
			return deliver_end(d, done, err);
		if (got == 2)
			d->tally.settled++;
		else
			d->tally.delivered++;
		d->nm->fresh = 1;
	}
	return deliver_next(d, request, request_len, done);
}

fzn_messages_err_t fzn_node_messages_deliver(fzn_node_messages_t *nm,
                                             const uint8_t contact[FZN_PUBKEY_LEN], int settle,
                                             fzn_node_messages_ask_t ask, void *ctx,
                                             fzn_node_messages_delivery_t *tally)
{
	static fzn_node_messages_delivering_t d;
	uint8_t request[FZN_NODE_MESSAGES_DELIVER_MAX], reply[FZN_NODE_MESSAGES_DELIVERED_LEN + 8u];
	size_t request_len = 0, reply_len;
	fzn_messages_err_t err;
	int done = 0, answered;

	if (tally)
		memset(tally, 0, sizeof(*tally));
	if (!nm || !contact || !ask || !tally)
		return FZN_MESSAGES_ERR_MALFORMED;
	err = fzn_node_messages_deliver_begin(&d, nm, contact, settle, request, sizeof(request),
	                                      &request_len, &done);
	while (err == FZN_MESSAGES_OK && !done) {
		/* Asked first, apart from the step: see `record/exchange.c`. */
		reply_len = 0;
		answered = ask(ctx, request, request_len, reply, sizeof(reply), &reply_len);
		err = fzn_node_messages_deliver_step(&d, answered ? reply : NULL, reply_len, request,
		                                     sizeof(request), &request_len, &done);
	}
	*tally = d.tally;
	return err;
}

size_t fzn_node_messages_contact(fzn_node_messages_t *nm, const uint8_t contact[FZN_PUBKEY_LEN],
                                 int keeps, const uint8_t *request, size_t request_len,
                                 uint8_t *reply, size_t reply_cap)
{
	const uint8_t *id;
	size_t text_len;
	int written = 0;

	if (!nm || !contact || !request || !reply || request_len < 2u
	    || request[0] != FZN_NODE_MESSAGES_VERSION || request[1] != FZN_NODE_MESSAGES_DELIVER
	    || reply_cap < FZN_NODE_MESSAGES_DELIVERED_LEN)
		return 0;
	if (request_len < FZN_NODE_MESSAGES_DELIVER_HEAD_LEN)
		return 0;
	id = request + 2;
	text_len = fzn_get_be16(request + 2 + FZN_MESSAGE_ID_LEN + 8);
	/* THE TEXT IS THE REST, exactly: a length that disagrees is not a line. */
	if (text_len > FZN_MESSAGE_TEXT_MAX
	    || request_len != FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + text_len)
		return 0;
	if (keeps) {
		/* HELD ALREADY IS HELD: a re-offer files nothing twice. */
		if (fzn_messages_import(&nm->m, contact, FZN_MESSAGE_IN, id,
		                        fzn_get_be64(request + 2 + FZN_MESSAGE_ID_LEN),
		                        (const char *)request + FZN_NODE_MESSAGES_DELIVER_HEAD_LEN,
		                        text_len, &written)
		    != FZN_MESSAGES_OK)
			return 0;
		if (written)
			nm->fresh = 1;
	}
	reply[0] = FZN_NODE_MESSAGES_VERSION;
	reply[1] = FZN_NODE_MESSAGES_DELIVERED;
	memcpy(reply + 2, id, FZN_MESSAGE_ID_LEN);
	reply[2 + FZN_MESSAGE_ID_LEN] =
	        !keeps ? FZN_NODE_MESSAGES_REFUSED
	        : fzn_messages_state(&nm->m, contact, FZN_MESSAGE_IN, id) == FZN_MESSAGE_SETTLED
	                ? FZN_NODE_MESSAGES_SETTLED
	                : FZN_NODE_MESSAGES_HELD;
	return FZN_NODE_MESSAGES_DELIVERED_LEN;
}

/* ---- settlement, sec 615 ---------------------------------------------------- */

/* A MEMBER'S HOLDS, answered: whether this host holds the item, or keeps
 * none of that conversation's lines. */
static size_t answer_holds(fzn_node_messages_t *nm, const uint8_t *request, size_t request_len,
                           uint8_t *reply, size_t reply_cap)
{
	const uint8_t *contact = request + 2, *id = request + 2 + FZN_PUBKEY_LEN;

	if (request_len != FZN_NODE_MESSAGES_HOLDS_LEN || reply_cap < FZN_NODE_MESSAGES_HOLDING_LEN)
		return 0;
	reply[0] = FZN_NODE_MESSAGES_VERSION;
	reply[1] = FZN_NODE_MESSAGES_HOLDING;
	memcpy(reply + 2, id, FZN_BUCKETS_ID_LEN);
	reply[2 + FZN_BUCKETS_ID_LEN] =
	        fzn_buckets_has(&nm->buckets, FZN_BUCKETS_MESSAGES, id) ? FZN_NODE_MESSAGES_HOLDS_IT
	        : nm->keeps && !nm->keeps(nm->keeps_ctx, contact) ? FZN_NODE_MESSAGES_DECLINES
	                                                          : FZN_NODE_MESSAGES_LACKS;
	return FZN_NODE_MESSAGES_HOLDING_LEN;
}

/* ONE MEMBER ASKED: its answer, or -1 for none that reads. */
static int ask_holds(const fzn_node_messages_member_t *member,
                     const uint8_t contact[FZN_PUBKEY_LEN], const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	uint8_t request[FZN_NODE_MESSAGES_HOLDS_LEN], reply[FZN_NODE_MESSAGES_HOLDING_LEN + 8u];
	size_t reply_len = 0;

	if (!member->ask)
		return -1;
	request[0] = FZN_NODE_MESSAGES_VERSION;
	request[1] = FZN_NODE_MESSAGES_HOLDS;
	memcpy(request + 2, contact, FZN_PUBKEY_LEN);
	memcpy(request + 2 + FZN_PUBKEY_LEN, id, FZN_BUCKETS_ID_LEN);
	if (!member->ask(member->ctx, request, sizeof(request), reply, sizeof(reply), &reply_len)
	    || reply_len != FZN_NODE_MESSAGES_HOLDING_LEN || reply[0] != FZN_NODE_MESSAGES_VERSION
	    || reply[1] != FZN_NODE_MESSAGES_HOLDING
	    || memcmp(reply + 2, id, FZN_BUCKETS_ID_LEN) != 0
	    || reply[2 + FZN_BUCKETS_ID_LEN] > FZN_NODE_MESSAGES_DECLINES)
		return -1;
	return reply[2 + FZN_BUCKETS_ID_LEN];
}

fzn_messages_err_t fzn_node_messages_settle(fzn_node_messages_t *nm,
                                            const fzn_node_messages_member_t *members,
                                            size_t n_members, size_t cap,
                                            fzn_node_messages_settlement_t *tally)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	static uint8_t item[FZN_MESSAGES_ITEM_MAX];
	size_t n = 0, b, count, i, k, len;
	uint64_t at;
	fzn_messages_err_t err;
	int more;

	if (tally)
		memset(tally, 0, sizeof(*tally));
	if (!nm || (!members && n_members) || !tally)
		return FZN_MESSAGES_ERR_MALFORMED;
	if (!conversations_listed(nm, &n))
		return FZN_MESSAGES_ERR_BACKEND;
	for (b = 0; b < n; b++) {
		const uint8_t *contact = buckets[b].subject;

		if (b > 0 && memcmp(buckets[b - 1u].subject, contact, FZN_PUBKEY_LEN) == 0)
			continue;
		for (at = 0, more = 1; more;) {
			count = 0;
			err = fzn_messages_owed(&nm->m, contact, &at, page, FZN_MESSAGES_PAGE_MAX, &count,
			                        &more);
			if (err != FZN_MESSAGES_OK)
				return err;
			for (i = 0; i < count; i++) {
				uint8_t id[FZN_BUCKETS_ID_LEN];
				int all = 1;

				/* FILED HERE, NOT YET SETTLED: the host that took a
				 * contact's line is the one that settles it. */
				if (page[i].direction != FZN_MESSAGE_IN || page[i].state != 0u
				    || !same_key(page[i].device, nm->m.issuer))
					continue;
				if (tally->weighed == cap)
					return FZN_MESSAGES_OK;
				tally->weighed++;
				len = 0;
				if (fzn_messages_line_item(&nm->m, page[i].device, page[i].seq, item,
				                           sizeof(item), &len)
				            != FZN_MESSAGES_OK
				    || !fzn_buckets_id(nm->m.hash, item, len, id)) {
					tally->waiting++;
					continue;
				}
				for (k = 0; k < n_members && all; k++) {
					int got = ask_holds(&members[k], contact, id);

					all = got == FZN_NODE_MESSAGES_HOLDS_IT
					      || got == FZN_NODE_MESSAGES_DECLINES;
				}
				if (!all) {
					tally->waiting++;
					continue;
				}
				err = fzn_messages_mark(&nm->m, contact, FZN_MESSAGE_IN, page[i].id,
				                        FZN_MESSAGE_SETTLED);
				if (err != FZN_MESSAGES_OK)
					return err;
				tally->settled++;
				nm->fresh = 1;
			}
		}
	}
	return FZN_MESSAGES_OK;
}

/* ---- the verbs ------------------------------------------------------------ */

/* WHO: a contact's name, or a key in hex. */
static int who(const fzn_node_messages_t *nm, const uint8_t *w, size_t w_len,
               uint8_t key[FZN_PUBKEY_LEN])
{
	fzn_contact_t c;

	if (parse_hex(w, w_len, key, FZN_PUBKEY_LEN))
		return 1;
	/* `@NAME` IS A GROUP, sec 629: its conversation is keyed by its id. */
	if (w_len > 1u && w[0] == '@')
		return fzn_node_group_find(nm->m.store, (const char *)w + 1, w_len - 1u, key)
		       == FZN_CONTACT_OK;
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

		/* AN ABSOLUTE PATH ONLY, sec 651: a relative one is read in the
		 * daemon's working directory, which no client sees. */
		if (rest_left == 0u || rest_left >= sizeof(name) || memchr(rest, '\0', rest_left)
		    || rest[0] != '/')
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
	} else if (memchr(at, ' ', left)) {
		/* TEXT IS ONE ESCAPED WORD, sec 651, a space written %20: a raw
		 * one let a text that began `file ` be read as the file form, and
		 * a local file's contents sent in its place. */
		return say(reply, cap, FZN_REPLY_MALFORMED, "a text's spaces are written %20");
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

/* `get message owed`, sec 661: `ok HELD DELIVERED MORE` -- this host's
 * lines to its contacts still owed, those not yet delivered and those
 * delivered and not settled, every conversation walked here rather than
 * by a client page by page: fuzzypickles' `outbox_held`. A group's lines
 * are left out, delivered once sealed and settled never (sec 629); a line
 * handed over or given up is no longer this host's to owe. MORE is 0
 * since sec 613 walks every conversation whole, from its owed floor; it
 * stays, so a client reading three numbers still reads three. */
static size_t get_owed(fzn_node_messages_t *nm, char *reply, size_t cap)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	static fzn_group_t g;
	size_t n = 0, b, count, i, held = 0, delivered = 0;
	uint64_t at;
	char detail[64];
	fzn_messages_err_t err;
	int more, k;

	if (!conversations_listed(nm, &n))
		return say(reply, cap, FZN_REPLY_ERROR, "the conversations did not list");
	for (b = 0; b < n; b++) {
		const uint8_t *contact = buckets[b].subject;

		if ((b > 0 && memcmp(buckets[b - 1u].subject, contact, FZN_PUBKEY_LEN) == 0)
		    || fzn_group_log_get(nm->m.store, contact, &g) == FZN_GROUP_LOG_OK)
			continue;
		for (at = 0, more = 1; more;) {
			count = 0;
			err = fzn_messages_owed(&nm->m, contact, &at, page, FZN_MESSAGES_PAGE_MAX, &count,
			                        &more);
			if (err != FZN_MESSAGES_OK)
				return refuse(reply, cap, err);
			for (i = 0; i < count; i++)
				if (page[i].direction == FZN_MESSAGE_OUT
				    && same_key(page[i].device, nm->m.issuer)) {
					held += page[i].state == 0u;
					delivered += page[i].state == FZN_MESSAGE_DELIVERED;
				}
		}
	}
	k = snprintf(detail, sizeof(detail), "%zu %zu 0", held, delivered);
	if (k < 0 || (size_t)k >= sizeof(detail))
		return 0;
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)k);
}

/* `get message [WHO] held-back`, sec 792: `ok MONTHS LINES NEWEST` from
 * the caller's table of months the rules declined at the last pass --
 * every conversation's, or `contact`'s alone. */
static size_t get_held_back(fzn_node_messages_t *nm, const uint8_t *contact, char *reply,
                            size_t cap)
{
	size_t i, months = 0;
	uint64_t lines = 0;
	uint32_t newest = 0;
	char detail[64];
	int k;

	for (i = 0; nm->held_back && i < nm->n_held_back; i++) {
		const fzn_node_message_held_back_t *h = &nm->held_back[i];

		if (contact && memcmp(h->contact, contact, FZN_PUBKEY_LEN) != 0)
			continue;
		months++;
		lines += h->lines;
		if (h->month > newest)
			newest = h->month;
	}
	k = snprintf(detail, sizeof(detail), "%zu %llu %lu", months, (unsigned long long)lines,
	             (unsigned long)newest);
	if (k < 0 || (size_t)k >= sizeof(detail))
		return 0;
	return answer(reply, cap, FZN_REPLY_OK, detail, (size_t)k);
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

	if (left == 4u && memcmp(at, "owed", 4u) == 0)
		return get_owed(nm, reply, cap);
	if (left == 9u && memcmp(at, "held-back", 9u) == 0)
		return get_held_back(nm, NULL, reply, cap);
	if (!word(&at, &left, &w, &w_len) || !who(nm, w, w_len, contact)
	    || !word(&at, &left, &w, &w_len) || left)
		return say(reply, cap, FZN_REPLY_MALFORMED,
		           "get message WHO unread|held-back, owed, or held-back");
	if (is_word(w, w_len, "held-back"))
		return get_held_back(nm, contact, reply, cap);
	if (!is_word(w, w_len, "unread"))
		return say(reply, cap, FZN_REPLY_MALFORMED,
		           "get message WHO unread|held-back, owed, or held-back");
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
	 * past the walk. A FROM is a size, never 64 digits, so the two never
	 * meet.
	 * One conversation pages at any depth (sec 790); everyone's together
	 * as far as FZN_MESSAGES_WALK_MAX. */
	if (word(&at, &left, &w, &w_len)) {
		if (!all_digits(w, w_len) || w_len == 2u * FZN_PUBKEY_LEN) {
			if (!who(nm, w, w_len, contact))
				return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
			filter = contact;
			if (!word(&at, &left, &w, &w_len))
				w_len = 0;
		}
		for (i = 0; i < w_len; i++) {
			if (w[i] < '0' || w[i] > '9' || from > (SIZE_MAX - 9u) / 10u)
				return say(reply, cap, FZN_REPLY_MALFORMED, USAGE);
			from = (from * 10u) + (size_t)(w[i] - '0');
		}
	}
	err = fzn_messages_page(&nm->m, filter, from, page, FZN_MESSAGES_PAGE_MAX, &count, &more);
	if (err != FZN_MESSAGES_OK)
		return refuse(reply, cap, err);
	for (i = 0; i < count; i++) {
		const fzn_message_t *p = &page[i];
		char head[2u * FZN_PUBKEY_LEN + 3u * FZN_CONTACT_NAME_MAX + 2u * FZN_MESSAGE_ID_LEN + 96u];
		char group[FZN_CONTACT_NAME_MAX + 1u];
		size_t h = 0, wrote = 0, group_len = 0;
		fzn_contact_t c;

		hex_of(p->contact, FZN_PUBKEY_LEN, head);
		h = 2u * FZN_PUBKEY_LEN;
		head[h++] = ',';
		if (fzn_contact_get(nm->m.store, p->contact, &c) == FZN_CONTACT_OK) {
			memcpy(head + h, c.name, c.name_len);
			h += c.name_len;
		} else if (fzn_node_group_name(nm->m.store, p->contact, group, &group_len)
		           == FZN_CONTACT_OK) {
			/* A GROUP'S LINE, sec 629: `@NAME`, and an IN line's sender
			 * after a colon -- a contact's name, or its root's first
			 * bytes -- which no name can hold. */
			const fzn_group_lines_t lines = { nm->m.store, nm->m.hash };
			uint8_t sender[FZN_PUBKEY_LEN];

			head[h++] = '@';
			memcpy(head + h, group, group_len);
			h += group_len;
			if (p->direction == FZN_MESSAGE_IN
			    && fzn_group_lines_sender(&lines, p->contact, p->id, sender)
			               == FZN_GROUP_LINES_OK) {
				head[h++] = ':';
				if (fzn_contact_get(nm->m.store, sender, &c) == FZN_CONTACT_OK) {
					memcpy(head + h, c.name, c.name_len);
					h += c.name_len;
				} else {
					hex_of(sender, 8u, head + h);
					h += 16u;
				}
			}
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
