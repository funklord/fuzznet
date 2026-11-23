/* Datagram reassembly under a hard memory bound. See reassembly.h.
 *
 * ONE MESSAGE'S ASSEMBLY IS SITU'S, project.md sec 1404: the table it
 * generates from wire/frame.situ's `reassemble pieces` (situ 26.1123),
 * one message at a time over each slot's own buffer -- the stride, a last
 * piece parked until the stride is known (sec 737), the marks of which
 * pieces are held, a piece claiming another count or past its count, a
 * resend compared with what is held, the 256-piece ceiling. What stays
 * here is the table AROUND the messages, which a caller's memory shapes:
 * which slot a message takes, the per-sender quota, time -- every
 * deadline and the sweep, in this module's 64-bit clock, so the generated
 * table is never asked the time -- and the hand-over of a completed
 * message until it is released.
 *
 * Held to what this file did before by chunk/test/reasm_agree_fuzz.c,
 * which runs the two on one stream (chunk/test/reasm_ref.h is that file,
 * kept as the oracle). */

#include "reassembly.h"
#include "../wire/generated/frame_converse.h"
#include "../wire/generated/frame_reassemble.h"

/* Diagnostics through flog, vendored and possibly absent. sec 209. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define REASM_LOG(t, sub, sev, ...)                                                        \
	do {                                                                               \
		if ((t) && (t)->log)                                                       \
			flog_printf((t)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);        \
	} while (0)
#else
#define REASM_LOG(t, sub, sev, ...) ((void)0)
#endif

#include <stdalign.h>
#include <string.h>

/* THE GENERATED TABLE'S STATE, kept in each slot's opaque words: its header,
 * its one slot, and the key it holds the message under. */
struct assembly {
	situ_pieces_t table;
	situ_pieces_slot_t slot;
};

_Static_assert(sizeof(struct assembly) <= sizeof(((fzn_partial_t *)0)->assembly),
               "FZN_REASM_ASSEMBLY_WORDS is too small for the generated table's state");
_Static_assert(alignof(struct assembly) <= alignof(uint64_t),
               "the generated table's state wants more alignment than its room has");
_Static_assert(FZN_REASM_MAX_CHUNKS == SITU_PIECES_COUNT_MAX,
               "wire/frame.situ's count_max and FZN_REASM_MAX_CHUNKS disagree");
_Static_assert(sizeof(((fzn_partial_t *)0)->marks) == SITU_PIECES_MARKS_FOR(1u, SITU_PIECES_COUNT_MAX),
               "a slot's marks are not what the generated table keeps for one message");

static struct assembly *assembly_of(fzn_partial_t *slot)
{
	return (struct assembly *)(void *)slot->assembly;
}

static const struct assembly *assembly_seen(const fzn_partial_t *slot)
{
	return (const struct assembly *)(const void *)slot->assembly;
}

static void key_of(const uint8_t *sender, uint32_t msg, uint8_t key[36])
{
	situ_conv_same_piece_of_key(msg, sender, key);
}

static fzn_partial_t *find(fzn_reasm_t *table, const uint8_t *sender, uint32_t msg)
{
	for (size_t i = 0; i < table->capacity; i++) {
		fzn_partial_t *slot = &table->partials[i];

		if (slot->live && slot->msg == msg && memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)
			return slot;
	}
	return NULL;
}

/* How many slots `sender` holds, HANDED ONES INCLUDED: the quota's own
 * definition, which `fzn_reasm_held_by` exposes. */
static size_t held_by(const fzn_reasm_t *table, const uint8_t *sender)
{
	size_t n = 0;

	for (size_t i = 0; i < table->capacity; i++) {
		const fzn_partial_t *slot = &table->partials[i];

		if (slot->live && memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)
			n++;
	}
	return n;
}

size_t fzn_reasm_held_by(const fzn_reasm_t *table, const uint8_t sender[FZN_SENDER_LEN])
{
	if (!table || !table->partials || !sender)
		return 0;
	return held_by(table, sender);
}

fzn_reasm_err_t fzn_reasm_slot_init(fzn_partial_t *slot, uint8_t *buf, size_t capacity)
{
	if (!slot || !buf || capacity == 0)
		return FZN_REASM_ERR_MALFORMED;
	memset(slot, 0, sizeof(*slot));
	slot->buf = buf;
	slot->buf_capacity = capacity;
	return FZN_REASM_OK;
}

void fzn_reasm_set_log(fzn_reasm_t *table, struct flog_t *log)
{
	if (!table)
		return;
	table->log = log;
}

fzn_reasm_err_t fzn_reasm_init(fzn_reasm_t *table, fzn_partial_t *partials, size_t capacity,
                                size_t per_sender_max, uint64_t max_hold)
{
	if (!table || !partials || capacity == 0 || per_sender_max == 0 || max_hold == 0)
		return FZN_REASM_ERR_MALFORMED;
	for (size_t i = 0; i < capacity; i++) {
		if (!partials[i].buf || partials[i].buf_capacity == 0)
			return FZN_REASM_ERR_MALFORMED;
	}
	table->partials = partials;
	table->capacity = capacity;
	table->log = NULL;
	table->per_sender_max = per_sender_max;
	table->max_hold = max_hold;
	return FZN_REASM_OK;
}

void fzn_reasm_release(fzn_partial_t *slot)
{
	uint8_t *buf;
	size_t capacity;

	if (!slot)
		return;
	buf = slot->buf;
	capacity = slot->buf_capacity;
	memset(slot, 0, sizeof(*slot));
	slot->buf = buf;
	slot->buf_capacity = capacity;
}

fzn_reasm_err_t fzn_reasm_plan_want(const fzn_reasm_t *table,
                                     const uint8_t sender[FZN_SENDER_LEN], uint32_t msg,
                                     uint16_t max_per_range, fzn_reasm_range_t *out, size_t cap,
                                     size_t *count)
{
	static uint32_t first[FZN_REASM_MAX_CHUNKS], run[FZN_REASM_MAX_CHUNKS];
	const fzn_partial_t *slot = NULL;
	uint8_t key[36];
	uint32_t n, i;

	if (!table || !table->partials || !sender || !out || !count || max_per_range == 0u)
		return FZN_REASM_ERR_MALFORMED;
	*count = 0;
	for (i = 0; i < table->capacity && !slot; i++) {
		const fzn_partial_t *candidate = &table->partials[i];

		if (candidate->live && candidate->msg == msg
		    && memcmp(candidate->sender, sender, FZN_SENDER_LEN) == 0)
			slot = candidate;
	}
	if (!slot)
		return FZN_REASM_ERR_ABSENT;
	/* A COMPLETED MESSAGE STILL HANDED wants nothing. */
	if (slot->handed)
		return FZN_REASM_OK;
	key_of(sender, msg, key);
	n = situ_pieces_missing(&assembly_seen(slot)->table, key, first, run,
	                        cap < FZN_REASM_MAX_CHUNKS ? (uint32_t)cap : FZN_REASM_MAX_CHUNKS, max_per_range);
	for (i = 0; i < n; i++) {
		out[i].first = (uint16_t)first[i];
		out[i].count = (uint16_t)run[i];
	}
	*count = n;
	return FZN_REASM_OK;
}

size_t fzn_reasm_expire(fzn_reasm_t *table, uint64_t now)
{
	size_t dropped = 0;

	if (!table || !table->partials)
		return 0;
	for (size_t i = 0; i < table->capacity; i++) {
		fzn_partial_t *slot = &table->partials[i];

		if (slot->live && !slot->handed && slot->expires_at <= now) {
			if (slot->arrived > 1u)
				REASM_LOG(table, "chunk/reasm", FLOG_WARN,
				          "expiring a message that was arriving: %u of %u "
				          "chunks and %zu bytes are dropped, so if this "
				          "repeats max_hold is shorter than a transfer "
				          "takes",
				          (unsigned)slot->arrived, (unsigned)slot->chunks, slot->bytes);
			else
				REASM_LOG(table, "chunk/reasm", FLOG_DEBUG,
				          "expiring a message that never progressed: %u of "
				          "%u chunks, held until %llu",
				          (unsigned)slot->arrived, (unsigned)slot->chunks,
				          (unsigned long long)slot->expires_at);
			fzn_reasm_release(slot);
			dropped++;
		}
	}
	return dropped;
}

size_t fzn_reasm_forget(fzn_reasm_t *table, const uint8_t sender[FZN_SENDER_LEN], uint32_t msg)
{
	size_t dropped = 0;

	if (!table || !table->partials || !sender)
		return 0;
	for (size_t i = 0; i < table->capacity; i++) {
		fzn_partial_t *slot = &table->partials[i];

		if (slot->live && !slot->handed && slot->msg == msg
		    && memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0) {
			fzn_reasm_release(slot);
			dropped++;
		}
	}
	return dropped;
}

static uint64_t hold_until(uint64_t now, uint64_t max_hold)
{
	return max_hold > UINT64_MAX - now ? UINT64_MAX : now + max_hold;
}

/* A FIRST PIECE: a slot taken for its message, the generated table set up
 * over the slot's buffer -- or the refusal that takes none. Freshness and
 * the bounds a stranger could otherwise spend a slot on come first. */
static fzn_reasm_err_t admit_first(fzn_reasm_t *table, const uint8_t *sender, uint32_t msg,
                                   uint16_t index, uint16_t chunks, size_t payload_len,
                                   uint64_t deadline, fzn_partial_t **out_slot)
{
	fzn_partial_t *slot = NULL;
	struct assembly *a;
	size_t capacity;

	if (chunks == 0 || chunks > FZN_REASM_MAX_CHUNKS)
		return FZN_REASM_ERR_TOO_LARGE;
	if (index >= chunks)
		return FZN_REASM_ERR_MISMATCH;
	if (held_by(table, sender) >= table->per_sender_max)
		return FZN_REASM_ERR_QUOTA;
	for (size_t i = 0; i < table->capacity && !slot; i++)
		if (!table->partials[i].live)
			slot = &table->partials[i];
	if (!slot) {
		REASM_LOG(table, "chunk/reasm", FLOG_WARN,
		          "reassembly table saturated: all %zu slots live, so this chunk is "
		          "dropped and the message will not complete",
		          table->capacity);
		return FZN_REASM_ERR_FULL;
	}
	/* NO BYTES, OR MORE THAN A PIECE MAY CARRY: refused before the slot is
	 * taken, so a refused first piece costs nothing. A message of one
	 * empty piece is refused too, which the generated table would take. */
	if (payload_len == 0 || payload_len > slot->buf_capacity / (size_t)chunks)
		return FZN_REASM_ERR_TOO_LARGE;
	capacity = slot->buf_capacity < SITU_PIECES_CAPACITY ? slot->buf_capacity : SITU_PIECES_CAPACITY;
	a = assembly_of(slot);
	memset(slot->assembly, 0, sizeof(slot->assembly));
	memset(slot->marks, 0, sizeof(slot->marks));
	if (situ_pieces_init_in(&a->table, 1u, (uint32_t)capacity, 1u, &a->slot, slot->buf, slot->marks, 1u)
	    != SITU_OK)
		return FZN_REASM_ERR_MALFORMED;
	memcpy(slot->sender, sender, FZN_SENDER_LEN);
	slot->msg = msg;
	slot->chunks = chunks;
	slot->arrived = 0;
	slot->expires_at = deadline;
	slot->bytes = 0;
	slot->live = 1;
	*out_slot = slot;
	return FZN_REASM_OK;
}

/* A RESEND TO A MESSAGE ALREADY HANDED, which the generated table no longer
 * holds: compared with the bytes at its place, as every resend is. */
static fzn_reasm_err_t resend_handed(const fzn_partial_t *slot, uint16_t index, uint16_t chunks,
                                     const uint8_t *payload, size_t payload_len)
{
	const situ_pieces_slot_t *m = &assembly_seen(slot)->slot;
	size_t at, held;

	if (chunks != slot->chunks || index >= slot->chunks)
		return FZN_REASM_ERR_MISMATCH;
	at = (size_t)index * m->stride;
	held = index + 1u == slot->chunks ? m->last_len : m->stride;
	if (slot->chunks == 1u) {
		at = 0;
		held = slot->bytes;
	}
	if (payload_len != held || at > slot->bytes || held > slot->bytes - at
	    || memcmp(slot->buf + at, payload, payload_len) != 0)
		return FZN_REASM_ERR_CONFLICT;
	return FZN_REASM_OK;
}

/* THE GENERATED TABLE'S REFUSAL in this module's words. */
static fzn_reasm_err_t refusal_of(uint32_t why)
{
	switch (why) {
	case SITU_PIECES_WHY_FULL:
		return FZN_REASM_ERR_FULL;
	case SITU_PIECES_WHY_PER:
		return FZN_REASM_ERR_QUOTA;
	case SITU_PIECES_WHY_TOO_LARGE:
		return FZN_REASM_ERR_TOO_LARGE;
	case SITU_PIECES_WHY_EXPIRED:
		return FZN_REASM_ERR_EXPIRED;
	case SITU_PIECES_WHY_CONFLICT:
		return FZN_REASM_ERR_CONFLICT;
	case SITU_PIECES_WHY_INDEX:
	case SITU_PIECES_WHY_COUNT:
	case SITU_PIECES_WHY_EMPTY:
	case SITU_PIECES_WHY_STRIDE:
	case SITU_PIECES_WHY_LAST_LONGER:
		return FZN_REASM_ERR_MISMATCH;
	default:
		return FZN_REASM_ERR_MALFORMED;
	}
}

fzn_reasm_err_t fzn_reasm_accept(fzn_reasm_t *table, const uint8_t sender[FZN_SENDER_LEN],
                                  uint32_t msg, uint16_t index, uint16_t chunks,
                                  const uint8_t *payload, size_t payload_len,
                                  uint64_t expires_at, uint64_t now, fzn_partial_t **out)
{
	fzn_partial_t *slot;
	struct assembly *a;
	fzn_reasm_err_t err;
	situ_err_t e;
	uint64_t deadline;
	uint8_t key[36];
	const uint8_t *whole = NULL;
	uint32_t whole_len = 0, held_before;
	int first = 0;

	if (!table || !table->partials || !sender || !payload || !out)
		return FZN_REASM_ERR_MALFORMED;
	*out = NULL;

	/* THE SWEEP BEFORE ANYTHING THAT CAN RETURN EARLY, so "reclaimed on
	 * every call" is true rather than nearly true: a receiver whose
	 * traffic is all stale chunks still hands its slots back. Freshness
	 * still comes before a slot is TAKEN -- a stale chunk must not cost
	 * one -- and the sweep takes nothing. */
	(void)fzn_reasm_expire(table, now);
	if (expires_at != 0 && expires_at <= now)
		return FZN_REASM_ERR_EXPIRED;

	/* THE DEADLINE THIS SLOT WILL BE HELD TO, fixed at its first piece: a
	 * chunk's own expiry where sooner, `max_hold` where later or absent
	 * (see `max_hold` in reassembly.h for what a zero used to cost). */
	deadline = expires_at == 0 ? hold_until(now, table->max_hold)
	                           : (expires_at < hold_until(now, table->max_hold)
	                                      ? expires_at
	                                      : hold_until(now, table->max_hold));

	slot = find(table, sender, msg);
	if (!slot) {
		err = admit_first(table, sender, msg, index, chunks, payload_len, deadline, &slot);
		if (err != FZN_REASM_OK)
			return err;
		first = 1;
	} else if (slot->handed) {
		/* HANDED ONCE, NOT ONCE PER RETRANSMISSION: a resend of a message
		 * the caller holds is compared and changes nothing, and is never
		 * handed again -- two pointers to one slot released twice let one
		 * peer's retransmission destroy another's message. */
		return resend_handed(slot, index, chunks, payload, payload_len);
	} else if (payload_len == 0) {
		return FZN_REASM_ERR_MISMATCH;
	}

	a = assembly_of(slot);
	/* A SLOT WHOSE CAPACITY SHRANK below what the table was given for it:
	 * caller-owned, so inside the threat model, and the generated table
	 * keeps its own copy of the capacity. Refused before any write. */
	if (a->table.capacity > slot->buf_capacity)
		return FZN_REASM_ERR_TOO_LARGE;
	held_before = a->slot.held;
	key_of(sender, msg, key);
	/* The generated table is never asked the time: this module holds every
	 * deadline in its own clock, so the piece's deadline given it is one it
	 * cannot have reached. */
	a->table.why = SITU_PIECES_WHY_NONE;
	e = situ_pieces_add_parts(&a->table, key, index, chunks, payload, (uint32_t)payload_len, 1u, 0u, &whole,
	                          &whole_len);
	if (e == SITU_OK) {
		/* WHERE A CALLER READS IT, the start of `buf`: a message of one
		 * piece the generated table completes where that piece was
		 * parked, at the buffer's end. */
		if (whole != slot->buf)
			memmove(slot->buf, whole, whole_len);
		slot->arrived = slot->chunks;
		slot->bytes = whole_len;
		slot->handed = 1;
		*out = slot;
		return FZN_REASM_OK;
	}
	if (e == SITU_ERR_TRUNCATED) {
		if (a->slot.held != held_before) {
			slot->arrived = (uint16_t)a->slot.held;
			slot->bytes += payload_len;
		}
		return FZN_REASM_OK;
	}
	/* A REFUSED FIRST PIECE TAKES NO SLOT, as before the table was situ's. */
	if (first)
		fzn_reasm_release(slot);
	/* THE STRIDE BEFORE THE REPEAT, as this module always checked: a held
	 * piece resent at a length its stride rules out is a piece that
	 * disagrees with the first, before it is a conflicting resend. */
	if (a->table.why == SITU_PIECES_WHY_CONFLICT && a->slot.stride_known
	    && (index + 1u == chunks ? payload_len > a->slot.stride : payload_len != a->slot.stride))
		return FZN_REASM_ERR_MISMATCH;
	return refusal_of(a->table.why);
}

/* See reassembly.h.
 *
 * NO `default:` LABEL, and that is the mechanism rather than an oversight.
 * `-Wswitch` -- which `-Wall` turns on -- warns about an enumerated switch
 * that omits a case only when there is no default, so leaving it out is what
 * makes the compiler notice a code added to fzn_reasm_err_t and not rendered here. A
 * default would silence exactly the warning worth having and turn a new code
 * into a silent "unknown" in somebody's log.
 *
 * The fallback then lives after the switch, where it catches a value that is
 * not an enumerator at all -- which no amount of compiler help can rule out,
 * since the argument may have come from a cast or from the wire. */
const char *fzn_reasm_err_str(fzn_reasm_err_t err)
{
	switch (err) {
	case FZN_REASM_OK:
		return "ok";
	case FZN_REASM_ERR_MALFORMED:
		return "malformed argument";
	case FZN_REASM_ERR_FULL:
		return "every slot holds a live message";
	case FZN_REASM_ERR_QUOTA:
		return "sender is at its slot quota";
	case FZN_REASM_ERR_MISMATCH:
		return "chunk disagrees with the first";
	case FZN_REASM_ERR_CONFLICT:
		return "index already arrived with other bytes";
	case FZN_REASM_ERR_TOO_LARGE:
		return "message exceeds what a slot holds";
	case FZN_REASM_ERR_EXPIRED:
		return "chunk expiry has passed";
	case FZN_REASM_ERR_ABSENT:
		return "no live message for that sender and id";
	}

	return "unknown";
}
