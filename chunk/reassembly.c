/* Datagram reassembly under a hard memory bound. See reassembly.h. */

#include "reassembly.h"

#include <string.h>

static int seen_get(const fzn_partial_t *slot, uint16_t index)
{
	return (slot->seen[index >> 3] >> (index & 7u)) & 1u;
}

static void seen_set(fzn_partial_t *slot, uint16_t index)
{
	slot->seen[index >> 3] |= (uint8_t)(1u << (index & 7u));
}

/* The offset a chunk lands at, which is fixed by the FIRST chunk's length.
 *
 * Every chunk but the last is exactly `chunk_size`; the last may be shorter.
 * That is what makes an out-of-order arrival addressable at all -- without a
 * uniform stride a receiver cannot place chunk 7 until it has seen 0 to 6,
 * which would mean buffering in arrival order and defeats the point of
 * carrying an index. */
static size_t offset_of(const fzn_partial_t *slot, uint16_t index)
{
	return (size_t)index * slot->chunk_size;
}

static fzn_partial_t *find(fzn_reasm_t *table, const uint8_t *sender, uint32_t msg)
{
	for (size_t i = 0; i < table->capacity; i++) {
		fzn_partial_t *slot = &table->slots[i];

		if (slot->live && slot->msg == msg &&
		    memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)
			return slot;
	}
	return NULL;
}

static size_t held_by(const fzn_reasm_t *table, const uint8_t *sender)
{
	size_t n = 0;

	for (size_t i = 0; i < table->capacity; i++) {
		const fzn_partial_t *slot = &table->slots[i];

		if (slot->live && memcmp(slot->sender, sender, FZN_SENDER_LEN) == 0)
			n++;
	}
	return n;
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

fzn_reasm_err_t fzn_reasm_init(fzn_reasm_t *table, fzn_partial_t *slots, size_t capacity,
                                size_t per_sender_max, uint64_t max_hold)
{
	if (!table || !slots || capacity == 0 || per_sender_max == 0 || max_hold == 0)
		return FZN_REASM_ERR_MALFORMED;

	for (size_t i = 0; i < capacity; i++) {
		if (!slots[i].buf || slots[i].buf_capacity == 0)
			return FZN_REASM_ERR_MALFORMED;
	}

	table->slots = slots;
	table->capacity = capacity;
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

	/* Keep the buffer, drop everything else. A slot is reusable storage
	 * rather than a thing to re-init, and zeroing the arrived-set here is
	 * what stops a stale bit admitting a chunk into the next message. */
	buf = slot->buf;
	capacity = slot->buf_capacity;
	memset(slot, 0, sizeof(*slot));
	slot->buf = buf;
	slot->buf_capacity = capacity;
}

size_t fzn_reasm_expire(fzn_reasm_t *table, uint64_t now)
{
	size_t dropped = 0;

	if (!table || !table->slots)
		return 0;

	for (size_t i = 0; i < table->capacity; i++) {
		fzn_partial_t *slot = &table->slots[i];

		/* `!slot->handed`, or expiry takes a slot the caller is still
		 * reading. See `handed` in reassembly.h: the promise is that the
		 * bytes are the caller's until it releases them, and a sweep is
		 * exactly what used to break it. */
		/* NO `expires_at != 0` CLAUSE ANY MORE. A stored deadline is
		 * never zero: `fzn_reasm_accept` bounds it by `max_hold`, so a
		 * chunk claiming no expiry gets `now + max_hold` rather than
		 * for ever. The clause that used to sit here is what made a
		 * zero-expiry chunk hold a slot permanently. */
		if (slot->live && !slot->handed && slot->expires_at <= now) {
			fzn_reasm_release(slot);
			dropped++;
		}
	}
	return dropped;
}

/* The latest instant a slot may be held, saturating rather than wrapping --
 * `now + max_hold` on caller-chosen uint64s overflows, and a wrapped deadline
 * would expire a slot the moment it was taken. Named after
 * `frame/freshness.c`'s `horizon_of`, which does the same arithmetic for the
 * same reason. */
static uint64_t hold_until(uint64_t now, uint64_t max_hold)
{
	return max_hold > UINT64_MAX - now ? UINT64_MAX : now + max_hold;
}

/* Take a slot for a message not yet being held, sizing it from this chunk. */
static fzn_reasm_err_t admit_first(fzn_reasm_t *table, const uint8_t *sender, uint32_t msg,
                                   uint16_t index, uint16_t chunks, size_t payload_len,
                                   uint64_t expires_at, fzn_partial_t **out_slot)
{
	fzn_partial_t *slot = NULL;

	/* Bounded before a slot is taken, so a claim nobody can satisfy costs
	 * nothing. `chunks` is a u16 off the wire and could say 65535. */
	if (chunks == 0 || chunks > FZN_REASM_MAX_CHUNKS)
		return FZN_REASM_ERR_TOO_LARGE;
	if (index >= chunks)
		return FZN_REASM_ERR_MISMATCH;

	/* The quota before the search for a free slot: one sender filling the
	 * table is the denial of service the capacity bound alone does not
	 * prevent, it only relocates. */
	if (held_by(table, sender) >= table->per_sender_max)
		return FZN_REASM_ERR_QUOTA;

	for (size_t i = 0; i < table->capacity; i++) {
		if (!table->slots[i].live) {
			slot = &table->slots[i];
			break;
		}
	}
	if (!slot)
		return FZN_REASM_ERR_FULL;

	/* Sized up front from what this chunk claims. A chunk that is not the
	 * last sets the stride; one that IS the last cannot, since it may be
	 * short -- so the worst case is assumed and checked against the
	 * buffer, and a first-arriving last chunk of a multi-chunk message
	 * simply reserves the maximum. */
	if (chunks > 1 && index + 1u == chunks) {
		/* Last chunk first: stride unknown, so nothing may be placed
		 * yet. Refuse rather than guess -- guessing would let the
		 * stride be chosen by whoever sends the final piece first. */
		return FZN_REASM_ERR_MISMATCH;
	}
	slot->chunk_size = payload_len;

	/* THE SIZE IS CHECKED BY DIVISION, and the multiplication it replaces
	 * is gone rather than merely unused.
	 *
	 * `payload_len` is a size_t the caller supplies, and this used to size
	 * the slot with `payload_len * chunks`: 2^62 with four chunks is
	 * exactly 2^64 -- zero -- which sailed through a capacity test and left
	 * a live slot claiming a stride of 2^62. Measured rather than reasoned
	 * about, before it was changed: `slot.live` set, `chunk_size` at 2^62,
	 * and the only thing between that and a memcpy of 2^62 bytes was the
	 * offset guard in `fzn_reasm_accept`, which no test and no fuzz case
	 * had ever made fire.
	 *
	 * Division cannot overflow, and `payload_len <= capacity / chunks` is
	 * exactly equivalent to `payload_len * chunks <= capacity` over the
	 * integers, so this is the same bound rather than a stricter one.
	 *
	 * The product was kept for a day afterwards, still compared against the
	 * capacity as defence in depth, and `make coverage` reported that
	 * comparison as a branch which had never gone both ways -- because
	 * `floor(capacity / chunks) * chunks <= capacity` makes it unreachable.
	 * It is deleted rather than silenced: dead code that cannot be tested
	 * is not depth, and leaving a wrapping multiplication in the file for a
	 * reader to puzzle over is worse than not having it. */
	if (payload_len == 0 || payload_len > slot->buf_capacity / (size_t)chunks)
		return FZN_REASM_ERR_TOO_LARGE;


	memcpy(slot->sender, sender, FZN_SENDER_LEN);
	slot->msg = msg;
	slot->chunks = chunks;
	slot->arrived = 0;
	slot->expires_at = expires_at;
	slot->bytes = 0;
	memset(slot->seen, 0, sizeof(slot->seen));
	slot->live = 1;

	*out_slot = slot;
	return FZN_REASM_OK;
}

fzn_reasm_err_t fzn_reasm_accept(fzn_reasm_t *table, const uint8_t sender[FZN_SENDER_LEN],
                                  uint32_t msg, uint16_t index, uint16_t chunks,
                                  const uint8_t *payload, size_t payload_len,
                                  uint64_t expires_at, uint64_t now, fzn_partial_t **out)
{
	fzn_partial_t *slot;
	fzn_reasm_err_t err;
	size_t offset;
	uint64_t deadline;

	if (!table || !table->slots || !sender || !payload || !out)
		return FZN_REASM_ERR_MALFORMED;

	*out = NULL;

	/* THE SWEEP BEFORE ANYTHING THAT CAN RETURN EARLY, so "reclaimed on
	 * every call" is true rather than nearly true.
	 *
	 * It used to sit BELOW the freshness return under this, which meant a
	 * stale chunk skipped it -- so a receiver whose traffic was made
	 * entirely of stale chunks never handed a slot back. Measured: four
	 * partials taken at an expiry of 200, then a thousand stale chunks at
	 * now = 100000, and all four slots were still live holding messages
	 * that had expired 99800 ticks earlier. An explicit
	 * `fzn_reasm_expire` then dropped all four, which is the proof they
	 * were reclaimable the whole time and nothing was reclaiming them.
	 *
	 * `frame/freshness.c` records the identical defect and its fix in the
	 * identical words -- "It used to sit below the two returns beneath
	 * this ... so traffic made entirely of grants, or entirely of stale
	 * commands, left dead entries holding slots indefinitely." The two
	 * modules are the same shape and only one of them had been corrected.
	 *
	 * Freshness still comes before a slot is TAKEN, which is what the old
	 * comment here was really about: a stale chunk must not cost a slot.
	 * That ordering is unchanged -- the sweep costs nothing and takes
	 * nothing. */
	(void)fzn_reasm_expire(table, now);

	/* Freshness before a slot is taken, so a stale chunk never costs one --
	 * the same ordering frame/freshness.c uses and for the same reason. */
	if (expires_at != 0 && expires_at <= now)
		return FZN_REASM_ERR_EXPIRED;

	/* THE DEADLINE THIS SLOT WILL ACTUALLY BE HELD TO. A chunk's own
	 * expiry is honoured when it is sooner, and bounded by `max_hold`
	 * when it is later or absent -- see `max_hold` in reassembly.h for
	 * what a zero used to cost. */
	deadline = expires_at == 0 ? hold_until(now, table->max_hold)
	                           : (expires_at < hold_until(now, table->max_hold)
	                                      ? expires_at
	                                      : hold_until(now, table->max_hold));

	slot = find(table, sender, msg);
	if (!slot) {
		err = admit_first(table, sender, msg, index, chunks, payload_len, deadline,
		                  &slot);
		if (err != FZN_REASM_OK)
			return err;
	} else {
		/* frame.situ's `same_message` relation, enforced. Each clause
		 * is an attack rather than an accident: a differing `chunks`
		 * resizes a buffer already sized against the first claim, and a
		 * differing `sender` cannot reach here at all because it is
		 * part of the key. */
		if (slot->chunks != chunks)
			return FZN_REASM_ERR_MISMATCH;
		if (index >= slot->chunks)
			return FZN_REASM_ERR_MISMATCH;

		/* Every chunk but the last is exactly the stride; the last may
		 * be shorter but never longer. */
		if (index + 1u == slot->chunks) {
			if (payload_len == 0 || payload_len > slot->chunk_size)
				return FZN_REASM_ERR_MISMATCH;
		} else if (payload_len != slot->chunk_size) {
			return FZN_REASM_ERR_MISMATCH;
		}
	}

	/* THE LAST CHECK BEFORE A WRITE, AND IT IS NOT DEAD -- which is worth
	 * saying, because an audit reported it as provably unreachable and
	 * cited this file's own rule that "dead code that cannot be tested is
	 * not depth" fifteen lines above.
	 *
	 * Through the public API with a consistent table it is unreachable, and
	 * that much is right: `admit_first` bounds `chunk_size` by
	 * `buf_capacity / chunks` and `index < chunks`, so `index * chunk_size
	 * + payload_len <= buf_capacity` by construction. An exhaustive sweep
	 * over the API fires it zero times.
	 *
	 * But `fzn_reasm_t` and its slots are CALLER-OWNED, and this module
	 * already treats a hand-built table as inside its threat model --
	 * `usable()` exists for that and `log_test.c` exercises the same shape.
	 * Measured: take a slot normally, then set `buf_capacity` to something
	 * smaller than what has already been placed in it, and this returns
	 * TOO_LARGE. The construction that makes it unreachable lives in a
	 * DIFFERENT function, and those bounds have moved twice today.
	 *
	 * So the rule above is right and does not reach this. What it forbids
	 * is a branch no input can take; this one takes a corrupt argument, and
	 * a bounds check immediately before a memcpy is the last place to trade
	 * a demonstrable branch for a proof that lives elsewhere. */
	offset = offset_of(slot, index);
	if (offset > slot->buf_capacity || payload_len > slot->buf_capacity - offset)
		return FZN_REASM_ERR_TOO_LARGE;

	if (seen_get(slot, index)) {
		/* A byte-identical repeat is what a retransmission looks like,
		 * so it is accepted and changes nothing. A differing repeat is
		 * an attempt to rewrite part of a message after the rest was
		 * accepted, and is refused. */
		if (memcmp(slot->buf + offset, payload, payload_len) != 0)
			return FZN_REASM_ERR_CONFLICT;
	} else {
		memcpy(slot->buf + offset, payload, payload_len);
		seen_set(slot, index);
		slot->arrived++;
		slot->bytes += payload_len;
	}

	/* HANDED ONCE, NOT ONCE PER RETRANSMISSION.
	 *
	 * `find` matches on `live`, and a handed slot is still live, so an
	 * identical resend of the last chunk -- which `reassembly.h` says is
	 * accepted and changes nothing, because that is what loss recovery
	 * looks like -- used to hand the caller the SAME slot a second time.
	 *
	 * The caller then holds two pointers to one slot and releases twice,
	 * which is exactly what the ownership contract asks of it. Measured:
	 * alice completes, resends, and is handed the slot twice; the first
	 * release frees it; bob takes it and puts a chunk in; the second
	 * release wipes bob's message and bob's next chunk is refused as a
	 * MISMATCH -- so one peer's ordinary retransmission destroys another's
	 * message and the damage is blamed on the victim. The completed
	 * message is also delivered twice, which at sec 4.4a is a router
	 * reconfigured twice.
	 *
	 * `fzn_reasm_release` says it is "safe on a slot that is already
	 * free", and that is what makes the second release look correct. It is
	 * not safe on a slot that is free AND REALLOCATED, and nothing in the
	 * caller can tell those apart.
	 *
	 * The `handed` flag was added to keep the sweep off a slot the caller
	 * still holds. It did that and left this open, so the ownership
	 * promise it exists to make true was half true. */
	if (slot->arrived == slot->chunks && !slot->handed) {
		slot->handed = 1;
		*out = slot;
	}

	return FZN_REASM_OK;
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
	}

	return "unknown";
}
