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
                                size_t per_sender_max)
{
	if (!table || !slots || capacity == 0 || per_sender_max == 0)
		return FZN_REASM_ERR_MALFORMED;

	for (size_t i = 0; i < capacity; i++) {
		if (!slots[i].buf || slots[i].buf_capacity == 0)
			return FZN_REASM_ERR_MALFORMED;
	}

	table->slots = slots;
	table->capacity = capacity;
	table->per_sender_max = per_sender_max;

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

		if (slot->live && slot->expires_at != 0 && slot->expires_at <= now) {
			fzn_reasm_release(slot);
			dropped++;
		}
	}
	return dropped;
}

/* Take a slot for a message not yet being held, sizing it from this chunk. */
static fzn_reasm_err_t admit_first(fzn_reasm_t *table, const uint8_t *sender, uint32_t msg,
                                   uint16_t index, uint16_t chunks, size_t payload_len,
                                   uint64_t expires_at, fzn_partial_t **out_slot)
{
	fzn_partial_t *slot = NULL;
	size_t total;

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
	if (chunks == 1) {
		total = payload_len;
		slot->chunk_size = payload_len;
	} else if (index + 1u == chunks) {
		/* Last chunk first: stride unknown, so nothing may be placed
		 * yet. Refuse rather than guess -- guessing would let the
		 * stride be chosen by whoever sends the final piece first. */
		return FZN_REASM_ERR_MISMATCH;
	} else {
		slot->chunk_size = payload_len;
		total = payload_len * (size_t)chunks;
	}

	if (payload_len == 0 || total > slot->buf_capacity)
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

	if (!table || !table->slots || !sender || !payload || !out)
		return FZN_REASM_ERR_MALFORMED;

	*out = NULL;

	/* Freshness first, so a stale chunk never costs a slot -- the same
	 * ordering frame/freshness.c uses and for the same reason. */
	if (expires_at != 0 && expires_at <= now)
		return FZN_REASM_ERR_EXPIRED;

	(void)fzn_reasm_expire(table, now);

	slot = find(table, sender, msg);
	if (!slot) {
		err = admit_first(table, sender, msg, index, chunks, payload_len, expires_at,
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

	if (slot->arrived == slot->chunks)
		*out = slot;

	return FZN_REASM_OK;
}
