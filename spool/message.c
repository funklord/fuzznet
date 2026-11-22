/* The filestore vocabulary's bytes. The reasoning is in message.h. */

#include "message.h"
#include "../wire/generated/message_wire.h"
#include "../wire/generated/message_wire_build.h"

#include <string.h>

#include "../wire/bytes.h"

_Static_assert(FZN_MSG_OFF_VERSION == 0u, "message layout: version moved");
_Static_assert(FZN_MSG_OFF_TYPE == 1u, "message layout: type moved");
_Static_assert(FZN_MSG_HAVE_QUERY_LEN == 2u + (size_t)FZN_BLOB_HASH_LEN,
               "message layout: a have_query is a header and a root");
_Static_assert(FZN_MSG_HAVE_OFF_RANGES == 60u, "message layout: have ranges moved");
_Static_assert(FZN_MSG_WANT_LEN == 70u, "message layout: want length moved");
_Static_assert(FZN_MSG_DATA_OFF_PROOF == 23u, "message layout: data proof moved");
/* The two variable-length messages must not overlap their own headers. */
_Static_assert(FZN_MSG_HAVE_OFF_RANGE_COUNT + 2u == FZN_MSG_HAVE_OFF_RANGES,
               "message layout: the range count abuts the ranges");
_Static_assert(FZN_MSG_DATA_OFF_PROOF_COUNT + 1u == FZN_MSG_DATA_OFF_PROOF,
               "message layout: the proof count abuts the proof");
/* A range on the wire is two 64-bit fields and nothing else. Asserted rather
 * than assumed, because `fzn_spool_range_t` is a struct this file does not
 * own and a third field added there must break the build here rather than
 * silently travel unencoded. */
_Static_assert(FZN_MSG_RANGE_LEN == 16u, "message layout: a range is two u64");
_Static_assert(sizeof(fzn_spool_range_t) >= FZN_MSG_RANGE_LEN,
               "message layout: a range no longer fits its encoding");

const char *fzn_msg_err_str(fzn_msg_err_t err)
{
	switch (err) {
	case FZN_MSG_OK:
		return "ok";
	case FZN_MSG_ERR_MALFORMED:
		return "malformed";
	case FZN_MSG_ERR_TOO_LARGE:
		return "too large";
	case FZN_MSG_ERR_EMPTY:
		return "empty";
	}
	return "unknown";
}

/* Every parser's first act, so a wrong version or a wrong type is one
 * refusal rather than four. `want` is the type the caller is about to
 * decode; a message of another type reaching a parser is MALFORMED, which
 * is what makes trying each parser in turn unnecessary. */
static fzn_msg_err_t check_header(const uint8_t *bytes, size_t len, size_t need,
                                  fzn_msg_type_t want)
{
	if (!bytes || len < need)
		return FZN_MSG_ERR_MALFORMED;
	if (bytes[FZN_MSG_OFF_VERSION] != FZN_CMD_FILES)
		return FZN_MSG_ERR_MALFORMED;
	if (bytes[FZN_MSG_OFF_TYPE] != (uint8_t)want)
		return FZN_MSG_ERR_MALFORMED;
	return FZN_MSG_OK;
}

/* WRITTEN AND READ BY THE CODE situ GENERATES from
 * `spool/message_wire.situ` (sec 1385): the queries and WANT by its
 * builders, HAVE and DATA -- a run of ranges, and leaves that arrive
 * apart -- through its edit layer, and all four read through its views'
 * getters. Each refusal keeps its own answer and its order, which is the
 * codec's: EMPTY, TOO_LARGE and MALFORMED say different things to a
 * caller, and the bounds a blob's size puts on a span are the codec's
 * too. */

fzn_msg_err_t fzn_msg_peek(const uint8_t *bytes, size_t len, fzn_msg_type_t *out_type)
{
	uint8_t type;

	if (!bytes || !out_type || len < 2u)
		return FZN_MSG_ERR_MALFORMED;
	if (bytes[FZN_MSG_OFF_VERSION] != FZN_CMD_FILES)
		return FZN_MSG_ERR_MALFORMED;

	type = bytes[FZN_MSG_OFF_TYPE];
	if (type != (uint8_t)FZN_MSG_HAVE_QUERY && type != (uint8_t)FZN_MSG_HAVE &&
	    type != (uint8_t)FZN_MSG_WANT && type != (uint8_t)FZN_MSG_DATA)
		return FZN_MSG_ERR_MALFORMED;

	*out_type = (fzn_msg_type_t)type;
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_have_query_encode(const uint8_t root[FZN_BLOB_HASH_LEN], uint8_t *out,
                                        size_t out_cap, size_t *out_len)
{
	if (!root || !out || !out_len)
		return FZN_MSG_ERR_MALFORMED;
	uint32_t wrote = 0;

	if (out_cap < FZN_MSG_HAVE_QUERY_LEN)
		return FZN_MSG_ERR_TOO_LARGE;
	if (fzn_message_wire_fzn_msg_have_query_build(out, FZN_MSG_HAVE_QUERY_LEN, FZN_CMD_FILES,
	                                              FZN_MESSAGE_WIRE_FZN_MSG_TYPE_HAVE_QUERY, root, &wrote)
	    != SITU_OK)
		return FZN_MSG_ERR_MALFORMED;
	*out_len = FZN_MSG_HAVE_QUERY_LEN;
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_have_query_parse(const uint8_t *bytes, size_t len,
                                       uint8_t out_root[FZN_BLOB_HASH_LEN])
{
	fzn_msg_err_t err;

	if (!out_root)
		return FZN_MSG_ERR_MALFORMED;
	err = check_header(bytes, len, FZN_MSG_HAVE_QUERY_LEN, FZN_MSG_HAVE_QUERY);
	if (err != FZN_MSG_OK)
		return err;
	/* Exact, not at-least. A trailing byte is a message this decoder does
	 * not understand, and accepting it would let two encodings of one
	 * query exist -- which is how a de-duplicating receiver is made to see
	 * two questions where a peer asked one. */
	if (len != FZN_MSG_HAVE_QUERY_LEN)
		return FZN_MSG_ERR_MALFORMED;

	{
		situ_msg_t m;
		situ_view_t v;

		situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
		if (fzn_message_wire_fzn_msg_have_query_view(&m, 0u, &v) != SITU_OK)
			return FZN_MSG_ERR_MALFORMED;
		memcpy(out_root, fzn_message_wire_fzn_msg_have_query_root_ptr(v), FZN_BLOB_HASH_LEN);
	}
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_have_encode(const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t leaf_count,
                                  const uint8_t cookie[FZN_MSG_COOKIE_LEN],
                                  const fzn_spool_range_t *ranges, size_t range_count,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
	size_t need, at;

	if (!root || !cookie || !ranges || !out || !out_len)
		return FZN_MSG_ERR_MALFORMED;
	if (range_count == 0u)
		return FZN_MSG_ERR_EMPTY;
	if (range_count > FZN_MSG_MAX_RANGES)
		return FZN_MSG_ERR_TOO_LARGE;
	/* A blob nobody can address is not a blob this host holds. Refused
	 * here so an encoder cannot produce a message its own parser calls
	 * malformed. */
	if (leaf_count == 0u || leaf_count > FZN_SPOOL_MAX_LEAVES)
		return FZN_MSG_ERR_MALFORMED;

	need = FZN_MSG_HAVE_LEN(range_count);
	if (out_cap < need)
		return FZN_MSG_ERR_TOO_LARGE;

	for (at = 0; at < range_count; at++) {
		/* An empty range says nothing and would decode as a hole in the
		 * middle of an answer. */
		if (ranges[at].count == 0u)
			return FZN_MSG_ERR_EMPTY;
		if (ranges[at].first > leaf_count ||
		    ranges[at].count > leaf_count - ranges[at].first)
			return FZN_MSG_ERR_MALFORMED;
	}

	{
		situ_msg_t m;
		situ_view_t v, r;

		memset(out, 0, need);
		situ_msg_init(&m, out, (uint32_t)need);
		if (fzn_message_wire_fzn_msg_have_view(&m, 0u, (uint32_t)need, &v) != SITU_OK)
			return FZN_MSG_ERR_MALFORMED;
		fzn_message_wire_fzn_msg_have_version_set(v, FZN_CMD_FILES);
		fzn_message_wire_fzn_msg_have_type_set(v, FZN_MESSAGE_WIRE_FZN_MSG_TYPE_HAVE);
		memcpy(fzn_message_wire_fzn_msg_have_root_ptr(v), root, FZN_BLOB_HASH_LEN);
		fzn_message_wire_fzn_msg_have_leaf_count_set(v, leaf_count);
		memcpy(fzn_message_wire_fzn_msg_have_cookie_ptr(v), cookie, FZN_MSG_COOKIE_LEN);
		fzn_message_wire_fzn_msg_have_range_count_set(&m, v, (uint16_t)range_count);
		for (at = 0; at < range_count; at++) {
			if (fzn_message_wire_fzn_msg_have_ranges_at(v, (uint32_t)at, &r) != SITU_OK)
				return FZN_MSG_ERR_MALFORMED;
			fzn_message_wire_fzn_msg_range_first_set(r, ranges[at].first);
			fzn_message_wire_fzn_msg_range_count_set(r, ranges[at].count);
		}
	}

	*out_len = need;
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_have_parse(const uint8_t *bytes, size_t len,
                                 uint8_t out_root[FZN_BLOB_HASH_LEN], uint64_t *out_leaf_count,
                                 uint8_t out_cookie[FZN_MSG_COOKIE_LEN],
                                 fzn_spool_range_t *out_ranges, size_t cap, size_t *out_count)
{
	fzn_msg_err_t err;
	uint64_t leaf_count;
	size_t range_count, at;
	situ_msg_t m;
	situ_view_t v, r;

	if (!out_root || !out_leaf_count || !out_cookie || !out_ranges || !out_count)
		return FZN_MSG_ERR_MALFORMED;
	err = check_header(bytes, len, FZN_MSG_HAVE_OFF_RANGES, FZN_MSG_HAVE);
	if (err != FZN_MSG_OK)
		return err;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, len > UINT32_MAX ? UINT32_MAX : (uint32_t)len);
	if (fzn_message_wire_fzn_msg_have_view(&m, 0u, len > UINT32_MAX ? UINT32_MAX : (uint32_t)len, &v) != SITU_OK)
		return FZN_MSG_ERR_MALFORMED;

	range_count = fzn_message_wire_fzn_msg_have_range_count_get(v);
	if (range_count == 0u)
		return FZN_MSG_ERR_EMPTY;
	if (range_count > FZN_MSG_MAX_RANGES)
		return FZN_MSG_ERR_TOO_LARGE;
	if (len != FZN_MSG_HAVE_LEN(range_count))
		return FZN_MSG_ERR_MALFORMED;
	/* TOO_LARGE and never a truncation: half a have-set read as a whole
	 * one reports a peer as holding less than it does, and schedules a
	 * re-fetch of leaves that were there all along. */
	if (range_count > cap)
		return FZN_MSG_ERR_TOO_LARGE;

	leaf_count = fzn_message_wire_fzn_msg_have_leaf_count_get(v);
	if (leaf_count == 0u || leaf_count > FZN_SPOOL_MAX_LEAVES)
		return FZN_MSG_ERR_MALFORMED;

	for (at = 0; at < range_count; at++) {
		uint64_t first, count;

		if (fzn_message_wire_fzn_msg_have_ranges_at(v, (uint32_t)at, &r) != SITU_OK)
			return FZN_MSG_ERR_MALFORMED;
		first = fzn_message_wire_fzn_msg_range_first_get(r);
		count = fzn_message_wire_fzn_msg_range_count_get(r);

		if (count == 0u)
			return FZN_MSG_ERR_EMPTY;
		/* Written so neither side can wrap: `first` is inside the blob
		 * and `count` is what remains after it. */
		if (first > leaf_count || count > leaf_count - first)
			return FZN_MSG_ERR_MALFORMED;
		out_ranges[at].first = first;
		out_ranges[at].count = count;
	}

	memcpy(out_root, fzn_message_wire_fzn_msg_have_root_ptr(v), FZN_BLOB_HASH_LEN);
	memcpy(out_cookie, fzn_message_wire_fzn_msg_have_cookie_ptr(v), FZN_MSG_COOKIE_LEN);
	*out_leaf_count = leaf_count;
	*out_count = range_count;
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_want_encode(uint32_t transfer, const uint8_t cookie[FZN_MSG_COOKIE_LEN],
                                  const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t first,
                                  uint64_t count, uint8_t *out, size_t out_cap, size_t *out_len)
{
	if (!cookie || !root || !out || !out_len)
		return FZN_MSG_ERR_MALFORMED;
	if (count == 0u)
		return FZN_MSG_ERR_EMPTY;
	if (count > FZN_MSG_MAX_SPAN)
		return FZN_MSG_ERR_TOO_LARGE;
	if (first > FZN_SPOOL_MAX_LEAVES || count > FZN_SPOOL_MAX_LEAVES - first)
		return FZN_MSG_ERR_MALFORMED;
	if (out_cap < FZN_MSG_WANT_LEN)
		return FZN_MSG_ERR_TOO_LARGE;
	{
		uint32_t wrote = 0;

		if (fzn_message_wire_fzn_msg_want_build(out, FZN_MSG_WANT_LEN, FZN_CMD_FILES,
		                                        FZN_MESSAGE_WIRE_FZN_MSG_TYPE_WANT, transfer, cookie, root, first,
		                                        count, &wrote)
		    != SITU_OK)
			return FZN_MSG_ERR_MALFORMED;
	}
	*out_len = FZN_MSG_WANT_LEN;
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_want_parse(const uint8_t *bytes, size_t len, uint32_t *out_transfer,
                                 uint8_t out_cookie[FZN_MSG_COOKIE_LEN],
                                 uint8_t out_root[FZN_BLOB_HASH_LEN], uint64_t *out_first,
                                 uint64_t *out_count)
{
	fzn_msg_err_t err;
	uint64_t first, count;
	situ_msg_t m;
	situ_view_t v;

	if (!out_transfer || !out_cookie || !out_root || !out_first || !out_count)
		return FZN_MSG_ERR_MALFORMED;
	err = check_header(bytes, len, FZN_MSG_WANT_LEN, FZN_MSG_WANT);
	if (err != FZN_MSG_OK)
		return err;
	if (len != FZN_MSG_WANT_LEN)
		return FZN_MSG_ERR_MALFORMED;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
	if (fzn_message_wire_fzn_msg_want_view(&m, 0u, &v) != SITU_OK)
		return FZN_MSG_ERR_MALFORMED;

	count = fzn_message_wire_fzn_msg_want_count_get(v);
	if (count == 0u)
		return FZN_MSG_ERR_EMPTY;
	if (count > FZN_MSG_MAX_SPAN)
		return FZN_MSG_ERR_TOO_LARGE;

	first = fzn_message_wire_fzn_msg_want_first_get(v);
	if (first > FZN_SPOOL_MAX_LEAVES || count > FZN_SPOOL_MAX_LEAVES - first)
		return FZN_MSG_ERR_MALFORMED;

	*out_transfer = fzn_message_wire_fzn_msg_want_transfer_get(v);
	memcpy(out_cookie, fzn_message_wire_fzn_msg_want_cookie_ptr(v), FZN_MSG_COOKIE_LEN);
	memcpy(out_root, fzn_message_wire_fzn_msg_want_root_ptr(v), FZN_BLOB_HASH_LEN);
	*out_first = first;
	*out_count = count;
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_data_encode(uint32_t transfer, uint64_t first, uint64_t count,
                                  const uint8_t *proof, unsigned proof_count,
                                  const uint8_t *const *sealed, const size_t *sealed_len,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
	size_t need, at, body;
	uint8_t *p;

	if (!sealed || !sealed_len || !out || !out_len)
		return FZN_MSG_ERR_MALFORMED;
	/* A proof of zero siblings is legitimate -- a span that IS the whole
	 * tree needs none -- so only the pointer is conditional on the count. */
	if (proof_count > 0u && !proof)
		return FZN_MSG_ERR_MALFORMED;
	if (count == 0u)
		return FZN_MSG_ERR_EMPTY;
	if (count > FZN_MSG_MAX_SPAN || proof_count > FZN_MSG_MAX_PROOF)
		return FZN_MSG_ERR_TOO_LARGE;
	if (first > FZN_SPOOL_MAX_LEAVES || count > FZN_SPOOL_MAX_LEAVES - first)
		return FZN_MSG_ERR_MALFORMED;

	need = FZN_MSG_DATA_OFF_PROOF + (size_t)proof_count * FZN_BLOB_HASH_LEN +
	       (size_t)count * 4u;
	/* Accumulated against the caller's cap as it goes rather than summed
	 * first and compared once: the sum of 64 peer-supplied lengths is
	 * exactly the kind of arithmetic that wraps, and a wrapped total
	 * compares small. */
	body = 0;
	for (at = 0; at < count; at++) {
		if (!sealed[at] || sealed_len[at] == 0u)
			return FZN_MSG_ERR_MALFORMED;
		if (sealed_len[at] > UINT32_MAX)
			return FZN_MSG_ERR_TOO_LARGE;
		if (out_cap < need || sealed_len[at] > out_cap - need - body)
			return FZN_MSG_ERR_TOO_LARGE;
		body += sealed_len[at];
	}
	need += body;
	if (out_cap < need)
		return FZN_MSG_ERR_TOO_LARGE;

	if (need > UINT32_MAX)
		return FZN_MSG_ERR_TOO_LARGE;
	{
		situ_msg_t m;
		situ_view_t v;
		uint8_t *lens;

		memset(out, 0, need);
		situ_msg_init(&m, out, (uint32_t)need);
		if (fzn_message_wire_fzn_msg_data_view(&m, 0u, (uint32_t)need, &v) != SITU_OK)
			return FZN_MSG_ERR_MALFORMED;
		fzn_message_wire_fzn_msg_data_version_set(v, FZN_CMD_FILES);
		fzn_message_wire_fzn_msg_data_type_set(v, FZN_MESSAGE_WIRE_FZN_MSG_TYPE_DATA);
		fzn_message_wire_fzn_msg_data_transfer_set(v, transfer);
		fzn_message_wire_fzn_msg_data_first_set(v, first);
		fzn_message_wire_fzn_msg_data_count_set(&m, v, count);
		fzn_message_wire_fzn_msg_data_proof_count_set(&m, v, (uint8_t)proof_count);
		if (proof_count > 0u)
			memcpy(situ_base(v) + FZN_MSG_DATA_OFF_PROOF, proof, (size_t)proof_count * FZN_BLOB_HASH_LEN);
		/* EACH LEAF'S LENGTH where the schema places the run, then the
		 * leaves, one after the other, where it places the payload. */
		lens = situ_base(v) + fzn_message_wire_fzn_msg_data_leaf_len_offset(v);
		for (at = 0; at < count; at++)
			situ_put_be32(lens + at * 4u, (uint32_t)sealed_len[at]);
		p = fzn_message_wire_fzn_msg_data_payload_ptr(v);
		for (at = 0; at < count; at++) {
			memcpy(p, sealed[at], sealed_len[at]);
			p += sealed_len[at];
		}
	}

	*out_len = need;
	return FZN_MSG_OK;
}

fzn_msg_err_t fzn_msg_data_parse(const uint8_t *bytes, size_t len, uint32_t *out_transfer,
                                 uint64_t *out_first, uint64_t *out_count,
                                 const uint8_t **out_proof, unsigned *out_proof_count,
                                 const uint8_t **out_sealed, size_t *out_sealed_len, size_t cap)
{
	fzn_msg_err_t err;
	uint64_t first, count;
	unsigned proof_count;
	size_t at, need, body;
	const uint8_t *p;

	situ_msg_t m;
	situ_view_t v;

	if (!out_transfer || !out_first || !out_count || !out_proof || !out_proof_count ||
	    !out_sealed || !out_sealed_len)
		return FZN_MSG_ERR_MALFORMED;
	err = check_header(bytes, len, FZN_MSG_DATA_OFF_PROOF, FZN_MSG_DATA);
	if (err != FZN_MSG_OK)
		return err;
	if (len > UINT32_MAX)
		return FZN_MSG_ERR_TOO_LARGE;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)bytes, (uint32_t)len);
	if (fzn_message_wire_fzn_msg_data_view(&m, 0u, (uint32_t)len, &v) != SITU_OK)
		return FZN_MSG_ERR_MALFORMED;

	count = fzn_message_wire_fzn_msg_data_count_get(v);
	if (count == 0u)
		return FZN_MSG_ERR_EMPTY;
	if (count > FZN_MSG_MAX_SPAN)
		return FZN_MSG_ERR_TOO_LARGE;
	if (count > cap)
		return FZN_MSG_ERR_TOO_LARGE;

	first = fzn_message_wire_fzn_msg_data_first_get(v);
	if (first > FZN_SPOOL_MAX_LEAVES || count > FZN_SPOOL_MAX_LEAVES - first)
		return FZN_MSG_ERR_MALFORMED;

	proof_count = fzn_message_wire_fzn_msg_data_proof_count_get(v);
	if (proof_count > FZN_MSG_MAX_PROOF)
		return FZN_MSG_ERR_TOO_LARGE;

	/* The fixed part: header, proof, and the length table. Checked before
	 * a single length is read out of it. */
	need = FZN_MSG_DATA_OFF_PROOF + (size_t)proof_count * FZN_BLOB_HASH_LEN +
	       (size_t)count * 4u;
	if (len < need)
		return FZN_MSG_ERR_MALFORMED;

	body = 0;
	for (at = 0; at < count; at++) {
		uint32_t one = fzn_message_wire_fzn_msg_data_leaf_len_get(v, (uint32_t)at);

		if (one == 0u)
			return FZN_MSG_ERR_MALFORMED;
		/* Against what is LEFT rather than against a running total, so
		 * the check cannot be defeated by a sum that wraps.
		 *
		 * REDUNDANT ON THIS MACHINE AND NOT ON EVERY MACHINE, measured
		 * rather than assumed: `count` is at most 64 and each length
		 * at most 2^32-1, so the sum reaches 2^38 and cannot wrap a
		 * 64-bit `size_t` -- the exact-length comparison below would
		 * catch anything this misses. On a 32-bit target, which this
		 * library is meant to run on, 64 lengths of 2^32-1 wrap to a
		 * small total that compares equal to a short message, and this
		 * is then the only thing standing between a peer's arithmetic
		 * and a read past the buffer. It is kept for the target that
		 * needs it, and a sabotage of it is caught on x86-64 by the
		 * comparison below rather than by this line. */
		if ((size_t)one > len - need - body)
			return FZN_MSG_ERR_MALFORMED;
		body += one;
	}
	/* Exact. Trailing bytes past the last leaf are a message this decoder
	 * does not understand. */
	if (len != need + body)
		return FZN_MSG_ERR_MALFORMED;

	p = fzn_message_wire_fzn_msg_data_payload_ptr(v);
	for (at = 0; at < count; at++) {
		out_sealed_len[at] = fzn_message_wire_fzn_msg_data_leaf_len_get(v, (uint32_t)at);
		out_sealed[at] = p;
		p += out_sealed_len[at];
	}

	*out_transfer = fzn_message_wire_fzn_msg_data_transfer_get(v);
	*out_first = first;
	*out_count = count;
	*out_proof = proof_count > 0u ? bytes + FZN_MSG_DATA_OFF_PROOF : NULL;
	*out_proof_count = proof_count;
	return FZN_MSG_OK;
}
