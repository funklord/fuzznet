/* See seal.h. */

#include "seal.h"

#include "../constant_time/constant_time.h"

#include "frame.h"

#include <string.h>

/* The head's own view, and the frame's, established once. Returns non-zero
 * only when the frame is the shape the schema describes. */
static int views(uint8_t *frame, size_t frame_len, situ_msg_t *msg, situ_view_t *fv,
                 situ_view_t *hv)
{
	if (frame_len > UINT32_MAX)
		return 0;

	situ_msg_init(msg, frame, (uint32_t)frame_len);
	if (situ_fzn_frame_view(msg, 0, (uint32_t)frame_len, fv) != SITU_OK)
		return 0;
	/* The schema's own constraints -- version, a non-zero chunk count, an
	 * index inside it. Enforced here rather than restated, so that a
	 * change to frame.situ reaches this file by regeneration. */
	if (situ_fzn_frame_validate(*fv) != SITU_OK)
		return 0;
	return situ_fzn_frame_head_view(*fv, hv) == SITU_OK;
}

fzn_seal_err_t fzn_seal_open(uint8_t *frame, size_t frame_len,
                              const uint8_t key[FZN_AEAD_KEY_LEN],
                              const uint8_t commitment[FZN_COMMITMENT_LEN],
                              const fzn_aead_ops_t *aead, fzn_opened_t *out)
{
	situ_msg_t msg;
	situ_view_t fv, hv;
	situ_fzn_frame_sealed_t gate;
	uint32_t covered_at, covered_len;
	uint8_t *tag;
	int verified;

	if (!frame || !key || !commitment || !aead || !aead->open || !out)
		return FZN_SEAL_ERR_MALFORMED;

	memset(out, 0, sizeof(*out));

	if (!views(frame, frame_len, &msg, &fv, &hv))
		return FZN_SEAL_ERR_SHAPE;

	/* THE COMMITMENT FIRST, before a decryption is spent on a frame this
	 * key was never going to open. Constant time because it is compared
	 * against a value derived from the key: a timing oracle here would
	 * leak which key a receiver holds, which is the metadata the sealed
	 * capability was moved inside the seal to protect. */
	if (!fzn_ct_memeq(situ_fzn_head_commitment_ptr(hv), commitment, FZN_COMMITMENT_LEN))
		return FZN_SEAL_ERR_COMMITMENT;

	if (situ_fzn_frame_tag_covered(fv, &covered_at, &covered_len) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;
	tag = situ_fzn_frame_tag_ptr(fv);
	if (!tag)
		return FZN_SEAL_ERR_SHAPE;

	/* The head is authenticated and not encrypted; the sealed region is
	 * both. situ's covered span is head + sealed, so the sealed part is
	 * what remains after the head, and the AEAD's associated data is the
	 * head itself. Derived from the layout rather than from constants,
	 * which is the whole reason this file talks to the generated code. */
	{
		uint32_t head_len = SITU_FZN_HEAD_SIZE_FIXED;
		uint8_t *sealed_at;
		uint32_t sealed_len;

		if (covered_len < head_len)
			return FZN_SEAL_ERR_SHAPE;
		sealed_at = frame + covered_at + head_len;
		sealed_len = covered_len - head_len;

		verified = aead->open(aead->ctx, key, situ_fzn_head_nonce_ptr(hv),
		                      frame + covered_at, head_len, sealed_at, sealed_len, tag);
	}

	/* The gate refuses without this, which is the property the generated
	 * header exists to give: no accessor for the capability or the payload
	 * can be reached until the line above has said so. */
	if (situ_fzn_frame_sealed_open(fv, verified, &gate) != SITU_OK)
		return FZN_SEAL_ERR_TAG;

	out->capability = situ_fzn_frame_sealed_capability_ptr(gate);
	out->payload = situ_fzn_frame_sealed_payload_ptr(gate);
	out->payload_len = situ_fzn_frame_sealed_payload_len(gate);
	out->sender = situ_fzn_head_sender_ptr(hv);
	out->nonce = situ_fzn_head_nonce_ptr(hv);
	out->expires_at = situ_fzn_head_expires_at_get(hv);
	out->msg = situ_fzn_head_msg_get(hv);
	out->index = situ_fzn_head_index_get(hv);
	out->chunks = situ_fzn_head_chunks_get(hv);
	/* Cast explicit: the accessor returns the schema's enum and `kind` is a
	 * byte, which clang reports as a narrowing and gcc does not. The values
	 * are 0x00 to 0x03 so nothing is lost, and saying so in the source beats
	 * two compilers disagreeing about whether it is worth mentioning. */
	out->kind = (uint8_t)situ_fzn_head_kind_get(hv);

	return FZN_SEAL_OK;
}

fzn_seal_err_t fzn_seal_build(uint8_t *frame, size_t frame_cap, size_t *frame_len,
                               const fzn_send_t *what, const uint8_t key[FZN_AEAD_KEY_LEN],
                               const uint8_t commitment[FZN_COMMITMENT_LEN],
                               const fzn_random_ops_t *rng, const fzn_aead_ops_t *aead)
{
	situ_msg_t msg;
	situ_view_t fv, hv, hopv;
	situ_fzn_frame_sealed_t gate;
	uint8_t nonce[FZN_AEAD_NONCE_LEN];
	size_t total;

	if (!frame || !frame_len || !what || !what->sender || !what->capability || !key ||
	    !commitment || !rng || !aead)
		return FZN_SEAL_ERR_MALFORMED;
	if (!what->payload && what->payload_len != 0)
		return FZN_SEAL_ERR_MALFORMED;
	/* THE PAYLOAD BOUND, CHECKED BEFORE THE BUFFER IS TOUCHED.
	 *
	 * It used to read `> UINT16_MAX`, which only made the cast to `uint16_t`
	 * below safe and let anything up to 65535 through. The schema caps
	 * `length` at 1024, so a payload between those refused anyway -- but not
	 * until `situ_fzn_frame_sealed_open` further down, by which point the
	 * `memset` had already written 2144 bytes into the caller's buffer.
	 * Measured with a 2000-byte payload: the call returned
	 * FZN_SEAL_ERR_SHAPE having modified 2144 bytes it was refusing to fill.
	 *
	 * That contradicted this function's own promise a few lines below --
	 * that a refusal leaves the caller's buffer untouched, "so there is no
	 * half-built frame for anybody to send by mistake". The promise was
	 * written about the nonce and is true there; the reason it gives is not
	 * specific to the nonce, and neither is the harm. A caller reusing one
	 * buffer for successive frames lost the previous frame to a refusal.
	 *
	 * FROM THE SCHEMA'S OWN CONSTANT rather than a literal 1024, on the same
	 * reasoning as the validate call above: a change to frame.situ reaches
	 * this file by regeneration instead of by somebody remembering.
	 *
	 * This was `SITU_FZN_FRAME_SIZE_MAX - SITU_FZN_FRAME_SIZE_MIN` for a
	 * day, which is the same number by a longer road -- it is the payload
	 * bound only because the payload is the sole variable-length member.
	 * situ 35a6c30 exports the field's own bound, so the check now says what
	 * it means rather than deriving it. constants_test.c asserts the two
	 * agree, which is what would catch a new fixed field moving one and not
	 * the other.
	 *
	 * Refused rather than clamped, which is chunk/split.c's argument for the
	 * same decision: clamping would leave the caller believing it sent bytes
	 * that were dropped. */
	if (what->payload_len > (size_t)SITU_FZN_HEAD_LENGTH_VALUE_MAX)
		return FZN_SEAL_ERR_SHAPE;

	total = (size_t)FZN_SEAL_OVERHEAD + what->payload_len;
	if (frame_cap < total)
		return FZN_SEAL_ERR_CAPACITY;

	/* THE NONCE FIRST, and the frame is not begun until one exists. Doing
	 * it here rather than after the header is written means a source that
	 * cannot answer leaves the caller's buffer untouched, so there is no
	 * half-built frame for anybody to send by mistake. */
	if (!fzn_nonce_next(rng, nonce))
		return FZN_SEAL_ERR_NO_NONCE;

	memset(frame, 0, total);
	situ_msg_init(&msg, frame, (uint32_t)total);
	if (situ_fzn_frame_view(&msg, 0, (uint32_t)total, &fv) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;
	if (situ_fzn_hop_view(&msg, 0, &hopv) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;
	if (situ_fzn_frame_head_view(fv, &hv) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;

	situ_fzn_hop_version_set(hopv, 1);

	/* THROUGH THE COVERAGE-AWARE SETTERS, which take the message and mark
	 * the tag stale. The plain `situ_fzn_head_*_set` family would write
	 * the same bytes and leave the layout believing the tag still covered
	 * them -- the generated header says to prefer these, and the check
	 * after this block is what makes the preference visible.
	 *
	 * THEY TAKE THE FRAME VIEW, NOT THE HEAD VIEW, and the names do not say
	 * so: `situ_fzn_frame_head_kind_set` reads as "the head's kind" and its
	 * body writes `view.base[5]`, which is an offset from the FRAME. Handed
	 * `hv` they compile, run, and put every field five bytes late. That is
	 * what a type-correct wrong argument looks like -- both are
	 * `situ_view_t` -- and it is the second time this exact confusion has
	 * cost time here; `wire/tests/generated_test.c` records the first. */
	situ_fzn_frame_head_kind_set(&msg, fv, (situ_fzn_kind_t)what->kind);
	situ_fzn_frame_head_expires_at_set(&msg, fv, what->expires_at);
	situ_fzn_frame_head_msg_set(&msg, fv, what->msg);
	situ_fzn_frame_head_index_set(&msg, fv, what->index);
	situ_fzn_frame_head_chunks_set(&msg, fv, what->chunks);
	/* `length` before anything reads the sealed region: its extent is
	 * computed from this field, so writing it late would move the span the
	 * tag is taken over. */
	situ_fzn_frame_head_length_set(&msg, fv, (uint16_t)what->payload_len);

	memcpy(situ_fzn_head_sender_ptr(hv), what->sender, SITU_FZN_HEAD_SENDER_COUNT);
	memcpy(situ_fzn_head_nonce_ptr(hv), nonce, SITU_FZN_HEAD_NONCE_COUNT);
	memcpy(situ_fzn_head_commitment_ptr(hv), commitment, SITU_FZN_HEAD_COMMITMENT_COUNT);

	/* The header is written, so the layout must consider the tag stale. If
	 * it does not, the setters above were not the coverage-aware ones and
	 * a later `finalize` would be clearing a bit nothing had set. */
	if (!situ_fzn_frame_tag_is_dirty(&msg))
		return FZN_SEAL_ERR_SHAPE;

	/* The sealed interior, as plaintext. The gate is opened with a verdict
	 * of `verified` here, and that is not the abuse it looks like: the
	 * gate exists to stop a RECEIVER addressing plaintext it has not
	 * authenticated, and a sender is the author of these bytes rather than
	 * a reader of somebody else's. */
	if (situ_fzn_frame_sealed_open(fv, 1, &gate) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;
	memcpy(situ_fzn_frame_sealed_capability_ptr(gate), what->capability,
	       SITU_FZN_FRAME_SEALED_CAPABILITY_COUNT);
	if (what->payload_len > 0)
		memcpy(situ_fzn_frame_sealed_payload_ptr(gate), what->payload, what->payload_len);

	/* NO VALIDATE CALL HERE, and its absence is deliberate. One stood in
	 * this spot with a comment about refusing a bad shape before the tag
	 * is spent -- and `fzn_seal_close` validates through the same
	 * `views()` helper before it seals, so the tag was never spent either
	 * way and removing this changed nothing a test could see. It was
	 * caught by sabotaging it and watching all 54 assertions still pass,
	 * which is the second piece of redundant defence this file has grown
	 * and removed. Duplicated checks read as thoroughness and cost a
	 * reader the time to work out which one is load-bearing. */
	{
		fzn_seal_err_t err = fzn_seal_close(frame, total, key, aead);

		if (err != FZN_SEAL_OK)
			return err;
	}

	*frame_len = total;
	return FZN_SEAL_OK;
}

fzn_seal_err_t fzn_seal_close(uint8_t *frame, size_t frame_len,
                               const uint8_t key[FZN_AEAD_KEY_LEN],
                               const fzn_aead_ops_t *aead)
{
	situ_msg_t msg;
	situ_view_t fv, hv;
	uint32_t covered_at, covered_len;
	uint8_t *tag;

	if (!frame || !key || !aead || !aead->seal)
		return FZN_SEAL_ERR_MALFORMED;

	if (!views(frame, frame_len, &msg, &fv, &hv))
		return FZN_SEAL_ERR_SHAPE;

	if (situ_fzn_frame_tag_covered(fv, &covered_at, &covered_len) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;
	tag = situ_fzn_frame_tag_ptr(fv);
	if (!tag)
		return FZN_SEAL_ERR_SHAPE;

	{
		uint32_t head_len = SITU_FZN_HEAD_SIZE_FIXED;

		if (covered_len < head_len)
			return FZN_SEAL_ERR_SHAPE;
		aead->seal(aead->ctx, key, situ_fzn_head_nonce_ptr(hv), frame + covered_at,
		           head_len, frame + covered_at + head_len, covered_len - head_len, tag);
	}

	/* The layout tracks whether the tag is stale; say it is not. A message
	 * whose dirty bit is set is one the generated code calls
	 * untransmittable, and nothing else here would have cleared it. */
	situ_fzn_frame_tag_finalize(&msg);
	return FZN_SEAL_OK;
}

/* See seal.h.
 *
 * NO `default:` LABEL, and that is the mechanism rather than an oversight.
 * `-Wswitch` -- which `-Wall` turns on -- warns about an enumerated switch
 * that omits a case only when there is no default, so leaving it out is what
 * makes the compiler notice a code added to fzn_seal_err_t and not rendered here. A
 * default would silence exactly the warning worth having and turn a new code
 * into a silent "unknown" in somebody's log.
 *
 * The fallback then lives after the switch, where it catches a value that is
 * not an enumerator at all -- which no amount of compiler help can rule out,
 * since the argument may have come from a cast or from the wire. */
const char *fzn_seal_err_str(fzn_seal_err_t err)
{
	switch (err) {
	case FZN_SEAL_OK:
		return "ok";
	case FZN_SEAL_ERR_MALFORMED:
		return "malformed argument";
	case FZN_SEAL_ERR_SHAPE:
		return "not the shape the schema describes";
	case FZN_SEAL_ERR_TAG:
		return "tag did not verify";
	case FZN_SEAL_ERR_COMMITMENT:
		return "key commitment mismatch";
	case FZN_SEAL_ERR_NO_NONCE:
		return "no nonce could be drawn";
	case FZN_SEAL_ERR_CAPACITY:
		return "caller buffer too small";
	}

	return "unknown";
}
