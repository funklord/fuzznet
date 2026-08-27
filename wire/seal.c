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
	/* EXACTLY THE FRAME, AND NOTHING AFTER IT.
	 *
	 * `validate` answers whether the bytes are a frame; it does not answer
	 * whether they are ONLY a frame. Nothing else here could: the tag
	 * covers `head` and the sealed region and stops at the tag, so bytes
	 * appended after it are outside every span this file computes and the
	 * AEAD verifies happily around them. Measured before this line: a valid
	 * 168-byte frame handed in as 232 bytes -- and at every size up to
	 * 168 + 4096 -- returned FZN_SEAL_OK with `payload_len` unchanged.
	 *
	 * The schema already says this, and says it somewhere that never
	 * reaches here: `wire/frame.situ` has `require canonical(fzn_frame)`,
	 * which situc checks at codegen time. A codegen-time proof that one
	 * encoding exists per value is worth nothing against a datagram if the
	 * runtime accepts a second encoding of the same frame, and an appended
	 * suffix is exactly that -- unlimited encodings, all of which open.
	 *
	 * The end is derived rather than recomputed: `tag_offset` is where the
	 * covered span stops, so the frame ends one tag later. Widened to
	 * size_t before the add, because `frame_len` is a size_t and both terms
	 * are uint32_t. `validate` has already proved the tag lies inside the
	 * view, so the sum cannot exceed `frame_len` and this can only catch a
	 * buffer that is too LONG -- a short one was refused above. */
	if (frame_len != (size_t)situ_fzn_frame_tag_offset(*fv) + SITU_FZN_FRAME_TAG_COUNT)
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

	/* THE THREE GUARDS BELOW CANNOT FIRE FOR A FRAME THAT REACHED HERE, and
	 * that is established rather than assumed -- `make coverage` reports
	 * them as never taken, and an unreachable guard and an untested one
	 * look identical from a percentage.
	 *
	 * Every path into this point has passed `situ_fzn_frame_validate`,
	 * whose last act is `situ_in_bounds(view, situ_fzn_frame_tag_offset(
	 * view), 16u)`. So the tag is known to lie inside the frame, which is
	 * exactly the precondition `tag_covered` and `tag_ptr` test for. And
	 * the contract states the covered span as "authenticated head ...
	 * sealed ...", so it contains the head by construction and cannot be
	 * shorter than it.
	 *
	 * They stay anyway, and the reason is not superstition: they are the
	 * boundary between this file's reasoning and the generated code's, and
	 * what they refuse to assume is that `validate` and `tag_covered`
	 * agree. That is a claim about situ rather than about a frame, and the
	 * day it stops holding -- a schema change, a codegen change, a
	 * regenerate somebody did not run the suite after -- this file returns
	 * SHAPE instead of computing an AEAD span from numbers that disagree.
	 *
	 * So: uncovered on purpose, provably unreachable today, and cheap. If a
	 * future reader is hunting the last few branches in this file, these
	 * are three of them and they are not worth the fixture it would take to
	 * force them. */
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

	/* `aead->seal` as well as `aead`, which `fzn_seal_open` and
	 * `fzn_seal_close` both do and this did not. Without it the null was
	 * met by `fzn_seal_close` at the very end, long past the memset, so a
	 * caller got MALFORMED with 152 bytes of their buffer already gone --
	 * breaking the promise this function makes twenty lines below about
	 * leaving the buffer untouched when it cannot proceed. */
	if (!frame || !frame_len || !what || !what->sender || !what->capability || !key ||
	    !commitment || !rng || !aead || !aead->seal)
		return FZN_SEAL_ERR_MALFORMED;
	if (!what->payload && what->payload_len != 0)
		return FZN_SEAL_ERR_MALFORMED;
	/* THE HOP BUDGET, BOUNDED BY WHAT THIS LIBRARY WOULD FORWARD.
	 *
	 * `fzn_relay_budget` clamps a claimed budget to the host's ceiling at
	 * the first honest host, so a frame built claiming 200 hops travels the
	 * same distance as one claiming 8 -- and the caller that asked for 200
	 * has no way to learn that. Refused rather than clamped for the reason
	 * `chunk/split.c` gives about payload bytes: clamping leaves a caller
	 * believing in something that did not happen.
	 *
	 * Here rather than lower down, with the other argument checks, so that
	 * a refusal leaves the buffer untouched -- the promise this function
	 * makes below, and the one the payload bound was moved up to keep. */
	if (what->hops > FZN_RELAY_MAX_HOPS)
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
	/* AND THE OTHER THREE HEADER RULES, FOR THE SAME REASON.
	 *
	 * The payload bound above was moved here so that a refusal leaves the
	 * caller's buffer untouched. `kind`, `chunks` and `index` are equally
	 * knowable before anything is written and were not moved with it, so
	 * they were caught only by `fzn_seal_close` -- after the `memset` below
	 * and after the interior had been copied in. Measured with the buffer
	 * prefilled 0xEE, each of them returned an error having modified 152
	 * bytes, where the payload bound modified none.
	 *
	 * Wiping on that path (which this function now also does) stops the
	 * capability being left in clear, but it does not restore the promise:
	 * a caller reusing one buffer across frames still loses the previous
	 * one. Checking first is what keeps it. The wipe stays for the case
	 * that genuinely cannot be pre-checked, since `fzn_seal_close` reaches
	 * the schema's validator over bytes only it has assembled.
	 *
	 * BORROWING THE SCHEMA'S OWN PREDICATES rather than restating them.
	 * `situ_fzn_kind_is_known` moves when the enum does, and the index rule
	 * is copied verbatim from the generated validator including its
	 * widening to int64_t -- which is load-bearing rather than stylistic:
	 * `chunks - 1` in uint16_t wraps to 65535 for a `chunks` of zero and
	 * would admit every index. Widened, a zero `chunks` gives -1 and
	 * refuses every index, which is how the zero case falls out of the
	 * index rule instead of needing one of its own. */
	if (!situ_fzn_kind_is_known((situ_fzn_kind_t)what->kind))
		return FZN_SEAL_ERR_SHAPE;
	if ((int64_t)what->index > (int64_t)what->chunks - 1)
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

	/* THESE THREE ARE UNREACHABLE TOO, for a different reason from the ones
	 * in the open path: there the frame came from a stranger and had been
	 * validated, here it was sized by the line above. `total` is
	 * FZN_SEAL_OVERHEAD plus a payload already bounded against the schema's
	 * own maximum, and `frame_cap` was checked against `total` -- so a view
	 * over exactly `total` bytes cannot fail for want of room, and neither
	 * can the hop or head views nested inside it.
	 *
	 * Kept for the same reason: they are where this file stops assuming the
	 * generated code agrees with the arithmetic above. A wrong answer here
	 * would otherwise be a frame built over a view that does not describe
	 * it. */
	memset(frame, 0, total);
	situ_msg_init(&msg, frame, (uint32_t)total);
	if (situ_fzn_frame_view(&msg, 0, (uint32_t)total, &fv) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;
	if (situ_fzn_hop_view(&msg, 0, &hopv) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;
	if (situ_fzn_frame_head_view(fv, &hv) != SITU_OK)
		return FZN_SEAL_ERR_SHAPE;

	situ_fzn_hop_version_set(hopv, 1);
	/* THE BUDGET, WHICH NOTHING IN THIS LIBRARY WROTE UNTIL NOW. Every
	 * frame it could build carried zero here, so `fzn_relay_budget`
	 * answered 0 and `fzn_relay_spend` answered EXHAUSTED for every frame
	 * that had ever been built through the public API -- see
	 * `fzn_send.hops`, which documents what zero means now that it is a
	 * choice rather than the only possibility.
	 *
	 * The PLAIN setter, not a coverage-aware one, and that is the schema
	 * speaking rather than an oversight: `frame.situ` says
	 * `require no_tag_invalidation(fzn_frame.hop.hops_left)`, so situ
	 * generates no `situ_fzn_frame_hop_*_set` family for it at all. A
	 * relay must be able to decrement this byte without a key, so a setter
	 * that dirtied the tag would contradict the field's whole purpose. */
	situ_fzn_hop_hops_left_set(hopv, what->hops);

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
	 * cost time here; `wire/test/generated_test.c` records the first. */
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

		/* A REFUSAL HERE MUST NOT LEAVE THE INTERIOR AS PLAINTEXT.
		 *
		 * The capability and the payload were copied in above, in the
		 * clear, because sealing happens in place. Every shape refusal
		 * this function has now surfaces from `fzn_seal_close` -- the
		 * validate that used to sit above was removed as redundant, and
		 * it was, for the tag. It was not redundant for this.
		 *
		 * Measured before the wipe, with the buffer prefilled 0xEE: a
		 * `chunks` of zero, a `kind` outside the enum, an `index` past
		 * `chunks`, and a null `aead->seal` each returned an error with
		 * the 32-byte capability sitting verbatim at offset 0x60 and the
		 * payload after it, the tag all zeroes and `*frame_len` still 0.
		 * A caller reusing the buffer, or one that ignored the return,
		 * holds or transmits the capability in clear.
		 *
		 * project.md records this same class found and fixed for the
		 * nonce, and says there that "the reason it gives is not
		 * specific to the nonce, and neither is the harm". These four
		 * paths are what that sentence was pointing at, and the residue
		 * here is secret material rather than zeroes.
		 *
		 * The whole frame goes, not just the interior: nothing in it is
		 * usable after a refused build, and wiping a computed span is a
		 * bound to get wrong later. */
		if (err != FZN_SEAL_OK) {
			fzn_wipe(frame, total);
			return err;
		}
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
