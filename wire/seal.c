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
	out->kind = situ_fzn_head_kind_get(hv);

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
