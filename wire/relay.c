/* See relay.h. */

#include "relay.h"

#include "frame.h"

/* A view over the hop header alone. The budget lives before the authenticated
 * region, so reading it needs neither a key nor a verdict -- which is the
 * point: a relay handles frames it cannot open. */
static int hop_view(const uint8_t *frame, size_t frame_len, situ_msg_t *msg, situ_view_t *hv)
{
	if (!frame || frame_len > UINT32_MAX)
		return 0;
	/* A relay is handed whole datagrams by something that already sized
	 * them, but the hop header is what it reads, so the minimum it needs is
	 * the hop header rather than a whole frame. */
	if (frame_len < SITU_FZN_HOP_SIZE_MAX)
		return 0;

	situ_msg_init(msg, (uint8_t *)(uintptr_t)frame, (uint32_t)frame_len);
	return situ_fzn_hop_view(msg, 0, hv) == SITU_OK;
}

fzn_relay_err_t fzn_relay_budget(const uint8_t *frame, size_t frame_len, uint8_t allowed,
                                  uint8_t *out)
{
	situ_msg_t msg;
	situ_view_t hv;
	uint8_t claimed;

	if (!frame || !out)
		return FZN_RELAY_ERR_MALFORMED;
	if (!hop_view(frame, frame_len, &msg, &hv))
		return FZN_RELAY_ERR_SHAPE;
	/* The version is the one field of the hop header the schema pins, and
	 * a relay that forwarded an unknown version would be forwarding
	 * something it cannot reason about at all. */
	if (situ_fzn_hop_validate(hv) != SITU_OK)
		return FZN_RELAY_ERR_SHAPE;

	claimed = situ_fzn_hop_hops_left_get(hv);
	*out = claimed < allowed ? claimed : allowed;

	return FZN_RELAY_OK;
}

fzn_relay_err_t fzn_relay_spend(uint8_t *frame, size_t frame_len, uint8_t allowed)
{
	situ_msg_t msg;
	situ_view_t hv;
	uint8_t budget;
	fzn_relay_err_t err;

	err = fzn_relay_budget(frame, frame_len, allowed, &budget);
	if (err != FZN_RELAY_OK)
		return err;

	/* EXHAUSTED LEAVES THE FRAME ALONE. A caller that ignores the return
	 * value and forwards anyway sends exactly what it received, which is
	 * wrong but not amplifying. Writing zero here and refusing would be the
	 * same outcome with a corrupted frame. */
	if (budget == 0)
		return FZN_RELAY_ERR_EXHAUSTED;

	if (!hop_view(frame, frame_len, &msg, &hv))
		return FZN_RELAY_ERR_SHAPE;

	/* The clamped value goes back, not the claimed one: a frame that
	 * arrived claiming 255 leaves claiming at most `allowed` minus one, so
	 * an inflated budget is cut at the first honest host rather than
	 * surviving until the last. */
	situ_fzn_hop_hops_left_set(hv, (uint8_t)(budget - 1u));

	return FZN_RELAY_OK;
}

const char *fzn_relay_err_str(fzn_relay_err_t err)
{
	switch (err) {
	case FZN_RELAY_OK:
		return "ok";
	case FZN_RELAY_ERR_MALFORMED:
		return "malformed argument";
	case FZN_RELAY_ERR_SHAPE:
		return "not a frame this host can read";
	case FZN_RELAY_ERR_EXHAUSTED:
		return "hop budget spent";
	}

	return "unknown";
}
