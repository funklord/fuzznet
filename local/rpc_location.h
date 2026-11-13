#ifndef FZN_RPC_LOCATION_INTERNAL_H
#define FZN_RPC_LOCATION_INTERNAL_H

#include "rpc_types.h"

/*
 * location -- position fixes as a binary append stream (project.md sec 6).
 *
 * A log-type subsystem like log_relay and group chat history: the same
 * (origin, seq) append-only stream over append_log, with the same dedup,
 * high-water and catch-up behaviour. Two things make it the odd one out.
 *
 * BINARY, NOT TEXT
 *   It is the first log-type stream whose entries are binary. A fix packs
 *   into 17 bytes; the conventional text representations of the same data
 *   (NMEA sentences, decimal-degree strings) are several times larger and
 *   carry no more information. See project.md sec 12 -- this uses
 *   FZN_RPC_STREAM_BINARY_FIXED, which is not merely denser than encoded text
 *   but structurally simpler: no escaping, no parsing, no length prefix.
 *
 * THE CONTENT COMES FROM LOCAL HARDWARE
 *   Every other subsystem's stream content arrives from a peer. A fix comes
 *   from a GNSS receiver, so the host supplies it through a callback in the
 *   same style as fzn_rpc_storage_ops_t / fzn_rpc_log_ops_t / the entropy hook. The
 *   core must never learn whether a fix came from gpsd, a serial NMEA
 *   device, Android's location API, or a human dropping a pin on a map.
 *   Sampling that source is periodic work, which is why daemon/timer.h
 *   exists before this does.
 *
 * WHY NOT `presence`
 *   presence is relay-only and now-only by design (project.md sec 6). A
 *   location history is the point here -- a track is an ordinary
 *   append-only per-origin stream -- so this has a real retention half.
 *
 * PRIVACY IS NOT SOLVED HERE
 *   Location is the most sensitive data this project would ever carry, and
 *   per-peer precision degradation (city-level to one peer, exact to
 *   another) is still an open design question in project.md sec 13. The
 *   record below reserves FZN_RPC_LOCATION_FLAG_COARSE for it so that a
 *   degraded fix is distinguishable from a precise one on the wire and at
 *   rest, rather than that having to be retrofitted onto a format that
 *   cannot express it. Nothing degrades anything yet.
 */

/* Payload only -- append_log prepends the 8-byte seq, so the stored record
 * is FZN_RPC_LOCATION_RECORD_SIZE bytes. */
#define FZN_RPC_LOCATION_FIX_SIZE 19
#define FZN_RPC_LOCATION_RECORD_SIZE (8 + FZN_RPC_LOCATION_FIX_SIZE)

typedef struct fzn_rpc_location_fix {
	int32_t lat_e7;
	int32_t lon_e7;
	uint32_t utc_s;
	int16_t alt_m;
	uint8_t bearing; /* 0..254, step 360/255 deg */
	/* All three encoded, see fzn_rpc_location_acc_encode. acc_e == acc_n is
	 * the circular case; acc_v is meaningful only when has_alt. */
	uint8_t acc_e;
	uint8_t acc_n;
	uint8_t acc_v;
	/* Presence and privacy state as plain booleans. The packed flags byte
	 * is deliberately NOT a field here: with both, a caller could set one
	 * and not the other and encode/decode would disagree about the same
	 * fix. The byte is an encoding detail, so it lives only in the encoded
	 * form. */
	uint8_t has_alt;
	uint8_t has_bearing;
	uint8_t is_coarse;
} fzn_rpc_location_fix_t;

/*
 * Horizontal accuracy is stored log-scaled: a receiver reporting 8m versus
 * 9m is not a distinction worth a byte's worth of linear range, while the
 * useful range spans 1m (good) to several thousand metres (indoors, which
 * must be representable so it can be discarded rather than believed).
 *
 * encode: metres -> byte, saturating. 0 metres and anything below 1 encode
 * as 0. decode: byte -> metres, rounded. Round-tripping is lossy by design,
 * within about 7% of the input.
 */
/*
 * Reserved code meaning "the receiver gave no estimate", distinct from any
 * real value. Without it, an unknown accuracy has to be faked as either 0
 * (claiming a metre, wildly optimistic) or a large number (which then reads
 * as a measurement, e.g. "+/-9728m", implying a precision that was never
 * reported). Neither is honest.
 *
 * 255 costs nothing real: it would otherwise decode to an absurd radius, so
 * no genuine estimate is lost. fzn_rpc_location_acc_encode saturates at 254 so a
 * real value can never collide with it.
 */
#define FZN_RPC_LOCATION_ACC_UNKNOWN 255

uint8_t fzn_rpc_location_acc_encode(uint32_t metres);
/* Returns 0 for FZN_RPC_LOCATION_ACC_UNKNOWN -- 0 metres is not a possible real
 * accuracy (code 0 already means "1 m or better"), so callers can treat 0 as
 * "unknown" without a second field. */
uint32_t fzn_rpc_location_acc_decode(uint8_t code);

/* Bearing in degrees (0..359) <-> stored byte. */
uint8_t fzn_rpc_location_bearing_encode(uint16_t degrees);
uint16_t fzn_rpc_location_bearing_decode(uint8_t code);

/* ---- the per-origin store (location_retention's half) ----
 *
 * Deliberately the same shape as log_relay's cache and group chat history:
 * ingest a batch keyed by (origin, seq), dedup against the high water mark,
 * evict oldest, answer catch-up queries. Nothing here is novel -- that is
 * the point of having generalised append_log first.
 *
 * The retention bound is larger than those two despite the same stack
 * budget, and that is the binary encoding paying for itself: a fix costs 25
 * bytes against a text line's several hundred, so 1024 fixes of scratch is
 * about half what group chat history spends on 100 lines. At a 30-second
 * sampling interval 1024 fixes is roughly eight hours of track.
 */
#define FZN_RPC_LOCATION_CACHE_MAX_ENTRIES 1024
/* One control-channel page, independent of and much smaller than the
 * retention bound -- matching how log_relay and group history separate
 * "what is kept" from "what one response carries". */
#define FZN_RPC_LOCATION_SHOW_PAGE_MAX 64

/* ---- location_relay: the peer-facing half ----
 *
 * The counterpart to log_relay, and structurally the same: a querier asks
 * "what do you have for this origin above this seq", the answerer replies
 * with a bounded batch of fixes, and the querier ingests them into its own
 * per-origin store where dedup makes re-delivery free.
 *
 * WHERE IT DIFFERS FROM log_relay, AND WHY IT MATTERS
 *   log_relay is siblings-only by deliberate design: a host's own log
 *   reveals detail about the user's other peers that a registered contact
 *   has no business seeing. Location is the opposite case -- the entire
 *   point is sharing it with peers ("find your friends"). That needs an
 *   authorization decision log_relay never had to make, and getting it
 *   wrong on the most sensitive data this project carries is worse than
 *   not having the feature.
 *
 *   So the wire below is complete and neutral, but SERVING is gated, and
 *   the gate currently permits siblings only -- the same trust domain
 *   log_relay already operates in, which needs no new model. Peer sharing
 *   is a deliberate follow-up, not an oversight: see geolocation.md.
 *
 * WHY THE PACKED RECORD IS USED HERE
 *   Unlike FZN_RPC_CMD_LOCATION's control-channel response, which spells fixes
 *   out as decoded fields for a frontend's convenience, the peer wire
 *   carries the 19-byte storage record verbatim. Compactness genuinely
 *   matters here (project.md sec 8's burst-radio budget), and both ends are
 *   fzp code that already owns the codec -- there is no third party to
 *   spare from knowing the layout.
 */

#endif /* FZN_RPC_LOCATION_INTERNAL_H */
