/* Opening and sealing a frame -- sec 10 step 2, and the first code here that
 * reads the wire.
 *
 * WHAT SITU CONTRIBUTES, and it is not what this library expected. The record
 * said this waited on "situ's sealed-region ABI" and that the calling
 * convention was still a guess. It is neither, and the convention is smaller
 * than the guess: the generated code never calls a codec at all. It gives
 *
 *   - `situ_fzn_frame_tag_covered()` -- the exact span the tag authenticates,
 *     computed from the layout rather than restated here;
 *   - `situ_fzn_frame_sealed_open(view, verified, &gate)` -- which refuses to
 *     produce an interior view unless `verified` is true, and every accessor
 *     for the capability and payload takes that gate as its argument.
 *
 * So the discipline situ enforces is ORDER: nothing can address the plaintext
 * before something has said the tag verified. This file is what says it, and
 * it is deliberately the only place in the library that may.
 *
 * THE ONE MODULE THAT DEPENDS ON THE GENERATED CODE. Every other source here
 * takes decoded fields from a caller and never sees a frame -- which is what
 * keeps them buildable, and shippable, without situ. That property is worth
 * more than the symmetry, so the dependency is confined to this file rather
 * than spread by having reassembly or freshness learn the layout.
 */

#ifndef FZN_SEAL_H
#define FZN_SEAL_H

#include "../session/aead.h"
#include "../session/commitment.h"
#include "../session/random.h"

/* For FZN_RELAY_MAX_HOPS. A sender now states a hop budget and this library
 * refuses one larger than it would itself forward -- see `fzn_send.hops`. */
#include "relay.h"

#include <stddef.h>
#include <stdint.h>

/* Bytes a frame costs before any payload. Stated here so a sender can size a
 * buffer without reading the schema, and checked against the generated layout
 * in wire/test/constants_test.c rather than trusted. */
#define FZN_SEAL_OVERHEAD 144u

typedef enum fzn_seal_err {
	FZN_SEAL_OK = 0,
	/* An argument this library cannot act on: a null pointer where one is
	 * required, a payload pointer absent with a non-zero length, or a hop
	 * budget past FZN_RELAY_MAX_HOPS. Distinct from ERR_SHAPE, which is
	 * about the bytes of a frame rather than about what a caller asked
	 * for. */
	FZN_SEAL_ERR_MALFORMED = -1,
	/* The frame is not the shape the schema describes -- too short, a bad
	 * version, an index past its own chunk count, or LONGER than the frame
	 * it contains. Refused before any cryptography, because a frame that is
	 * not a frame is not worth a decryption.
	 *
	 * SHORT AND OVER-LONG ARE ONE CODE AND NOT ONE FAULT, which is worth
	 * knowing when one of them is being diagnosed. A short buffer is a
	 * TRUNCATED datagram: bytes the sender wrote that did not arrive, which
	 * a network does by itself and which every check below notices because
	 * the missing bytes were authenticated. An over-long buffer is bytes
	 * the sender did NOT write and somebody else appended: the frame inside
	 * it is intact and its tag verifies, because the tag covers `head` and
	 * the sealed region and stops there, so no amount of cryptography would
	 * ever object to a suffix.
	 *
	 * `wire/frame.situ` says `require canonical(fzn_frame)`, which situc
	 * checks at codegen time and which never reached this C. Until this
	 * check existed a valid 168-byte frame handed in as 232 bytes -- and at
	 * every size up to 168 + 4096 -- returned FZN_SEAL_OK with
	 * `payload_len` unchanged. Anything keyed on the DATAGRAM rather than
	 * on the frame inside it -- a dedup cache, a forwarding relay, one
	 * capture compared against another -- then sees a single frame wearing
	 * as many identities as an attacker cares to append, at no cost and
	 * with no key. */
	FZN_SEAL_ERR_SHAPE = -2,
	/* The tag did not verify. Says nothing about who sent it or why: a
	 * forgery and a corrupted datagram are the same answer here. */
	FZN_SEAL_ERR_TAG = -3,
	/* The key-commitment in the header is not the one this commitment key
	 * derives FOR THIS FRAME'S NONCE. DISTINCT FROM A BAD TAG on purpose,
	 * and A VERDICT AN ATTACKER MAY CHOOSE -- fzn_seal_open() states both
	 * halves, and the second one governs what a consumer may do about it.
	 *
	 * It now answers one more question than it used to, and the widening is
	 * worth knowing when one is being diagnosed. Before the commitment
	 * depended on the nonce, this meant "a different key". It now also
	 * means "this commitment does not belong to this nonce" -- a frame
	 * whose head was spliced from two others, or one whose nonce was
	 * rewritten in flight. Both are the same answer here and neither is
	 * worth telling apart, because both are reached from unauthenticated
	 * bytes. */
	FZN_SEAL_ERR_COMMITMENT = -4,
	/* No nonce could be drawn. A refusal rather than a frame sealed under
	 * something predictable -- see session/random.h. */
	FZN_SEAL_ERR_NO_NONCE = -5,
	/* The caller's buffer is too small for the frame it asked for. */
	FZN_SEAL_ERR_CAPACITY = -6,
	/* The hash seam refused. NOT FZN_SEAL_ERR_COMMITMENT, and keeping the
	 * two apart is the whole reason this code exists.
	 *
	 * The commitment is derived rather than supplied on both paths now, so
	 * a hash that cannot answer is a LOCAL fault -- a seam wired to
	 * nothing, an implementation that has not been initialised -- and it
	 * fails on every frame rather than on one. Reported as a mismatch it
	 * would be indistinguishable from a peer whose key has moved, and the
	 * advice below is to act on the RATE: a broken hash produces a rate of
	 * one, which is exactly the shape that says the key really has moved.
	 * A consumer would then rekey against a healthy peer because its own
	 * hash was missing.
	 *
	 * A NULL `hash` or `hash->hash` is FZN_SEAL_ERR_MALFORMED instead, with
	 * the other absent arguments; this is for a seam that is present and
	 * answers no. Same split as FZN_SEAL_ERR_NO_NONCE against a null
	 * `rng`. */
	FZN_SEAL_ERR_HASH = -7,
} fzn_seal_err_t;

/* What opening a frame yields: pointers into the caller's own buffer, which
 * this library does not own and does not copy. Valid only while that buffer
 * is, and only after FZN_SEAL_OK. */
typedef struct fzn_opened {
	/* Bytes rather than `fzn_cap_id_t`, and the layering is the reason:
	 * `wire/` sits below `chain/` and never includes it, so the type
	 * cannot reach here without inverting that. It is also the right
	 * place to stop -- a capability becomes bytes on the wire
	 * deliberately, and a caller assigning a typed one must write
	 * `->b`, which is explicit rather than a silent conversion. */
	const uint8_t *capability; /* FZN_CAP_ID_LEN bytes */
	const uint8_t *payload;
	size_t payload_len;
	/* Decoded header fields the rest of the library takes as arguments,
	 * so that a caller need not learn the accessors to use them. */
	const uint8_t *sender; /* 32 bytes */
	const uint8_t *nonce;  /* FZN_AEAD_NONCE_LEN bytes */
	uint64_t expires_at;
	uint32_t msg;
	uint16_t index;
	uint16_t chunks;
	uint8_t kind;
} fzn_opened_t;

/* Open a frame in place. `frame` is decrypted where it lies, so the buffer
 * must be writable and the caller must treat it as consumed.
 *
 * THE ORDER IS THE POINT, and it is checked rather than described:
 *
 *   1. shape, from the schema's own validator;
 *   2. the commitment -- DERIVED HERE, from `commitment_key` and the nonce
 *      this frame arrived carrying, then compared against the frame's own
 *      field, before a decryption is spent;
 *   3. the tag, over exactly the span situ says it covers;
 *   4. only then the gate, and only then any plaintext.
 *
 * IT TAKES THE COMMITMENT KEY AND DERIVES, RATHER THAN TAKING A FINISHED
 * COMMITMENT, and there was no choice about that. `session/commitment.h`
 * made the frame's commitment a function of the commitment key AND THE
 * NONCE, because a commitment derived from long-lived material alone is a
 * per-pair constant sitting in a cleartext head beside `sender[32]` -- the
 * social graph, readable by anyone who forwards a datagram. A receiver
 * cannot produce that value before it has seen the frame: the nonce is IN
 * the frame. So the only argument a receiver can supply in advance is the
 * commitment key, and the derivation belongs here, where the nonce is.
 *
 * WHAT STEP 2 COSTS NOW, and it is a hash where it used to be a compare.
 * Measured through THIS call rather than assembled from its parts, because
 * the number a consumer needs is what one candidate key costs it. At -Os
 * against Monocypher's BLAKE2b and XChaCha20-Poly1305 on a 3.07 GHz Westmere
 * Xeon, minimum of five runs of fifty 2000-call batches -- the machine
 * carried a load average in the tens, so a mean would have been measuring
 * the other tenants and each figure is an UPPER BOUND:
 *
 *     refused at the commitment                            640 ns
 *     refused at the tag, 24-byte payload                 1840 ns
 *     refused at the tag, 1024-byte payload               2750 ns
 *     opened, 24-byte payload                             2310 ns
 *
 *     of the 640: fzn_commitment_for_nonce                  500 ns
 *                 fzn_commitment_check                       50 ns
 *                 shape, from the schema's validator          50 ns
 *
 * Each of the four includes one memcpy of the frame -- 44 ns at 24 bytes, 52
 * at 1024 -- since this call decrypts in place and a repeated measurement
 * needs a fresh copy. Net of it, a candidate key that is not the sender's
 * costs about 600 ns to reject, and what that avoids is the AEAD: 2100 ns at
 * the schema's 1024-byte maximum, 1200 ns on a 24-byte frame.
 *
 * SAY THE RATIO RATHER THAN "FAR CHEAPER", because anyone sizing a
 * candidate-key set needs the real number. A receiver with no commitment
 * step pays shape plus the AEAD, so the saving is about 3.6 times at the
 * largest payload and about 2.1 times on a small frame -- the AEAD's cost
 * falls with the payload and this one does not, so the ratio is bounded by
 * BLAKE2b over 72 fixed bytes against Poly1305 over the whole datagram.
 * Concretely: 100 candidate keys cost about 60 microseconds to decide a
 * frame is not yours, against about 215 microseconds of AEAD.
 *
 * THAT IS A GOOD TRADE AND IT IS NOT AN ORDER OF MAGNITUDE, which is what
 * this header used to imply by saying the step turned K verifications into
 * K compares. It turns K verifications into K hashes, and the factor is
 * between two and four. `session/commitment.h` carries the same arithmetic
 * in component form and reaches the same place from the other side.
 *
 * ADDRESSING BY DECRYPTION WITH A LARGE K IS NOW THE CONSUMER'S PROBLEM.
 * `wire/relay.h` calls the commitment the addressing mechanism, and it still
 * is -- but K candidate keys cost K hashes and K compares where they used to
 * cost K compares against a table a receiver could have INDEXED by the
 * commitment. That index is gone on purpose: a table keyed by a per-pair
 * constant is the proof that the constant identifies the pair, and an
 * observer's copy of it would have been no harder to build than ours.
 *
 * WHAT TO DO INSTEAD IS ALREADY STEP 2 OF sec 4.7: select on `sender`. It is
 * 32 bytes of the head, it is a per-peer constant, and indexing on it hides
 * nothing the frame does not already show to everyone on the path -- so the
 * privacy this change bought is not being handed back. That reduces K to the
 * keys held for one sender, which is usually one. Scanning every key a host
 * holds, on every datagram, was always the shape sec 4.7 step 2 was written
 * to discourage; it is merely more expensive now.
 *
 * AND THERE IS NO SECOND ENTRY POINT TAKING A FINISHED COMMITMENT, which was
 * considered and refused. The argument for one is real but small: a receiver
 * looping over candidates has already derived the winning key's commitment,
 * so this call derives it a second time -- one hash, about 500 ns, once per
 * ACCEPTED frame, against the 600 ns per candidate the scan costs anyway.
 * The argument against is that such a function cannot check that the
 * commitment it was handed belongs to the nonce in the frame it was handed,
 * which is the whole property this change exists to create. It would
 * accept a commitment cached per peer -- exactly the thing that must stop
 * existing -- and it would do so silently, on the good path, for the caller
 * who wrote the loop the fast way. One entry point that cannot be called
 * wrongly beats two, one of which reintroduces the defect.
 *
 * WHAT FZN_SEAL_ERR_COMMITMENT DOES NOT MEAN, AND THIS HEADER USED TO SAY THE
 * OPPOSITE. It said the difference was "between rotating a key and hunting an
 * attacker", which reads as an instruction to rotate. It is not one, and the
 * reason is the order above rather than anything about key management:
 * `commitment` is a PLAINTEXT header field compared BEFORE the AEAD runs, so
 * the verdict is reached entirely from bytes anybody on the path may rewrite.
 * Measured here with a call-counting stub: flipping one byte at frame offset
 * 0x49 turns FZN_SEAL_OK into this error with the AEAD never called.
 *
 * A consumer acting on a single one of these has therefore handed a stranger
 * a remote control -- one flipped byte per datagram and a healthy receiver
 * concludes its own key is wrong. project.md sec 4.7 states the corollary in
 * general, and it governs every pre-tag verdict rather than only this one:
 *
 *   - COUNT IT IN AGGREGATE AND ACT ON THE RATE, which is the only form the
 *     honest signal survives in. Mismatch on every frame from a peer means
 *     the key really has moved. Mismatch on one frame in a thousand means
 *     somebody is flipping bits, and no single frame can tell the two apart.
 *   - NEVER let one on its own trigger a rekey, evict a peer, or reach a
 *     sentence that names an identity. A verdict reached before the tag names
 *     nobody, because nothing it was reached from was authenticated.
 *
 * THE ORDER IS NOT WHAT WAS WRONG and does not move. Checking the commitment
 * first is what saves the decryptions; putting it below the tag would cost
 * exactly what it was put there to buy. What was wrong was the advice about
 * the answer.
 *
 * `frame_len` MUST BE THE FRAME EXACTLY. A buffer longer than the frame it
 * holds is refused as FZN_SEAL_ERR_SHAPE, and it has to be refused HERE
 * because nothing else can: the tag covers `head` and the sealed region and
 * stops there, so a suffix after the tag changes nothing any check below
 * looks at. See FZN_SEAL_ERR_SHAPE for what an appended suffix buys an
 * attacker, and for why an over-long buffer is a different fault from a short
 * one even though it is the same code.
 */
/* The sender a frame CLAIMS, before any key has been chosen.
 *
 * WHY THIS EXISTS: this header already tells a receiver what to do, and until
 * now the API could not do it. sec 4.7 step 2 is "select on `sender`", which
 * "reduces K to the keys held for one sender, which is usually one" -- and
 * `sender` arrived only in `fzn_opened_t`, which `fzn_seal_open` produces,
 * which needs the key. **The one field a receiver must have before choosing a
 * key was offered only after using one.** The alternative is trying every key
 * against every datagram, which is the shape step 2 exists to discourage.
 * Reported by fuzzypickles 2026-09-01, who had implemented the advice by
 * reading the plaintext head through the generated accessors -- correct, and
 * layout knowledge no consumer should need.
 *
 * IT IS A CLAIM AND NOT A FACT, which is the whole of the contract. The head
 * is plaintext, so anyone can write any sender into a frame. Nothing is
 * authenticated until `fzn_seal_open` verifies the tag.
 *
 *   - SAFE: choosing which key to try. A wrong claim costs one failed open.
 *   - NOT SAFE: anything that treats it as identity before the tag verifies
 *     -- logging it as the sender, rate-limiting by it, counting it, or any
 *     authorization question. `fzn_opened_t.sender` is the authenticated one
 *     and is the same bytes only when the frame was genuine.
 *
 * The frame is shape-checked exactly as `fzn_seal_open` checks it -- the
 * schema's own constraints and the no-trailing-bytes rule -- so a malformed
 * or suffixed frame is refused here too rather than yielding a pointer into
 * something that is not a frame.
 *
 * `*out` points INTO `frame` and is valid for as long as it is. */
fzn_seal_err_t fzn_seal_peek_sender(const uint8_t *frame, size_t frame_len,
                                     const uint8_t **out);

fzn_seal_err_t fzn_seal_open(uint8_t *frame, size_t frame_len,
                              const uint8_t key[FZN_AEAD_KEY_LEN],
                              const uint8_t commitment_key[FZN_COMMITMENT_KEY_LEN],
                              const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                              fzn_opened_t *out);

/* What a sender is putting into one frame. Everything here is the caller's
 * except the nonce, which is deliberately absent: `fzn_seal_build` draws it
 * from the entropy seam and refuses if it cannot, because a nonce a caller
 * supplied is a nonce a caller can repeat. See `session/random.h` for what
 * repeating one costs.
 *
 * THE COMMITMENT IS ABSENT FOR THE SAME REASON, ONE STEP ON. It is derived
 * from the nonce, so the only party that could compute it is the one holding
 * the nonce, and that is `fzn_seal_build` rather than anybody calling it.
 * A caller hands in the commitment KEY instead. */
/* WHAT A DATAGRAM IS FOR, hand-written so a consumer need not reach into
 * situ's output to fill `fzn_send_t.kind`.
 *
 * The generated `SITU_FZN_KIND_*` enumerators are the schema's and move with
 * it; sec 16 records that they are not the anchor a consumer should hold,
 * which is why `FZN_SEAL_OVERHEAD` is hand-written too. Without these a send
 * path could not name a kind without including the generated header, which
 * also costs the property that every module but `wire/` builds without situ.
 *
 * Held to the generated values by `_Static_assert` in `wire/seal.c`, which
 * has both -- so the two cannot drift, and the assert rather than this
 * comment is what says so. Reported by fuzzypickles 2026-09-01.
 *
 * A CLOSED SET: `fzn_head_validate` refuses anything else and adding a value
 * is a conversation rather than an edit -- `wire/frame.situ` says why, and it
 * is that two networks assigning 0x04 differently would each refuse the
 * other's traffic as malformed and neither would be wrong. */
#define FZN_KIND_NOP   0u
#define FZN_KIND_UNIT  1u
#define FZN_KIND_CHUNK 2u
#define FZN_KIND_ACK   3u

typedef struct fzn_send {
	const uint8_t *sender;     /* 32 bytes */
	const uint8_t *capability; /* FZN_CAP_ID_LEN, sealed rather than sent clear */
	const uint8_t *payload;
	size_t payload_len;
	uint64_t expires_at;
	uint32_t msg;
	uint16_t index;
	/* MUST BE AT LEAST 1, INCLUDING FOR A `unit` FRAME, so a zeroed
	 * struct is invalid rather than minimal.
	 *
	 * The schema bounds `index [max = chunks - 1]`, so `chunks = 0` has
	 * no legal index and `fzn_seal_build` refuses with
	 * FZN_SEAL_ERR_SHAPE. A one-piece message states `chunks = 1,
	 * index = 0` -- one shape on the wire rather than two, which the
	 * schema argues for and which costs exactly this.
	 *
	 * IT IS THE INVERSE OF `hops` BELOW AND THE CONTRAST IS THE POINT.
	 * Zero hops means "not offered for relaying", so the safest-looking
	 * initialisation is the safest behaviour. Zero chunks is simply
	 * invalid, so `memset` yields a struct that cannot be sent and an
	 * error naming no field. Reported by fuzzypickles 2026-09-01, who
	 * hit it building a send path and had nothing to act on. */
	uint16_t chunks;
	/* One of FZN_KIND_* above. */
	uint8_t kind;
	/* THE HOP BUDGET, and the first thing on the send path that has ever
	 * written one.
	 *
	 * `fzn_hop.hops_left` has been in every frame since the schema existed
	 * and until this field nothing in this library set it. `fzn_seal_build`
	 * memset the frame and wrote only `version`, so EVERY frame this
	 * library could build carried a budget of zero: `fzn_relay_budget`
	 * answered 0 and `fzn_relay_spend` answered FZN_RELAY_ERR_EXHAUSTED,
	 * for every frame, always. A consumer wanting a relayable frame had to
	 * poke `frame[1]` by hand -- exactly the raw-offset knowledge this
	 * header exists to spare it. It is also the mechanical reason the
	 * seal -> relay -> open round trip had never been written: it could
	 * not be written against the public API.
	 *
	 * ZERO MEANS THIS FRAME IS NOT OFFERED FOR RELAYING. The first host to
	 * receive it does not forward it. That is what a `memset` to zero
	 * leaves behind, and the coincidence is deliberate rather than
	 * convenient: relaying is opted INTO. A zero meaning FZN_RELAY_MAX_HOPS
	 * would turn every consumer written before this field existed into a
	 * traffic source without one of them changing a line, and it would do
	 * it by making the safest-looking initialisation the most expansive
	 * one.
	 *
	 * REFUSED ABOVE FZN_RELAY_MAX_HOPS, with FZN_SEAL_ERR_MALFORMED, before
	 * the buffer is touched. A frame claiming more hops than this library
	 * will forward states a reach the same library refuses on receipt --
	 * `fzn_relay_budget` clamps it at the first honest host -- so accepting
	 * it would leave the caller believing in a reach it does not have.
	 * Refused rather than clamped, on `chunk/split.c`'s argument for the
	 * same decision: clamping leaves a caller believing something was sent.
	 *
	 * AND IT IS A REQUEST RATHER THAN A GUARANTEE. The byte sits before the
	 * authenticated region, necessarily, because a relay decrements it --
	 * so anyone on the path may rewrite it, and `wire/relay.h` says what
	 * does and does not follow from that. A sender states a budget; it does
	 * not set one. */
	uint8_t hops;
} fzn_send_t;

/* Build one frame and seal it, which is the send path's whole order in one
 * call.
 *
 * THE ORDER IS HERE RATHER THAN IN A DOCUMENT, and that is the point. sec 4.7
 * states what a receiver must do and `frame/test/receive_fuzz.c` runs it;
 * the sender's order was never written down at all, and it has traps that a
 * consumer would meet one at a time:
 *
 *   1. **A fresh nonce per frame**, from the entropy seam, refusing if none
 *      can be had. Not per message -- per FRAME. Two chunks of one message
 *      sealed under one nonce is the same key-and-nonce reuse as two
 *      unrelated frames, and this is the trap a caller is likeliest to walk
 *      into, because "one message, one nonce" reads as tidy.
 *   2. **The commitment, derived from THAT nonce**, by
 *      `fzn_commitment_for_nonce`. After step 1, necessarily -- the nonce is
 *      an input -- and before the buffer is touched, so that a hash which
 *      refuses leaves the caller's buffer as it found it, exactly as a
 *      refused nonce draw does.
 *   3. **Every authenticated byte final before the tag.** The header is the
 *      AEAD's associated data, so a field written after sealing is a field
 *      the tag does not cover; `length` is worse still, since the sealed
 *      region's extent is computed from it and writing it late moves the
 *      span the tag was taken over.
 *   4. **The capability and the payload inside the seal**, written as
 *      plaintext and encrypted in place by the same call.
 *   5. **The hop budget, from `what->hops`**, which is the one header field
 *      the tag deliberately does NOT cover -- see `fzn_send.hops` and
 *      `wire/relay.h`. Written before the seal here, though nothing requires
 *      it to be: the whole point of the field's position is that changing it
 *      neither invalidates nor needs the tag. `wire/test/seal_test.c` asserts
 *      that property directly rather than restating it, by spending the
 *      entire budget between build and open and requiring the frame to still
 *      open with its payload and capability byte-identical.
 *
 * WHY STEP 2 IS HERE AND NOT IN THE CALLER, WHICH IS FORCED RATHER THAN
 * CHOSEN. This function draws the nonce itself, and it has to: a nonce a
 * caller supplied is a nonce a caller can repeat, and a repeated nonce under
 * one key is not a weaker seal but no seal at all plus the Poly1305 key --
 * see `fzn_send_t` and `session/random.h`. Since
 * `session/commitment.h` made the commitment a function of the nonce, NO
 * CALLER CAN COMPUTE THE COMMITMENT IN ADVANCE: the only party that knows
 * the nonce before the frame exists is this function. Those two properties
 * were in direct conflict while this took a finished `commitment` argument,
 * and the conflict is settled the only way it can be -- by handing the
 * commitment KEY in and deriving here.
 *
 * The argument list changed shape rather than only meaning, and that is
 * deliberate. A 32-byte commitment key where a 16-byte commitment used to go
 * is a silent 16-byte overread if a call site keeps compiling, because an
 * array parameter is a pointer and nothing checks the extent --
 * `fzn_commitment_derive_root` records the same hazard and answers it by
 * renaming. Here the added `hash` argument does it: every existing call site
 * fails to compile on the arity, which is the loud failure and the only one
 * available in C.
 *
 * `frame` receives the whole datagram and `*frame_len` its length. The buffer
 * must have room for FZN_SEAL_OVERHEAD + `payload_len`.
 */
fzn_seal_err_t fzn_seal_build(uint8_t *frame, size_t frame_cap, size_t *frame_len,
                               const fzn_send_t *what, const uint8_t key[FZN_AEAD_KEY_LEN],
                               const uint8_t commitment_key[FZN_COMMITMENT_KEY_LEN],
                               const fzn_hash_ops_t *hash, const fzn_random_ops_t *rng,
                               const fzn_aead_ops_t *aead);

/* Seal a frame whose header and plaintext a caller has already written.
 * Encrypts the sealed region in place and writes the tag where the layout
 * puts it, which is not immediately after the ciphertext. */
fzn_seal_err_t fzn_seal_close(uint8_t *frame, size_t frame_len,
                               const uint8_t key[FZN_AEAD_KEY_LEN],
                               const fzn_aead_ops_t *aead);

/* A short name for `fzn_seal_err_t`, for a log line or a message to a user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check.
 * An unrecognised value renders as "unknown", which is deliberately not any
 * real code's text -- a caller that cannot tell "we do not know" from a
 * genuine answer is the failure this whole library is careful about
 * elsewhere.
 *
 * The strings are lowercase, carry no trailing punctuation and name the
 * condition rather than restating the constant, on the same reasoning as
 * strerror: the caller supplies the sentence, this supplies the noun. */
const char *fzn_seal_err_str(fzn_seal_err_t err);

#endif /* FZN_SEAL_H */
