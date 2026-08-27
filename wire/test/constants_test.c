/* Every constant this library states twice, checked once.
 *
 * Four of the hand-written modules define the length of a field that
 * `wire/frame.situ` also defines, and until this file existed **nothing
 * compared them**. They agree today. Nothing made them keep agreeing, and
 * `FZN_NONCE_LEN`'s own comment says "which is what wire/frame.situ carries"
 * -- the C asserted the correspondence in prose and left it there.
 *
 * WHY THE DUPLICATION IS CORRECT and the fix is a check rather than an
 * include. These modules must not depend on the generated header: their
 * independence from the schema is what kept them buildable while sec 10
 * step 2 was blocked, and what lets a consumer take the replay window
 * without taking `situc`. So the numbers are repeated on purpose. What was
 * missing was anything to notice when a repetition stopped being a copy.
 *
 * WHAT DRIFT WOULD COST, because these are not cosmetic:
 *
 *   - `FZN_NONCE_LEN` is what `fzn_replay_admit` compares. The caller hands
 *     it a pointer into a frame, so a C constant larger than the wire field
 *     reads past that field -- and replay defence that compares the wrong
 *     bytes is the failure this library least wants to have quietly.
 *   - `FZN_SENDER_LEN` keys the reassembly slot. Drift means chunks are
 *     filed under a truncated or over-read key, which is the cross-sender
 *     splice `chunk/reassembly.c` exists to refuse.
 *   - `FZN_CAP_ID_LEN` is compared when a chain is verified against the
 *     capability a frame claims.
 *   - `FZN_COMMITMENT_LEN` is the committing half of the 48 bytes
 *     `session/commitment.c` splits, and sec 4.4a says key commitment is
 *     not optional.
 *
 * TWO INDEPENDENT WITNESSES, which is the point of the runtime half below.
 * The static asserts compare a C macro against a generated macro -- both
 * emitted from the schema, so a generator whose `_COUNT` disagreed with the
 * layout it actually produced would satisfy every one of them. The runtime
 * check measures the distance between two field pointers in a real frame,
 * which is the layout itself rather than a claim about it.
 *
 * `FZN_PUBKEY_LEN` and `FZN_SIG_LEN` are deliberately absent. The chain that
 * proves a capability is not carried in the frame at all -- `fzn_hop` is 5
 * bytes -- so there is no schema counterpart to check them against. An
 * assertion that cannot exist is worth distinguishing from one that is
 * missing, which is why they are named here rather than left out silently.
 */

#include "../../chain/chain.h"
#include "../../chunk/reassembly.h"
#include "../../chunk/split.h"
#include "../../frame/freshness.h"
#include "../../record/record.h"
#include "../../session/commitment.h"

#include "../seal.h"

#include "frame.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The four field lengths. */
_Static_assert(FZN_SENDER_LEN == SITU_FZN_HEAD_SENDER_COUNT,
                "chunk/reassembly.h's sender key and wire/frame.situ's sender[] differ");
_Static_assert(FZN_NONCE_LEN == SITU_FZN_HEAD_NONCE_COUNT,
                "frame/freshness.h's nonce and wire/frame.situ's nonce[] differ");
_Static_assert(FZN_COMMITMENT_LEN == SITU_FZN_HEAD_COMMITMENT_COUNT,
                "session/commitment.h's commitment and wire/frame.situ's commitment[] differ");
_Static_assert(FZN_CAP_ID_LEN == SITU_FZN_FRAME_SEALED_CAPABILITY_COUNT,
                "chain/chain.h's capability id and wire/frame.situ's capability[] differ");

/* The payload ceiling, moved here from chunk/test/agreement_test.c so that
 * every schema-versus-C constant is in one place. That file is about
 * BEHAVIOURAL agreement -- whether the reassembler enforces what the
 * relation says -- and a constant is a different question. */
_Static_assert(SITU_FZN_FRAME_SIZE_MAX - SITU_FZN_FRAME_SIZE_MIN == FZN_SPLIT_MAX_PAYLOAD,
                "chunk/split.h's payload ceiling and wire/frame.situ's [max] have diverged");

/* THE STREAM NAMESPACE HAS A BOUNDARY AND EVERY TEST STAYS BELOW IT.
 *
 * `FZN_STREAM_RESERVED` divides fuzznet's half from a consumer's. Nothing in
 * this library assigns a meaning below it yet, and the assertion is here so
 * that the day something does, a test using that number stops the build
 * rather than quietly meaning two things. */
_Static_assert(FZN_STREAM_RESERVED > 0u, "the reserved stream range is empty");

/* IDENTITIES THAT ARE THE SAME THING UNDER DIFFERENT NAMES.
 *
 * Found by a normalisation pass over the central types (project.md sec 5k),
 * which turned up four separate 32-byte constants and two 24-byte ones. Some
 * of those pairs are the same value by coincidence and must NOT be pinned
 * together; these two are the same THING, and nothing said so.
 *
 * A SENDER IS A HOST KEY. `chunk/reassembly.h` files a partial message under
 * `sender[FZN_SENDER_LEN]` and `chain/chain.h` grants to
 * `grantee[FZN_PUBKEY_LEN]`, and a receiver compares one against the other --
 * `wire/seal.c` hands `opened.sender` to reassembly while the chain names the
 * grantee, and the simulation compares them directly. If the two widths ever
 * parted, that comparison would read past one of them.
 *
 * THE FRAME'S NONCE IS BOTH NONCES. `frame.situ` says so in as many words:
 * "Replay defence and the AEAD nonce in one." So `FZN_NONCE_LEN` and
 * `FZN_AEAD_NONCE_LEN` are two names for one field, and a divergence would
 * have `fzn_replay_admit` comparing a different number of bytes than the AEAD
 * used -- the failure `constants_test.c`'s own header calls the one this
 * library least wants to have quietly.
 *
 * `FZN_CAP_ID_LEN` and `FZN_SUBJECT_LEN` are deliberately NOT pinned to
 * `FZN_PUBKEY_LEN`. Both are 32 today and neither is a key: a capability is
 * opaque bytes by sec 4.2, and a subject is opaque by sec 5. Asserting those
 * equal would pin a coincidence and make a later change look like a
 * regression. */
_Static_assert(FZN_SENDER_LEN == FZN_PUBKEY_LEN,
                "a frame's sender and a chain's grantee are compared, and differ in width");
_Static_assert(FZN_NONCE_LEN == FZN_AEAD_NONCE_LEN,
                "the replay nonce and the AEAD nonce are one field and differ in width");

/* And the claim `record/record.h` makes about a subject: 32 bytes "so that it
 * can hold a public key -- the common case is a statement about a host or a
 * user". A subject narrower than a key would make that false. */
_Static_assert(FZN_SUBJECT_LEN >= FZN_PUBKEY_LEN,
                "a subject cannot hold a public key, which record.h says it can");

/* THE TWO SPELLINGS OF "no expiry", which are now two headers' business.
 *
 * `chain/chain.h` and `frame/freshness.h` both need the name and neither
 * module may depend on the other, so each carries its own copy of the value
 * under its own module prefix and offers `FZN_NO_EXPIRY` as a guarded alias
 * for it. The prefixed pair is what is compared here.
 *
 * ASSERTING ON `FZN_NO_EXPIRY` COULD NOT DO IT, and the comment that used to
 * stand here argued that it could -- "the guard makes disagreement SILENT,
 * which is precisely the case worth catching ... chain.h comes first". That
 * reasoning is backwards, and chain.h coming first is what made it so: with
 * both headers defining the public name directly, the guard meant the second
 * header's definition never compiled, so this assertion only ever saw
 * chain.h's number and freshness.h's was witnessed by nothing. Measured
 * rather than reasoned about: with `frame/freshness.h`'s value set to 1u this
 * binary compiled clean, linked, and reported every check passing.
 *
 * A check whose comment argues it is not vacuous is worse than no check,
 * because it is the sentence that stops the next reader writing a real one.
 *
 * `FZN_CHAIN_NO_EXPIRY` and `FZN_FRESH_NO_EXPIRY` are both defined
 * unconditionally, so both are present here whatever the include order, and
 * the first line below fails if either moves. The second pins the value
 * itself; the third holds the public alias to it, since that is the name a
 * consumer writes and the wire format means zero by it. */
_Static_assert(FZN_CHAIN_NO_EXPIRY == FZN_FRESH_NO_EXPIRY,
                "chain.h's and freshness.h's 'no expiry' are different values");
_Static_assert(FZN_CHAIN_NO_EXPIRY == 0u,
                "FZN_CHAIN_NO_EXPIRY is not the zero the wire format means");
_Static_assert(FZN_NO_EXPIRY == FZN_CHAIN_NO_EXPIRY,
                "the public FZN_NO_EXPIRY is not the value its own header defines");

/* THE ADVERTISED OVERHEAD AGAINST THE SCHEMA'S OWN MINIMUM.
 *
 * `FZN_SEAL_OVERHEAD` is hand-written in seal.h and `fzn_seal_build` sizes
 * every frame with it. A frame carrying no payload IS the overhead, which is
 * what `SITU_FZN_FRAME_SIZE_MIN` states, so the two are the same number and
 * one of them is a copy.
 *
 * WHAT WAS THERE BEFORE COULD NOT FAIL. seal_test.c asked
 * `FZN_SEAL_OVERHEAD == 144u` under the message "the advertised overhead is
 * not the real one" -- a literal compared against a literal, insensitive to
 * every schema constant by construction. Demonstrated rather than argued:
 * a 4-byte field was added to `fzn_head`, the schema regenerated
 * consistently, and with `SITU_FZN_FRAME_SIZE_MIN` at 148 against an
 * unchanged `FZN_SEAL_OVERHEAD` of 144 that check still PASSED. Every frame
 * would have been sized four bytes short.
 *
 * The check moved here rather than being repaired in place, because this is
 * the file for a constant this library states twice, and leaving a second
 * copy of the question in seal_test.c would be the same duplication one rung
 * down.
 *
 * Prompted by fuzzypickles, who found the identical asymmetry in their own
 * tree on 2026-08-25 and described it exactly: the principle stated three
 * times and the discipline zero times. Worth acting on rather than agreeing
 * with. */
_Static_assert(FZN_SEAL_OVERHEAD == SITU_FZN_FRAME_SIZE_MIN,
                "seal.h's advertised overhead is not the schema's minimum frame");

/* THE SAME BOUND BY TWO ROADS, which is what makes either trustworthy.
 *
 * situ 35a6c30 began exporting a field's value bounds, so `length`'s maximum
 * is now stated directly as well as being derivable from the spread between
 * the smallest and largest frame. `wire/seal.c` uses the direct one and this
 * is what holds the derivation to it.
 *
 * It is not a tautology, and the case it catches is specific: the spread is
 * the payload bound ONLY because the payload is the sole variable-length
 * member. Add a fixed field to the head and `SITU_FZN_FRAME_SIZE_MIN` moves
 * while `..._LENGTH_VALUE_MAX` does not, so the two part company here rather
 * than in a sender that quietly stops accepting its largest payload. */
_Static_assert(SITU_FZN_HEAD_LENGTH_VALUE_MAX ==
                       SITU_FZN_FRAME_SIZE_MAX - SITU_FZN_FRAME_SIZE_MIN,
                "the length field's own bound and the frame's payload spread disagree");
_Static_assert(SITU_FZN_HEAD_LENGTH_VALUE_MAX == FZN_SPLIT_MAX_PAYLOAD,
                "chunk/split.h's payload ceiling and the schema's length bound disagree");

/* And the premise that line rests on: the spread between the smallest and
 * largest frame is the payload only because `payload[head.length]` is the
 * sole variable-length member. Spelled out so a new fixed field forces this
 * to be re-read and a new variable one breaks it. */
_Static_assert(SITU_FZN_FRAME_SIZE_MIN == SITU_FZN_HOP_SIZE_MAX + SITU_FZN_HEAD_SIZE_MAX +
                                                  SITU_FZN_FRAME_SEALED_CAPABILITY_COUNT +
                                                  SITU_FZN_FRAME_TAG_COUNT,
                "fzn_frame's fixed part no longer accounts for its minimum size");

/* THE PAYLOAD BOUND AGAINST THE PATH, which is what actually decides it.
 *
 * `frame.situ` calls `[max = 1024]` a placeholder wanting measurement against
 * netcfgd's largest chunk, and that is the wrong question: chunking means a
 * response's size sets the chunk COUNT, not the chunk size. What bounds a
 * chunk is the smallest path a datagram must cross whole, because fragmented
 * UDP is widely dropped and avoiding it is the reason this library chunks at
 * all.
 *
 * RFC 8200 requires every IPv6 link to carry 1280 bytes, so that is the floor
 * a self-contained frame has to fit under. Forty of IPv6 header and eight of
 * UDP leave 1232, against a largest frame of 1168 -- 64 bytes spare, which is
 * room for one extension header or a tunnel and is the margin worth keeping.
 *
 * The largest payload that would still fit is 1088. 1024 is under it
 * deliberately rather than accidentally, and this is the assertion that says
 * so: raise `[max]` past 1088 and a full frame stops fitting the smallest
 * link IPv6 guarantees, which is a decision to take deliberately rather than
 * discover from a router dropping traffic. */
#define FZN_IPV6_MIN_MTU     1280u
#define FZN_IPV6_UDP_HEADERS 48u

_Static_assert(SITU_FZN_FRAME_SIZE_MAX + FZN_IPV6_UDP_HEADERS <= FZN_IPV6_MIN_MTU,
                "a largest frame no longer fits the smallest link IPv6 guarantees");

/* THE ASSERT THAT USED TO BE HERE COULD NOT FAIL. It read
 *
 *     FZN_DERIVED_LEN == FZN_AEAD_KEY_LEN + FZN_COMMITMENT_LEN
 *
 * and `commitment.h:48` defines `FZN_DERIVED_LEN` as literally that sum, so
 * the two sides were the same expression twice. It sat in a file whose whole
 * purpose is that a repeated constant gets compared, under a comment saying
 * the derived block "is the key and the commitment and nothing else" -- so it
 * read as covering exactly the thing it could not have caught.
 *
 * That is this project's vacuous pass wearing the costume of rigour: a check
 * present where a reader would otherwise have written a real one.
 *
 * What is actually worth pinning is the half that is NOT internal. The key
 * length is a requirement of the AEAD, which exports no macro for it --
 * Monocypher's `crypto_aead_lock` takes 32 bytes and would take the address
 * of 32 bytes whatever this said -- so a shrunken constant here would hand it
 * a short buffer to read past. The commitment half is already pinned to the
 * schema at the top of this file, which leaves the key as the one unwitnessed
 * width in the derived block. */
_Static_assert(FZN_AEAD_KEY_LEN == 32u,
                "the AEAD key is no longer 32 bytes, which is what the AEAD reads "
                "regardless of what this constant says");

/* THE TAG WAS THE LAST FRAME FIELD WITH NO WITNESS. `wire/seal.c` hands
 * `situ_fzn_frame_tag_ptr(fv)` straight to `ops->seal` and `ops->open`, which
 * write and read FZN_AEAD_TAG_LEN bytes there. The tag is the frame's final
 * field, so a widened constant writes past the end of the frame -- and the
 * sum at SITU_FZN_FRAME_SIZE_MIN above stays green, because it uses the
 * schema's own count rather than the one the AEAD is being told. The test
 * stubs take the same macro, so they would agree with the bug. */
_Static_assert(FZN_AEAD_TAG_LEN == SITU_FZN_FRAME_TAG_COUNT,
                "the AEAD tag and the frame's tag field are different sizes, so "
                "sealing writes past the end of the frame");

/* THE ARRIVED-SET MUST COVER EVERY INDEX IT IS ASKED ABOUT.
 * `chunk/reassembly.c` indexes `slot->seen[index >> 3]` for index up to
 * FZN_REASM_MAX_CHUNKS - 1, while the array is sized
 * `FZN_REASM_MAX_CHUNKS / 8u` -- an integer division that TRUNCATES. Any
 * ceiling that is not a multiple of eight therefore gives a one-byte
 * out-of-bounds write inside `fzn_partial_t`.
 *
 * The top of the bitset is genuinely unexercised, though not as barely as
 * this comment first claimed. `chunk/test/split_test.c`'s `round_trip(1000,
 * 8, 0)` splits 1000 bytes at a cap of 8, which is 125 chunks and reaches
 * `seen[15]` of the 32 bytes. So half the array is written and the last byte
 * -- indices 248 to 255, where a ceiling that is not a multiple of eight
 * would do its damage -- is not. The first version of this said the largest
 * chunk counts in chunk/test were 4 and 9, which was taken from a report and
 * repeated without being checked.
 *
 * Comparing the array to the index range rather than checking `% 8u`, since
 * that is the property the code depends on and it stays correct if the array
 * is ever sized some other way. */
_Static_assert(sizeof(((fzn_partial_t *)0)->seen) * 8u >= FZN_REASM_MAX_CHUNKS,
                "the arrived-set has fewer bits than there are chunk indices, so "
                "the highest chunks write past it");

/* THE FAIL-CLOSED RULE MUST STAY THE ZERO VALUE. `frame/freshness.c` branches
 * on `kind == FZN_EXPIRY_OPTIONAL`, so REQUIRED -- the strict reading, which
 * refuses a command carrying no expiry -- is the default only because it is
 * first in the enumeration. Prepend an enumerator and a zeroed struct field
 * or a defaulted argument silently means OPTIONAL, which is the exact
 * inversion `freshness.h` says the rename existed to prevent. Every test
 * passes these by name, so every test would still pass. */
_Static_assert(FZN_EXPIRY_REQUIRED == 0u,
                "the fail-closed expiry rule is no longer the zero value, so a "
                "zeroed field now means OPTIONAL");
_Static_assert(FZN_EXPIRY_OPTIONAL == 1u, "the expiry kinds were renumbered");

/* THE WORKED EXAMPLES IN split.h AND reassembly.h ARE PROSE, and a consumer
 * sizes buffers from them. Both have been wrong before: split.h records that
 * its overhead figure was 96 once and "was instructing a caller into the bug
 * the paragraph above describes", and frame.situ records its payload ceiling
 * moving off a placeholder. Pinned here because this is the one file that
 * sees the constant and the schema together. */
_Static_assert(FZN_SEAL_OVERHEAD == 144u,
                "split.h's worked example (1500 - 28 - 144) no longer uses the "
                "real frame overhead");
_Static_assert((uint64_t)FZN_REASM_MAX_CHUNKS * FZN_SPLIT_MAX_PAYLOAD == 262144u,
                "reassembly.h's 256 KiB worked example is no longer what the "
                "constants come to");

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

int main(void)
{
	uint8_t frame[SITU_FZN_FRAME_SIZE_MIN];
	situ_msg_t msg;
	situ_view_t fv, hv;
	const uint8_t *nonce, *commitment;

	/* A minimum-size frame is enough: every field checked here is in the
	 * fixed part, and `length` is zero. */
	memset(frame, 0, sizeof(frame));
	frame[0] = 1; /* version, so validation would accept it */

	situ_msg_init(&msg, frame, sizeof(frame));
	check(situ_fzn_frame_view(&msg, 0, (uint32_t)sizeof(frame), &fv) == SITU_OK,
	      "no frame view over a minimum-size frame");
	check(situ_fzn_frame_head_view(fv, &hv) == SITU_OK, "no head view");

	nonce = situ_fzn_head_nonce_ptr(hv);
	commitment = situ_fzn_head_commitment_ptr(hv);

	/* THE INDEPENDENT WITNESS. `commitment` immediately follows `nonce` in
	 * the head, so the distance between them is how many bytes the nonce
	 * actually occupies -- measured from the layout rather than read off a
	 * macro the same generator emitted. This is the one check here that a
	 * generator could fail while satisfying every static assert above. */
	check(commitment > nonce, "commitment does not follow nonce -- the head was reordered");
	check((size_t)(commitment - nonce) == FZN_NONCE_LEN,
	      "the nonce's laid-out size is not FZN_NONCE_LEN, so the replay window "
	      "compares the wrong number of bytes");

	/* Both pointers must land inside the frame. A field accessor that
	 * returned something outside it would make the distance above
	 * meaningless, and meaningless arithmetic that happens to come to 24
	 * is exactly what this file is trying not to be. */
	check(nonce >= frame && nonce + FZN_NONCE_LEN <= frame + sizeof(frame),
	      "the nonce field does not lie within the frame");
	check(commitment >= frame && commitment + FZN_COMMITMENT_LEN <= frame + sizeof(frame),
	      "the commitment field does not lie within the frame");

	/* THE BIG-ENDIAN ACCESSORS, AND ONE OF THEM WAS CALLED NOWHERE.
	 *
	 * `wire/bytes.h` declares six. Five are exercised somewhere in the
	 * tree; `fzn_get_be32` was called by NO library source and NO test --
	 * grepped across every `.c`, not inferred. Its writer `fzn_put_be32`
	 * is used by `record/record.c` and asserted in `record_test`, so the
	 * pair was half covered: bytes went out and nothing ever read them
	 * back.
	 *
	 * That matters because these are PUBLIC. A consumer decoding a field
	 * this library encoded is exactly who calls the getter, and a reader
	 * that disagreed with the writer -- byte-swapped, or sign-extending --
	 * would produce wrong values in their tree and none in ours. The
	 * round trip is the assertion that binds the two halves; the literal
	 * is what makes it more than the two functions agreeing with each
	 * other, since a matched pair of wrong implementations round-trips
	 * perfectly. */
	{
		uint8_t be[8];
		static const uint8_t WANT32[4] = { 0xde, 0xad, 0xbe, 0xef };

		memset(be, 0, sizeof(be));
		fzn_put_be32(be, 0xdeadbeefu);
		check(memcmp(be, WANT32, sizeof(WANT32)) == 0,
		      "fzn_put_be32 did not write big-endian bytes");
		check(fzn_get_be32(be) == 0xdeadbeefu,
		      "fzn_get_be32 did not read back what fzn_put_be32 wrote");
		check(fzn_get_be32(WANT32) == 0xdeadbeefu,
		      "fzn_get_be32 disagrees with a literal big-endian encoding -- a "
		      "matched pair of wrong implementations round-trips perfectly, so "
		      "this is the check that is not just the two agreeing");

		fzn_put_be16(be, 0xbeefu);
		check(be[0] == 0xbeu && be[1] == 0xefu && fzn_get_be16(be) == 0xbeefu,
		      "the 16-bit pair does not round trip against a literal");
		fzn_put_be64(be, 0x0123456789abcdefull);
		check(be[0] == 0x01u && be[7] == 0xefu &&
		              fzn_get_be64(be) == 0x0123456789abcdefull,
		      "the 64-bit pair does not round trip against a literal");
	}

	printf("constants_test: %d checks, %d failure(s); %d constants pinned at compile time\n",
	       checks, failures, 24);
	return failures == 0 ? 0 : 1;
}
