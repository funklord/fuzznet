/* The receive sequence run in order -- sec 4.7, and sec 350.
 *
 * WHAT THIS SUITE IS FOR is the two properties only the ORCHESTRATOR can get
 * wrong. Each module already tests itself; what nothing tested until now is
 * the sequence.
 *
 *   1. EACH STEP REFUSES AT ITS OWN PLACE, with its own module's error and a
 *      vocabulary that says which module that was.
 *   2. A REFUSAL AT ANY STEP COSTS NO SLOT AT A LATER ONE. sec 4.7 states it
 *      as a rule that is not an ordering, and it is the one an implementation
 *      silently breaks: replay is the first mutation, so any refusal above it
 *      must leave the window untouched.
 *
 * THE SECOND IS TESTED BEHAVIOURALLY RATHER THAN BY COUNTING. After each
 * early refusal the suite runs the GENUINE frame -- same nonce -- and
 * requires it admitted. If the refusal had taken a replay slot for that
 * nonce, the genuine frame would come back refused at REPLAY, which is
 * exactly the failure the rule exists to prevent and is invisible to a
 * counter that nobody thought to read.
 *
 * STUB AEAD, HASH AND SIGNER, as `wire/test/seal_test.c` and
 * `chain/test/chain_test.c` do: what is under test is the order, not the
 * cryptography, and a stub makes every case reproducible from this source
 * alone.
 */

#include "../admit.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL sequence_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* ---- the stubs ------------------------------------------------------- */

static void stub_tag(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, const uint8_t *text, size_t text_len,
                     uint8_t out[FZN_AEAD_TAG_LEN])
{
	uint8_t acc[FZN_AEAD_TAG_LEN];
	size_t i;

	memset(acc, 0, sizeof(acc));
	for (i = 0; i < FZN_AEAD_KEY_LEN; i++)
		acc[i % FZN_AEAD_TAG_LEN] =
		        (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] * 31u + key[i] + (uint8_t)i);
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++)
		acc[i % FZN_AEAD_TAG_LEN] = (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] + nonce[i]);
	for (i = 0; i < aad_len; i++)
		acc[i % FZN_AEAD_TAG_LEN] = (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] * 31u + aad[i]);
	for (i = 0; i < text_len; i++)
		acc[i % FZN_AEAD_TAG_LEN] = (uint8_t)(acc[i % FZN_AEAD_TAG_LEN] * 17u + text[i]);
	memcpy(out, acc, FZN_AEAD_TAG_LEN);
}

static int stub_seal(void *ctx, const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len, uint8_t *text,
                     size_t text_len, uint8_t *tag)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	stub_tag(key, nonce, aad, aad_len, text, text_len, tag);
	return 1;
}

static int stub_open(void *ctx, const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len, uint8_t *text,
                     size_t text_len, const uint8_t *tag)
{
	uint8_t want[FZN_AEAD_TAG_LEN];
	size_t i;

	(void)ctx;
	stub_tag(key, nonce, aad, aad_len, text, text_len, want);
	/* Verify before writing, which is the contract. */
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	for (i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	return 1;
}

/* FNV-1a, and the first draft was a one-byte `acc = acc * 31 + in[i]` which
 * COULD NOT TELL TWO KEYS APART. 31^8 == 1 (mod 256), so over a 32-byte
 * constant input the key's coefficients sum to zero and the accumulator ends
 * where it started whatever the key was -- two different commitment keys
 * derived the same commitment, and the commitment step could not refuse.
 *
 * The suite reported it as the frame being ADMITTED with a stranger's key,
 * which read as a defect in `fzn_admit` and was a defect in its stand-in. A
 * stub models the half of a primitive its author happened to need, and what
 * this one needed was the half it did not have: the ability to DIFFER. */
static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                     size_t in_len)
{
	size_t i;
	uint32_t acc = 0x811c9dc5u;

	(void)ctx;
	for (i = 0; i < in_len; i++) {
		acc ^= in[i];
		acc *= 16777619u;
	}
	for (i = 0; i < out_len; i++) {
		acc ^= (uint32_t)i + 0x9e3779b9u;
		acc *= 16777619u;
		out[i] = (uint8_t)(acc >> 24);
	}
	return 1;
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg,
                     size_t msg_len)
{
	(void)ctx;
	return stub_hash(NULL, sig, FZN_SIG_LEN, msg, msg_len);
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	(void)pubkey;
	stub_hash(NULL, want, sizeof(want), msg, msg_len);
	return memcmp(want, sig, sizeof(want)) == 0;
}

/* A signer that signs and CANNOT VERIFY. It exists so the memo case has a
 * fixture where the plausible wrong answer and the right one differ: with it
 * installed, a real chain verification must fail, so a frame that is still
 * admitted was admitted BY THE MEMO and by nothing else. Asserting only that
 * the second frame is admitted would pass against a memo that never hits. */
static int never_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[FZN_SIG_LEN])
{
	(void)ctx;
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	return 0;
}

static fzn_hash_ops_t hash = { stub_hash, NULL };
static fzn_aead_ops_t aead = { stub_seal, stub_open, NULL };
static fzn_sign_ops_t sign = { stub_verify, stub_sign, NULL };
static fzn_sign_ops_t broken_sign = { never_verify, stub_sign, NULL };

/* ---- the fixture ------------------------------------------------------ */

#define OFF_VERSION 0x00
#define OFF_KIND    0x05
#define OFF_SENDER  0x06
#define OFF_EXPIRES 0x26
#define OFF_NONCE   0x2e
#define OFF_COMMIT  0x46
#define OFF_MSG     0x56
#define OFF_INDEX   0x5a
#define OFF_CHUNKS  0x5c
#define OFF_LENGTH  0x5e
#define OFF_CAP     0x60
#define OFF_PAYLOAD 0x80
#define FRAME_MIN   144
#define PAYLOAD_LEN 24
#define FRAME_LEN   (FRAME_MIN + PAYLOAD_LEN)

#define NOW        1000u
#define EXPIRES    5000u
#define MAX_AHEAD  100000u

static uint8_t aead_key[FZN_AEAD_KEY_LEN];
static uint8_t commit_key[FZN_COMMITMENT_KEY_LEN];
static uint8_t SENDER[FZN_PUBKEY_LEN];
static uint8_t ROOT[FZN_PUBKEY_LEN];
static fzn_cap_id_t CAP;

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xffu);
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)((v >> 16) & 0xffu);
	p[2] = (uint8_t)((v >> 8) & 0xffu);
	p[3] = (uint8_t)(v & 0xffu);
}

static void build_sealed(uint8_t *f, const uint8_t *nonce, uint64_t expires)
{
	memset(f, 0, FRAME_LEN);
	f[OFF_VERSION] = 1;
	f[OFF_KIND] = 2; /* chunk */
	memcpy(f + OFF_SENDER, SENDER, 32);
	put_be32(f + OFF_EXPIRES + 4, (uint32_t)expires);
	memcpy(f + OFF_NONCE, nonce, 24);
	fzn_commitment_for_nonce(&hash, commit_key, f + OFF_NONCE, f + OFF_COMMIT);
	put_be32(f + OFF_MSG, 7);
	put_be16(f + OFF_INDEX, 0);
	put_be16(f + OFF_CHUNKS, 2);
	put_be16(f + OFF_LENGTH, PAYLOAD_LEN);
	memcpy(f + OFF_CAP, CAP.b, 32);
	memcpy(f + OFF_PAYLOAD, "twenty-four bytes here.", PAYLOAD_LEN);
	fzn_seal_close(f, FRAME_LEN, aead_key, &aead);
}

/* ---- the ops ---------------------------------------------------------- */

static int keys_known = 1;
static int root_known = 1;
static uint8_t serve_commit[FZN_COMMITMENT_KEY_LEN];
static uint8_t serve_aead[FZN_AEAD_KEY_LEN];

static size_t ops_keys(void *ctx, const uint8_t *sender, fzn_admit_key_t *out,
                       size_t out_cap)
{
	(void)ctx;
	(void)sender;
	if (!keys_known || out_cap == 0)
		return 0;
	memcpy(out[0].aead, serve_aead, sizeof(out[0].aead));
	memcpy(out[0].commitment, serve_commit, sizeof(out[0].commitment));
	return 1;
}

static fzn_expiry_rule_t ops_rule(void *ctx, uint8_t kind)
{
	(void)ctx;
	(void)kind;
	return FZN_EXPIRY_OPTIONAL;
}

static int ops_root(void *ctx, const uint8_t *sender, uint8_t out[FZN_PUBKEY_LEN])
{
	(void)ctx;
	(void)sender;
	if (!root_known)
		return 0;
	memcpy(out, ROOT, FZN_PUBKEY_LEN);
	return 1;
}

static fzn_admit_ops_t ops = { NULL, ops_keys, ops_rule, ops_root };

/* ---- the environment -------------------------------------------------- */

static fzn_replay_entry_t replay_entries[32];
static fzn_replay_window_t replay;
static fzn_chain_entry_t chain_entries[4];
static fzn_chain_store_t chains;
static fzn_partial_t partials[4];
static uint8_t partial_bufs[4][256];
static fzn_reasm_t reasm;
static fzn_revocation_t rev_entries[4];
static fzn_revocation_store_t revocations;
static fzn_chain_memo_entry_t memo_entries[4];
static fzn_chain_memo_t memo;

static void reset_state(void)
{
	size_t i;

	fzn_replay_init(&replay, replay_entries,
	                sizeof(replay_entries) / sizeof(replay_entries[0]),
	                MAX_AHEAD);
	/* SLOTS FIRST. `fzn_reasm_init` walks the array and refuses a slot
	 * with no buffer, and reassembly.h says so because a caller did it the
	 * other way and got MALFORMED from a table whose arguments were all
	 * fine. This suite was that caller a second time. */
	for (i = 0; i < sizeof(partials) / sizeof(partials[0]); i++)
		fzn_reasm_slot_init(&partials[i], partial_bufs[i],
		                    sizeof(partial_bufs[i]));
	fzn_reasm_init(&reasm, partials,
	               sizeof(partials) / sizeof(partials[0]), 2, MAX_AHEAD);
	fzn_revocation_store_init(&revocations, rev_entries,
	                          sizeof(rev_entries) / sizeof(rev_entries[0]));
	fzn_chain_memo_init(&memo, memo_entries,
	                    sizeof(memo_entries) / sizeof(memo_entries[0]));
	keys_known = 1;
	root_known = 1;
	memcpy(serve_aead, aead_key, sizeof(serve_aead));
	memcpy(serve_commit, commit_key, sizeof(serve_commit));
}

static fzn_admit_env_t env_for(fzn_reasm_t *table)
{
	fzn_admit_env_t env;

	memset(&env, 0, sizeof(env));
	env.ops = &ops;
	env.hash = &hash;
	env.aead = &aead;
	env.sign = &sign;
	env.replay = &replay;
	env.chains = &chains;
	env.revocations = NULL;
	env.manifest = NULL;
	env.reassembly = table;
	env.max_ahead = MAX_AHEAD;
	return env;
}

static fzn_admit_result_t run(uint8_t *frame, size_t len, fzn_reasm_t *table)
{
	fzn_admit_env_t env = env_for(table);
	fzn_admit_key_t candidates[2];
	fzn_admit_result_t r;

	fzn_admit(frame, len, NOW, &env, candidates, 2, &r);
	return r;
}

int main(void)
{
	static const uint8_t NONCE_A[24] = "nonce a, twenty-four by";
	uint8_t good[FRAME_LEN], work[FRAME_LEN];
	uint8_t hop_bytes[FZN_HOP_LEN];
	uint8_t chain_bytes[FZN_CHAIN_HEADER_LEN + FZN_HOP_LEN];
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	size_t hop_count = 0;
	fzn_admit_result_t r;

	memset(aead_key, 0x11, sizeof(aead_key));
	memset(commit_key, 0x22, sizeof(commit_key));
	memset(SENDER, 0xa1, sizeof(SENDER));
	memset(ROOT, 0xb2, sizeof(ROOT));
	memset(CAP.b, 0xc3, sizeof(CAP.b));

	/* One live chain: the root grants CAP to SENDER. */
	fzn_chain_store_init(&chains, chain_entries,
	                     sizeof(chain_entries) / sizeof(chain_entries[0]));
	CHECK(fzn_chain_mint(ROOT, SENDER, &CAP, 1, 0, 0, &sign, hop_bytes)
	          == FZN_CHAIN_OK, "the fixture chain would not mint");
	/* A chain is a CONTAINER -- version, hop count, then the hops -- and a
	 * bare hop is not one. The first draft handed `fzn_chain_open` the
	 * minted hop directly and it refused, correctly. */
	chain_bytes[0] = FZN_SIGNED_VERSION;
	chain_bytes[1] = 1;
	memcpy(chain_bytes + FZN_CHAIN_HEADER_LEN, hop_bytes, sizeof(hop_bytes));
	CHECK(fzn_chain_open(chain_bytes, sizeof(chain_bytes), hops, &hop_count)
	          == FZN_CHAIN_OK, "the fixture chain would not open");
	CHECK(fzn_chain_store_admit(&chains, hops, hop_count, ROOT, &CAP, NOW,
	                            &sign, NULL, NULL) == FZN_CHAIN_OK,
	      "the fixture chain was not admitted to the store");

	build_sealed(good, NONCE_A, EXPIRES);

	/* ---- THE POSITIVE CONTROL. Without it every refusal below is
	 * satisfied by a function that refuses everything. ---- */
	reset_state();
	memcpy(work, good, sizeof(work));
	r = run(work, sizeof(work), &reasm);
	CHECK(r.step == FZN_ADMIT_ADMITTED,
	      "a genuine frame was refused at %s (vocab %s, err %d)",
	      fzn_admit_step_str(r.step), fzn_admit_vocab_str(r.vocab), r.err);
	CHECK(r.vocab == FZN_ADMIT_VOCAB_NONE, "an admitted frame carried a vocabulary");
	CHECK(r.opened.payload_len == PAYLOAD_LEN, "the payload did not survive");

	/* ---- EACH STEP REFUSES AT ITS OWN PLACE, and the genuine frame is
	 * admitted afterwards with the SAME NONCE. That second half is the
	 * no-slot-cost rule: replay is the first mutation, so a refusal above
	 * it that took the nonce would show up here as the genuine frame
	 * coming back refused at REPLAY. ---- */
	/* `above_replay` says whether the refusal happens BEFORE step 6. The
	 * rule is DIRECTIONAL -- "a refusal at any step must not have cost a
	 * slot at a LATER one" -- so a step-7 refusal having taken a replay
	 * entry is correct, not a violation: the frame was genuine and fresh
	 * and the window is right to remember it. The first draft asserted it
	 * undirected and the CHAIN case failed for being right. */
#define REFUSES(setup, want_step, want_vocab, above_replay, what)             \
	do {                                                                 \
		fzn_admit_result_t rr, ok;                                   \
		reset_state();                                               \
		memcpy(work, good, sizeof(work));                            \
		setup;                                                       \
		rr = run(work, sizeof(work), &reasm);                        \
		CHECK(rr.step == (want_step),                                \
		      what " refused at %s, expected %s",                    \
		      fzn_admit_step_str(rr.step),                           \
		      fzn_admit_step_str(want_step));                        \
		CHECK(rr.vocab == (want_vocab),                              \
		      what " carried vocabulary %s",                         \
		      fzn_admit_vocab_str(rr.vocab));                        \
		CHECK(fzn_reasm_held_by(&reasm, SENDER) == 0,                \
		      what " left a partial message behind");                \
		keys_known = 1;                                              \
		root_known = 1;                                              \
		memcpy(serve_aead, aead_key, sizeof(serve_aead));            \
		memcpy(serve_commit, commit_key, sizeof(serve_commit));      \
		if (above_replay) {                                          \
			memcpy(work, good, sizeof(work));                    \
			ok = run(work, sizeof(work), &reasm);                \
			CHECK(ok.step == FZN_ADMIT_ADMITTED,                 \
			      what " cost the genuine frame its slot: %s",   \
			      fzn_admit_step_str(ok.step));                  \
		} else {                                                     \
			(void)ok;                                            \
		}                                                            \
	} while (0)

	/* A FLIPPED TAG BYTE, which reaches step 4 and fails there. It was
	 * labelled "1. SHAPE: a frame with bytes appended" and appended
	 * nothing -- the case was sound and the comment described a different
	 * case, so step 1 had no test at all while appearing to have one. */
	REFUSES(memset(work + FRAME_LEN - 1u, 0xff, 1),
	        FZN_ADMIT_TAG, FZN_ADMIT_VOCAB_SEAL, 1,
	        "a frame with a flipped tag byte");

	/* 1. SHAPE, for real: a frame handed in SHORT is not a frame, and is
	 * refused by the layout check before any key is chosen. */
	{
		fzn_admit_result_t rr;

		reset_state();
		memcpy(work, good, sizeof(work));
		rr = run(work, sizeof(work) - 1u, &reasm);
		CHECK(rr.step == FZN_ADMIT_SHAPE,
		      "a truncated frame refused at %s rather than shape",
		      fzn_admit_step_str(rr.step));
		CHECK(rr.vocab == FZN_ADMIT_VOCAB_SEAL,
		      "a truncated frame carried vocabulary %s",
		      fzn_admit_vocab_str(rr.vocab));
		/* And the genuine frame is still admitted afterwards: a shape
		 * refusal is five steps above the first mutation. */
		memcpy(work, good, sizeof(work));
		rr = run(work, sizeof(work), &reasm);
		CHECK(rr.step == FZN_ADMIT_ADMITTED,
		      "a shape refusal cost the genuine frame its slot: %s",
		      fzn_admit_step_str(rr.step));
	}

	/* 2. KEY SELECT: an unknown sender is a DROP, with no vocabulary --
	 * no module was reached, so there is no code to render. */
	REFUSES(keys_known = 0, FZN_ADMIT_KEY_SELECT,
	        FZN_ADMIT_VOCAB_UNKNOWN_SENDER, 1, "an unknown sender");

	/* 3. COMMITMENT: a key that addresses somebody else's frame. */
	REFUSES(memset(serve_commit, 0x77, sizeof(serve_commit)),
	        FZN_ADMIT_COMMITMENT, FZN_ADMIT_VOCAB_COMMITMENT, 1,
	        "a frame for another pair");

	/* 4. TAG: the commitment matches and the AEAD key does not, which is
	 * the only way to reach step 4 and fail it. */
	REFUSES(memset(serve_aead, 0x88, sizeof(serve_aead)),
	        FZN_ADMIT_TAG, FZN_ADMIT_VOCAB_SEAL, 1, "a wrong AEAD key");

	/* 7. CHAIN, before the chain module is reached: no root anchors this
	 * sender, so there is no chain error to give. */
	REFUSES(root_known = 0, FZN_ADMIT_CHAIN, FZN_ADMIT_VOCAB_NO_CHAIN, 0,
	        "a sender anchored to no root");

	/* 5. FRESHNESS: an expired frame, same nonce so the rule above still
	 * has something to say. */
	{
		fzn_admit_result_t rr, ok;

		reset_state();
		build_sealed(work, NONCE_A, NOW - 1u);
		rr = run(work, sizeof(work), &reasm);
		CHECK(rr.step == FZN_ADMIT_FRESHNESS,
		      "an expired frame refused at %s", fzn_admit_step_str(rr.step));
		CHECK(rr.vocab == FZN_ADMIT_VOCAB_FRESH,
		      "an expired frame carried vocabulary %s",
		      fzn_admit_vocab_str(rr.vocab));
		memcpy(work, good, sizeof(work));
		ok = run(work, sizeof(work), &reasm);
		CHECK(ok.step == FZN_ADMIT_ADMITTED,
		      "an expired frame cost the genuine frame its slot: %s",
		      fzn_admit_step_str(ok.step));
	}

	/* 6. REPLAY: the same genuine frame twice. The FIRST mutation, so this
	 * is the one case where the second run is SUPPOSED to be refused. */
	{
		fzn_admit_result_t first, again;

		reset_state();
		memcpy(work, good, sizeof(work));
		first = run(work, sizeof(work), &reasm);
		CHECK(first.step == FZN_ADMIT_ADMITTED,
		      "the first genuine frame was refused at %s",
		      fzn_admit_step_str(first.step));
		memcpy(work, good, sizeof(work));
		again = run(work, sizeof(work), &reasm);
		CHECK(again.step == FZN_ADMIT_REPLAY,
		      "a replayed frame refused at %s rather than replay",
		      fzn_admit_step_str(again.step));
		CHECK(again.vocab == FZN_ADMIT_VOCAB_FRESH,
		      "a replay carried vocabulary %s",
		      fzn_admit_vocab_str(again.vocab));
	}

	/* 7b. CHAIN: a capability this host holds no chain for. The store is
	 * consulted and answers nothing, which is an ABSENCE and not a chain
	 * error -- the module is still never reached. */
	{
		fzn_admit_result_t rr;
		fzn_cap_id_t save = CAP;

		reset_state();
		memset(CAP.b, 0xd4, sizeof(CAP.b));
		build_sealed(work, NONCE_A, EXPIRES);
		CAP = save;
		rr = run(work, sizeof(work), &reasm);
		CHECK(rr.step == FZN_ADMIT_CHAIN,
		      "an unprovable capability refused at %s",
		      fzn_admit_step_str(rr.step));
		CHECK(rr.vocab == FZN_ADMIT_VOCAB_NO_CHAIN,
		      "an unprovable capability carried vocabulary %s -- an "
		      "absence is not a chain error",
		      fzn_admit_vocab_str(rr.vocab));
	}

	/* 8. REASSEMBLY is optional, and a consumer that does not chunk gets
	 * the opened frame with no table invented for it. */
	{
		fzn_admit_result_t rr;

		reset_state();
		memcpy(work, good, sizeof(work));
		rr = run(work, sizeof(work), NULL);
		CHECK(rr.step == FZN_ADMIT_ADMITTED,
		      "a frame was refused when no reassembly table was given");
		CHECK(rr.message == NULL, "a message appeared with no table");
		CHECK(rr.opened.payload_len == PAYLOAD_LEN,
		      "the opened payload did not survive without a table");
	}

	/* A null environment is refused before anything runs. */
	{
		fzn_admit_result_t rr;
		fzn_admit_key_t candidates[1];

		memcpy(work, good, sizeof(work));
		fzn_admit(work, sizeof(work), NOW, NULL, candidates, 1, &rr);
		CHECK(rr.step == FZN_ADMIT_SHAPE && rr.vocab == FZN_ADMIT_VOCAB_SEAL,
		      "a null environment was not refused at shape");
	}

	/* ---- THE MEMO BRANCH. Wired at step 7 and, until this case existed,
	 * never executed by any test: sequence_test zeroed its env so
	 * `env.memo` was NULL, and memo_test exercises the memo with no
	 * `fzn_admit` anywhere near it. Each module was covered and the seam
	 * between them was not. ---- */
	{
		static const uint8_t NONCE_B[24] = "nonce b, twenty-four by";
		fzn_admit_env_t env;
		fzn_admit_key_t candidates[2];
		fzn_admit_result_t r1, r2;
		uint8_t second[FRAME_LEN];

		reset_state();
		build_sealed(second, NONCE_B, EXPIRES);

		env = env_for(&reasm);
		env.revocations = &revocations;
		env.memo = &memo;

		memcpy(work, good, sizeof(work));
		fzn_admit(work, sizeof(work), NOW, &env, candidates, 2, &r1);
		CHECK(r1.step == FZN_ADMIT_ADMITTED,
		      "the first frame was refused at %s",
		      fzn_admit_step_str(r1.step));
		CHECK(memo.hits == 0 && fzn_chain_memo_live(&memo,
		          fzn_revocation_generation(&revocations)) == 1,
		      "the first frame did not record a verdict");

		/* NOW MAKE VERIFICATION IMPOSSIBLE. A second frame that is
		 * still admitted was admitted by the memo, because nothing
		 * else could have said yes. */
		env.sign = &broken_sign;
		memcpy(work, second, sizeof(work));
		fzn_admit(work, sizeof(work), NOW, &env, candidates, 2, &r2);
		CHECK(r2.step == FZN_ADMIT_ADMITTED,
		      "the second frame was refused at %s -- the memo did not "
		      "answer", fzn_admit_step_str(r2.step));
		CHECK(memo.hits == 1, "the hit was not counted: hits=%u",
		      (unsigned)memo.hits);

		/* The control for the control: with the broken signer and NO
		 * memo, the same frame is refused. Without this the case
		 * above would pass against a `broken_sign` that happened to
		 * verify. */
		reset_state();
		env = env_for(&reasm);
		env.revocations = &revocations;
		env.memo = NULL;
		env.sign = &broken_sign;
		memcpy(work, second, sizeof(work));
		fzn_admit(work, sizeof(work), NOW, &env, candidates, 2, &r2);
		CHECK(r2.step == FZN_ADMIT_CHAIN,
		      "a frame whose chain cannot verify was admitted at %s "
		      "with no memo", fzn_admit_step_str(r2.step));
	}

	/* NO REVOCATION STORE MEANS NO CACHING, and by arithmetic rather than
	 * by a rule: a null store's generation is zero, and a memo refuses to
	 * record or match on zero. A cache nothing can invalidate would be a
	 * permanent authorisation, so the degenerate case has to fail safe. */
	{
		static const uint8_t NONCE_C[24] = "nonce c, twenty-four by";
		fzn_admit_env_t env;
		fzn_admit_key_t candidates[2];
		fzn_admit_result_t r1, r2;
		uint8_t second[FRAME_LEN];

		reset_state();
		build_sealed(second, NONCE_C, EXPIRES);

		env = env_for(&reasm);
		env.revocations = NULL;
		env.memo = &memo;

		memcpy(work, good, sizeof(work));
		fzn_admit(work, sizeof(work), NOW, &env, candidates, 2, &r1);
		CHECK(r1.step == FZN_ADMIT_ADMITTED,
		      "the first frame was refused with no revocation store");
		CHECK(fzn_chain_memo_live(&memo, 1) == 0,
		      "a verdict was cached with no store to invalidate it");

		env.sign = &broken_sign;
		memcpy(work, second, sizeof(work));
		fzn_admit(work, sizeof(work), NOW, &env, candidates, 2, &r2);
		CHECK(r2.step == FZN_ADMIT_CHAIN,
		      "a cache with no invalidator answered: admitted at %s",
		      fzn_admit_step_str(r2.step));
	}

	printf("sequence_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
