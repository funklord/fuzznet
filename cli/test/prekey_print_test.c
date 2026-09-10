/* Tests for cli/prekey_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is the one `prekey.h` says an operator has to
 * see. A rollback is "a real, correctly signed, older record replayed" -- and
 * if that key has since leaked, accepting it is the attack. It reaches a
 * consumer as an integer alongside six others.
 *
 * THE SECOND is the direction that gets confused. FZN_PREKEY_ERR_SIGNER is
 * THIS host having no verifier, and a consumer that renders it as "the peer
 * could not be verified" has accused somebody of something the host did.
 *
 * THE THIRD is that one code covers three events: a first pin, a rotation and
 * a re-delivery all answer FZN_PREKEY_OK, and the header calls the last of
 * them "ordinary and is not an event". The cases below drive all three
 * through the module rather than hand-building peers, so the printer is told
 * apart by what really moved.
 */

#include "../prekey_print.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL prekey_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* The keyed stub `prekey_fuzz.c` uses, for its reason: a signature made by one
 * host must not verify under another, or "the record verifies under the host
 * it names" is unfalsifiable. */
static uint8_t signing_as;

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t identity, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	h ^= identity;
	h *= 0x100000001b3ull;
	for (i = 0; i < len; i++) {
		h ^= msg[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 24);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	mac(sig, signing_as, msg, msg_len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pubkey[0], msg, msg_len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t OPS = { stub_verify, stub_sign, NULL };

/* THIS HOST HAVING NO VERIFIER AT ALL, which is a NULL function pointer and
 * not one that answers no.
 *
 * MEASURED RATHER THAN ASSUMED, and the first draft had it wrong: a verifier
 * that RETURNS zero yields FZN_PREKEY_ERR_SIGNATURE -- correctly, since a
 * verifier saying no is the signature not verifying -- and only an absent one
 * yields FZN_PREKEY_ERR_SIGNER. The draft asserted the SIGNER mapping behind
 * an `if` that could never be true, which is an assertion that does not run
 * wearing one that does. */
static const fzn_sign_ops_t NO_VERIFIER = { NULL, stub_sign, NULL };

static void expand(uint8_t *out, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		out[i] = (uint8_t)(seed + i);
}

/* Issue a record for `host_seed`, signed by `signer_seed`. */
static int issue(uint8_t *bytes, uint8_t host_seed, uint8_t signer_seed, uint8_t prekey_seed,
                 uint64_t created_at)
{
	uint8_t host[FZN_PUBKEY_LEN], prekey[FZN_PREKEY_LEN];

	expand(host, sizeof(host), host_seed);
	expand(prekey, sizeof(prekey), prekey_seed);
	signing_as = signer_seed;
	return fzn_prekey_issue(host, prekey, created_at, &OPS, bytes) == FZN_PREKEY_OK;
}

static size_t line_of(const fzn_prekey_peer_t *b, const fzn_prekey_peer_t *a,
                      fzn_prekey_err_t err, char *out, fzn_prekey_line_t *said)
{
	size_t len = 99;

	*said = (fzn_prekey_line_t)-1;
	CHECK(fzn_prekey_print(b, a, err, out, FZN_PREKEY_PRINT_MAX, &len, said)
	              == FZN_PREKEY_OK,
	      "rendering refused an offer it should have printed");
	return len;
}

int main(void)
{
	char line[FZN_PREKEY_PRINT_MAX];
	char rollback[FZN_PREKEY_PRINT_MAX];
	char wrong[FZN_PREKEY_PRINT_MAX];
	char local[FZN_PREKEY_PRINT_MAX];
	char unverified[FZN_PREKEY_PRINT_MAX];
	uint8_t bytes[FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_peer_t peer, before;
	fzn_prekey_record_t rec;
	fzn_prekey_line_t said;
	fzn_prekey_err_t err;
	size_t len = 0;

	/* ---- NOTHING TO REPORT ON. Both halves are needed to tell a rotation
	 * from a re-delivery, so one of them missing is NONE. */
	fzn_prekey_peer_init(&peer);
	len = line_of(NULL, &peer, FZN_PREKEY_OK, line, &said);
	CHECK(said == FZN_PREKEY_LINE_NONE, "one half of the pair was given a verdict");
	CHECK(len > 0 && line[len] == '\0', "the line is not terminated at its length");
	CHECK(strstr(line, "cannot say") != NULL, "the line does not say it cannot say");

	/* ---- A FIRST PIN. */
	CHECK(issue(bytes, 0x40u, 0x40u, 0x10u, 100u), "issuing refused");
	CHECK(fzn_prekey_open(bytes, sizeof(bytes), &rec) == FZN_PREKEY_OK, "open refused");
	before = peer;
	err = fzn_prekey_pin(&peer, rec, &OPS, FZN_TRUST_PINNED, 1000u);
	CHECK(err == FZN_PREKEY_OK, "a first pin was refused");
	len = line_of(&before, &peer, err, line, &said);
	CHECK(said == FZN_PREKEY_LINE_LEARNED, "a first pin was not reported as learned");
	CHECK(strstr(line, "ATTENTION") == NULL, "a first pin alarmed");

	/* ---- THE SAME RECORD AGAIN: ordinary, and not an event. */
	before = peer;
	err = fzn_prekey_pin(&peer, rec, &OPS, FZN_TRUST_PINNED, 1001u);
	CHECK(err == FZN_PREKEY_OK, "a re-delivery was refused");
	len = line_of(&before, &peer, err, line, &said);
	CHECK(said == FZN_PREKEY_LINE_UNCHANGED,
	      "a re-delivery of a record already held was reported as a change");
	CHECK(strstr(line, "ordinary") != NULL,
	      "the line does not say this is ordinary, which is what prekey.h calls it");

	/* ---- A ROTATION: same host, newer key. */
	CHECK(issue(bytes, 0x40u, 0x40u, 0x11u, 200u), "issuing refused");
	CHECK(fzn_prekey_open(bytes, sizeof(bytes), &rec) == FZN_PREKEY_OK, "open refused");
	before = peer;
	err = fzn_prekey_pin(&peer, rec, &OPS, FZN_TRUST_PINNED, 1002u);
	CHECK(err == FZN_PREKEY_OK, "a rotation was refused");
	len = line_of(&before, &peer, err, line, &said);
	CHECK(said == FZN_PREKEY_LINE_ROTATED, "a rotation was not reported as one");
	CHECK(strstr(line, "rotated") != NULL, "the line does not say the peer rotated");

	/* ---- THE ROLLBACK, which is the one an operator has to see. */
	CHECK(issue(bytes, 0x40u, 0x40u, 0x12u, 150u), "issuing refused");
	CHECK(fzn_prekey_open(bytes, sizeof(bytes), &rec) == FZN_PREKEY_OK, "open refused");
	before = peer;
	err = fzn_prekey_pin(&peer, rec, &OPS, FZN_TRUST_PINNED, 1003u);
	CHECK(err == FZN_PREKEY_ERR_ROLLBACK, "an older key was not refused as a rollback");
	len = line_of(&before, &peer, err, rollback, &said);
	CHECK(said == FZN_PREKEY_LINE_ROLLBACK, "a rollback was not reported as one");
	CHECK(strstr(rollback, "ATTENTION") != NULL,
	      "the case prekey.h says an operator has to see does not announce itself");
	CHECK(strstr(rollback, "leaked") != NULL,
	      "the line does not say why a correctly signed record is refused, which is "
	      "the only part a reader cannot work out");

	/* ---- A DIFFERENT HOST IN THIS SLOT. */
	CHECK(issue(bytes, 0x50u, 0x50u, 0x13u, 300u), "issuing refused");
	CHECK(fzn_prekey_open(bytes, sizeof(bytes), &rec) == FZN_PREKEY_OK, "open refused");
	before = peer;
	err = fzn_prekey_pin(&peer, rec, &OPS, FZN_TRUST_PINNED, 1004u);
	CHECK(err == FZN_PREKEY_ERR_WRONG_HOST, "another host was not refused as such");
	len = line_of(&before, &peer, err, wrong, &said);
	CHECK(said == FZN_PREKEY_LINE_WRONG_HOST, "a different host was not reported");
	CHECK(strstr(wrong, "different peer in this slot") != NULL,
	      "the line does not separate another peer arriving from this one rotating");

	/* ---- A FORGERY: signed by somebody else. */
	fzn_prekey_peer_init(&peer);
	CHECK(issue(bytes, 0x60u, 0x99u, 0x14u, 400u), "issuing refused");
	CHECK(fzn_prekey_open(bytes, sizeof(bytes), &rec) == FZN_PREKEY_OK, "open refused");
	before = peer;
	err = fzn_prekey_pin(&peer, rec, &OPS, FZN_TRUST_PINNED, 1005u);
	CHECK(err == FZN_PREKEY_ERR_SIGNATURE, "a forged record was not refused");
	len = line_of(&before, &peer, err, unverified, &said);
	CHECK(said == FZN_PREKEY_LINE_UNVERIFIED, "a forgery was not reported as unverified");

	/* ---- AND THIS HOST HAVING NO VERIFIER, which is not about the peer at
	 * all. The record below is GENUINE and correctly signed -- the only
	 * thing wrong is on this side. */
	fzn_prekey_peer_init(&peer);
	CHECK(issue(bytes, 0x70u, 0x70u, 0x15u, 500u), "issuing refused");
	CHECK(fzn_prekey_open(bytes, sizeof(bytes), &rec) == FZN_PREKEY_OK, "open refused");
	before = peer;
	err = fzn_prekey_pin(&peer, rec, &NO_VERIFIER, FZN_TRUST_PINNED, 1006u);
	CHECK(err == FZN_PREKEY_ERR_SIGNER,
	      "an absent verifier was not reported as this host's own problem");
	len = line_of(&before, &peer, err, local, &said);
	CHECK(said == FZN_PREKEY_LINE_LOCAL,
	      "this host having no verifier was reported as the peer's fault");
	CHECK(strstr(local, "nothing here is a statement about the peer") != NULL,
	      "the line accuses the peer of something this host did");
	CHECK(strcmp(local, unverified) != 0,
	      "a host with no verifier and a forged record produced the same sentence, "
	      "which is the confusion this state exists to prevent");

	/* ---- MALFORMED IS THIS SIDE TOO. */
	len = line_of(&before, &peer, FZN_PREKEY_ERR_MALFORMED, line, &said);
	CHECK(said == FZN_PREKEY_LINE_LOCAL,
	      "a caller's own bug was reported as something about the peer");

	/* ---- FOREIGN BYTES ARE PROBABLY SKEW. */
	len = line_of(&before, &peer, FZN_PREKEY_ERR_SHAPE, line, &said);
	CHECK(said == FZN_PREKEY_LINE_FOREIGN, "a wrong shape was not reported as foreign");
	CHECK(strstr(line, "version difference") != NULL,
	      "the line does not offer the likely explanation, so a reader suspects a "
	      "peer over a version number");

	/* ---- AND THE ALARMING ONES ARE DISTINCT FROM THE REST. */
	CHECK(strcmp(rollback, wrong) != 0 && strcmp(rollback, unverified) != 0
	              && strcmp(wrong, unverified) != 0,
	      "two refusals wanting different responses produced the same sentence");

	/* ---- THE OPERANDS. */
	CHECK(fzn_prekey_print(&before, &peer, FZN_PREKEY_OK, NULL, sizeof(line), &len, &said)
	              == FZN_PREKEY_ERR_MALFORMED, "printing accepted a null buffer");
	CHECK(fzn_prekey_print(&before, &peer, FZN_PREKEY_OK, line, sizeof(line), NULL, &said)
	              == FZN_PREKEY_ERR_MALFORMED, "printing accepted a null length");
	CHECK(fzn_prekey_print(&before, &peer, FZN_PREKEY_OK, line, sizeof(line), &len, NULL)
	              == FZN_PREKEY_ERR_MALFORMED,
	      "printing accepted a null state out-parameter, which is the required half");

	/* ---- A BUFFER TOO SMALL REPORTS WHAT IT NEEDED AND WRITES NOTHING. */
	said = FZN_PREKEY_LINE_ROTATED;
	len = 0;
	CHECK(fzn_prekey_print(&before, &peer, FZN_PREKEY_ERR_ROLLBACK, line, 4u, &len, &said)
	              == FZN_PREKEY_ERR_MALFORMED, "a four-byte buffer took a line");
	CHECK(len > 4u, "the refusal does not say how much room the line needed");
	CHECK(said == FZN_PREKEY_LINE_NONE,
	      "a refused render left a verdict behind, which a caller would read as one");

	printf("prekey_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
