/*
 * A fuzz harness for what a group's members send, `node/group_act.c` and
 * `node/group_line.c` (secs 626, 628): an act of a group's log, signed by a
 * host of a member, and a line sealed under an epoch's secret. Both arrive
 * from other users' hosts, contacts among them.
 *
 * Each case makes a random act -- every kind, a payload of up to 512
 * bytes, signed by its host for its user -- and a random line sealed under
 * a random secret, and bends both as line_fuzz does: bits flipped, cut
 * short, grown, a slice repeated or two bytes swapped. Every decode, peek
 * and open reads a copy that ends where an unreadable page begins, so a
 * read past the end faults in any build.
 *
 * THE PROPERTIES:
 *   1. AN ACT round-trips: it decodes as made, encodes back as its own
 *      bytes, and verifies. A bent act that decodes encodes back as
 *      exactly its bytes -- one encoding -- and none verifies: every byte
 *      of an act is its signer's word or the proof of who that is.
 *   2. A LINE opens under its secret as sealed, and under no other. A bent
 *      line never opens: its clear head -- the group, the epoch, the
 *      member it names, the host -- is bound to its sealed text, or a
 *      member could hand on a line naming another.
 *
 * FLOORS: a run in which no bent act decoded, or none was refused, or no
 * bent line still peeked, has not tested what it claims.
 */

#include "../group_act.h"
#include "../group_line.h"
#include "../../prekey/prekey.h"
#include "../../session/aead_monocypher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FUZZ_DEFAULT_CASES 4000u
#define FUZZ_MIN_CASES 500u
#define ACT_PAYLOAD 512u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL group_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0xa54ff53a5f1d36f1ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

static void fill(uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)next();
}

static int rng_fill(void *ctx, uint8_t *out, size_t len)
{
	(void)ctx;
	fill(out, len);
	return 1;
}

static const fzn_random_ops_t RNG = { rng_fill, NULL };

/* ---- a signature and a hash, stubbed: which key signed, not the curve --- */

static void mac(uint8_t *out, size_t out_len, uint64_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, FZN_SIG_LEN, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, FZN_SIG_LEN, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	mac(out, out_len, 0x5eedu, in, in_len);
	return 1;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };
static const fzn_hash_ops_t HASH = { stub_hash, NULL };

/* ---- the lie ----------------------------------------------------------- */

#define BUF_MAX (FZN_GROUP_ACT_MAX + 64u)

/* Bend `b`, `len` bytes of `cap`, and return its new length; never the
 * bytes unchanged. */
static size_t bend(uint8_t *b, size_t len, size_t cap)
{
	static uint8_t was[BUF_MAX];
	size_t k, i, j;
	uint8_t t;

	memcpy(was, b, len);
	switch (next() % 5u) {
	case 1:
		if (len)
			return (size_t)(next() % len);
		break;
	case 2:
		if (len < cap) {
			for (k = 1u + next() % 8u; k > 0u && len < cap; k--)
				b[len++] = (uint8_t)next();
			return len;
		}
		break;
	case 3:
		if (len >= 8u) {
			i = next() % (len - 4u);
			for (j = 0; j < 4u && i + j + 4u < len && b[i + j] == b[i + j + 4u]; j++)
				;
			if (j < 4u && i + j + 4u < len) {
				memmove(b + i + 4u, b + i, len - i - 4u);
				return len;
			}
		}
		break;
	case 4:
		if (len >= 2u) {
			i = next() % len;
			j = next() % len;
			if (b[i] != b[j]) {
				t = b[i];
				b[i] = b[j];
				b[j] = t;
				return len;
			}
		}
		break;
	default:
		break;
	}
	for (k = 1u + next() % 2u; k > 0u && len; k--)
		b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
	if (len && memcmp(b, was, len) == 0)
		b[next() % len] ^= 0x01u;
	return len;
}

/* ---- the page an over-read meets ---------------------------------------- */

static uint8_t *guarded_end;

static void guard(void)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t room;
	uint8_t *map;

	if (page <= 0)
		abort();
	room = ((BUF_MAX + (size_t)page - 1u) / (size_t)page) * (size_t)page;
	map = mmap(NULL, room + (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	           -1, 0);
	if (map == MAP_FAILED || mprotect(map + room, (size_t)page, PROT_NONE) != 0)
		abort();
	guarded_end = map + room;
}

static const uint8_t *guarded(const uint8_t *bytes, size_t len)
{
	memcpy(guarded_end - len, bytes, len);
	return guarded_end - len;
}

/* ---- what is made ------------------------------------------------------- */

static fzn_cap_id_t member;

/* AN ACT of a random kind by user `user`, its host its root -- as
 * group_log_test makes one -- signed. */
static void an_act(fzn_group_act_t *a, uint8_t user)
{
	uint8_t agree[FZN_PREKEY_LEN];

	memset(a, 0, sizeof(*a));
	a->kind = (uint8_t)(1u + next() % 10u);
	if (a->kind != FZN_GROUP_ACT_CREATE) {
		a->seq = (uint32_t)(1u + next() % 1000u);
		fill(a->group, sizeof(a->group));
		fill(a->prev, sizeof(a->prev));
	}
	fill(a->subject, sizeof(a->subject));
	a->setting = (uint8_t)(next() & 1u);
	a->value = next() >> (next() % 64u);
	a->at = 5000u + next() % 100000u;
	if (a->kind == FZN_GROUP_ACT_KEYS) {
		a->payload_len = (size_t)(next() % (ACT_PAYLOAD + 1u));
		fill(a->payload, a->payload_len);
	}
	memset(a->signer.owner, user, sizeof(a->signer.owner));
	memset(agree, user ^ 0x5au, sizeof(agree));
	signing_as = user;
	(void)fzn_prekey_issue(a->signer.owner, agree, 1000u, &SIGN, a->signer.record);
	(void)fzn_group_act_sign(a, &SIGN);
}

int main(int argc, char **argv)
{
	static uint8_t bytes[BUF_MAX], again[BUF_MAX];
	static fzn_group_act_t a, back;
	static fzn_group_line_t line, opened;
	fzn_aead_ops_t aead;
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long act_decoded = 0, act_refused = 0, line_peeked = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	guard();
	fzn_aead_monocypher_init(&aead);
	memset(member.b, 0x44, sizeof(member.b));

	for (c = 0; c < cases; c++) {
		uint8_t secret[FZN_GROUP_SECRET_LEN], other[FZN_GROUP_SECRET_LEN];
		size_t len = 0, n = 0, again_len = 0;

		/* 1: AN ACT. */
		an_act(&a, (uint8_t)(0x10u + next() % 0x40u));
		if (fzn_group_act_encode(&a, bytes, sizeof(bytes), &len) != FZN_GROUP_ACT_OK) {
			fail("an act made would not encode", c);
			continue;
		}
		if (fzn_group_act_decode(guarded(bytes, len), len, &back) != FZN_GROUP_ACT_OK
		    || fzn_group_act_encode(&back, again, sizeof(again), &again_len)
		               != FZN_GROUP_ACT_OK
		    || again_len != len || memcmp(again, bytes, len) != 0
		    || fzn_group_act_verify(&back, &SIGN, &member) != FZN_GROUP_ACT_OK)
			fail("an act did not decode as made, encode back, or verify", c);
		n = bend(bytes, len, sizeof(bytes));
		if (fzn_group_act_decode(guarded(bytes, n), n, &back) != FZN_GROUP_ACT_OK) {
			act_refused++;
		} else {
			act_decoded++;
			if (fzn_group_act_encode(&back, again, sizeof(again), &again_len)
			            != FZN_GROUP_ACT_OK
			    || again_len != n || memcmp(again, bytes, n) != 0)
				fail("a bent act decoded that is not the one encoding of what it said", c);
			else if (fzn_group_act_verify(&back, &SIGN, &member) == FZN_GROUP_ACT_OK)
				fail("a bent act verified as its signer's", c);
		}

		/* 2: A LINE. */
		memset(&line, 0, sizeof(line));
		fill(line.group, sizeof(line.group));
		line.epoch = (uint32_t)next();
		fill(line.sender, sizeof(line.sender));
		fill(line.host, sizeof(line.host));
		fill(line.id, sizeof(line.id));
		line.stime = next() >> (next() % 64u);
		line.text_len = 1u + (size_t)(next() % FZN_GROUP_LINE_TEXT_MAX);
		fill(line.text, line.text_len);
		fill(secret, sizeof(secret));
		memcpy(other, secret, sizeof(other));
		other[next() % sizeof(other)] ^= (uint8_t)(1u << (next() % 8u));
		if (fzn_group_line_seal(&line, secret, &HASH, &aead, &RNG, bytes, sizeof(bytes), &len)
		    != FZN_GROUP_LINE_OK) {
			fail("a line made would not seal", c);
			continue;
		}
		if (fzn_group_line_open(guarded(bytes, len), len, secret, &HASH, &aead, &opened)
		            != FZN_GROUP_LINE_OK
		    || memcmp(opened.group, line.group, sizeof(line.group)) != 0
		    || opened.epoch != line.epoch
		    || memcmp(opened.sender, line.sender, sizeof(line.sender)) != 0
		    || memcmp(opened.host, line.host, sizeof(line.host)) != 0
		    || memcmp(opened.id, line.id, sizeof(line.id)) != 0 || opened.stime != line.stime
		    || opened.text_len != line.text_len
		    || memcmp(opened.text, line.text, line.text_len) != 0)
			fail("a line did not open as sealed", c);
		if (fzn_group_line_open(guarded(bytes, len), len, other, &HASH, &aead, &opened)
		    == FZN_GROUP_LINE_OK)
			fail("a line opened under another secret", c);
		n = bend(bytes, len, sizeof(bytes));
		if (fzn_group_line_peek(guarded(bytes, n), n, &opened) == FZN_GROUP_LINE_OK)
			line_peeked++;
		if (fzn_group_line_open(guarded(bytes, n), n, secret, &HASH, &aead, &opened)
		    == FZN_GROUP_LINE_OK)
			fail("a bent line opened", c);
	}

	if (act_decoded == 0u || act_refused == 0u)
		fail("FLOOR: no bent act decoded, or none was refused", cases);
	if (line_peeked == 0u)
		fail("FLOOR: no bent line still peeked: the open was never asked of one", cases);
	printf("group_fuzz: %lu cases, bent acts %lu decoded %lu refused, bent lines %lu peeked, "
	       "%d failure(s)\n",
	       cases, act_decoded, act_refused, line_peeked, failures);
	return failures ? 1 : 0;
}
