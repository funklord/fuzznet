/* node contact_request_test -- a contact request, sec 619: its encoding,
 * what makes one hold as a request to this host, and the two queues. A
 * stub signature keyed by a key's first byte, as contact_card_test's. */

#include "../contact_request.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL contact_request_test.c:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };


/* ---- a store of every slot ---------------------------------------------- */

#define ROWS 48u
#define ROW_MAX (2u * FZN_CONTACT_REQUEST_MAX + 16u)

static struct {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[ROW_MAX];
	size_t len;
} rows[ROWS];

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0
		    && rows[i].len <= cap) {
			memcpy(out, rows[i].bytes, rows[i].len);
			*len = rows[i].len;
			return 1;
		}
	return 0;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	size_t i, free_one = ROWS;

	(void)ctx;
	if (len > ROW_MAX)
		return 0;
	for (i = 0; i < ROWS; i++) {
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			break;
		if (!rows[i].used && free_one == ROWS)
			free_one = i;
	}
	if (i == ROWS)
		i = free_one;
	if (i == ROWS)
		return 0;
	rows[i].used = 1;
	rows[i].slot = slot;
	memcpy(rows[i].subject, subject, 32u);
	memcpy(rows[i].bytes, bytes, len);
	rows[i].len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + 32u * n++, rows[i].subject, 32u);
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && memcmp(rows[i].subject, subject, 32u) == 0)
			rows[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL, NULL };

/* ---- fixtures ----------------------------------------------------------- */

static uint8_t target[32], elsewhere[32];
static fzn_cap_id_t member;

/* A request from the user whose root -- its own host -- has `first` as its
 * first byte, to `target`, expiring at `expires_at`, signed by its host. */
static void request_from(fzn_contact_request_t *r, uint8_t first, uint64_t expires_at)
{
	uint8_t root[32], agree[FZN_PREKEY_LEN];

	memset(r, 0, sizeof(*r));
	memset(root, first, sizeof(root));
	memcpy(r->card.host.owner, root, 32u);
	memset(agree, first ^ 0x5au, sizeof(agree));
	signing_as = first;
	(void)fzn_prekey_issue(root, agree, 1000u, &SIGN, r->card.host.record);
	memcpy(r->card.host.address, "10.0.0.9", 8u);
	r->card.host.address_len = 8u;
	r->card.host.port = 47009u;
	(void)fzn_contact_card_sign(&r->card, &SIGN);
	memcpy(r->target, target, 32u);
	memset(r->nonce, first, sizeof(r->nonce));
	r->expires_at = expires_at;
	(void)fzn_contact_request_sign(r, &SIGN);
}

static void test_a_request_holds_for_its_host(void)
{
	static fzn_contact_request_t r, back;
	static uint8_t bytes[FZN_CONTACT_REQUEST_MAX];
	size_t len = 0;

	request_from(&r, 0x61, 3000u);
	CHECK(fzn_contact_request_encode(&r, bytes, sizeof(bytes), &len) == FZN_CONTACT_REQUEST_OK
	              && fzn_contact_request_decode(bytes, len, &back) == FZN_CONTACT_REQUEST_OK
	              && memcmp(back.target, target, 32u) == 0 && back.expires_at == 3000u
	              && fzn_contact_request_verify(&back, &SIGN, &member, target, 2000u)
	                         == FZN_CONTACT_REQUEST_OK,
	      "a signed request decodes to itself and holds at its host");
	CHECK(fzn_contact_request_decode(bytes, len - 1u, &back) == FZN_CONTACT_REQUEST_ERR_SHAPE
	              && (bytes[len] = 0, fzn_contact_request_decode(bytes, len + 1u, &back))
	                         == FZN_CONTACT_REQUEST_ERR_SHAPE,
	      "a request a byte short or long decodes");
	CHECK(fzn_contact_request_verify(&r, &SIGN, &member, elsewhere, 2000u)
	              == FZN_CONTACT_REQUEST_ERR_NOT_HERE,
	      "a request for another host held here");
	r.nonce[0] ^= 1u;
	CHECK(fzn_contact_request_verify(&r, &SIGN, &member, target, 2000u)
	              == FZN_CONTACT_REQUEST_ERR_REFUSED,
	      "a request changed after signing held");
	request_from(&r, 0x61, 3000u);
	signing_as = 0x62;
	(void)fzn_contact_request_sign(&r, &SIGN);
	CHECK(fzn_contact_request_verify(&r, &SIGN, &member, target, 2000u)
	              == FZN_CONTACT_REQUEST_ERR_REFUSED,
	      "a request signed by a key other than its card's host held");
	request_from(&r, 0x61, 3000u);
	r.card.name[0] = 'x';
	r.card.name_len = 1u;
	signing_as = 0x61;
	(void)fzn_contact_request_sign(&r, &SIGN);
	CHECK(fzn_contact_request_verify(&r, &SIGN, &member, target, 2000u)
	              == FZN_CONTACT_REQUEST_ERR_REFUSED,
	      "a request whose card was changed after the card was signed held");
	request_from(&r, 0x61, 1500u);
	CHECK(fzn_contact_request_verify(&r, &SIGN, &member, target, 2000u)
	              == FZN_CONTACT_REQUEST_ERR_EXPIRED,
	      "an expired request held");
	request_from(&r, 0x61, 2000u + FZN_CONTACT_REQUEST_LIFE_MAX + 1u);
	CHECK(fzn_contact_request_verify(&r, &SIGN, &member, target, 2000u)
	              == FZN_CONTACT_REQUEST_ERR_EXPIRED,
	      "a request claiming to outlive the longest life held");
	request_from(&r, 0x61, 2000u + FZN_CONTACT_REQUEST_LIFE_MAX);
	CHECK(fzn_contact_request_verify(&r, &SIGN, &member, target, 2000u)
	              == FZN_CONTACT_REQUEST_OK,
	      "a request at the longest life was refused");
}

static void test_the_queue_of_strangers(void)
{
	static fzn_contact_request_t r;
	static fzn_contact_request_held_t held[32];
	uint8_t root[32];
	size_t n = 0, i;

	memset(rows, 0, sizeof(rows));
	for (i = 0; i < 20u; i++) {
		request_from(&r, (uint8_t)(0x40u + i), 9000u);
		CHECK(fzn_contact_request_keep(&STORE, &r, 100u + i, NULL) == FZN_CONTACT_REQUEST_OK,
		      "a request was not kept");
	}
	CHECK(fzn_contact_request_list(&STORE, held, 32u, &n) == FZN_CONTACT_REQUEST_OK
	              && n == 20u && held[0].request.card.host.owner[0] == 0x40u
	              && held[n - 1u].request.card.host.owner[0] == 0x53u,
	      "the requests held did not list whole, oldest first");
	CHECK(fzn_contact_request_list(&STORE, held, 10u, &n) == FZN_CONTACT_REQUEST_ERR_ROOM
	              && n == 20u,
	      "a listing into less room than is held did not say how many");
	request_from(&r, 0x45, 9000u);
	CHECK(fzn_contact_request_keep(&STORE, &r, 500u, NULL) == FZN_CONTACT_REQUEST_OK
	              && fzn_contact_request_list(&STORE, held, 32u, &n) == FZN_CONTACT_REQUEST_OK
	              && n == 20u && held[0].request.card.host.owner[0] == 0x40u
	              && held[n - 1u].request.card.host.owner[0] == 0x45u
	              && held[n - 1u].received_at == 500u,
	      "a newer request from one asker did not replace its older, or evicted another");
	memset(root, 0x45, sizeof(root));
	CHECK(fzn_contact_request_drop(&STORE, root) == FZN_CONTACT_REQUEST_OK
	              && fzn_contact_request_drop(&STORE, root) == FZN_CONTACT_REQUEST_ERR_ABSENT,
	      "a request dropped was not gone, or dropping it again said otherwise");
	/* A ROW UNDER ANOTHER ROOT is one nobody kept. */
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && rows[i].slot == FZN_PERSIST_CONTACT_REQUEST) {
			rows[i].subject[0] ^= 1u;
			break;
		}
	CHECK(fzn_contact_request_list(&STORE, held, 32u, &n) == FZN_CONTACT_REQUEST_OK && n == 18u,
	      "a request filed under another root read as that root's");
}

/* ---- thousands, sec 704 ------------------------------------------------- */

/* A STORE OF MANY, indexed by a root's first two bytes, the rest 0x33:
 * what `request_numbered` makes. One table per slot, rows allocated as
 * saved. */
#define MANY 65536u
static struct many_row {
	uint8_t bytes[ROW_MAX];
	size_t len;
} *many[2][MANY];

static int many_at(fzn_persist_slot_t slot, const uint8_t *subject, size_t *table, size_t *at)
{
	size_t i;

	if (slot != FZN_PERSIST_CONTACT_REQUEST && slot != FZN_PERSIST_CONTACT_ASKED)
		return 0;
	for (i = 2; i < 32u; i++)
		if (subject[i] != 0x33u)
			return 0;
	*table = slot == FZN_PERSIST_CONTACT_REQUEST ? 0u : 1u;
	*at = ((size_t)subject[0] << 8) | subject[1];
	return 1;
}

static int many_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                     size_t cap, size_t *len)
{
	size_t t, at;

	(void)ctx;
	if (!many_at(slot, subject, &t, &at) || !many[t][at] || many[t][at]->len > cap)
		return 0;
	memcpy(out, many[t][at]->bytes, many[t][at]->len);
	*len = many[t][at]->len;
	return 1;
}

static int many_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                     const uint8_t *bytes, size_t len)
{
	size_t t, at;

	(void)ctx;
	if (len > ROW_MAX || !many_at(slot, subject, &t, &at))
		return 0;
	if (!many[t][at] && !(many[t][at] = malloc(sizeof(*many[t][at]))))
		return 0;
	memcpy(many[t][at]->bytes, bytes, len);
	many[t][at]->len = len;
	return 1;
}

static int many_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t t, at;

	(void)ctx;
	if (many_at(slot, subject, &t, &at)) {
		free(many[t][at]);
		many[t][at] = NULL;
	}
	return 1;
}

static int many_each(void *ctx, fzn_persist_slot_t slot,
                     int (*fn)(void *arg, const uint8_t subject[FZN_PUBKEY_LEN]), void *arg)
{
	uint8_t subject[32];
	size_t t, at;

	(void)ctx;
	memset(subject, 0x33, sizeof(subject));
	if (!many_at(slot, subject, &t, &at))
		return 1;
	for (at = 0; at < MANY; at++)
		if (many[t][at]) {
			subject[0] = (uint8_t)(at >> 8);
			subject[1] = (uint8_t)at;
			if (!fn(arg, subject))
				break;
		}
	return 1;
}

static void many_free(void)
{
	size_t t, at;

	for (t = 0; t < 2u; t++)
		for (at = 0; at < MANY; at++) {
			free(many[t][at]);
			many[t][at] = NULL;
		}
}

/* As `request_from`, from the user whose root is numbered `n`. */
static void request_numbered(fzn_contact_request_t *r, size_t n, uint64_t expires_at)
{
	uint8_t root[32], agree[FZN_PREKEY_LEN];

	memset(r, 0, sizeof(*r));
	memset(root, 0x33, sizeof(root));
	root[0] = (uint8_t)(n >> 8);
	root[1] = (uint8_t)n;
	memcpy(r->card.host.owner, root, 32u);
	memset(agree, 0x5a, sizeof(agree));
	signing_as = 0x33;
	(void)fzn_prekey_issue(root, agree, 1000u, &SIGN, r->card.host.record);
	memcpy(r->card.host.address, "10.0.0.9", 8u);
	r->card.host.address_len = 8u;
	r->card.host.port = 47009u;
	(void)fzn_contact_card_sign(&r->card, &SIGN);
	memcpy(r->target, target, 32u);
	r->expires_at = expires_at;
	(void)fzn_contact_request_sign(r, &SIGN);
}

static int counted(void *ctx, const fzn_contact_asked_t *asked)
{
	(void)asked;
	(*(size_t *)ctx)++;
	return 1;
}

static void test_thousands(void)
{
	static fzn_contact_request_t r;
	static fzn_contact_request_held_t probe;
	static fzn_contact_asked_t a, few[16];
	fzn_contact_request_held_t *held;
	fzn_persist_ops_t store = { 0 };
	uint8_t root[32];
	size_t i, n = 0, evicted = 9, walked = 0;
	int kept = 1;

	store.load = many_load;
	store.save = many_save;
	store.remove = many_remove;
	store.each = many_each;
	/* STRANGERS TO THE BOUND, the sixth expiring early: not the oldest, so
	 * letting the oldest go would not pass for letting the expired. */
	for (i = 0; i < FZN_CONTACT_REQUESTS_MAX && kept; i++) {
		request_numbered(&r, i, i == 5u ? 1500u : 9000u);
		kept = fzn_contact_request_keep(&store, &r, 1000u + i, &evicted)
		               == FZN_CONTACT_REQUEST_OK
		       && evicted == 0;
	}
	CHECK(kept, "a request under the bound was not kept, or let another go");
	/* ONE MORE: the expired goes, and nobody unanswered. */
	request_numbered(&r, i, 9000u);
	memset(root, 0x33, sizeof(root));
	root[0] = 0;
	root[1] = 5;
	CHECK(fzn_contact_request_keep(&store, &r, 6000u, &evicted) == FZN_CONTACT_REQUEST_OK
	              && evicted == 0
	              && fzn_contact_request_get(&store, root, &probe) == FZN_CONTACT_REQUEST_ERR_ABSENT,
	      "at the bound, the expired request was not the one let go");
	/* AND ANOTHER: the oldest goes, and is counted. */
	request_numbered(&r, i + 1u, 9000u);
	root[1] = 0;
	CHECK(fzn_contact_request_keep(&store, &r, 6001u, &evicted) == FZN_CONTACT_REQUEST_OK
	              && evicted == 1u
	              && fzn_contact_request_get(&store, root, &probe) == FZN_CONTACT_REQUEST_ERR_ABSENT,
	      "at the bound with none expired, the oldest was not let go and counted");
	held = calloc(FZN_CONTACT_REQUESTS_MAX, sizeof(*held));
	CHECK(held && fzn_contact_request_list(&store, held, 16u, &n) == FZN_CONTACT_REQUEST_ERR_ROOM
	              && n == FZN_CONTACT_REQUESTS_MAX
	              && fzn_contact_request_list(&store, held, FZN_CONTACT_REQUESTS_MAX, &n)
	                         == FZN_CONTACT_REQUEST_OK
	              && n == FZN_CONTACT_REQUESTS_MAX && held[0].request.card.host.owner[1] == 1u
	              && held[n - 1u].received_at == 6001u,
	      "the requests at the bound did not list whole, oldest first");
	free(held);

	/* THE USER'S OWN, 3000 of them: no bound. */
	for (i = 0, kept = 1; i < 3000u && kept; i++) {
		request_numbered(&a.request, 0, 9000u);
		request_numbered(&r, i, 9000u);
		a.card = r.card;
		a.answered = 0;
		kept = fzn_contact_asked_keep(&store, &a) == FZN_CONTACT_REQUEST_OK;
	}
	CHECK(kept && fzn_contact_asked_each(&store, counted, &walked) == FZN_CONTACT_REQUEST_OK
	              && walked == 3000u
	              && fzn_contact_asked_list(&store, few, 16u, &n) == FZN_CONTACT_REQUEST_ERR_ROOM
	              && n == 3000u,
	      "3000 requests asked were not all kept, walked and counted");
	many_free();
}

static void test_the_requests_asked(void)
{
	static fzn_contact_asked_t a, back[24];
	uint8_t root[32];
	size_t n = 0, i;

	memset(rows, 0, sizeof(rows));
	for (i = 0; i < 20u; i++) {
		request_from(&a.request, 0x30, 9000u);
		memset(&a.card, 0, sizeof(a.card));
		{
			fzn_contact_request_t other;

			request_from(&other, (uint8_t)(0x70u + i), 9000u);
			a.card = other.card;
		}
		a.answered = 0;
		CHECK(fzn_contact_asked_keep(&STORE, &a) == FZN_CONTACT_REQUEST_OK,
		      "a request asked was not kept");
	}
	memset(root, 0x70, sizeof(root));
	CHECK(fzn_contact_asked_get(&STORE, root, &back[0]) == FZN_CONTACT_REQUEST_OK
	              && !back[0].answered
	              && fzn_contact_asked_answered(&STORE, root) == FZN_CONTACT_REQUEST_OK
	              && fzn_contact_asked_get(&STORE, root, &back[0]) == FZN_CONTACT_REQUEST_OK
	              && back[0].answered
	              && memcmp(back[0].card.host.owner, root, 32u) == 0,
	      "a request answered did not read back answered");
	CHECK(fzn_contact_asked_list(&STORE, back, 24u, &n) == FZN_CONTACT_REQUEST_OK && n == 20u,
	      "the requests asked did not all list");
	memset(root, 0x6f, sizeof(root));
	CHECK(fzn_contact_asked_answered(&STORE, root) == FZN_CONTACT_REQUEST_ERR_ABSENT,
	      "a request never sent was answered");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	memset(target, 0x77, sizeof(target));
	memset(elsewhere, 0x78, sizeof(elsewhere));
	memset(member.b, 0x44, sizeof(member.b));
	test_the_suite_can_tell_pass_from_fail();
	test_a_request_holds_for_its_host();
	test_the_queue_of_strangers();
	test_the_requests_asked();
	test_thousands();
	if (failures) {
		fprintf(stderr, "node contact_request_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node contact_request_test: all %d checks passed\n", checks);
	return 0;
}
