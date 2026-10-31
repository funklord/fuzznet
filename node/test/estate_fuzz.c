/*
 * A fuzz harness for a contact's estate as it reaches this host, secs 776
 * to 783: what a contact's host -- or a member of this user's passing it on
 * -- hands over so this host can judge the contact's devices as their own
 * estate does.
 *
 *   - A PAGE OF THE ROOT'S RECORDS (REVOKED / RECORDS, sec 776).
 *   - AN ESTATE ITEM, and a page of them (ESTATE / ITEMS, sec 781): a root
 *     change or quorum setting, a vote, a confirmation, each with a chain.
 *   - A PAGE OF ROWS a member passes on (KEPT_ESTATE / KEPT_ROWS, sec 782),
 *     and each row as it is taken.
 *   - A PAGE OF A KEY'S ACT LOG (ACTS / ACT_ENTRIES, sec 783).
 *
 * THE PEER LIES BY MUTATION: each input is made whole, then with even odds
 * bent -- bits flipped, cut short, grown, a slice repeated or two bytes
 * swapped.
 *
 * THE PROPERTIES:
 *   1. AN ITEM round-trips; a bent one that decodes encodes back as exactly
 *      its bytes -- one encoding an item.
 *   2. A WHOLE PAGE of each kind is taken whole, each item as made. A BENT
 *      ONE is refused with nothing taken, or taken with every item a slice
 *      of the page's own bytes and no more of them than it claims -- never
 *      half a page.
 *   3. A ROW, whole or bent, taken into a store, then the estate built over
 *      everything kept, and a device judged by it: nothing read past an
 *      end, and a row kept only signed.
 *
 * FLOORS: a run in which no bent item decoded, no bent page of each kind
 * was both refused and taken, or no bent row was kept and none refused, has
 * not tested what it claims.
 */

#include "../contact_devices.h"
#include "../../record/record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 2000u
#define FUZZ_MIN_CASES 500u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL estate_fuzz.c: case %lu: %s\n", c, what);
}

/* ---- a generator, seeded ---------------------------------------------- */

static uint64_t state = 0x9e3779b97f4a7c15ull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

/* ---- the lie ----------------------------------------------------------- */

static size_t bend(uint8_t *p, size_t len, size_t cap)
{
	size_t i, n, a, b;
	uint8_t t;

	if (!len)
		return len;
	switch (next() % 5u) {
	case 0: /* bits flipped */
		n = 1u + (size_t)(next() % 6u);
		for (i = 0; i < n; i++)
			p[next() % len] ^= (uint8_t)(1u << (next() % 8u));
		return len;
	case 1: /* cut short */
		return (size_t)(next() % len);
	case 2: /* grown */
		n = 1u + (size_t)(next() % 32u);
		if (len + n > cap)
			n = cap - len;
		for (i = 0; i < n; i++)
			p[len + i] = (uint8_t)next();
		return len + n;
	case 3: /* a slice repeated */
		a = (size_t)(next() % len);
		n = 1u + (size_t)(next() % 16u);
		if (a + n > len)
			n = len - a;
		if (len + n > cap)
			return len;
		memmove(p + a + n, p + a, len - a);
		return len + n;
	default: /* two bytes swapped */
		a = (size_t)(next() % len);
		b = (size_t)(next() % len);
		t = p[a];
		p[a] = p[b];
		p[b] = t;
		return len;
	}
}

/* ---- a signature and a hash, stubbed: which key signed, not the curve --- */

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

static int mix_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0x84222325cbf29ce4ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 40);
	}
	return 1;
}

static const fzn_hash_ops_t HASH = { mix_hash, NULL };

/* ---- a store in memory, cleared each case -------------------------------- */

#define ROWS 64u

static struct {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[FZN_CONTACT_ESTATE_ROW_MAX];
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
	if (len > sizeof(rows[0].bytes))
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

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, NULL, NULL, NULL };

/* ---- what is made ------------------------------------------------------- */

static uint8_t owner[32], admin_key[32], phone[32];
static fzn_cap_id_t member, admin_cap;

/* An item of a kind chosen at random, signed as its kind needs. */
static void an_item(fzn_contact_estate_item_t *it)
{
	memset(it, 0, sizeof(*it));
	switch (next() % 3u) {
	case 0:
		it->kind = FZN_CONTACT_ESTATE_VOTE;
		it->record_len = FZN_REVOCATION_LEN;
		signing_as = admin_key[0];
		(void)fzn_revocation_issue(admin_key, &member, phone, 100u + (next() % 50u), 0u, NULL,
		                           &SIGN, it->record);
		signing_as = owner[0];
		(void)fzn_chain_mint(owner, admin_key, &admin_cap, 100u, FZN_NO_EXPIRY, 1, &SIGN,
		                     it->hops[0]);
		it->hop_count = 1u;
		break;
	case 1:
		it->kind = FZN_CONTACT_ESTATE_CHANGE;
		it->record_len = FZN_QUORUM_SET_LEN;
		signing_as = owner[0];
		(void)fzn_quorum_set_issue(owner, (uint8_t)(1u + next() % 4u), NULL, &SIGN, it->record);
		break;
	default:
		it->kind = FZN_CONTACT_ESTATE_CHANGE;
		it->record_len = FZN_ROOT_ADD_LEN;
		signing_as = owner[0];
		(void)fzn_root_add_issue(owner, admin_key, &SIGN, it->record);
		break;
	}
}

/* ---- the four pages: made whole by the answer, taken by the step -------- */

static fzn_contact_estate_item_t items[24];
static uint8_t records[24][FZN_REVOCATION_LEN];
static uint8_t row_bytes[24][FZN_CONTACT_ESTATE_ROW_MAX];
static size_t row_lens[24];
static fzn_contact_act_t acts[24];
static size_t n_made;

/* WHAT A STEP TOOK, each checked against the page it came from. */
static const uint8_t *page_at;
static size_t page_len_at, taken, foreign;

/* Whether `p`, `len` bytes, lies within the page. */
static int within(const uint8_t *p, size_t len)
{
	size_t i;

	for (i = 0; i + len <= page_len_at; i++)
		if (memcmp(page_at + i, p, len) == 0)
			return 1;
	return 0;
}

static int record_at(void *ctx, size_t i, uint8_t out[FZN_REVOCATION_LEN])
{
	(void)ctx;
	if (i >= n_made)
		return 0;
	memcpy(out, records[i], FZN_REVOCATION_LEN);
	return 1;
}

static void take_record(void *ctx, const uint8_t record[FZN_REVOCATION_LEN])
{
	(void)ctx;
	taken++;
	foreign += !within(record, FZN_REVOCATION_LEN);
}

static int item_at(void *ctx, size_t i, fzn_contact_estate_item_t *out)
{
	(void)ctx;
	if (i >= n_made)
		return 0;
	*out = items[i];
	return 1;
}

static void take_item(void *ctx, const fzn_contact_estate_item_t *item)
{
	static uint8_t bytes[FZN_CONTACT_ESTATE_ITEM_MAX];
	size_t len = 0;

	(void)ctx;
	taken++;
	/* AS ITS BYTES SAID: encoded back, it is a slice of the page. */
	foreign += fzn_contact_estate_item_encode(item, bytes, sizeof(bytes), &len)
	                   != FZN_CONTACT_DEVICE_OK
	           || !within(bytes, len);
}

static int row_at(void *ctx, size_t i, uint8_t *out, size_t *len)
{
	(void)ctx;
	if (i >= n_made)
		return 0;
	memcpy(out, row_bytes[i], row_lens[i]);
	*len = row_lens[i];
	return 1;
}

static void take_row(void *ctx, const uint8_t *row, size_t len)
{
	(void)ctx;
	taken++;
	foreign += !within(row, len);
}

static int act_at(void *ctx, const uint8_t key[32], size_t i, fzn_contact_act_t *out)
{
	(void)ctx;
	(void)key;
	if (i >= n_made)
		return 0;
	*out = acts[i];
	return 1;
}

static void take_act(void *ctx, const uint8_t key[32], const fzn_contact_act_t *act)
{
	(void)ctx;
	(void)key;
	taken++;
	foreign += act->len > FZN_CONTACT_ACT_MAX || !within(act->bytes, act->len);
}

/* ONE PAGE OF `kind`, made whole by its answer, bent with even odds, then
 * stepped: `*refused` when the step would not take it, `*bent` when it was
 * bent. 0 when a property failed. */
static int a_page(int kind, int *bent, int *refused)
{
	static uint8_t page[FZN_CONTACT_DEVICES_REPLY_MAX + 64u], req[64];
	fzn_contact_revoked_querying_t rq;
	fzn_contact_estate_querying_t eq;
	fzn_contact_rows_querying_t wq;
	fzn_contact_acts_querying_t aq;
	size_t req_len = 0, len = 0, claimed;
	int ok = 0, done = 0;

	switch (kind) {
	case 0:
		(void)fzn_contact_revoked_query_begin(&rq, take_record, NULL, req, sizeof(req), &req_len);
		len = fzn_contact_revoked_answer(req, req_len, record_at, NULL, page,
		                                 FZN_CONTACT_DEVICES_REPLY_MAX);
		break;
	case 1:
		(void)fzn_contact_estate_query_begin(&eq, take_item, NULL, req, sizeof(req), &req_len);
		len = fzn_contact_estate_answer(req, req_len, item_at, 2u, NULL, page,
		                                FZN_CONTACT_DEVICES_REPLY_MAX);
		break;
	case 2:
		(void)fzn_contact_rows_query_begin(&wq, take_row, NULL, req, sizeof(req), &req_len);
		len = fzn_contact_rows_answer(req, req_len, row_at, NULL, page,
		                              FZN_CONTACT_DEVICES_REPLY_MAX);
		break;
	default:
		(void)fzn_contact_acts_query_begin(&aq, admin_key, take_act, NULL, req, sizeof(req),
		                                   &req_len);
		len = fzn_contact_acts_answer(req, req_len, act_at, NULL, page,
		                              FZN_CONTACT_DEVICES_REPLY_MAX);
		break;
	}
	if (!len)
		return 0;
	claimed = page[6];
	*bent = (int)(next() & 1u);
	if (*bent)
		len = bend(page, len, sizeof(page));
	page_at = page;
	page_len_at = len;
	taken = foreign = 0;
	switch (kind) {
	case 0:
		ok = fzn_contact_revoked_query_step(&rq, page, len, req, sizeof(req), &req_len, &done);
		break;
	case 1:
		ok = fzn_contact_estate_query_step(&eq, page, len, req, sizeof(req), &req_len, &done);
		break;
	case 2:
		ok = fzn_contact_rows_query_step(&wq, page, len, req, sizeof(req), &req_len, &done);
		break;
	default:
		ok = fzn_contact_acts_query_step(&aq, page, len, req, sizeof(req), &req_len, &done);
		break;
	}
	*refused = !ok;
	/* REFUSED, NOTHING TAKEN; TAKEN, ONLY THE PAGE'S OWN AND NO MORE THAN
	 * IT CLAIMED; WHOLE, ALL OF IT. */
	if (!ok)
		return taken == 0u;
	if (foreign || (!*bent && taken != claimed) || taken > 255u)
		return 0;
	return 1;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long item_bent = 0, refused_of[4] = { 0 }, taken_of[4] = { 0 };
	unsigned long row_kept = 0, row_refused = 0;
	static fzn_contact_device_t d;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases < FUZZ_MIN_CASES)
			cases = FUZZ_MIN_CASES;
	}
	if (argc > 2)
		state = strtoull(argv[2], NULL, 0) | 1u;
	memset(owner, 0x11, sizeof(owner));
	memset(admin_key, 0x77, sizeof(admin_key));
	memset(phone, 0x22, sizeof(phone));
	memset(member.b, 0x44, sizeof(member.b));
	memset(admin_cap.b, 0x66, sizeof(admin_cap.b));
	/* THE DEVICE JUDGED: the owner's member, one hop. */
	memset(&d, 0, sizeof(d));
	memcpy(d.owner, owner, 32u);
	{
		uint8_t agree[FZN_PREKEY_LEN];

		memset(agree, 0x78, sizeof(agree));
		signing_as = phone[0];
		(void)fzn_prekey_issue(phone, agree, 1000u, &SIGN, d.record);
		signing_as = owner[0];
		(void)fzn_chain_mint(owner, phone, &member, 100u, FZN_NO_EXPIRY, 0, &SIGN, d.hops[0]);
		d.hop_count = 1u;
	}

	for (c = 0; c < cases; c++) {
		size_t i;
		int kind;

		/* WHAT THE PAGES CARRY, a few of each. */
		n_made = 1u + (size_t)(next() % 20u);
		for (i = 0; i < n_made; i++) {
			uint8_t zero[32] = { 0 }, subject[32], id[32];
			size_t len = 0;

			an_item(&items[i]);
			signing_as = owner[0];
			(void)fzn_revocation_issue(owner, &member, phone, 200u + i, 0u, NULL, &SIGN,
			                           records[i]);
			memcpy(row_bytes[i], owner, 32u);
			(void)fzn_contact_estate_item_encode(&items[i], row_bytes[i] + 32u,
			                                     sizeof(row_bytes[i]) - 32u, &len);
			row_lens[i] = 32u + len;
			memset(subject, (int)(next() & 0xffu), sizeof(subject));
			memset(&acts[i], 0, sizeof(acts[i]));
			if (next() & 1u) {
				acts[i].spine = 1;
				acts[i].len = FZN_CONTACT_ACT_SPINE_LEN;
				memcpy(acts[i].bytes, subject, 32u);
				memcpy(acts[i].bytes + 64u, subject, 32u);
			} else {
				signing_as = admin_key[0];
				(void)fzn_record_sign(admin_key, subject, 1u, 1u, i + 1u, zero, 300u, subject,
				                      8u, &SIGN, acts[i].bytes, sizeof(acts[i].bytes),
				                      &acts[i].len);
				(void)id;
			}
		}

		/* 1: AN ITEM. */
		{
			static uint8_t bytes[FZN_CONTACT_ESTATE_ITEM_MAX + 64u], again[FZN_CONTACT_ESTATE_ITEM_MAX];
			static fzn_contact_estate_item_t back;
			size_t len = 0, n = 0;

			if (fzn_contact_estate_item_encode(&items[0], bytes, sizeof(bytes), &len)
			            != FZN_CONTACT_DEVICE_OK
			    || fzn_contact_estate_item_decode(bytes, len, &back) != FZN_CONTACT_DEVICE_OK
			    || fzn_contact_estate_item_encode(&back, again, sizeof(again), &n)
			               != FZN_CONTACT_DEVICE_OK
			    || n != len || memcmp(again, bytes, len) != 0)
				fail("a whole item did not round-trip", c);
			len = bend(bytes, len, sizeof(bytes));
			if (fzn_contact_estate_item_decode(bytes, len, &back) == FZN_CONTACT_DEVICE_OK) {
				item_bent++;
				if (fzn_contact_estate_item_encode(&back, again, sizeof(again), &n)
				            != FZN_CONTACT_DEVICE_OK
				    || n != len || memcmp(again, bytes, len) != 0)
					fail("a bent item decoded to other than its own bytes", c);
			}
		}

		/* 2: A PAGE OF EACH KIND. */
		for (kind = 0; kind < 4; kind++) {
			int bent = 0, refused = 0;

			if (!a_page(kind, &bent, &refused))
				fail(kind == 0   ? "a page of the root's records was taken in part or foreign"
				     : kind == 1 ? "a page of estate items was taken in part or foreign"
				     : kind == 2 ? "a page of rows was taken in part or foreign"
				                 : "a page of an act log was taken in part or foreign",
				     c);
			if (bent && refused)
				refused_of[kind]++;
			if (bent && !refused)
				taken_of[kind]++;
		}

		/* 3: ROWS TAKEN, then the estate built over them and a device
		 * judged. Every few cases the store starts empty. */
		if (c % 8u == 0u)
			memset(rows, 0, sizeof(rows));
		for (i = 0; i < 3u && i < n_made; i++) {
			static uint8_t row[FZN_CONTACT_ESTATE_ROW_MAX + 64u];
			size_t len = row_lens[i];
			fzn_contact_device_err_t err;
			int bent = (int)(next() & 1u);

			memcpy(row, row_bytes[i], len);
			if (bent)
				len = bend(row, len, sizeof(row));
			err = fzn_contact_estate_take_row(&STORE, &HASH, &SIGN, 1u, row, len);
			if (bent && err == FZN_CONTACT_DEVICE_OK)
				row_kept++;
			if (bent && err == FZN_CONTACT_DEVICE_ERR_REFUSED)
				row_refused++;
			if (!bent && err != FZN_CONTACT_DEVICE_OK)
				fail("a whole row, signed, was not kept", c);
		}
		{
			fzn_contact_estate_t *e =
			        fzn_contact_estate_open(&STORE, owner, &member, &admin_cap, &SIGN, &HASH);

			if (!e)
				fail("the estate would not build over what was kept", c);
			(void)fzn_contact_estate_revoked(e, &d);
			fzn_contact_estate_close(e);
		}
	}

	{
		int k;

		if (item_bent == 0u)
			fail("FLOOR: no bent item decoded", cases);
		for (k = 0; k < 4; k++)
			if (refused_of[k] == 0u || taken_of[k] == 0u)
				fail("FLOOR: a page kind was never both refused and taken bent", cases);
		if (row_kept == 0u || row_refused == 0u)
			fail("FLOOR: no bent row was kept, or none refused", cases);
	}
	if (failures) {
		fprintf(stderr, "estate_fuzz: %lu cases, %d failure(s)\n", cases, failures);
		return 1;
	}
	printf("estate_fuzz: %lu cases, 0 failure(s); bent items decoded %lu, pages refused/taken "
	       "%lu/%lu %lu/%lu %lu/%lu %lu/%lu, rows kept %lu refused %lu\n",
	       cases, item_bent, refused_of[0], taken_of[0], refused_of[1], taken_of[1],
	       refused_of[2], taken_of[2], refused_of[3], taken_of[3], row_kept, row_refused);
	return 0;
}
