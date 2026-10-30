/* node contact_devices_test -- a contact's devices, sec 614: the entry's
 * encoding, what makes one hold, and the store. A stub signature keyed by a
 * key's first byte, as routing_test's, since what is tested is which key
 * signed, not the curve. */

#include "../contact_devices.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL contact_devices_test.c:%d: %s\n", __LINE__, what); \
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

/* ---- a store ------------------------------------------------------------ */

#define ROWS 8u

static struct {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[32];
	uint8_t bytes[FZN_CONTACT_DEVICE_MAX];
	size_t len;
} rows[ROWS];

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used && slot == rows[i].slot
		    && memcmp(rows[i].subject, subject, 32u) == 0 && rows[i].len <= cap) {
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
	if ((slot != FZN_PERSIST_CONTACT_DEVICE && slot != FZN_PERSIST_CONTACT_REVOCATION)
	    || len > sizeof(rows[0].bytes))
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
	if (slot != FZN_PERSIST_CONTACT_DEVICE && slot != FZN_PERSIST_CONTACT_REVOCATION)
		return 0;
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
		if (rows[i].used && slot == rows[i].slot
		    && memcmp(rows[i].subject, subject, 32u) == 0)
			rows[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL, NULL };

/* ---- fixtures ----------------------------------------------------------- */

static uint8_t owner[32], phone[32], other[32];
static fzn_cap_id_t member, share;

/* `d` for `host`, owned by `owner`, its record dated `at`. */
static void device(fzn_contact_device_t *d, const uint8_t host[32], uint64_t at)
{
	uint8_t agree[FZN_PREKEY_LEN];

	memset(d, 0, sizeof(*d));
	memcpy(d->owner, owner, 32u);
	memset(agree, host[0] ^ 0x5au, sizeof(agree));
	signing_as = host[0];
	(void)fzn_prekey_issue(host, agree, at, &SIGN, d->record);
}

/* The owner's chain to `host` for `cap`, one hop. */
static void granted(fzn_contact_device_t *d, const uint8_t host[32], const fzn_cap_id_t *cap)
{
	signing_as = owner[0];
	d->hop_count = fzn_chain_mint(owner, host, cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, d->hops[0])
	                               == FZN_CHAIN_OK
	                       ? 1u
	                       : 0u;
}

static void test_an_entry_round_trips(void)
{
	static fzn_contact_device_t d, back;
	static uint8_t bytes[FZN_CONTACT_DEVICE_MAX];
	size_t len = 0;

	device(&d, phone, 1000u);
	granted(&d, phone, &member);
	memcpy(d.address, "host-1.example", 14u);
	d.address_len = 14u;
	d.port = 47000u;
	CHECK(fzn_contact_device_encode(&d, bytes, sizeof(bytes), &len) == FZN_CONTACT_DEVICE_OK
	              && len == FZN_CONTACT_DEVICE_HEAD_LEN + 1u + 14u + 2u + 1u + FZN_HOP_LEN
	              && fzn_contact_device_decode(bytes, len, &back) == FZN_CONTACT_DEVICE_OK
	              && memcmp(back.owner, owner, 32u) == 0
	              && memcmp(fzn_contact_device_key(&back), phone, 32u) == 0
	              && back.address_len == 14u && memcmp(back.address, "host-1.example", 14u) == 0
	              && back.port == 47000u && back.hop_count == 1u
	              && memcmp(back.hops[0], d.hops[0], FZN_HOP_LEN) == 0,
	      "an entry with an address and a chain decodes to itself");
	CHECK(fzn_contact_device_decode(bytes, len - 1u, &back) == FZN_CONTACT_DEVICE_ERR_SHAPE
	              && (bytes[len] = 0, fzn_contact_device_decode(bytes, len + 1u, &back))
	                         == FZN_CONTACT_DEVICE_ERR_SHAPE,
	      "an entry a byte short or long decodes");
	bytes[0] = 2u;
	CHECK(fzn_contact_device_decode(bytes, len, &back) == FZN_CONTACT_DEVICE_ERR_SHAPE,
	      "another version decodes");
	d.port = 0u;
	CHECK(fzn_contact_device_encode(&d, bytes, sizeof(bytes), &len)
	              == FZN_CONTACT_DEVICE_ERR_MALFORMED,
	      "an address with no port encodes");
	d.port = 1u;
	memcpy(d.address, "a b", 3u);
	d.address_len = 3u;
	CHECK(fzn_contact_device_encode(&d, bytes, sizeof(bytes), &len)
	              == FZN_CONTACT_DEVICE_ERR_MALFORMED,
	      "an address with a space encodes");
	d.address_len = 0u;
	d.port = 0u;
	CHECK(fzn_contact_device_encode(&d, bytes, sizeof(bytes), &len) == FZN_CONTACT_DEVICE_OK
	              && (bytes[FZN_CONTACT_DEVICE_HEAD_LEN + 2u] = 9u,
	                  fzn_contact_device_decode(bytes, len, &back))
	                         == FZN_CONTACT_DEVICE_ERR_SHAPE,
	      "a port with no address decodes");
}

static void test_what_makes_one_hold(void)
{
	static fzn_contact_device_t d;

	device(&d, owner, 1000u);
	CHECK(fzn_contact_device_verify(&d, &SIGN, &member, 2000u) == FZN_CONTACT_DEVICE_OK,
	      "the owner's own record, no chain, did not hold");
	device(&d, phone, 1000u);
	CHECK(fzn_contact_device_verify(&d, &SIGN, &member, 2000u) == FZN_CONTACT_DEVICE_ERR_REFUSED,
	      "another key with no chain held");
	granted(&d, phone, &member);
	CHECK(fzn_contact_device_verify(&d, &SIGN, &member, 2000u) == FZN_CONTACT_DEVICE_OK,
	      "a member by the owner's chain did not hold");
	granted(&d, phone, &share);
	CHECK(fzn_contact_device_verify(&d, &SIGN, &member, 2000u) == FZN_CONTACT_DEVICE_ERR_REFUSED,
	      "a key the owner granted another capability -- a contact of theirs -- held");
	granted(&d, other, &member);
	CHECK(fzn_contact_device_verify(&d, &SIGN, &member, 2000u) == FZN_CONTACT_DEVICE_ERR_REFUSED,
	      "a record carried with a chain to another key held");
	granted(&d, phone, &member);
	memcpy(d.owner, other, 32u);
	CHECK(fzn_contact_device_verify(&d, &SIGN, &member, 2000u) == FZN_CONTACT_DEVICE_ERR_REFUSED,
	      "an entry naming another owner than its chain's held");
	memcpy(d.owner, owner, 32u);
	d.record[FZN_PREKEY_OFF_PREKEY] ^= 1u;
	CHECK(fzn_contact_device_verify(&d, &SIGN, &member, 2000u) == FZN_CONTACT_DEVICE_ERR_REFUSED,
	      "a record whose prekey was changed after signing held");
}

static void test_the_store(void)
{
	static fzn_contact_device_t d, got, list[FZN_CONTACT_DEVICES_MAX];
	size_t count = 0;

	memset(rows, 0, sizeof(rows));
	device(&d, phone, 1000u);
	granted(&d, phone, &member);
	CHECK(fzn_contact_device_keep(&STORE, &d) == FZN_CONTACT_DEVICE_OK
	              && fzn_contact_device_get(&STORE, phone, &got) == FZN_CONTACT_DEVICE_OK
	              && got.hop_count == 1u && got.port == 0u,
	      "a device kept reads back");
	memcpy(d.address, "10.0.0.2", 8u);
	d.address_len = 8u;
	d.port = 47000u;
	CHECK(fzn_contact_device_keep(&STORE, &d) == FZN_CONTACT_DEVICE_OK
	              && fzn_contact_device_get(&STORE, phone, &got) == FZN_CONTACT_DEVICE_OK
	              && got.port == 47000u,
	      "the same record with an address replaces it");
	device(&d, phone, 900u);
	granted(&d, phone, &member);
	CHECK(fzn_contact_device_keep(&STORE, &d) == FZN_CONTACT_DEVICE_ERR_STALE
	              && fzn_contact_device_get(&STORE, phone, &got) == FZN_CONTACT_DEVICE_OK
	              && got.port == 47000u,
	      "an older record replaced the newer");
	device(&d, owner, 1000u);
	CHECK(fzn_contact_device_keep(&STORE, &d) == FZN_CONTACT_DEVICE_OK
	              && fzn_contact_device_list(&STORE, list, FZN_CONTACT_DEVICES_MAX, &count)
	                         == FZN_CONTACT_DEVICE_OK
	              && count == 2u,
	      "two devices list");
	/* A ROW UNDER ANOTHER KEY is one nobody kept. */
	memcpy(rows[0].subject, other, 32u);
	CHECK(fzn_contact_device_get(&STORE, other, &got) == FZN_CONTACT_DEVICE_ERR_ABSENT
	              && fzn_contact_device_list(&STORE, list, FZN_CONTACT_DEVICES_MAX, &count)
	                         == FZN_CONTACT_DEVICE_OK
	              && count == 1u,
	      "a row filed under another device's key read as that device");
	CHECK(fzn_contact_device_remove(&STORE, owner) == FZN_CONTACT_DEVICE_OK
	              && fzn_contact_device_get(&STORE, owner, &got) == FZN_CONTACT_DEVICE_ERR_ABSENT
	              && fzn_contact_device_remove(&STORE, owner) == FZN_CONTACT_DEVICE_ERR_ABSENT,
	      "a device removed is gone, and removing it again says so");
}

/* ---- the messages -------------------------------------------------------- */

/* THE ANSWERER: five hosts with full chains, so a page holds two; KEPT is
 * not answered. `mode` 1 echoes another `from`; 2 adds a trailing byte. */
static fzn_contact_device_t hosts[5];
static int mode;
static size_t taken_n, offered_n;

static int hosts_at(void *ctx, size_t i, fzn_contact_device_t *out)
{
	(void)ctx;
	if (i >= 5u)
		return 0;
	*out = hosts[i];
	return 1;
}

static int take_offer(void *ctx, const fzn_contact_device_t *d)
{
	(void)ctx;
	offered_n++;
	return memcmp(fzn_contact_device_key(d), phone, 32u) == 0;
}

static int link(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                size_t reply_cap, size_t *reply_len)
{
	size_t n;

	(void)ctx;
	n = fzn_contact_devices_offer_answer(request, request_len, take_offer, NULL, reply,
	                                     reply_cap);
	if (!n)
		n = fzn_contact_devices_query_answer(request, request_len, hosts_at, NULL, NULL,
		                                     reply, reply_cap);
	if (!n)
		return 0;
	if (mode == 1 && reply[1] == FZN_CONTACT_DEVICES_LIST)
		reply[2] ^= 1u;
	if (mode == 2 && n < reply_cap)
		reply[n++] = 0u;
	*reply_len = n;
	return 1;
}

static void take(void *ctx, const fzn_contact_device_t *d)
{
	(void)ctx;
	(void)d;
	taken_n++;
}

/* ---- AT THOUSANDS, sec 704 --------------------------------------------- *
 *
 * A store of 5000 rows that walks, past the generic fallback's room: every
 * contact's devices together were once read into 128, and past it the
 * listing failed and delivery to every contact stopped with nothing said. */
#define BIG_ROWS 5000u
static struct {
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_CONTACT_DEVICE_MAX];
	size_t len;
} big[BIG_ROWS];
static size_t big_used;

static int big_find(const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < big_used; i++)
		if (memcmp(big[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return (int)i;
	return -1;
}

static int big_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	int i = big_find(subject);

	(void)ctx;
	(void)slot;
	if (i < 0 || big[i].len > cap)
		return 0;
	memcpy(out, big[i].bytes, big[i].len);
	*len = big[i].len;
	return 1;
}

static int big_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	int i = big_find(subject);

	(void)ctx;
	(void)slot;
	if (i < 0) {
		if (big_used == BIG_ROWS || len > sizeof(big[0].bytes))
			return 0;
		i = (int)big_used++;
		memcpy(big[i].subject, subject, FZN_PUBKEY_LEN);
	}
	memcpy(big[i].bytes, bytes, len);
	big[i].len = len;
	return 1;
}

static int big_each(void *ctx, fzn_persist_slot_t slot,
                    int (*fn)(void *arg, const uint8_t subject[FZN_PUBKEY_LEN]), void *arg)
{
	size_t i;

	(void)ctx;
	(void)slot;
	for (i = 0; i < big_used; i++)
		if (!fn(arg, big[i].subject))
			break;
	return 1;
}

static void test_thousands_of_devices(void)
{
	static fzn_contact_device_t d, list[BIG_ROWS];
	fzn_persist_ops_t store;
	uint8_t host[32];
	size_t k, kept = 0, count = 0;

	memset(&store, 0, sizeof(store));
	store.load = big_load;
	store.save = big_save;
	store.each = big_each;
	big_used = 0;
	for (k = 0; k < 4500u; k++) {
		memcpy(host, phone, sizeof(host));
		host[1] = (uint8_t)k;
		host[2] = (uint8_t)(k >> 8);
		device(&d, host, 1000u);
		kept += fzn_contact_device_keep(&store, &d) == FZN_CONTACT_DEVICE_OK;
	}
	CHECK(kept == 4500u, "fixture: 4500 devices kept");
	CHECK(fzn_contact_device_list(&store, list, FZN_CONTACT_DEVICES_MAX, &count)
	                      == FZN_CONTACT_DEVICE_ERR_ROOM
	              && count == 4500u,
	      "4500 devices in room for 128 did not answer room with the count");
	CHECK(fzn_contact_device_list(&store, list, BIG_ROWS, &count) == FZN_CONTACT_DEVICE_OK
	              && count == 4500u,
	      "4500 devices did not list into room for them");
}

static void test_the_messages(void)
{
	static fzn_contact_device_t d;
	size_t i, h, count = 0;

	device(&d, phone, 1000u);
	granted(&d, phone, &member);
	offered_n = 0;
	CHECK(fzn_contact_devices_offer(&d, link, NULL) == 1 && offered_n == 1u,
	      "an offer reached the answerer and was taken");
	device(&d, other, 1000u);
	CHECK(fzn_contact_devices_offer(&d, link, NULL) == 0, "an offer refused read as taken");

	for (i = 0; i < 5u; i++) {
		uint8_t key[32];

		memset(key, 0x60 + (int)i, sizeof(key));
		device(&hosts[i], key, 1000u);
		memcpy(hosts[i].address, "10.0.0.1", 8u);
		hosts[i].address_len = 8u;
		hosts[i].port = (uint16_t)(47000u + i);
		signing_as = owner[0];
		for (h = 0; h < FZN_CHAIN_MAX_HOPS; h++)
			(void)fzn_chain_mint(owner, key, &member, 100u, FZN_NO_EXPIRY, 0, &SIGN,
			                     hosts[i].hops[h]);
		hosts[i].hop_count = FZN_CHAIN_MAX_HOPS;
	}
	mode = 0;
	taken_n = 0;
	CHECK(fzn_contact_devices_query(FZN_CONTACT_DEVICES_HOSTS, link, NULL, take, NULL, &count)
	              && count == 5u && taken_n == 5u,
	      "five of the largest entries, over pages, all arrived once");
	/* BY STEPS, sec 636: the same pages, each answer handed in; and no
	 * answer ending it. */
	{
		static uint8_t page[FZN_CONTACT_DEVICES_REPLY_MAX];
		fzn_contact_devices_querying_t q;
		uint8_t req[FZN_CONTACT_DEVICES_QUERY_LEN];
		size_t req_len = 0, page_len, pages = 0;
		int ok, done = 0;

		taken_n = 0;
		ok = fzn_contact_devices_query_begin(&q, FZN_CONTACT_DEVICES_HOSTS, take, NULL, req,
		                                     sizeof(req), &req_len);
		while (ok && !done && pages++ < 16u) {
			page_len = 0;
			(void)link(NULL, req, req_len, page, sizeof(page), &page_len);
			ok = fzn_contact_devices_query_step(&q, page, page_len, req, sizeof(req), &req_len,
			                                    &done);
		}
		CHECK(ok && done && pages > 1u && q.count == 5u && taken_n == 5u,
		      "the devices queried by steps, over pages, are not the five");
		CHECK(fzn_contact_devices_query_begin(&q, FZN_CONTACT_DEVICES_HOSTS, take, NULL, req,
		                                      sizeof(req), &req_len)
		              && !fzn_contact_devices_query_step(&q, NULL, 0, req, sizeof(req),
		                                                 &req_len, &done)
		              && done
		              && !fzn_contact_devices_query_step(&q, page, 8, req, sizeof(req),
		                                                 &req_len, &done),
		      "a devices query with no answer did not end, refusing a step after");
	}
	taken_n = 0;
	CHECK(!fzn_contact_devices_query(FZN_CONTACT_DEVICES_KEPT, link, NULL, take, NULL, &count)
	              && taken_n == 0u,
	      "a list the answerer does not answer read as one");
	mode = 1;
	CHECK(!fzn_contact_devices_query(FZN_CONTACT_DEVICES_HOSTS, link, NULL, take, NULL, &count),
	      "a page answering another `from` was taken");
	mode = 2;
	CHECK(!fzn_contact_devices_query(FZN_CONTACT_DEVICES_HOSTS, link, NULL, take, NULL, &count),
	      "a page with a trailing byte was taken");
	CHECK(fzn_contact_devices_offer(&d, link, NULL) == -1,
	      "a TAKEN with a trailing byte was read as an answer");
	mode = 0;
}

/* ---- a contact's revocations, sec 776 ------------------------------------ */

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

/* `issuer` revokes `grantee` of `cap`, its line at `cut` (NULL none). */
static void revoked_by(uint8_t out[FZN_REVOCATION_LEN], const uint8_t issuer[32],
                       const fzn_cap_id_t *cap, const uint8_t grantee[32], uint64_t at,
                       const uint8_t *cut)
{
	signing_as = issuer[0];
	(void)fzn_revocation_issue(issuer, cap, grantee, at, 0u, cut, &SIGN, out);
}

static size_t rows_in(fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		n += rows[i].used && rows[i].slot == slot;
	return n;
}

static void test_a_contacts_revocations(void)
{
	static fzn_revocation_t e[8], e2[8];
	static fzn_contact_device_t d, mine, deep;
	fzn_revocation_store_t rs, fresh;
	uint8_t rec[FZN_REVOCATION_LEN], undo[FZN_REVOCATION_LEN], foreign[FZN_REVOCATION_LEN];
	uint8_t target[FZN_REVOCATION_ID_LEN], line[FZN_REVOCATION_ID_LEN];
	size_t count = 0, skipped = 0;

	memset(rows, 0, sizeof(rows));
	CHECK(fzn_revocation_store_init(&rs, e, 8u) == FZN_CHAIN_OK, "fixture: a store");
	device(&d, phone, 1000u);
	granted(&d, phone, &member);
	device(&mine, owner, 1000u);
	CHECK(!fzn_contact_device_revoked(&d, &rs, &member), "a device fell with nothing held");

	/* THE OWNER'S, AND NOBODY ELSE'S. */
	revoked_by(foreign, other, &member, phone, 200u, NULL);
	CHECK(fzn_contact_revocation_take(&rs, &STORE, owner, &member, foreign, &SIGN, &HASH)
	                      == FZN_CONTACT_DEVICE_ERR_REFUSED
	              && rows_in(FZN_PERSIST_CONTACT_REVOCATION) == 0u,
	      "another key's revocation of the owner's device was taken");
	revoked_by(foreign, owner, &share, phone, 200u, NULL);
	CHECK(fzn_contact_revocation_take(&rs, &STORE, owner, &member, foreign, &SIGN, &HASH)
	              == FZN_CONTACT_DEVICE_ERR_REFUSED,
	      "the owner's revocation of another capability was taken");
	revoked_by(rec, owner, &member, phone, 200u, NULL);
	memcpy(foreign, rec, sizeof(rec));
	foreign[FZN_REV_OFF_GRANTEE] ^= 1u;
	CHECK(fzn_contact_revocation_take(&rs, &STORE, owner, &member, foreign, &SIGN, &HASH)
	              == FZN_CONTACT_DEVICE_ERR_REFUSED,
	      "a record whose grantee was changed after signing was taken");
	CHECK(!fzn_contact_device_revoked(&d, &rs, &member), "a refused record dropped a device");

	/* TAKEN, SAVED, AND THE DEVICE FALLS; THE OWNER ITSELF NEVER. */
	CHECK(fzn_contact_revocation_take(&rs, &STORE, owner, &member, rec, &SIGN, &HASH)
	                      == FZN_CONTACT_DEVICE_OK
	              && rows_in(FZN_PERSIST_CONTACT_REVOCATION) == 1u
	              && fzn_contact_device_revoked(&d, &rs, &member),
	      "the owner's revocation was not taken and saved, or its device did not fall");
	revoked_by(foreign, owner, &member, owner, 200u, NULL);
	(void)fzn_contact_revocation_take(&rs, &STORE, owner, &member, foreign, &SIGN, &HASH);
	CHECK(!fzn_contact_device_revoked(&mine, &rs, &member), "the owner fell by its own record");
	{
		static fzn_contact_device_t elsewhere;

		elsewhere = d;
		memset(elsewhere.owner, 0x66, sizeof(elsewhere.owner));
		CHECK(!fzn_contact_device_revoked(&elsewhere, &rs, &member),
		      "a device of another owner fell by this owner's record");
	}

	/* WITHDRAWN: THE DEVICE STANDS, AND A STALE COPY IS NOT SAVED OVER IT. */
	(void)mix_hash(NULL, target, sizeof(target), rec, sizeof(rec));
	signing_as = owner[0];
	CHECK(fzn_revocation_issue_withdrawal(owner, &member, phone, 300u, 0u, target, &SIGN, undo)
	                      == FZN_CHAIN_OK
	              && fzn_contact_revocation_take(&rs, &STORE, owner, &member, undo, &SIGN, &HASH)
	                         == FZN_CONTACT_DEVICE_OK
	              && !fzn_contact_device_revoked(&d, &rs, &member),
	      "the owner's withdrawal did not restore the device");
	CHECK(fzn_contact_revocation_take(&rs, &STORE, owner, &member, rec, &SIGN, &HASH)
	                      == FZN_CONTACT_DEVICE_OK
	              && !fzn_contact_device_revoked(&d, &rs, &member),
	      "the withdrawn revocation, handed over again, dropped the device");

	/* A RESTART: WHAT WAS SAVED ADMITS AGAIN, the withdrawal and not the
	 * stale copy. */
	CHECK(fzn_revocation_store_init(&fresh, e2, 8u) == FZN_CHAIN_OK
	              && fzn_contact_revocations_load(&fresh, &STORE, &SIGN, &HASH, &count,
	                                              &skipped)
	                         == FZN_CONTACT_DEVICE_OK
	              && count == 2u && skipped == 0u && !fzn_contact_device_revoked(&d, &fresh, &member),
	      "a restart did not load the two records saved, or read the device as revoked");
	CHECK(fzn_revocation_store_init(&fresh, e2, 1u) == FZN_CHAIN_OK
	              && fzn_contact_revocations_load(&fresh, &STORE, &SIGN, &HASH, &count,
	                                              &skipped)
	                         == FZN_CONTACT_DEVICE_ERR_ROOM,
	      "a load into a store with no room was not ROOM");

	/* LISTED FOR A MEMBER, sec 780: each row once, as saved. */
	{
		uint8_t listed[4][FZN_REVOCATION_LEN];
		size_t n = 0, i, withdrawals = 0;
		fzn_revocation_record_t got;

		CHECK(fzn_contact_revocations_list(&STORE, &HASH, listed, 4u, &n)
		                      == FZN_CONTACT_DEVICE_OK
		              && n == 2u,
		      "the two rows saved did not list");
		for (i = 0; i < n && i < 4u; i++)
			withdrawals += fzn_revocation_open(listed[i], FZN_REVOCATION_LEN, &got)
			                       == FZN_CHAIN_OK
			               && fzn_revocation_is_withdrawal(got);
		CHECK(withdrawals == 1u, "the withdrawal saved did not list as itself");
		n = 9u;
		CHECK(fzn_contact_revocations_list(&STORE, &HASH, listed, 1u, &n)
		                      == FZN_CONTACT_DEVICE_ERR_ROOM
		              && n == 2u,
		      "no room for the rows was not ROOM with the count");
	}

	/* A KEY ABOVE THE DEVICE: falls with it when its vote trusts none of
	 * its acts, and is not judged under a line. */
	memset(rows, 0, sizeof(rows));
	CHECK(fzn_revocation_store_init(&rs, e, 8u) == FZN_CHAIN_OK, "fixture: a store again");
	device(&deep, phone, 1000u);
	signing_as = owner[0];
	(void)fzn_chain_mint(owner, other, &member, 100u, FZN_NO_EXPIRY, 1, &SIGN, deep.hops[0]);
	signing_as = other[0];
	(void)fzn_chain_mint(other, phone, &member, 100u, FZN_NO_EXPIRY, 0, &SIGN, deep.hops[1]);
	deep.hop_count = 2u;
	memset(line, 0x99, sizeof(line));
	revoked_by(rec, owner, &member, other, 200u, line);
	CHECK(fzn_contact_revocation_take(&rs, &STORE, owner, &member, rec, &SIGN, &HASH)
	                      == FZN_CONTACT_DEVICE_OK
	              && !fzn_contact_device_revoked(&deep, &rs, &member),
	      "a device fell by its grantor's revocation under a line");
	memset(rows, 0, sizeof(rows));
	CHECK(fzn_revocation_store_init(&rs, e, 8u) == FZN_CHAIN_OK, "fixture: a store a third time");
	revoked_by(rec, owner, &member, other, 200u, NULL);
	CHECK(fzn_contact_revocation_take(&rs, &STORE, owner, &member, rec, &SIGN, &HASH)
	                      == FZN_CONTACT_DEVICE_OK
	              && fzn_contact_device_revoked(&deep, &rs, &member),
	      "a device stood by its grantor's revocation that trusts none of its acts");

	/* A FULL STORE IS ROOM, so the caller grows it. */
	CHECK(fzn_revocation_store_init(&fresh, e2, 1u) == FZN_CHAIN_OK
	              && fzn_contact_revocation_take(&fresh, &STORE, owner, &member, rec, &SIGN,
	                                             &HASH)
	                         == FZN_CONTACT_DEVICE_OK
	              && (revoked_by(foreign, owner, &member, phone, 201u, NULL),
	                  fzn_contact_revocation_take(&fresh, &STORE, owner, &member, foreign,
	                                              &SIGN, &HASH))
	                         == FZN_CONTACT_DEVICE_ERR_ROOM,
	      "a record past a full store was not ROOM");
}

/* THE RECORDS' ANSWERER: twenty of them, so a page holds sixteen. `mode` 1
 * echoes another `from`; 2 adds a trailing byte; 3 says more with none. */
static uint8_t records[20][FZN_REVOCATION_LEN];
static size_t records_taken;

static int record_at(void *ctx, size_t i, uint8_t out[FZN_REVOCATION_LEN])
{
	(void)ctx;
	if (i >= 20u)
		return 0;
	memcpy(out, records[i], FZN_REVOCATION_LEN);
	return 1;
}

static void take_record(void *ctx, const uint8_t record[FZN_REVOCATION_LEN])
{
	(void)ctx;
	records_taken += memcmp(record, records[records_taken], FZN_REVOCATION_LEN) == 0;
}

static int revoked_link(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                        size_t reply_cap, size_t *reply_len)
{
	(void)ctx;
	*reply_len = fzn_contact_revoked_answer(request, request_len, record_at, NULL, reply,
	                                        reply_cap);
	if (!*reply_len)
		return 0;
	if (mode == 1)
		reply[5] ^= 1u;
	if (mode == 2)
		reply[(*reply_len)++] = 0u;
	if (mode == 3) {
		reply[6] = 0u;
		reply[7] = 1u;
		*reply_len = FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN;
	}
	return 1;
}

/* THE QUERY BY STEPS through `revoked_link`: 1 when it ended well. */
static int revoked_query(size_t *pages)
{
	static uint8_t page[FZN_CONTACT_DEVICES_REPLY_MAX + 1u];
	fzn_contact_revoked_querying_t q;
	uint8_t req[FZN_CONTACT_DEVICES_REVOKED_LEN];
	size_t req_len = 0, page_len = 0;
	int ok, done = 0;

	records_taken = 0;
	*pages = 0;
	ok = fzn_contact_revoked_query_begin(&q, take_record, NULL, req, sizeof(req), &req_len);
	/* BOUNDED HERE, so an asker that never ends fails rather than hangs. */
	while (ok && !done && *pages < 8u) {
		(*pages)++;
		ok = revoked_link(NULL, req, req_len, page, sizeof(page), &page_len)
		     && fzn_contact_revoked_query_step(&q, page, page_len, req, sizeof(req), &req_len,
		                                       &done);
	}
	return ok && done && q.count == records_taken;
}

static void test_the_revoked_messages(void)
{
	uint8_t req[FZN_CONTACT_DEVICES_QUERY_LEN], page[64];
	size_t i, pages = 0;

	for (i = 0; i < 20u; i++)
		revoked_by(records[i], owner, &member, phone, 1000u + i, NULL);
	mode = 0;
	CHECK(revoked_query(&pages) && records_taken == 20u && pages == 2u,
	      "twenty records over two pages were not each taken once, in order");
	mode = 1;
	CHECK(!revoked_query(&pages), "a page answering another `from` was taken");
	mode = 2;
	CHECK(!revoked_query(&pages), "a page with a trailing byte was taken");
	mode = 3;
	{
		static uint8_t one[FZN_CONTACT_DEVICES_REPLY_MAX + 1u];
		fzn_contact_revoked_querying_t q;
		uint8_t asked[FZN_CONTACT_DEVICES_REVOKED_LEN];
		size_t asked_len = 0, one_len = 0;
		int done = 0;

		/* REFUSED AT THE FIRST PAGE, not merely never finished: asked
		 * again from the same `from` it would go on for ever. */
		CHECK(fzn_contact_revoked_query_begin(&q, take_record, NULL, asked, sizeof(asked),
		                                      &asked_len)
		              && revoked_link(NULL, asked, asked_len, one, sizeof(one), &one_len)
		              && !fzn_contact_revoked_query_step(&q, one, one_len, asked, sizeof(asked),
		                                                 &asked_len, &done)
		              && done,
		      "a page saying more and naming none was taken");
	}
	mode = 0;
	/* A DEVICES QUERY IS NOT THIS ONE'S, and a reply too small for a head
	 * answers nothing. */
	req[0] = FZN_CONTACT_DEVICES_VERSION;
	req[1] = FZN_CONTACT_DEVICES_QUERY;
	req[2] = 0u;
	req[3] = FZN_CONTACT_DEVICES_HOSTS;
	CHECK(fzn_contact_revoked_answer(req, sizeof(req), record_at, NULL, page, sizeof(page))
	              == 0u,
	      "a devices query was answered with records");
	{
		uint8_t asked[FZN_CONTACT_DEVICES_REVOKED_LEN];
		fzn_contact_revoked_querying_t q;
		size_t len = 0;

		CHECK(fzn_contact_revoked_query_begin(&q, take_record, NULL, asked, sizeof(asked),
		                                      &len)
		              && fzn_contact_revoked_answer(asked, len, record_at, NULL, page, 7u) == 0u
		              && fzn_contact_revoked_answer(asked, len, record_at, NULL, page,
		                                            sizeof(page))
		                         == FZN_CONTACT_DEVICES_RECORDS_HEAD_LEN
		              && page[6] == 0u && page[7] == 1u,
		      "a reply with no room for a record did not say more follow, naming none");
	}
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
	memset(owner, 0x11, sizeof(owner));
	memset(phone, 0x22, sizeof(phone));
	memset(other, 0x33, sizeof(other));
	memset(member.b, 0x44, sizeof(member.b));
	memset(share.b, 0x55, sizeof(share.b));
	test_the_suite_can_tell_pass_from_fail();
	test_an_entry_round_trips();
	test_what_makes_one_hold();
	test_the_store();
	test_the_messages();
	test_thousands_of_devices();
	test_a_contacts_revocations();
	test_the_revoked_messages();
	if (failures) {
		fprintf(stderr, "node contact_devices_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node contact_devices_test: all %d checks passed\n", checks);
	return 0;
}
