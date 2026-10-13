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

#define ROWS 4u

static struct {
	int used;
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
		if (rows[i].used && slot == FZN_PERSIST_CONTACT_DEVICE
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
	if (slot != FZN_PERSIST_CONTACT_DEVICE || len > sizeof(rows[0].bytes))
		return 0;
	for (i = 0; i < ROWS; i++) {
		if (rows[i].used && memcmp(rows[i].subject, subject, 32u) == 0)
			break;
		if (!rows[i].used && free_one == ROWS)
			free_one = i;
	}
	if (i == ROWS)
		i = free_one;
	if (i == ROWS)
		return 0;
	rows[i].used = 1;
	memcpy(rows[i].subject, subject, 32u);
	memcpy(rows[i].bytes, bytes, len);
	rows[i].len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	if (slot != FZN_PERSIST_CONTACT_DEVICE)
		return 0;
	for (i = 0; i < ROWS; i++)
		if (rows[i].used) {
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
		if (rows[i].used && slot == FZN_PERSIST_CONTACT_DEVICE
		    && memcmp(rows[i].subject, subject, 32u) == 0)
			rows[i].used = 0;
	return 1;
}

static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, NULL };

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
	if (failures) {
		fprintf(stderr, "node contact_devices_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node contact_devices_test: all %d checks passed\n", checks);
	return 0;
}
