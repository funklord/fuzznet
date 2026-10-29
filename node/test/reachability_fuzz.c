/*
 * A fuzz harness for journey 4's wire inputs, sec 689's reachability: a
 * user's routing manifest (`node/routing.h`), which a contact's host hands
 * over and this host keeps, and a clock's answer to a time ask
 * (`node/clocks.h`), which any member or contact sends back.
 *
 * AND A CONTACT'S DEVICE (`node/contact_devices.h`): its prekey record, as
 * the device signed it, its address, and its owner's chain to it -- what a
 * contact's host offers so this host can reach that device.
 *
 * WHY THESE. A routing manifest is another user's, every byte: it says
 * where that user's hosts are reached, and this host sends to what it
 * says. The claim is that only the signed manifest holds, byte for byte --
 * that no bent one verifies -- and that a manifest decodes one way only,
 * so the bytes kept are the bytes signed. A time answer moves this host's
 * estimate of a peer's clock, which every request to that peer is stamped
 * by (sec 757); the claim is that one is taken only for the ask it
 * answers, and only from its own bytes.
 *
 * THE PEER LIES BY MUTATION. Each case signs a manifest of a few entries,
 * real Ed25519 over BLAKE2b, and with even odds bends its encoding: bits
 * flipped, cut short, grown, a slice repeated or two bytes swapped. A time
 * answer is made for a nonce and bent the same way.
 *
 * THE PROPERTIES:
 *   1. A WHOLE MANIFEST decodes, verifies, and encodes back as itself.
 *   2. A BENT ONE that decodes encodes back as exactly its bytes -- one
 *      encoding a manifest -- and verifies only when those bytes are the
 *      signed ones.
 *   2b. THE SAME FOR A CONTACT'S DEVICE: whole, it decodes, holds and
 *      encodes back as itself; bent, it decodes to exactly its bytes, and
 *      holds only with its signed parts -- owner, record, chain -- as they
 *      were. Its address and port are signed by nobody, and a bent one may
 *      move them and still hold (sec 764).
 *   3. A WHOLE TIME ANSWER is taken for its nonce, with the offset it
 *      carries, and not for another nonce.
 *   4. A BENT ONE taken is one whose nonce and length are the ask's, its
 *      offset its own bytes' less the midpoint.
 *
 * FLOORS: a run that never decoded a bent manifest, never refused one, or
 * never took a whole time answer has not tested what it claims.
 */

#include "../routing.h"
#include "../contact_devices.h"
#include "../clocks.h"
#include "../../chain/sign_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../wire/bytes.h"

#include <monocypher-ed25519.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 3000u
#define FUZZ_MIN_CASES 1000u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL reachability_fuzz.c: case %lu: %s\n", c, what);
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

/* ---- the manifest -------------------------------------------------------- */

static fzn_hash_ops_t HASH;
static fzn_sign_monocypher_t key;
static fzn_sign_ops_t SIGN;
static uint8_t root[FZN_PUBKEY_LEN];

/* A PHONE OF THE ROOT'S, its record signed by the phone and granted by
 * the root's chain for the member capability. */
static fzn_sign_monocypher_t phone_key;
static fzn_sign_ops_t PHONE_SIGN;
static uint8_t phone[FZN_PUBKEY_LEN];
static fzn_cap_id_t member;

static int signed_device(fzn_contact_device_t *d)
{
	uint8_t agree[FZN_PREKEY_LEN];
	size_t i;

	memset(d, 0, sizeof(*d));
	memcpy(d->owner, root, FZN_PUBKEY_LEN);
	for (i = 0; i < sizeof(agree); i++)
		agree[i] = (uint8_t)next();
	if (fzn_prekey_issue(phone, agree, 1000u + next() % 1000u, &PHONE_SIGN, d->record)
	    != FZN_PREKEY_OK)
		return 0;
	d->address_len = (size_t)snprintf(d->address, sizeof(d->address), "203.0.113.%u",
	                                  (unsigned)(next() % 250u));
	d->port = (uint16_t)(1u + next() % 65535u);
	if (fzn_chain_mint(root, phone, &member, 100u, FZN_NO_EXPIRY, 0, &SIGN, d->hops[0])
	    != FZN_CHAIN_OK)
		return 0;
	d->hop_count = 1u;
	return 1;
}

/* A manifest of one to four entries, signed by the root alone. */
static int signed_manifest(fzn_routing_t *r)
{
	static const char *const HOSTS[] = { "198.51.100.7", "home.example", "2001:db8::1",
		                             "relay-1.example.net" };
	size_t i, n = 1u + (size_t)(next() % 4u);

	memset(r, 0, sizeof(*r));
	r->public_relay = (int)(next() & 1u);
	for (i = 0; i < n; i++)
		if (fzn_routing_add(r, HOSTS[i], strlen(HOSTS[i]), (uint16_t)(1u + next() % 65535u),
		                    (uint8_t)(next() % 2u), (uint8_t)(next() % 8u))
		    != FZN_ROUTING_OK)
			return 0;
	return fzn_routing_sign(r, &HASH, &SIGN, root, NULL, 0u, 1u + next() % 1000u,
	                        1791460800000ull)
	       == FZN_ROUTING_OK;
}

int main(int argc, char **argv)
{
	static uint8_t whole[FZN_ROUTING_MAX], bent[FZN_ROUTING_MAX + 64u],
	        again[FZN_ROUTING_MAX + 64u];
	static fzn_routing_t r, got;
	unsigned long cases = FUZZ_DEFAULT_CASES, c;
	unsigned long decoded_bent = 0, refused = 0, time_whole = 0, time_bent = 0;
	unsigned long device_bent = 0, device_refused = 0, device_moved = 0;
	uint8_t seed[32];

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	fzn_hash_monocypher_init(&HASH);
	memset(seed, 0x42, sizeof(seed));
	crypto_ed25519_key_pair(key.secret_key, root, seed);
	key.can_sign = 1;
	fzn_sign_monocypher_init(&SIGN, &key);
	memset(seed, 0x43, sizeof(seed));
	crypto_ed25519_key_pair(phone_key.secret_key, phone, seed);
	phone_key.can_sign = 1;
	fzn_sign_monocypher_init(&PHONE_SIGN, &phone_key);
	memset(member.b, 0x44, sizeof(member.b));

	for (c = 0; c < cases; c++) {
		size_t wlen = 0, blen, alen = 0;

		/* 1 and 2: THE MANIFEST. */
		if (!signed_manifest(&r)
		    || fzn_routing_encode(&r, whole, sizeof(whole), &wlen) != FZN_ROUTING_OK) {
			fail("fixture: a manifest was not signed and encoded", c);
			continue;
		}
		memcpy(bent, whole, wlen);
		blen = wlen;
		if (next() & 1u)
			blen = bend(bent, wlen, sizeof(bent));
		if (fzn_routing_decode(bent, blen, &got) != FZN_ROUTING_OK) {
			if (blen == wlen && memcmp(bent, whole, wlen) == 0)
				fail("a whole manifest did not decode", c);
			refused++;
		} else {
			int same = blen == wlen && memcmp(bent, whole, wlen) == 0;

			if (!same)
				decoded_bent++;
			if (fzn_routing_encode(&got, again, sizeof(again), &alen) != FZN_ROUTING_OK
			    || alen != blen || memcmp(again, bent, blen) != 0)
				fail("a decoded manifest did not encode back as its bytes", c);
			if (fzn_routing_verify(&got, &HASH, &SIGN, root, NULL, 1791460900000ull)
			    == FZN_ROUTING_OK) {
				if (!same)
					fail("a bent manifest verified", c);
			} else if (same) {
				fail("a whole manifest did not verify", c);
			}
		}

		/* 2b: A CONTACT'S DEVICE. */
		{
			static fzn_contact_device_t d, back;
			static uint8_t dw[FZN_CONTACT_DEVICE_MAX], db[FZN_CONTACT_DEVICE_MAX + 64u],
			        da[FZN_CONTACT_DEVICE_MAX + 64u];
			size_t dwl = 0, dbl, dal = 0;
			int same;

			if (!signed_device(&d)
			    || fzn_contact_device_encode(&d, dw, sizeof(dw), &dwl) != FZN_CONTACT_DEVICE_OK) {
				fail("fixture: a device was not signed and encoded", c);
				continue;
			}
			memcpy(db, dw, dwl);
			dbl = dwl;
			if (next() & 1u)
				dbl = bend(db, dwl, sizeof(db));
			same = dbl == dwl && memcmp(db, dw, dwl) == 0;
			if (fzn_contact_device_decode(db, dbl, &back) != FZN_CONTACT_DEVICE_OK) {
				if (same)
					fail("a whole device did not decode", c);
				device_refused++;
			} else {
				if (!same)
					device_bent++;
				if (fzn_contact_device_encode(&back, da, sizeof(da), &dal)
				            != FZN_CONTACT_DEVICE_OK
				    || dal != dbl || memcmp(da, db, dbl) != 0)
					fail("a decoded device did not encode back as its bytes", c);
				/* WHAT IS SIGNED, held only as signed: the owner, the
				 * record and the chain. The address and port are not
				 * signed by anyone (`node/contact_devices.h`). */
				if (fzn_contact_device_verify(&back, &SIGN, &member, 2000u)
				    == FZN_CONTACT_DEVICE_OK) {
					if (memcmp(back.owner, d.owner, FZN_PUBKEY_LEN) != 0
					    || memcmp(back.record, d.record, sizeof(d.record)) != 0
					    || back.hop_count != d.hop_count
					    || memcmp(back.hops, d.hops, d.hop_count * FZN_HOP_LEN) != 0)
						fail("a bent device held with other than its signed parts", c);
					else if (!same)
						device_moved++;
				} else if (same) {
					fail("a whole device did not hold", c);
				}
			}
		}

		/* 3 and 4: A TIME ANSWER. */
		{
			uint8_t nonce[FZN_NODE_TIME_NONCE_LEN], other[FZN_NODE_TIME_NONCE_LEN];
			uint8_t ask[FZN_NODE_TIME_ASK_LEN + 8u], answer[FZN_NODE_TIME_ANSWER_LEN + 64u];
			uint64_t sent = 1791460800000ull + next() % 100000u, peer = sent + next() % 10000u;
			int64_t offset = 0;
			uint64_t rtt = 0;
			size_t askn, n, i;

			for (i = 0; i < sizeof(nonce); i++) {
				nonce[i] = (uint8_t)next();
				other[i] = (uint8_t)(nonce[i] ^ 0x5au);
			}
			askn = fzn_node_time_ask(nonce, ask, sizeof(ask));
			n = askn ? fzn_node_time_answer(ask, askn, peer, answer, sizeof(answer)) : 0u;
			if (!askn || n != FZN_NODE_TIME_ANSWER_LEN) {
				fail("fixture: a time ask was not answered", c);
				continue;
			}
			if (fzn_node_time_take(answer, n, nonce, sent, sent + 20u, &offset, &rtt)
			    && offset == (int64_t)peer - (int64_t)(sent + 10u) && rtt == 20u)
				time_whole++;
			else
				fail("a whole time answer was not taken with its offset", c);
			if (fzn_node_time_take(answer, n, other, sent, sent + 20u, &offset, &rtt))
				fail("a time answer was taken for another ask's nonce", c);
			n = bend(answer, n, sizeof(answer));
			if (fzn_node_time_take(answer, n, nonce, sent, sent + 20u, &offset, &rtt)) {
				time_bent++;
				if (n != FZN_NODE_TIME_ANSWER_LEN
				    || memcmp(answer + 2, nonce, FZN_NODE_TIME_NONCE_LEN) != 0
				    || offset != (int64_t)fzn_get_be64(answer + 2 + FZN_NODE_TIME_NONCE_LEN)
				                         - (int64_t)(sent + 10u))
					fail("a bent time answer was taken for other than its own bytes", c);
			}
		}
	}

	if (decoded_bent == 0u)
		fail("no bent manifest decoded: the mutations never reached the decoder", cases);
	if (refused == 0u)
		fail("no bent manifest was refused: the shape check was never met", cases);
	if (time_whole == 0u)
		fail("no whole time answer was taken", cases);
	if (device_bent == 0u || device_refused == 0u)
		fail("no bent device decoded, or none was refused", cases);
	printf("reachability_fuzz: %lu cases, %lu bent manifest(s) decoded, %lu refused, %lu bent "
	       "device(s) decoded, %lu refused, %lu held with only the address moved, %lu time "
	       "answer(s) whole, %lu bent taken, %d failure(s)\n",
	       cases, decoded_bent, refused, device_bent, device_refused, device_moved, time_whole,
	       time_bent, failures);
	return failures ? 1 : 0;
}
