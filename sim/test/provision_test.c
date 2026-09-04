/*
 * PROVISIONING A DEVICE THAT KNOWS NOTHING, THEN TALKING TO IT.
 *
 * The software half of scanning a code: a device holding no anchor, no
 * capability and no session is handed a few hundred bytes out of band, and
 * afterwards exchanges sealed, authenticated, authorised traffic. Under all
 * four real primitives, because a provisioning story told with stub keys is
 * a story about the stubs.
 *
 * WHY THIS FILE EXISTS, and it is a gap rather than a preference. Three
 * files each hold a third of this and none crosses the joins:
 *
 *   sim/test/network_test.c   scenario_join starts a host with no anchor and
 *                             gets it authorised -- on stub crypto, with the
 *                             session key agreed by magic, and with the
 *                             joiner keeping the capability sim_init minted
 *                             for it. The bundle that "asserts the root" is
 *                             narrative; the joiner reaches into net.root.
 *   sim/test/real_crypto_test.c  gets two hosts from prekeys to a sealed
 *                             frame under real primitives -- and calls
 *                             neither fzn_trust_pin nor fzn_chain_verify.
 *                             Its capability is memset(0x4c) and is checked
 *                             against nothing.
 *   tool/consumer_check.c     calls every function here, each in its own
 *                             block with memset-filled keys, and connects
 *                             none of them.
 *
 * So "a device provisioned out of band can be authorised and then talk" was
 * held by nothing. project.md sec 68.
 *
 * PINNED, NOT ADOPTED, AND THAT IS THE WHOLE POINT OF A SCANNED CODE.
 * `trust/trust.h` separates FZN_TRUST_PINNED -- "configured out of band: an
 * operator typed it, a package shipped it; authenticated by whatever put it
 * there" -- from FZN_TRUST_ADOPTED, "adopted on first contact, authenticated
 * by nothing". It also says a consumer that adopts "owes its user a way to
 * check the anchor out of band -- a fingerprint to compare, a confirmation
 * step, something". A code the user physically scans IS that check, so the
 * scan is the pinned case and `scenario_join`'s TOFU path is a different
 * one. Both source values are asserted below, because recording a scan as
 * ADOPTED would misreport provenance to the person holding the phone.
 *
 * THE EXCHANGE IS TWO-WAY, WHICH IS A FACT ABOUT THE MATHS AND NOT A CHOICE.
 * A hop names its grantee, so the sponsor cannot mint one until it knows the
 * device's identity key. A one-way code cannot provision a device the
 * sponsor has never seen. So the device shows its own prekey record first --
 * 138 bytes, self-signed, already a "here is me" object -- and the sponsor
 * answers with the payload below. Nothing had to be invented for either leg.
 *
 * THE PAYLOAD IS THIS FILE'S, NOT THE LIBRARY'S. Slicing at fixed offsets is
 * a consumer's encoding and sec 2 keeps encodings out of fuzznet; what the
 * library provides is that every field is a fixed-length self-delimiting
 * object, so the concatenation needs no framing, no length prefixes and no
 * new signed object. That is the finding worth carrying out of this file: a
 * provisioning payload is assembly, not design.
 */

#include "../../chain/chain.h"
#include "../../chunk/split.h"
#include "../../chunk/reassembly.h"
#include "../../prekey/prekey.h"
#include "../../session/agree.h"
#include "../../session/agree_monocypher.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random.h"
#include "../../session/random_system.h"
#include "../../session/session.h"
#include "../../chain/sign_monocypher.h"
#include "../../trust/trust.h"
#include "../../wire/seal.h"
#include "../../constant_time/constant_time.h"
#include "../../version/version.h"

#include <monocypher.h>
#include <stdio.h>
#include <string.h>

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

/* Deterministic seeds, for `real_crypto_test.c`'s reason: a test drawing its
 * identities from the system pool is one whose failures cannot be reproduced
 * from the source. */
static void seed_bytes(uint8_t out[32], uint8_t v)
{
	memset(out, v, 32);
}

/* ---- the payload a code would carry ----------------------------------- */

/* Fixed offsets, because every object in it is fixed length. A reader slices
 * and hands each slice to the call that owns it; both `fzn_hop_open` and
 * `fzn_prekey_open` refuse a wrong length outright, so a mis-slice fails at
 * the parser rather than becoming a subtly wrong grant. */
#define QR_OFF_ROOT    0u
#define QR_OFF_HOP     (QR_OFF_ROOT + FZN_PUBKEY_LEN)
#define QR_OFF_PREKEY  (QR_OFF_HOP + FZN_HOP_LEN)
#define QR_LEN         (QR_OFF_PREKEY + FZN_PREKEY_LEN_TOTAL)

/* THE ROOT IS SHIPPED RATHER THAN READ OUT OF THE HOP, and 32 bytes buys
 * something real. The hop's grantor field holds the same key, so a reader
 * COULD recover it -- but taking the anchor out of the object it is about to
 * authenticate is circular, which is trust on first use with extra steps.
 * `trust.h` is explicit that a pinned anchor's authentication comes from the
 * channel, so shipping it makes the pin auditable: the device compares what
 * it pinned against what the hop claims, and this file asserts they agree. */

int main(void)
{
	fzn_sign_monocypher_t sponsor_signer, device_signer;
	fzn_sign_ops_t sponsor_sign, device_sign, verify_ops;
	fzn_sign_monocypher_t verify_only;
	fzn_hash_ops_t hash_ops;
	fzn_aead_ops_t aead_ops;
	fzn_agree_ops_t agree_ops;
	fzn_random_ops_t rng_ops;

	uint8_t root_pub[FZN_PUBKEY_LEN], device_pub[FZN_PUBKEY_LEN];
	uint8_t seed[32];
	fzn_cap_id_t cap;

	fzn_agree_secret_t sponsor_sk, device_sk;
	uint8_t raw_sponsor[FZN_AGREE_SECRET_LEN], raw_device[FZN_AGREE_SECRET_LEN];

	uint8_t device_record_bytes[FZN_PREKEY_LEN_TOTAL];
	uint8_t sponsor_record_bytes[FZN_PREKEY_LEN_TOTAL];
	fzn_prekey_record_t device_record, sponsor_record;
	fzn_prekey_peer_t device_view_of_sponsor, sponsor_view_of_device;

	uint8_t payload[QR_LEN];
	uint8_t hop_bytes[FZN_HOP_LEN];
	fzn_chain_hop_t hop;
	fzn_chain_t proven;
	fzn_trust_t anchor;

	uint8_t key_device[FZN_AEAD_KEY_LEN], key_sponsor[FZN_AEAD_KEY_LEN];
	uint8_t ck_device[FZN_COMMITMENT_KEY_LEN], ck_sponsor[FZN_COMMITMENT_KEY_LEN];

	unsigned i;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_aead_monocypher_init(&aead_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);

	/* ---- identities, really Ed25519 -------------------------------- */

	memset(&sponsor_signer, 0, sizeof(sponsor_signer));
	seed_bytes(seed, 0x51u);
	crypto_eddsa_key_pair(sponsor_signer.secret_key, root_pub, seed);
	sponsor_signer.can_sign = 1;
	fzn_sign_monocypher_init(&sponsor_sign, &sponsor_signer);

	memset(&device_signer, 0, sizeof(device_signer));
	seed_bytes(seed, 0x52u);
	crypto_eddsa_key_pair(device_signer.secret_key, device_pub, seed);
	device_signer.can_sign = 1;
	fzn_sign_monocypher_init(&device_sign, &device_signer);

	check(memcmp(root_pub, device_pub, FZN_PUBKEY_LEN) != 0,
	      "the sponsor and the device were given the same identity, so nothing "
	      "below distinguishes them");

	/* A VERIFY-ONLY VTABLE, because the device must be able to check the
	 * sponsor's signatures without holding its secret -- which is the
	 * whole shape of provisioning, and a verifier that could sign would
	 * let this file prove less than it claims. */
	memset(&verify_only, 0, sizeof(verify_only));
	verify_only.can_sign = 0;
	fzn_sign_monocypher_init(&verify_ops, &verify_only);

	memset(cap.b, 0x7au, sizeof(cap.b));

	/* ---- both sides hold an agreement secret ----------------------- */

	memset(&sponsor_sk, 0, sizeof(sponsor_sk));
	memset(&device_sk, 0, sizeof(device_sk));
	for (i = 0; i < FZN_AGREE_SECRET_LEN; i++) {
		raw_sponsor[i] = (uint8_t)((i * 17u) + 3u);
		raw_device[i] = (uint8_t)((i * 29u) + 11u);
	}
	check(fzn_agree_secret_install(&sponsor_sk, &agree_ops, raw_sponsor) == FZN_AGREE_OK,
	      "the sponsor's X25519 secret would not install");
	check(fzn_agree_secret_install(&device_sk, &agree_ops, raw_device) == FZN_AGREE_OK,
	      "the device's X25519 secret would not install");

	/* ---- LEG ONE: the device shows itself -------------------------- */

	/* Nothing here is invented: a prekey record already says "host H
	 * published agreement key P at time T", signed by H. That is exactly
	 * what a sponsor needs before it can mint. */
	check(fzn_prekey_issue(device_pub, fzn_agree_secret_public(&device_sk), 1000u,
	                       &device_sign, device_record_bytes) == FZN_PREKEY_OK,
	      "the device could not state its own prekey");
	check(fzn_prekey_open(device_record_bytes, FZN_PREKEY_LEN_TOTAL, &device_record) ==
	              FZN_PREKEY_OK,
	      "the device's own record will not open");

	fzn_prekey_peer_init(&sponsor_view_of_device);
	check(fzn_prekey_pin(&sponsor_view_of_device, device_record, &verify_ops,
	                     FZN_TRUST_PINNED, 1000u) == FZN_PREKEY_OK,
	      "the sponsor refused the device's record");

	/* ---- LEG TWO: the sponsor answers with the payload -------------- */

	check(fzn_chain_mint(root_pub, device_pub, &cap, 1000u, FZN_NO_EXPIRY, 0,
	                     &sponsor_sign, hop_bytes) == FZN_CHAIN_OK,
	      "the sponsor could not mint a grant for the device");
	check(fzn_prekey_issue(root_pub, fzn_agree_secret_public(&sponsor_sk), 1000u,
	                       &sponsor_sign, sponsor_record_bytes) == FZN_PREKEY_OK,
	      "the sponsor could not state its own prekey");

	memcpy(payload + QR_OFF_ROOT, root_pub, FZN_PUBKEY_LEN);
	memcpy(payload + QR_OFF_HOP, hop_bytes, FZN_HOP_LEN);
	memcpy(payload + QR_OFF_PREKEY, sponsor_record_bytes, FZN_PREKEY_LEN_TOTAL);

	/* 349 bytes, which is worth stating: it is inside every QR version
	 * from 8 upwards at the lowest error correction, and this file's point
	 * is that no field of it had to be designed. */
	check(QR_LEN == 349u, "the payload is not the size this file documents");

	/* ---- the device, which so far knows nothing -------------------- */

	fzn_trust_init(&anchor);
	check(fzn_trust_root(&anchor) == NULL,
	      "a device that has scanned nothing already has an anchor");
	check(fzn_trust_source_of(&anchor) == FZN_TRUST_NONE,
	      "an unscanned device reports a provenance for an anchor it does not have");

	/* THE THIRD STATE, ASSERTED RATHER THAN ASSUMED, and raised by
	 * fuzzypickles on 2026-09-04 while pinning against a stored root for
	 * the first time in anger: a bootstrap module needs "we have none and
	 * must refuse" as well as pinned and adopted, or a peer added from a
	 * bare prekey blob carries an all-zero root that reads as an anchor.
	 *
	 * This module has it twice over. `fzn_trust_root` answers NULL rather
	 * than a zero key, which `fzn_chain_verify` refuses -- and an all-zero
	 * root is refused at the door, which `trust.c` records as a defect it
	 * once had: the guard was keyed on `source` rather than on the bytes,
	 * so anchoring all zeroes succeeded and the accessor then handed them
	 * over as a real root, permanently, since the next anchor is ANCHORED. */
	{
		uint8_t zero_root[FZN_PUBKEY_LEN];

		memset(zero_root, 0, sizeof(zero_root));
		check(fzn_trust_pin(&anchor, zero_root) == FZN_TRUST_ERR_MALFORMED,
		      "a device pinned an all-zero root, so a payload whose root field "
		      "was never filled anchors it permanently to a key nobody holds");
		check(fzn_trust_root(&anchor) == NULL,
		      "and the refused pin left an anchor behind");
	}

	/* THE CHAIN IS REFUSED BEFORE THE SCAN, and this is the control for
	 * everything after it: without it, a chain that verifies afterwards
	 * proves only that it verifies, not that the scan is what changed. */
	check(fzn_hop_open(payload + QR_OFF_HOP, FZN_HOP_LEN, &hop) == FZN_CHAIN_OK,
	      "the hop in the payload will not open");
	check(fzn_chain_verify(&hop, 1u, root_pub, &cap, 1100u, &verify_ops, NULL, NULL,
	                       &proven) == FZN_CHAIN_OK,
	      "the grant does not verify under the root that minted it, so the "
	      "refusals below would be about a broken hop rather than a missing anchor");

	/* ---- the scan --------------------------------------------------- */

	check(fzn_trust_pin(&anchor, payload + QR_OFF_ROOT) == FZN_TRUST_OK,
	      "the device could not pin the root it scanned");
	check(fzn_trust_source_of(&anchor) == FZN_TRUST_PINNED,
	      "a scanned root was recorded as adopted, which tells the user it was "
	      "authenticated by nothing when it was authenticated by the scan");
	check(fzn_trust_adopted_at(&anchor) == 0u,
	      "a pinned anchor recorded a moment of first contact, which it does not have");

	/* THE PIN IS AUDITED AGAINST THE GRANT, which is what shipping the
	 * root separately buys. A payload whose hop was minted under some
	 * other root is caught here rather than at the first refused frame. */
	check(fzn_trust_root(&anchor)
	              && memcmp(fzn_trust_root(&anchor), fzn_hop_grantor(hop),
	                        FZN_PUBKEY_LEN) == 0,
	      "the root the device pinned is not the one that minted its grant");

	check(fzn_prekey_open(payload + QR_OFF_PREKEY, FZN_PREKEY_LEN_TOTAL,
	                      &sponsor_record) == FZN_PREKEY_OK,
	      "the sponsor's record in the payload will not open");
	fzn_prekey_peer_init(&device_view_of_sponsor);
	check(fzn_prekey_pin(&device_view_of_sponsor, sponsor_record, &verify_ops,
	                     FZN_TRUST_PINNED, 1100u) == FZN_PREKEY_OK,
	      "the device refused the sponsor's prekey record");
	check(fzn_trust_source_of(&device_view_of_sponsor.trust) == FZN_TRUST_PINNED,
	      "the sponsor's prekey was recorded as adopted rather than scanned");

	/* AND THE GRANT VERIFIES UNDER THE ANCHOR THE DEVICE NOW HOLDS,
	 * rather than under a root passed in beside it. */
	check(fzn_chain_verify(&hop, 1u, fzn_trust_root(&anchor), &cap, 1100u, &verify_ops,
	                       NULL, NULL, &proven) == FZN_CHAIN_OK,
	      "the scanned grant does not verify under the scanned anchor");
	check(memcmp(proven.grantee, device_pub, FZN_PUBKEY_LEN) == 0,
	      "the grant authorises somebody other than the device that scanned it");

	/* ---- A FORGED CODE, which is the threat a scan actually has ------ */

	/* Somebody prints their own code. The root field says one key and the
	 * hop was minted under another -- or the whole payload is a stranger's.
	 * Either way the device must refuse, and it must refuse at
	 * verification rather than only at the audit above, because a consumer
	 * that skipped the audit would otherwise be provisioned by anybody
	 * with a printer.
	 *
	 * MEASURED: without this leg, disabling `fzn_chain_verify`'s check
	 * that hop 0's grantor is the pinned root leaves this file green. The
	 * audit compares the payload against itself and a forger controls
	 * both halves of it. */
	{
		fzn_sign_monocypher_t forger_signer;
		fzn_sign_ops_t forger_sign;
		uint8_t forger_pub[FZN_PUBKEY_LEN];
		uint8_t forged_hop[FZN_HOP_LEN];
		uint8_t forged_seed[32];
		fzn_chain_hop_t forged;
		fzn_chain_t refused;

		memset(&forger_signer, 0, sizeof(forger_signer));
		seed_bytes(forged_seed, 0x53u);
		crypto_eddsa_key_pair(forger_signer.secret_key, forger_pub, forged_seed);
		forger_signer.can_sign = 1;
		fzn_sign_monocypher_init(&forger_sign, &forger_signer);

		check(memcmp(forger_pub, root_pub, FZN_PUBKEY_LEN) != 0,
		      "the forger was given the sponsor's identity, so nothing below is a "
		      "forgery");
		check(fzn_chain_mint(forger_pub, device_pub, &cap, 1000u, FZN_NO_EXPIRY, 0,
		                     &forger_sign, forged_hop) == FZN_CHAIN_OK,
		      "the forger could not mint its own grant");
		check(fzn_hop_open(forged_hop, FZN_HOP_LEN, &forged) == FZN_CHAIN_OK,
		      "the forged hop will not open");

		/* IT IS A PERFECTLY GOOD GRANT UNDER ITS OWN ROOT, which is what
		 * makes it a forgery rather than a broken record: the refusal
		 * below is about whose root it is, not about whether it parses. */
		check(fzn_chain_verify(&forged, 1u, forger_pub, &cap, 1100u, &verify_ops, NULL,
		                       NULL, &refused) == FZN_CHAIN_OK,
		      "the forged grant does not verify under the forger's own root, so the "
		      "refusal below would prove nothing");

		check(fzn_chain_verify(&forged, 1u, fzn_trust_root(&anchor), &cap, 1100u,
		                       &verify_ops, NULL, NULL, &refused) ==
		              FZN_CHAIN_ERR_WRONG_ROOT,
		      "a grant minted under a root the device never scanned was accepted, so "
		      "anybody with a printer can provision this device");

		/* AND THE AUDIT CATCHES THE MIXED PAYLOAD, the other way a
		 * forged code is built: a real root in the root field and
		 * somebody else's hop after it. */
		check(memcmp(fzn_trust_root(&anchor), fzn_hop_grantor(forged),
		             FZN_PUBKEY_LEN) != 0,
		      "the forged hop names the scanned root as its grantor, so this case is "
		      "not the mixed payload it says it is");

		fzn_sign_monocypher_wipe(&forger_signer);
	}

	/* ---- the session, and the join nothing else in this tree makes ---- */

	/* BOTH SIDES CALL `fzn_session_establish`, symmetrically. The
	 * transcript is ordered canonically by identity, so neither side has
	 * to know who scanned whom -- which is what lets a provisioning
	 * exchange derive a key from published prekeys alone. */
	check(fzn_session_establish(&device_sk, &agree_ops, &hash_ops, device_pub, root_pub,
	                            device_view_of_sponsor.prekey, key_device, ck_device) ==
	              FZN_SESSION_OK,
	      "the device could not establish a session with the sponsor it scanned");
	check(fzn_session_establish(&sponsor_sk, &agree_ops, &hash_ops, root_pub, device_pub,
	                            sponsor_view_of_device.prekey, key_sponsor, ck_sponsor) ==
	              FZN_SESSION_OK,
	      "the sponsor could not establish a session with the device it provisioned");
	check(memcmp(key_device, key_sponsor, FZN_AEAD_KEY_LEN) == 0,
	      "the two sides derived different session keys from the scanned prekeys, so "
	      "provisioning produced a pair that cannot talk");
	check(memcmp(ck_device, ck_sponsor, FZN_COMMITMENT_KEY_LEN) == 0,
	      "and different commitment keys");

	/* ---- a sealed frame under that key, authorised by that grant ----- */

	/* WHAT NO OTHER FILE DOES. `sim/test/network_test.c` seals under keys
	 * agreed by magic and never calls `fzn_session_establish` on the path;
	 * `sim/test/real_crypto_test.c` seals under a real session key and
	 * calls neither `fzn_trust_pin` nor `fzn_chain_verify`. The frame
	 * below is sealed under a key the scan produced and authorised by a
	 * grant the scan carried, which is the join. */
	{
		static const uint8_t PLAIN[] = "provisioned, and speaking";
		uint8_t frame[FZN_SEAL_OVERHEAD + sizeof(PLAIN)];
		size_t frame_len = 0;
		fzn_send_t what;
		fzn_opened_t got;
		const uint8_t *claimed = NULL;

		memset(&what, 0, sizeof(what));
		what.sender = device_pub;
		what.capability = cap.b;
		what.payload = PLAIN;
		what.payload_len = sizeof(PLAIN);
		what.expires_at = 2000u;
		what.msg = 1u;
		what.index = 0u;
		what.chunks = 1u;
		what.kind = 1u;

		check(fzn_seal_build(frame, sizeof(frame), &frame_len, &what, key_device,
		                     ck_device, &hash_ops, &rng_ops, &aead_ops) == FZN_SEAL_OK,
		      "the device could not seal a frame under the session it just established");

		/* The sender is readable without a key, which is how a receiver
		 * chooses one -- and it is a CLAIM until the tag verifies. */
		check(fzn_seal_peek_sender(frame, frame_len, &claimed) == FZN_SEAL_OK
		              && claimed && memcmp(claimed, device_pub, FZN_PUBKEY_LEN) == 0,
		      "the frame does not name the device as its sender before it is opened");

		/* OPENED UNDER THE SPONSOR'S OWN DERIVED KEY, not the device's
		 * buffer: opening with `key_device` would pass against a
		 * session that never agreed. */
		check(fzn_seal_open(frame, frame_len, key_sponsor, ck_sponsor, &hash_ops,
		                    &aead_ops, &got) == FZN_SEAL_OK,
		      "the sponsor could not open a frame sealed under the session both sides "
		      "derived from the scan");
		check(got.payload_len == sizeof(PLAIN)
		              && memcmp(got.payload, PLAIN, sizeof(PLAIN)) == 0,
		      "the payload did not survive the round trip");

		/* AND THE AUTHORISED SENDER IS THE ONE THAT SEALED IT. A
		 * verified chain says SOMEBODY holds the capability; this is
		 * the line that says it was this frame's sender. Constant time,
		 * because the comparison is against a value an attacker
		 * chooses. */
		check(fzn_chain_verify(&hop, 1u, fzn_trust_root(&anchor), &cap, 1100u,
		                       &verify_ops, NULL, NULL, &proven) == FZN_CHAIN_OK,
		      "the grant stopped verifying once traffic started");
		check(fzn_ct_memeq(proven.grantee, got.sender, FZN_PUBKEY_LEN),
		      "the chain authorises a key other than the one that sealed this frame");
	}

	fzn_agree_secret_wipe(&device_sk);
	fzn_agree_secret_wipe(&sponsor_sk);
	fzn_sign_monocypher_wipe(&device_signer);
	fzn_sign_monocypher_wipe(&sponsor_signer);

	printf("provision_test: %d checks, %d failure(s); fuzznet %s\n", checks, failures,
	       fzn_version_string());
	return failures == 0 ? 0 : 1;
}
