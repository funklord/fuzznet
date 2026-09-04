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
 * AND IT DOES NOT TAKE A DECISION THE HOLDER HOLDS. project.md sec 5, under
 * "Answered 2026-08-26: user signs for hosts", is
 * explicit that this library "deliberately has no such path" for joining --
 * `chain.h` says so, sec 4.2 says so, the root is pinned with no
 * nullable-root variant -- and that absorbing host management means either
 * growing a bootstrap it was designed to refuse, or leaving joining above the
 * library and taking in only the steady state. "That is a decision, not a
 * detail, and it is the holder's."
 *
 * This file adds no bootstrap. It exercises the anchoring the library DOES
 * provide -- `trust/`, which records provenance precisely so a consumer can
 * show it -- and assembles the joining above it, in the test. So it is
 * evidence about one branch of that decision rather than a vote on it: the
 * "joining stays above the library" branch costs 349 bytes of concatenation,
 * no new signed object, and the two-way exchange below. What the other branch
 * would cost is not measured here.
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
#include "../../record/record.h"
#include "../../record/journal.h"
#include "../../state/state.h"
#include "../../log/log.h"
#include "../../blob/blob.h"
#include "../../spool/spool.h"
#include "../../ratchet/ratchet.h"
#include "../../wire/relay.h"
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

/* ---- a spool that keeps its bytes in memory --------------------------- */

/* `spool/spool_file.c` is the real backend; this is the same seam over a
 * buffer, so the transfer below is about the store's POLICY -- verify, place,
 * track -- rather than about a filesystem. Modelled on
 * `spool/test/spool_test.c`, which does the same thing for the same reason. */
#define PROV_SPOOL_BYTES 8192u

static uint8_t spool_disk[PROV_SPOOL_BYTES];

static int mem_read(void *ctx, uint64_t offset, uint8_t *out, size_t len)
{
	(void)ctx;
	if (offset > PROV_SPOOL_BYTES || len > PROV_SPOOL_BYTES - offset)
		return 0;
	memcpy(out, spool_disk + offset, len);
	return 1;
}

static int mem_write(void *ctx, uint64_t offset, const uint8_t *bytes, size_t len)
{
	(void)ctx;
	if (offset > PROV_SPOOL_BYTES || len > PROV_SPOOL_BYTES - offset)
		return 0;
	memcpy(spool_disk + offset, bytes, len);
	return 1;
}

static int mem_sync(void *ctx)
{
	(void)ctx;
	return 1;
}

static const fzn_spool_ops_t SPOOL_OPS = { mem_read, mem_write, mem_sync, NULL };

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

	/* ---- a RECORD, chunked, sealed, and put to work ------------------ */

	/* THE NESTING IS THE POINT AND IT IS THE ONE NOTHING ELSE ASSEMBLES:
	 * a signed record travels inside chunks inside frames sealed under the
	 * session the scan produced, and only after the tag and the signature
	 * both check does it reach a journal, a state table and a log.
	 *
	 * SPLIT AT 256 RATHER THAN THE 1024 CEILING, deliberately. A record
	 * with a full body is about 600 bytes and would be one chunk, which
	 * would leave `fzn_split_at` and the reassembly path asserting nothing.
	 * `max_payload` is the caller's, so the fixture asks for a size that
	 * makes the message really travel in pieces. */
	{
		enum { PIECE = 256u, SLOTS = 4u, SLOT_CAP = 2048u };
		static const uint32_t STREAM = FZN_STREAM_RESERVED + 1u;
		static const uint32_t KIND = 9u;

		uint8_t subject[FZN_SUBJECT_LEN];
		uint8_t body[FZN_RECORD_BODY_MAX];
		uint8_t wire[FZN_RECORD_MAX_LEN];
		size_t wire_len = 0;
		fzn_split_t plan;

		fzn_partial_t slots[SLOTS];
		uint8_t slot_bufs[SLOTS][SLOT_CAP];
		fzn_reasm_t table;
		fzn_partial_t *done = NULL;

		fzn_journal_t journal;
		fzn_journal_entry_t jentries[2];
		fzn_state_t state;
		fzn_state_entry_t sentries[2];
		fzn_log_t log;
		fzn_log_entry_t lentries[2];
		fzn_record_t arrived;
		const fzn_state_entry_t *settled = NULL;
		const fzn_log_entry_t *held = NULL;

		uint16_t piece_index;
		unsigned delivered_chunks = 0;

		memset(subject, 0x11, sizeof(subject));
		for (i = 0; i < sizeof(body); i++)
			body[i] = (uint8_t)((i * 7u) + 1u);

		check(fzn_record_sign(device_pub, subject, STREAM, KIND, 1u, 1000u, body,
		                      sizeof(body), &device_sign, wire, sizeof(wire),
		                      &wire_len) == FZN_RECORD_OK,
		      "the device could not sign the record it wants to send");
		check(wire_len > PIECE,
		      "the record fits in one piece, so the chunking below asserts nothing");

		check(fzn_split_plan(wire_len, PIECE, &plan) == FZN_SPLIT_OK,
		      "the record would not plan into pieces");
		check(plan.chunks > 1u, "the plan is a single chunk after all");

		for (i = 0; i < SLOTS; i++)
			fzn_reasm_slot_init(&slots[i], slot_bufs[i], SLOT_CAP);
		check(fzn_reasm_init(&table, slots, SLOTS, 2u, 100000u) == FZN_REASM_OK,
		      "the sponsor's reassembly table would not initialise");

		/* EACH PIECE IS ITS OWN SEALED FRAME, opened under the sponsor's
		 * own derived key, and the reassembly is fed from what the tag
		 * authenticated rather than from the sender's buffer. */
		for (piece_index = 0; piece_index < plan.chunks; piece_index++) {
			uint8_t frame[FZN_SEAL_OVERHEAD + PIECE];
			size_t frame_len = 0, offset = 0, piece = 0;
			fzn_send_t what;
			fzn_opened_t got;

			check(fzn_split_at(&plan, piece_index, &offset, &piece) == FZN_SPLIT_OK,
			      "a piece of the record could not be located");

			memset(&what, 0, sizeof(what));
			what.sender = device_pub;
			what.capability = cap.b;
			what.payload = wire + offset;
			what.payload_len = piece;
			what.expires_at = 2000u;
			what.msg = 42u;
			what.index = piece_index;
			what.chunks = plan.chunks;
			what.kind = 1u;

			check(fzn_seal_build(frame, sizeof(frame), &frame_len, &what, key_device,
			                     ck_device, &hash_ops, &rng_ops,
			                     &aead_ops) == FZN_SEAL_OK,
			      "a piece of the record would not seal");
			check(fzn_seal_open(frame, frame_len, key_sponsor, ck_sponsor, &hash_ops,
			                    &aead_ops, &got) == FZN_SEAL_OK,
			      "a piece of the record would not open under the sponsor's key");
			check(fzn_reasm_accept(&table, got.sender, got.msg, got.index, got.chunks,
			                       got.payload, got.payload_len, got.expires_at,
			                       1100u, &done) == FZN_REASM_OK,
			      "a piece the sponsor authenticated was refused by reassembly");
			delivered_chunks++;
		}

		check(delivered_chunks == plan.chunks, "not every piece was carried");
		check(done != NULL,
		      "every piece arrived and the message never completed");
		check(done && done->bytes == wire_len,
		      "the reassembled record is a different length from the one sent");
		check(done && memcmp(done->buf, wire, wire_len) == 0,
		      "the record did not survive being split, sealed, opened and rejoined");

		/* VERIFY BEFORE ADMIT, which is the ordering `record/journal.h`
		 * insists on: a journal position advanced for a record whose
		 * signature was never checked is a replay window opened by the
		 * bookkeeping. */
		check(fzn_record_open(done->buf, done->bytes, &arrived) == FZN_RECORD_OK,
		      "the reassembled bytes will not open as a record");
		check(fzn_record_verify(arrived, &verify_ops) == FZN_RECORD_OK,
		      "the record that survived the wire does not verify");
		check(memcmp(fzn_record_issuer(arrived), device_pub, FZN_PUBKEY_LEN) == 0,
		      "the record names an issuer other than the provisioned device");

		check(fzn_journal_init(&journal, jentries, 2u) == FZN_JOURNAL_OK, "journal");
		check(fzn_journal_anchor(&journal, fzn_record_issuer(arrived),
		                         fzn_record_stream(arrived), 0u) == FZN_JOURNAL_OK,
		      "the sponsor could not follow the device's stream");
		check(fzn_journal_admit(&journal, fzn_record_issuer(arrived),
		                        fzn_record_stream(arrived),
		                        fzn_record_seq(arrived)) == FZN_JOURNAL_OK,
		      "the first record of a followed stream was refused");
		check(fzn_journal_admit(&journal, fzn_record_issuer(arrived),
		                        fzn_record_stream(arrived),
		                        fzn_record_seq(arrived)) == FZN_JOURNAL_ERR_DUPLICATE,
		      "the same record was admitted twice, so a replay advances the position");

		check(fzn_state_init(&state, sentries, 2u) == FZN_STATE_OK, "state");
		check(fzn_state_apply(&state, &arrived) == FZN_STATE_OK,
		      "the verified record would not apply to the state table");
		settled = fzn_state_get(&state, subject, KIND);
		check(settled != NULL, "the setting the record carried is not readable back");

		check(fzn_log_init(&log, lentries, 2u) == FZN_LOG_OK, "log");
		check(fzn_log_append(&log, &arrived) == FZN_LOG_OK,
		      "the verified record would not append to the log");
		check(fzn_log_get(&log, &journal, fzn_record_issuer(arrived),
		                  fzn_record_stream(arrived), fzn_record_seq(arrived),
		                  &held) == FZN_LOG_OK && held != NULL,
		      "the record the log just took cannot be fetched back");

		/* AND THE TWO ABSENCES ARE DIFFERENT, which is what the journal
		 * argument to `fzn_log_get` is for: a sequence the log evicted
		 * is GONE and must not be asked for again, while one above what
		 * this host has received is merely ABSENT. */
		check(fzn_log_get(&log, &journal, fzn_record_issuer(arrived),
		                  fzn_record_stream(arrived), fzn_record_seq(arrived) + 5u,
		                  &held) == FZN_LOG_ERR_ABSENT,
		      "a sequence this host has never received reads as evicted rather than "
		      "as not yet arrived");

		fzn_reasm_release(done);
	}

	/* ---- A BLOB, AND THE JOIN NOTHING IN THIS TREE MAKES -------------- */

	/* SESSION KEY -> SEALED FRAME -> BLOB LEAF -> SPOOL. Each of those
	 * three hops is tested somewhere; none of the joins is. `blob/` and
	 * `spool/` are not so much as INCLUDED by `sim/test/network_test.c`,
	 * and the only file that seals under a real session key sends one
	 * frame and stops.
	 *
	 * The content key is what has to cross, and it crosses the way a
	 * consumer would send it: inside a frame sealed under the session the
	 * scan established. Everything after that is keyless -- which is the
	 * property the last leg asserts.
	 */
	{
		enum { LEAVES = 2u, TAIL = 400u };

		uint8_t content_key[FZN_BLOB_KEY_LEN];
		uint8_t plain[LEAVES][FZN_BLOB_LEAF_SIZE];
		uint8_t sealed[LEAVES][FZN_BLOB_SEALED_MAX];
		size_t sealed_len[LEAVES];
		size_t plain_len[LEAVES];
		uint8_t leaf_hash[LEAVES][FZN_BLOB_HASH_LEN];
		uint8_t proof[LEAVES][FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
		unsigned proof_len[LEAVES];
		uint8_t blob_root[FZN_BLOB_HASH_LEN];
		fzn_blob_tree_t tree;

		uint8_t carried_key[FZN_BLOB_KEY_LEN];
		fzn_spool_t spool;
		uint8_t present[FZN_SPOOL_BITMAP_LEN(LEAVES)];
		uint8_t back[FZN_BLOB_SEALED_MAX];
		size_t back_len = 0;
		uint8_t recovered[FZN_BLOB_LEAF_SIZE];
		size_t recovered_len = 0;
		unsigned n;

		for (n = 0; n < LEAVES; n++) {
			/* Every leaf is FZN_BLOB_LEAF_SIZE except the last,
			 * which may be short and never empty. */
			plain_len[n] = (n + 1u == LEAVES) ? TAIL : FZN_BLOB_LEAF_SIZE;
			for (i = 0; i < plain_len[n]; i++)
				plain[n][i] = (uint8_t)((n * 31u) + (i * 13u) + 5u);
		}
		memset(content_key, 0x2bu, sizeof(content_key));

		/* THE SEEDER: seal, hash, fold. */
		fzn_blob_tree_init(&tree);
		for (n = 0; n < LEAVES; n++) {
			check(fzn_blob_leaf_seal(&hash_ops, &aead_ops, content_key, n, plain[n],
			                         plain_len[n], sealed[n], sizeof(sealed[n]),
			                         &sealed_len[n]) == FZN_BLOB_OK,
			      "a blob leaf would not seal");
			check(fzn_blob_leaf_hash(&hash_ops, sealed[n], sealed_len[n],
			                         leaf_hash[n]) == FZN_BLOB_OK,
			      "a sealed leaf would not hash");
			check(fzn_blob_tree_push(&hash_ops, &tree, leaf_hash[n]) == FZN_BLOB_OK,
			      "a leaf hash would not fold into the tree");
		}
		check(fzn_blob_tree_root(&hash_ops, &tree, blob_root) == FZN_BLOB_OK,
		      "the blob has no root");
		for (n = 0; n < LEAVES; n++)
			check(fzn_blob_proof_build(&hash_ops, leaf_hash[0], LEAVES, n, proof[n],
			                           sizeof(proof[n]), &proof_len[n]) == FZN_BLOB_OK,
			      "a leaf proof would not build");

		/* THE HAND-OFF, and it is the join. The content key is 32 bytes
		 * of secret and it travels sealed under the session the scan
		 * produced -- not beside it, not in the payload the code
		 * carried, which is reusable and public. */
		{
			uint8_t frame[FZN_SEAL_OVERHEAD + FZN_BLOB_KEY_LEN];
			size_t frame_len = 0;
			fzn_send_t what;
			fzn_opened_t got;

			memset(&what, 0, sizeof(what));
			what.sender = device_pub;
			what.capability = cap.b;
			what.payload = content_key;
			what.payload_len = sizeof(content_key);
			what.expires_at = 2000u;
			what.msg = 77u;
			what.index = 0u;
			what.chunks = 1u;
			what.kind = 2u;

			check(fzn_seal_build(frame, sizeof(frame), &frame_len, &what, key_device,
			                     ck_device, &hash_ops, &rng_ops,
			                     &aead_ops) == FZN_SEAL_OK,
			      "the content key would not seal");
			check(fzn_seal_open(frame, frame_len, key_sponsor, ck_sponsor, &hash_ops,
			                    &aead_ops, &got) == FZN_SEAL_OK,
			      "the sponsor could not open the frame carrying the content key");
			check(got.payload_len == FZN_BLOB_KEY_LEN,
			      "the content key arrived the wrong length");
			memcpy(carried_key, got.payload, FZN_BLOB_KEY_LEN);
		}

		/* THE RECEIVER: a spool over the root, leaves placed in the
		 * wrong order, each verified against the root before it is
		 * written. */
		memset(present, 0, sizeof(present));
		memset(spool_disk, 0, sizeof(spool_disk));
		check(fzn_spool_open(&spool, blob_root, LEAVES, present, sizeof(present),
		                     &SPOOL_OPS) == FZN_SPOOL_OK,
		      "the sponsor could not open a spool over the blob's root");
		check(!fzn_spool_complete(&spool), "an empty spool reports itself complete");

		for (n = LEAVES; n-- > 0;) {
			check(fzn_spool_place(&spool, &hash_ops, n, sealed[n], sealed_len[n],
			                      proof[n], proof_len[n]) == FZN_SPOOL_OK,
			      "a leaf that proves against the root was refused by the spool");
			check(fzn_spool_has(&spool, n), "and the spool does not hold it");
		}
		check(fzn_spool_complete(&spool),
		      "every leaf was placed and the spool is not complete");

		/* AND ONLY NOW DOES THE KEY MATTER. Placing was keyless -- the
		 * proof is what admitted each leaf -- so a relay can carry and
		 * verify bytes it cannot read. Reading the plaintext back needs
		 * the key that crossed inside the sealed frame. */
		check(fzn_spool_read(&spool, 0u, back, sizeof(back), &back_len) ==
		              FZN_SPOOL_OK,
		      "a placed leaf cannot be read back out of the spool");
		check(back_len == sealed_len[0],
		      "the leaf came back a different length from the one placed");
		check(fzn_blob_leaf_open(&hash_ops, &aead_ops, carried_key, 0u, back, back_len,
		                         recovered, sizeof(recovered),
		                         &recovered_len) == FZN_BLOB_OK,
		      "the leaf would not open under the content key that crossed the wire");
		check(recovered_len == plain_len[0]
		              && memcmp(recovered, plain[0], plain_len[0]) == 0,
		      "the blob's bytes did not survive seal, frame, spool and open");

		/* THE RELAY'S POSITION, asserted rather than described: the same
		 * leaf under a key nobody sent is refused, so the bytes a relay
		 * holds are bytes it cannot read. */
		{
			uint8_t stranger_key[FZN_BLOB_KEY_LEN];

			memset(stranger_key, 0x2cu, sizeof(stranger_key));
			check(memcmp(stranger_key, carried_key, FZN_BLOB_KEY_LEN) != 0,
			      "the stranger's key is the real one, so the refusal below is empty");
			check(fzn_blob_leaf_open(&hash_ops, &aead_ops, stranger_key, 0u, back,
			                         back_len, recovered, sizeof(recovered),
			                         &recovered_len) != FZN_BLOB_OK,
			      "a leaf opened under a content key nobody sent, so a relay can read "
			      "what it is only supposed to carry");
		}
		/* A LEAF THAT DOES NOT PROVE IS REFUSED, and without this leg
		 * the spool's whole argument is untested: measured, deleting
		 * `fzn_spool_place`'s proof check leaves every assertion above
		 * green, because they only ever place leaves that are correct.
		 * A store that writes whatever it is handed is a store an
		 * attacker fills.
		 *
		 * The bytes are leaf 0's, offered as leaf 1. They are a real
		 * sealed leaf of this very blob, so what refuses them is the
		 * proof against the root rather than anything about their
		 * shape. */
		{
			fzn_spool_t fresh;
			uint8_t fresh_present[FZN_SPOOL_BITMAP_LEN(LEAVES)];

			memset(fresh_present, 0, sizeof(fresh_present));
			memset(spool_disk, 0, sizeof(spool_disk));
			check(fzn_spool_open(&fresh, blob_root, LEAVES, fresh_present,
			                     sizeof(fresh_present), &SPOOL_OPS) == FZN_SPOOL_OK,
			      "the control spool would not open");
			check(fzn_spool_place(&fresh, &hash_ops, 1u, sealed[0], sealed_len[0],
			                      proof[1], proof_len[1]) != FZN_SPOOL_OK,
			      "a leaf that does not prove against the root was placed, so the "
			      "spool writes whatever it is handed");
			check(!fzn_spool_has(&fresh, 1u),
			      "and the spool recorded holding it anyway");
			check(!fzn_spool_complete(&fresh),
			      "and it called itself complete on a leaf it refused");
		}

	}

	/* ---- THE RATCHET, AND THE ORDER ITS HEADER IS BUILT ON ------------ */

	/* ADVANCE, OPEN, AND ONLY THEN COMMIT. `ratchet/ratchet.h` spends four
	 * paragraphs on this and nothing in this tree exercises it: the two
	 * scenarios that derive message keys compare them in memory and throw
	 * them away, so the ordering has never carried a frame.
	 *
	 * WHAT THE ORDER PREVENTS, in that header's words: a receiver that
	 * fast-forwards before it verifies has still advanced on a frame that
	 * FAILS to open, and a ratchet moves one way -- so every later genuine
	 * message from that sender is behind the position, refused as an
	 * ordinary duplicate, with its keys gone. "One forged datagram from
	 * anyone who has seen a real one therefore ENDS that sender's delivery
	 * to that receiver, permanently, with no key material." Traced by
	 * fuzzypickles in their own live path at a311c7f.
	 *
	 * SO BOTH RECEIVERS ARE RUN, which is what makes this a demonstration
	 * rather than an assertion. `careful` commits only when the frame
	 * opens; `hasty` commits whatever happens, which is the caller the
	 * header says cannot be spelled through the API and can still be
	 * written by hand. They are fed the same three datagrams. Without the
	 * discipline the difference is not a smaller number, it is a dead
	 * conversation. */
	{
		static const uint8_t MSG0[] = "first, under a message key";
		static const uint8_t MSG1[] = "second, after somebody forged one";

		uint8_t dev_send[FZN_CHAIN_KEY_LEN], dev_recv[FZN_CHAIN_KEY_LEN];
		uint8_t spo_send[FZN_CHAIN_KEY_LEN], spo_recv[FZN_CHAIN_KEY_LEN];
		fzn_ratchet_chain_t sender, careful, hasty, next;
		uint8_t mk[FZN_MESSAGE_KEY_LEN], mk_careful[FZN_MESSAGE_KEY_LEN];
		uint8_t mk_hasty[FZN_MESSAGE_KEY_LEN];
		uint8_t frame0[FZN_SEAL_OVERHEAD + sizeof(MSG0)];
		uint8_t frame1[FZN_SEAL_OVERHEAD + sizeof(MSG1)];
		uint8_t forged[FZN_SEAL_OVERHEAD + sizeof(MSG1)];
		size_t len0 = 0, len1 = 0, forged_len = 0;
		fzn_send_t what;
		fzn_opened_t got;
		unsigned careful_delivered = 0, hasty_delivered = 0;

		/* THE CHAINS ARE DIRECTED, which is the property that keeps a
		 * message replayed at its own sender from opening under the key
		 * it is waiting to receive under. */
		check(fzn_session_chains(&hash_ops, key_device, device_pub, root_pub, dev_send,
		                         dev_recv) == FZN_SESSION_OK,
		      "the device could not derive its ratchet chains");
		check(fzn_session_chains(&hash_ops, key_sponsor, root_pub, device_pub, spo_send,
		                         spo_recv) == FZN_SESSION_OK,
		      "the sponsor could not derive its ratchet chains");
		check(memcmp(dev_send, spo_recv, FZN_CHAIN_KEY_LEN) == 0,
		      "the device's send chain is not the sponsor's receive chain, so nothing "
		      "it sends can be opened");
		check(memcmp(dev_send, dev_recv, FZN_CHAIN_KEY_LEN) != 0,
		      "the two directions share a chain, so a message replayed at its sender "
		      "opens under the key it is waiting to receive under");

		fzn_ratchet_init(&sender, dev_send, 0u);
		fzn_ratchet_init(&careful, spo_recv, 0u);
		fzn_ratchet_init(&hasty, spo_recv, 0u);

		/* THE UNSAFE SPELLING IS REFUSED, which is what makes the rule
		 * a mechanism rather than a sentence in a header. */
		check(fzn_ratchet_advance(&hash_ops, &careful, 0u, mk, &careful, NULL, 0, NULL,
		                          NULL) == FZN_RATCHET_ERR_IN_PLACE,
		      "advancing a chain in place was allowed, so the one caller the header "
		      "says cannot be written can be written");

		/* ---- message 0, genuine ---------------------------------- */
		check(fzn_ratchet_advance(&hash_ops, &sender, 0u, mk, &next, NULL, 0, NULL,
		                          NULL) == FZN_RATCHET_OK,
		      "the sender could not derive its first message key");
		sender = next;

		memset(&what, 0, sizeof(what));
		what.sender = device_pub;
		what.capability = cap.b;
		what.payload = MSG0;
		what.payload_len = sizeof(MSG0);
		what.expires_at = 2000u;
		what.msg = 100u;
		what.index = 0u;
		what.chunks = 1u;
		what.kind = 1u;
		check(fzn_seal_build(frame0, sizeof(frame0), &len0, &what, mk, ck_device,
		                     &hash_ops, &rng_ops, &aead_ops) == FZN_SEAL_OK,
		      "a frame would not seal under a ratchet message key");

		/* Both receivers take it, and both are entitled to advance --
		 * this one opens. */
		{
			uint8_t copy[sizeof(frame0)];

			check(fzn_ratchet_advance(&hash_ops, &careful, 0u, mk_careful, &next,
			                          NULL, 0, NULL, NULL) == FZN_RATCHET_OK,
			      "the careful receiver could not advance to the first message");
			memcpy(copy, frame0, len0);
			if (fzn_seal_open(copy, len0, mk_careful, ck_sponsor, &hash_ops,
			                  &aead_ops, &got) == FZN_SEAL_OK) {
				careful = next;   /* committed only now */
				careful_delivered++;
			}
			check(careful_delivered == 1u,
			      "the first genuine message did not open under the receiver's own "
			      "derived message key");

			check(fzn_ratchet_advance(&hash_ops, &hasty, 0u, mk_hasty, &next, NULL, 0,
			                          NULL, NULL) == FZN_RATCHET_OK,
			      "the hasty receiver could not advance to the first message");
			hasty = next;             /* committed before verifying */
			memcpy(copy, frame0, len0);
			if (fzn_seal_open(copy, len0, mk_hasty, ck_sponsor, &hash_ops, &aead_ops,
			                  &got) == FZN_SEAL_OK)
				hasty_delivered++;
			check(hasty_delivered == 1u,
			      "the hasty receiver did not take the first message either, so the "
			      "divergence below would not be about the commit");
		}

		/* ---- a forgery claiming the next sequence ----------------- */

		/* Sealed under a key nobody shares, which is what anyone who has
		 * seen a real datagram can produce: the shape is right and the
		 * tag is not. */
		{
			uint8_t stranger[FZN_AEAD_KEY_LEN];

			memset(stranger, 0x6du, sizeof(stranger));
			memset(&what, 0, sizeof(what));
			what.sender = device_pub;
			what.capability = cap.b;
			what.payload = MSG1;
			what.payload_len = sizeof(MSG1);
			what.expires_at = 2000u;
			what.msg = 101u;
			what.index = 0u;
			what.chunks = 1u;
			what.kind = 1u;
			check(fzn_seal_build(forged, sizeof(forged), &forged_len, &what, stranger,
			                     ck_device, &hash_ops, &rng_ops,
			                     &aead_ops) == FZN_SEAL_OK,
			      "the forgery would not seal");
		}

		{
			uint8_t copy[sizeof(forged)];

			/* CAREFUL: derives, fails to open, does not commit. */
			check(fzn_ratchet_advance(&hash_ops, &careful, 1u, mk_careful, &next, NULL,
			                          0, NULL, NULL) == FZN_RATCHET_OK,
			      "the careful receiver could not advance for the forgery");
			memcpy(copy, forged, forged_len);
			check(fzn_seal_open(copy, forged_len, mk_careful, ck_sponsor, &hash_ops,
			                    &aead_ops, &got) != FZN_SEAL_OK,
			      "a frame sealed under a key nobody shares opened, so the forgery is "
			      "not one");
			/* no commit */

			/* HASTY: derives and commits, then fails to open. */
			check(fzn_ratchet_advance(&hash_ops, &hasty, 1u, mk_hasty, &next, NULL, 0,
			                          NULL, NULL) == FZN_RATCHET_OK,
			      "the hasty receiver could not advance for the forgery");
			hasty = next;
			memcpy(copy, forged, forged_len);
			check(fzn_seal_open(copy, forged_len, mk_hasty, ck_sponsor, &hash_ops,
			                    &aead_ops, &got) != FZN_SEAL_OK,
			      "the forgery opened for the hasty receiver");
		}

		/* ---- message 1, genuine, after the forgery ---------------- */
		check(fzn_ratchet_advance(&hash_ops, &sender, 1u, mk, &next, NULL, 0, NULL,
		                          NULL) == FZN_RATCHET_OK,
		      "the sender could not derive its second message key");
		sender = next;

		memset(&what, 0, sizeof(what));
		what.sender = device_pub;
		what.capability = cap.b;
		what.payload = MSG1;
		what.payload_len = sizeof(MSG1);
		what.expires_at = 2000u;
		what.msg = 102u;
		what.index = 0u;
		what.chunks = 1u;
		what.kind = 1u;
		check(fzn_seal_build(frame1, sizeof(frame1), &len1, &what, mk, ck_device,
		                     &hash_ops, &rng_ops, &aead_ops) == FZN_SEAL_OK,
		      "the second genuine frame would not seal");

		{
			uint8_t copy[sizeof(frame1)];
			fzn_ratchet_err_t hasty_err;

			/* THE CAREFUL RECEIVER IS EXACTLY WHERE IT WAS, so the
			 * genuine message opens and the forgery cost it nothing
			 * but the derivations. */
			check(fzn_ratchet_advance(&hash_ops, &careful, 1u, mk_careful, &next, NULL,
			                          0, NULL, NULL) == FZN_RATCHET_OK,
			      "the careful receiver could not advance to the second message, so "
			      "the forgery moved it after all");
			memcpy(copy, frame1, len1);
			if (fzn_seal_open(copy, len1, mk_careful, ck_sponsor, &hash_ops, &aead_ops,
			                  &got) == FZN_SEAL_OK) {
				careful = next;
				careful_delivered++;
			}
			check(careful_delivered == 2u,
			      "a genuine message after a forgery did not open, which is the "
			      "defect the advance-open-commit order exists to prevent");
			check(got.payload_len == sizeof(MSG1)
			              && memcmp(got.payload, MSG1, sizeof(MSG1)) == 0,
			      "it opened and the payload is not the one that was sent");

			/* AND THE HASTY ONE IS DEAD. The chain is past sequence
			 * 1, so the genuine message is BEHIND it -- refused, with
			 * the key material it needed already overwritten. This is
			 * the permanent, silent failure the header describes, and
			 * it reports itself as an ordinary duplicate. */
			hasty_err = fzn_ratchet_advance(&hash_ops, &hasty, 1u, mk_hasty, &next,
			                                NULL, 0, NULL, NULL);
			check(hasty_err == FZN_RATCHET_ERR_BEHIND,
			      "the hasty receiver could still advance to the message it had "
			      "already burned, so this case is not the defect it names");
			check(hasty_delivered == 1u,
			      "the hasty receiver delivered the second message, so committing "
			      "before verifying costs nothing and this whole leg is theatre");
		}

		fzn_wipe(mk, sizeof(mk));
		fzn_wipe(mk_careful, sizeof(mk_careful));
		fzn_wipe(mk_hasty, sizeof(mk_hasty));
		fzn_ratchet_wipe(&sender);
		fzn_ratchet_wipe(&careful);
		fzn_ratchet_wipe(&hasty);
	}

	/* ---- A RELAY, WHICH FORWARDS WHAT IT CANNOT READ ------------------ */

	/* `fzn_send_t.hops` is never set anywhere in this tree's simulation --
	 * the harness memsets the struct, so every frame it has ever moved was
	 * unrelayable -- and `wire/relay.h` appears in no scenario. This leg
	 * puts a frame through a hop that has no key.
	 *
	 * THE BUDGET IS PLAINTEXT AND THAT IS THE DESIGN. A relay must be able
	 * to decrement it without holding anything, so the byte sits outside
	 * what the tag covers. The claim that then has to hold is that
	 * decrementing it does not disturb the frame: the receiver's payload
	 * must come back identical after a hop has spent from it.
	 *
	 * WHAT THE BUDGET DEFENDS, in the header's words, is "the network
	 * against itself: loops, and one misconfigured host multiplying
	 * traffic. That is a real property and a narrow one." A stranger
	 * writing zero merely drops the frame, which anybody on the path could
	 * do by discarding it. So this leg asserts the narrow property and not
	 * a wider one. */
	{
		static const uint8_t CARRIED[] = "forwarded by a host that cannot read it";
		uint8_t frame[FZN_SEAL_OVERHEAD + sizeof(CARRIED)];
		uint8_t hopped[sizeof(frame)];
		uint8_t stranger[FZN_AEAD_KEY_LEN];
		size_t frame_len = 0;
		fzn_send_t what;
		fzn_opened_t got;
		uint8_t budget = 0;
		unsigned spent;

		/* THE CONSTANT IS HALF A FRAME-FORMAT DISCRIMINATOR IN ANOTHER
		 * TREE, and until now that was held by a paragraph. fuzzypickles
		 * demultiplex one UDP port on offset 1 alone: this frame carries
		 * `hops_left` there, which `fzn_seal_build` refuses above the
		 * bound, so the byte is 0..8; their command byte's lowest
		 * reaching value is 0x0E. Offset 0 cannot separate them -- both
		 * are the byte 1.
		 *
		 * Their side pins it too, and their header says that pin "fails
		 * once somebody has already changed this". This is the half that
		 * fires first, and it is where the person raising the bound is
		 * looking. */
		check(FZN_RELAY_MAX_HOPS < 0x0Eu,
		      "FZN_RELAY_MAX_HOPS has reached the value fuzzypickles' demultiplexer "
		      "reads as a pairing command, so this frame's hop count is about to be "
		      "mistaken for one of theirs on a live path, silently and with no "
		      "compile error in either tree");

		memset(&what, 0, sizeof(what));
		what.sender = device_pub;
		what.capability = cap.b;
		what.payload = CARRIED;
		what.payload_len = sizeof(CARRIED);
		what.expires_at = 2000u;
		what.msg = 200u;
		what.index = 0u;
		what.chunks = 1u;
		what.kind = 1u;
		what.hops = FZN_RELAY_MAX_HOPS;

		check(fzn_seal_build(frame, sizeof(frame), &frame_len, &what, key_device,
		                     ck_device, &hash_ops, &rng_ops, &aead_ops) == FZN_SEAL_OK,
		      "a relayable frame would not seal");

		/* A BOUND ABOVE THE CEILING IS REFUSED AT SEALING, which is what
		 * keeps the byte inside 0..8 and therefore keeps the
		 * disambiguation above true of every frame this library emits. */
		{
			uint8_t over[sizeof(frame)];
			size_t over_len = 0;

			what.hops = (uint8_t)(FZN_RELAY_MAX_HOPS + 1u);
			check(fzn_seal_build(over, sizeof(over), &over_len, &what, key_device,
			                     ck_device, &hash_ops, &rng_ops,
			                     &aead_ops) != FZN_SEAL_OK,
			      "a frame claiming more hops than this library forwards was sealed, "
			      "so the byte at offset 1 is no longer bounded");
			what.hops = FZN_RELAY_MAX_HOPS;
		}

		/* THE RELAY HOLDS NO KEY. It reads the budget and spends from it
		 * on a copy, exactly as a forwarding host would. */
		memcpy(hopped, frame, frame_len);
		check(fzn_relay_budget(hopped, frame_len, FZN_RELAY_MAX_HOPS, &budget) ==
		              FZN_RELAY_OK && budget == FZN_RELAY_MAX_HOPS,
		      "a relay could not read the budget out of a frame it is asked to forward");

		memset(stranger, 0x9au, sizeof(stranger));
		{
			uint8_t attempt[sizeof(frame)];

			memcpy(attempt, hopped, frame_len);
			check(fzn_seal_open(attempt, frame_len, stranger, ck_sponsor, &hash_ops,
			                    &aead_ops, &got) != FZN_SEAL_OK,
			      "the relay opened the frame it is only supposed to forward");
		}

		check(fzn_relay_spend(hopped, frame_len, FZN_RELAY_MAX_HOPS) == FZN_RELAY_OK,
		      "a relay could not spend from the budget");
		check(fzn_relay_budget(hopped, frame_len, FZN_RELAY_MAX_HOPS, &budget) ==
		              FZN_RELAY_OK && budget == FZN_RELAY_MAX_HOPS - 1u,
		      "spending a hop did not move the budget");

		/* AND THE FRAME IS STILL THE FRAME. This is the claim the
		 * plaintext byte has to earn: the receiver derives its own key,
		 * opens what a relay has rewritten, and gets the payload that
		 * was sent. */
		check(fzn_seal_open(hopped, frame_len, key_sponsor, ck_sponsor, &hash_ops,
		                    &aead_ops, &got) == FZN_SEAL_OK,
		      "a frame that a relay decremented no longer opens, so the hop byte is "
		      "inside what the tag covers");
		check(got.payload_len == sizeof(CARRIED)
		              && memcmp(got.payload, CARRIED, sizeof(CARRIED)) == 0,
		      "the payload changed when a relay spent a hop");
		check(memcmp(got.sender, device_pub, FZN_PUBKEY_LEN) == 0,
		      "the relayed frame names a different sender than the one that sealed it");

		/* THE BUDGET IS A LOOP BOUND, so it runs out. Spent from a fresh
		 * copy, because the open above consumed the one in flight. */
		memcpy(hopped, frame, frame_len);
		for (spent = 0; spent < FZN_RELAY_MAX_HOPS; spent++)
			check(fzn_relay_spend(hopped, frame_len, FZN_RELAY_MAX_HOPS) ==
			              FZN_RELAY_OK,
			      "a hop within the budget was refused");
		check(fzn_relay_budget(hopped, frame_len, FZN_RELAY_MAX_HOPS, &budget) ==
		              FZN_RELAY_OK && budget == 0u,
		      "the budget did not reach zero after being spent in full");
		check(fzn_relay_spend(hopped, frame_len, FZN_RELAY_MAX_HOPS) ==
		              FZN_RELAY_ERR_EXHAUSTED,
		      "a frame with no budget left was forwarded anyway, so a loop does not "
		      "die -- which is the one thing this byte is for");

		/* AND IT STILL OPENS AT ZERO. A frame that may travel no further
		 * is not a frame that has stopped being valid: the last host on
		 * the path is the one it was for. */
		check(fzn_seal_open(hopped, frame_len, key_sponsor, ck_sponsor, &hash_ops,
		                    &aead_ops, &got) == FZN_SEAL_OK
		              && got.payload_len == sizeof(CARRIED),
		      "a frame whose budget is spent no longer opens, so the last host on a "
		      "path cannot read what was sent to it");

		/* A FRAME NOBODY OFFERED FOR RELAYING IS NOT RELAYABLE, which is
		 * what `hops = 0` means and what every other frame in this file
		 * has been. */
		{
			uint8_t solo[sizeof(frame)];
			size_t solo_len = 0;

			what.hops = 0u;
			check(fzn_seal_build(solo, sizeof(solo), &solo_len, &what, key_device,
			                     ck_device, &hash_ops, &rng_ops,
			                     &aead_ops) == FZN_SEAL_OK,
			      "an unrelayable frame would not seal");
			check(fzn_relay_spend(solo, solo_len, FZN_RELAY_MAX_HOPS) ==
			              FZN_RELAY_ERR_EXHAUSTED,
			      "a frame offered for no hops was forwarded");
			check(fzn_seal_open(solo, solo_len, key_sponsor, ck_sponsor, &hash_ops,
			                    &aead_ops, &got) == FZN_SEAL_OK,
			      "and an unrelayable frame does not open for the host it was for");
		}
	}

	fzn_agree_secret_wipe(&device_sk);
	fzn_agree_secret_wipe(&sponsor_sk);
	fzn_sign_monocypher_wipe(&device_signer);
	fzn_sign_monocypher_wipe(&sponsor_signer);

	printf("provision_test: %d checks, %d failure(s); fuzznet %s\n", checks, failures,
	       fzn_version_string());
	return failures == 0 ? 0 : 1;
}
