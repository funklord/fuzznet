#ifndef FZN_RPC_CONTROL_H
#define FZN_RPC_CONTROL_H

#include "../state/schema.h"
#include <stddef.h>
#include <stdint.h>

#include "rpc_capability.h" /* fzn_rpc_capability_type_t, project.md sec 3/12 */
#include "rpc_limits.h" /* FZN_RPC_PEER_ADDRESS_MAX / _TEXT_MAX / _NAME_MAX */

/*
 * What the clients hold of what a node told them: the structs the typed calls
 * (client/calls.h) fill, and the bounds on them.
 */

#define FZN_RPC_HOST_NAME_MAX 64

/* Which tier the blob is stored under (project.md sec 11). Public means a
 * convergent key, so identical content dedups across users who never
 * coordinated; private means a random one, so it does not. */
#define FZN_RPC_BLOB_TIER_PUBLIC 1
#define FZN_RPC_BLOB_TIER_PRIVATE 2

#define FZN_RPC_BLOB_PATH_MAX 4095
#define FZN_RPC_BLOB_MAX_FILE_BYTES (64u * 1024u * 1024u)

/*
 * Whether a name may be used as a peer or sibling name: ASCII [a-zA-Z0-9_],
 * 1..FZN_RPC_PEER_NAME_MAX bytes. Stricter than a host name, which permits
 * general UTF-8, because this one becomes a literal storage-key suffix.
 *
 * Public because clients need it before the fact. A host may legitimately be
 * called "my-laptop", and that host can then never be registered as anyone's
 * sibling -- so a revocation can never reach it -- and until the caller can
 * check the rule up front, the only way to discover that is to link the host
 * and read a warning afterwards.
 */
int fzn_rpc_is_valid_peer_name(const char *name, size_t len);
#define FZN_RPC_SIBLING_LIST_MAX 32  /* entries per FZN_RPC_SIBLING_SUBCMD_LIST response; a
                                    user's own hosts, so not raised with contacts */
#define FZN_RPC_PEER_REQUEST_MAX 1024     /* pending_peer_request_index bound, project.md sec 8
                                        bounded buffers -- overflow policy is LRU-evict the
                                        oldest unapproved entry, not reject, see peer_pair.c */
#define FZN_RPC_CONTACT_MANIFEST_SEED_MAX 4 /* max other-host entries a contact card may embed --
                                            seeds initial manifest knowledge only, NOT the full
                                            manifest mechanism (project.md sec 10, still OPEN) */
#define FZN_RPC_PREKEY_RECORD_LEN 138 /* version(1)+tag(1)+host_pubkey(32)+prekey_pk(32)
                                      + created_at(8)+signature(64) -- see
                                      messaging_internal.h. The tag is signed_tag.h's;
                                      without it this record's transcript collides with
                                      a host record's. */
#define FZN_RPC_INBOX_MAX_ENTRIES 100 /* storage cap, project.md sec 8 bounded buffers */
#define FZN_RPC_INBOX_PAGE_MAX 20     /* per-response cap, independent of the storage cap;
                                      most-recent-first */

/* version(1)+tag(1)+host_pubkey(32)+host_name lenprefixed(2+MAX)+created_at(8)+
 * signer_pubkey(32)+signature(64) -- see identity_internal.h. A MAXIMUM (host_name is
 * variable), not an exact length -- unlike FZN_RPC_PREKEY_RECORD_LEN, nothing here is
 * fixed-width throughout. tag is signed_tag.h's, and is inside the signed range. */
#define FZN_RPC_HOST_RECORD_BLOB_LEN (1 + 1 + 32 + (2 + FZN_RPC_HOST_NAME_MAX) + 8 + 32 + 64)
/* version(1)+tag(1)+host_pubkey(32)+host_name lenprefixed(2+MAX)+created_at(8)+
 * signature(64) -- the host-join request blob, self-signed by the new host's own (not yet
 * cross-signed) key -- see identity_internal.h. Also a maximum. Its tag differs from a
 * host record's despite the identical layout: same bytes, different signed object. */
/* version(1)+host_pubkey(32)+host_name lenprefixed+created_at(8)+
 * address lenprefixed+prekey_record lenprefixed+signature(64).
 *
 * The address and prekey are OPTIONAL (either may be empty) and exist so the
 * approving host can register this one as a sibling on the spot, rather than
 * leaving the operator to do it by hand afterwards -- without which a freshly
 * linked device can never be told its authority was withdrawn (see
 * fzn_rpc_host_join_approve). Both sit INSIDE the signed region, so a host is
 * self-signing where it says it can be reached.
 *
 * Carrying an address in an offline blob does not make the exchange require
 * networking: it records where to find a host later, which is exactly what
 * the contact card (sec 12) already does for a stranger, printed and
 * scanned. Empty is fine and degrades to the older behaviour -- a device not
 * yet on a network, or with no prekey generated, simply says nothing here. */
#define FZN_RPC_JOIN_REQUEST_BLOB_LEN                                             \
  (1 + 1 + 32 + (2 + FZN_RPC_HOST_NAME_MAX) + 8 + (2 + FZN_RPC_PEER_ADDRESS_MAX) +     \
   (2 + FZN_RPC_PREKEY_RECORD_LEN) + 64)

/* Capability delegation chain (project.md sec 3/12) -- see
 * core/src/capability_internal.h for the full mint/install/verify contract.
 * One hop: grantor_pubkey(32)+grantee_pubkey(32)+capability_type(1)+
 * scope lenprefixed(2+FZN_RPC_CAP_SCOPE_MAX)+issued_at(8)+expires_at(8)+signature(64).
 * scope is always empty this milestone (no groups/scoped resources exist yet
 * to narrow to) but the field is sized now rather than retrofitted later,
 * same reasoning applied to fzn_rpc_capability_type_t itself. */
#define FZN_RPC_CAP_SCOPE_MAX 32
#define FZN_RPC_CAP_CHAIN_MAX_HOPS 8 /* bounded, project.md sec 8 -- an unbounded chain is an
                                    eventual DoS-by-bureaucracy risk; 8 is generous for
                                    any real delegation depth in a small personal mesh */
/* Each hop repeats the chain version and carries signed_tag.h's tag, both
 * INSIDE its own signed range -- see capability.c for why they are per-hop
 * rather than read from the chain header. */
#define FZN_RPC_CAP_CHAIN_HOP_LEN (1 + 1 + 32 + 32 + 1 + (2 + FZN_RPC_CAP_SCOPE_MAX) + 8 + 8 + 64)
/* version(1)+hop_count(1)+hops -- a MAXIMUM (hop_count and scope both vary). */
#define FZN_RPC_CAP_CHAIN_BLOB_LEN (1 + 1 + FZN_RPC_CAP_CHAIN_MAX_HOPS * FZN_RPC_CAP_CHAIN_HOP_LEN)
/* A hop's expires_at of 0 means NO EXPIRY, and is the default. Same
 * convention the contact card already uses (project.md sec 12,
 * "expires_at (0 = permanent, the default)").
 *
 * Authority in this project is not supposed to hinge on a clock. A host
 * whose grant quietly ran out while it was switched off, or whose clock
 * disagrees with its root's, must not thereby fall out of the mesh --
 * losing a device to arithmetic is a worse and far more likely failure than
 * the one a timer defends against. Revocation is an explicit, signed act
 * that propagates host to host on contact (see fzn_rpc_capability_revoke),
 * which is what makes not-expiring safe rather than merely convenient.
 *
 * An expiry may still be set deliberately, and is then honoured -- an
 * operator asking for a time-boxed grant gets one. It is simply never the
 * mechanism anything else depends on. */
#define FZN_RPC_CAP_NO_EXPIRY 0ULL

#define FZN_RPC_GRANT_LIST_MAX 1024

/* version(1)+host_record_blob lenprefixed(2+FZN_RPC_HOST_RECORD_BLOB_LEN)+
 * signer_chain lenprefixed(2+FZN_RPC_CAP_CHAIN_BLOB_LEN, empty when the root
 * signed directly) -- the "host proof bundle": who a host is and who
 * vouched for it. Also a maximum. Grown from milestone 3's shape (which had
 * no signer_chain field) to let a CAP_HOST_MANAGE delegate's approval carry
 * proof of its own authority alongside the host_record it signs.
 *
 * This is a pure IDENTITY assertion, and deliberately says nothing about
 * what the host may DO. That is why the conferred-capability grants added
 * to host-join live in a separate envelope wrapping this one
 * (FZN_RPC_JOIN_APPROVAL_BLOB_LEN below) rather than as another field here:
 * this bundle is also embedded verbatim in the contact card and the peer
 * pairing request below, both of which travel to OTHER USERS' hosts. A
 * capability set has no business in either, and growing this constant would
 * have silently inflated both. */
#define FZN_RPC_HOST_PROOF_BLOB_LEN \
  (1 + (2 + FZN_RPC_HOST_RECORD_BLOB_LEN) + (2 + FZN_RPC_CAP_CHAIN_BLOB_LEN))

/* version(1)+host_proof_bundle lenprefixed(2+FZN_RPC_HOST_PROOF_BLOB_LEN)+
 * grant_count(1)+grants(FZN_RPC_JOIN_GRANT_MAX * (capability_type(1)+chain
 * lenprefixed(2+FZN_RPC_CAP_CHAIN_BLOB_LEN))) -- the host-join approval blob
 * handed back to the new host. A maximum.
 *
 * The envelope exists so an approver can hand a new host its capabilities
 * in the SAME exchange that establishes its identity, rather than the
 * operator having to follow every join with a separate cap-grant round trip
 * to the root (project.md sec 3). What may be conferred is bounded by what
 * the approver itself holds -- see fzn_rpc_host_join_approve, which delegates
 * that entire question to fzn_rpc_capability_grant rather than re-deciding it. */
#define FZN_RPC_JOIN_GRANT_MAX FZN_RPC_CAP_TYPE_COUNT
/* ... followed by the APPROVER's own proof bundle, address and prekey, each
 * length-prefixed and each optionally empty. Same purpose as the request's
 * own address/prekey, in the other direction: with them the new host can
 * register its approver as a sibling as part of installing, so revocations
 * can flow both ways from the moment linking finishes. The approver's proof
 * is independently verifiable against the root the new host is adopting, so
 * it needs no signature of its own -- the same reasoning the attached
 * signer_chain already relies on. */
#define FZN_RPC_JOIN_APPROVAL_BLOB_LEN                                              \
  (1 + (2 + FZN_RPC_HOST_PROOF_BLOB_LEN) + 1 +                                       \
   FZN_RPC_JOIN_GRANT_MAX * (1 + (2 + FZN_RPC_CAP_CHAIN_BLOB_LEN)) +                     \
   (2 + FZN_RPC_HOST_PROOF_BLOB_LEN) + (2 + FZN_RPC_PEER_ADDRESS_MAX) +                  \
   (2 + FZN_RPC_PREKEY_RECORD_LEN))

/* Truncated-BLAKE2b transcription checksum appended to the tail of the
 * contact card's own canonical blob (core/src/peer_pair.c) -- NOT part of
 * its signed region, pure fast-fail for a mistyped/mis-scanned character,
 * checked before attempting to parse or verify anything else. Computed
 * directly via Monocypher in peer_pair.c, independent of
 * common/encoding.c's similarly-shaped but separate Base58Check wrapper
 * (core/ has no dependency on common/ anywhere else in this codebase, and
 * this constant intentionally doesn't change that). */
#define FZN_RPC_CONTACT_CARD_CHECKSUM_LEN 3

/* version(1)+host_proof_bundle lenprefixed(2+FZN_RPC_HOST_PROOF_BLOB_LEN)+
 * address lenprefixed(2+FZN_RPC_PEER_ADDRESS_MAX)+prekey_blob(FZN_RPC_PREKEY_RECORD_LEN,
 * fixed)+manifest_seed_count(1)+seeds(FZN_RPC_CONTACT_MANIFEST_SEED_MAX *
 * (address lenprefixed(2+FZN_RPC_PEER_ADDRESS_MAX)+transport_bitmask(1)+metric(1)))+
 * display_name lenprefixed(2+FZN_RPC_PEER_NAME_MAX)+expires_at(8)+signature(64)+
 * checksum(FZN_RPC_CONTACT_CARD_CHECKSUM_LEN) -- a user's own reusable "add me as
 * your peer" credential, see core/src/peer_pair_internal.h. A maximum (the
 * bundle, address, and manifest seeds all vary). */
#define FZN_RPC_CONTACT_CARD_BLOB_LEN                                                            \
  (1 + 1 + (2 + FZN_RPC_HOST_PROOF_BLOB_LEN) + (2 + FZN_RPC_PEER_ADDRESS_MAX) +                      \
   FZN_RPC_PREKEY_RECORD_LEN +                                                                   \
   1 + FZN_RPC_CONTACT_MANIFEST_SEED_MAX * ((2 + FZN_RPC_PEER_ADDRESS_MAX) + 1 + 1) +                 \
   (2 + FZN_RPC_PEER_NAME_MAX) + 8 + 64 + FZN_RPC_CONTACT_CARD_CHECKSUM_LEN)

typedef struct fzn_rpc_identity_generate_resp {
	uint8_t user_pubkey[32];
	uint64_t created_at;
} fzn_rpc_identity_generate_resp_t;

typedef struct fzn_rpc_host_create_resp {
	uint8_t host_pubkey[32];
	uint64_t created_at;
	uint8_t cross_sign_sig[64];
} fzn_rpc_host_create_resp_t;

typedef struct fzn_rpc_status_resp {
	uint8_t user_pubkey[32];
	uint64_t identity_created_at; /* only meaningful if is_root -- a joined (non-root) host
	                                  never holds "identity" and so has no local record of
	                                  when the user root key was generated; 0 otherwise */
	int is_root; /* 0 or 1 -- whether this host holds the user root secret key locally
	                 ("identity"), vs. having joined via the host-join exchange */
	int has_host; /* 0 or 1 */
	uint8_t host_pubkey[32];
	char host_name[FZN_RPC_HOST_NAME_MAX + 1];
	size_t host_name_len;
	int cross_signed; /* 0 or 1; only meaningful if has_host */
	uint64_t host_created_at;
	/*
	 * What this host is still holding for the far end (project.md sec 9).
	 * `outbox_held` is every message not yet settled; `outbox_delivered` is
	 * how many of those are known to have arrived and are waiting only on the
	 * recipient's own durability policy.
	 *
	 * Two numbers rather than one because they mean opposite things to
	 * whoever is reading. Held-and-undelivered is "nobody has this yet";
	 * held-and-delivered is "somebody does, and their realm is not finished
	 * with it" -- which is not a fault and needs no action. Sec 9 asks for a
	 * sender to report who is behind, and one combined number would report
	 * a working system as a stuck one.
	 */
	uint64_t outbox_held;
	uint64_t outbox_delivered;
	/*
	 * And the other side of the same section: messages this host has taken in
	 * and is still replicating to the user's own retention hosts before it
	 * can call them settled (project.md sec 9).
	 *
	 * Worth reporting separately from the two above rather than folded in,
	 * because it is the only visible symptom of a host of one's OWN that has
	 * been unreachable for a while -- the senders on the other side see their
	 * copies not settling and cannot know why, and this is where the cause
	 * actually is.
	 */
	uint64_t settle_pending;
	/*
	 * And messages handed to ANOTHER OF THIS USER'S OWN HOSTS to send, which
	 * that host has not yet said it has taken (core/src/delegate_internal.h).
	 *
	 * Its own number rather than folded into outbox_held, because a delegated
	 * message deliberately has no outbox entry HERE -- this host sealed
	 * nothing for the contact and holds no acknowledgement tag to retire, so
	 * the hold that matters is the owning host's. Without this line the only
	 * honest report a delegating host could give is silence, which is exactly
	 * the state sec 9 spends its effort making impossible: something is owed,
	 * and every counter says zero.
	 *
	 * What it means when it is not zero is also different from the others,
	 * and narrower: not "a contact is unreachable" but "a device of yours is
	 * off" -- which is the one cause on this list the reader can walk into
	 * the next room and fix.
	 */
	uint64_t delegate_queued;
	/*
	 * Hand-offs given up on since the daemon started (sec 204): nobody
	 * linked owns the contact any more, or it was removed. The text was not
	 * delivered and is not kept -- showing it in the conversation is a
	 * requirement on fuzznet's message storage -- so this, with the last
	 * contact's name, is what tells the person. Not persisted: the daemon's
	 * log is the lasting record. Absent in an older daemon's answer.
	 */
	uint64_t delegate_failed;
	char delegate_failed_last[FZN_RPC_PEER_NAME_MAX + 1];
	size_t delegate_failed_last_len;
	/*
	 * The UDP port this daemon listens on for peers (sec 253), so a client
	 * can offer "your address" without the person having to know it: the
	 * clients know the machine's interfaces, and only the daemon knows the
	 * port. 0 when the daemon did not say (an older daemon, or none set).
	 */
	uint16_t peer_port;
	/*
	 * 1 when a secret key this host holds was made before every signature
	 * became RFC 8032 Ed25519 (project.md sec 109). Such a key's signatures
	 * verify nowhere any more -- not here, not at a sibling, not in fuzznet's
	 * chain -- so an old identity fails as "not cross-signed", chains that do
	 * not verify, pairings refused, all of it true and none of it saying why.
	 * This says why. Exact rather than inferred: a stored secret is the seed
	 * and the public key side by side, and re-deriving the public key from
	 * the seed with Ed25519 either reproduces it or does not.
	 */
	int old_keys;
} fzn_rpc_status_resp_t;

typedef struct fzn_rpc_prekey_show_resp {
	uint8_t blob[FZN_RPC_PREKEY_RECORD_LEN]; /* the full signed prekey_record blob, opaque --
	                                         this exact byte string is what peer-add's
	                                         --prekey-blob consumes */
} fzn_rpc_prekey_show_resp_t;

typedef struct fzn_rpc_peer_list_entry {
	char name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t name_len;
	uint8_t host_pubkey[32];
	char address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t address_len;
	/* All-zero if unknown -- see messaging_internal.h's peer_record_t doc
	 * comment. Exposed here (not printed by the CLI) so core/src/manifest.c
	 * can verify a registered peer's own manifest against it without a
	 * second, dedicated lookup call. */
	uint8_t root_pubkey[32];
	/* Whether this host has granted this peer permission to query its
	 * location track -- the read-back half of location-share, which for a
	 * while had none: fzn_rpc_peer_may_share_location is reachable only inside
	 * core, where it gates answering, so a client could grant and revoke
	 * somebody's access to its location and never show what it had granted.
	 * A consent control that cannot be read back is the wrong shape, which
	 * is why neither client offered one at all.
	 *
	 * It rides on the peer rather than on a screen of its own, decided with
	 * the user (2026-08-08): consent belongs beside the peer it is about, so
	 * it appears wherever a peer is drawn and there is no second rendering to
	 * disagree with the first -- the same "one list, not two" argument the
	 * Hosts tree already makes. A dedicated read-back sub-command was the
	 * alternative, and the audit view it would buy is not worth a consent
	 * state that is invisible next to the peer itself. */
	uint8_t share_location;
	/* The precision that share is served at (a fzn_rpc_location_precision_t) --
	 * the read-back half of location-share's --precision, carried for the
	 * same reason share_location is: a consent control that cannot say it is
	 * sharing a coarsened track rather than an exact one is the wrong shape.
	 * EXACT (0) when not sharing or when granted before precision existed. */
	uint8_t share_precision;
} fzn_rpc_peer_list_entry_t;

typedef struct fzn_rpc_peer_list_resp {
	/* Sized to what the host holds: grown by the call and kept for the next one
	 * into the same struct, so a struct starts zeroed, as a static is, and is
	 * released by fzn_rpc_peer_list_release. The five lists of contacts, groups,
	 * a group's members, notes and files share this shape: nothing here says
	 * how many a person may have. */
	fzn_rpc_peer_list_entry_t *entries;
	size_t count;
	size_t room;
} fzn_rpc_peer_list_resp_t;

typedef struct fzn_rpc_inbox_entry {
	/* What names this message everywhere else (sec 9's outbox, the dedup
	 * ring, the acknowledgements). Carried here so a client can ask where
	 * one of its OWN messages has got to and put the answer beside it --
	 * without it, a delivery mark has nothing to attach to. Zero for a line
	 * written before the field existed. */
	uint8_t commitment[16];
	uint8_t sender_host_pubkey[32];
	char sender_name[FZN_RPC_PEER_NAME_MAX + 1]; /* empty if no matching peer record found --
	                                             resolved live at response-encode time */
	size_t sender_name_len;
	uint64_t stime; /* sender-claimed send time (authenticated -- inside the AEAD boundary) */
	uint64_t rtime; /* local receive time (never transmitted) */
	char text[FZN_RPC_PEER_TEXT_MAX + 1];
	size_t text_len;
	/* 1 when this host SENT it. `sender_host_pubkey` and `sender_name` then
	 * describe the RECIPIENT -- the other end of the conversation either
	 * way, which is what a reader wants and why one field serves both. */
	uint8_t outgoing;
} fzn_rpc_inbox_entry_t;


#define FZN_RPC_LOG_LINE_MAX 240 /* matches daemon/log_retention.c's own per-line truncation
                                 budget (a 20-digit seq prefix + a space eat a fixed ~21
                                 bytes of it) */
#define FZN_RPC_LOG_SHOW_PAGE_MAX 50 /* per-response cap -- 50 * (240 + ~4B overhead) ~= 12.2KB,
                                     same order of magnitude as FZN_RPC_INBOX_PAGE_MAX's own
                                     */

typedef struct fzn_rpc_log_entry {
	uint64_t seq; /* this line's local, monotonic sequence number -- never wall-clock-derived,
	                 see core/src/log_show_internal.h */
	char text[FZN_RPC_LOG_LINE_MAX + 1];
	size_t text_len;
} fzn_rpc_log_entry_t;

typedef struct fzn_rpc_log_show_resp {
	fzn_rpc_log_entry_t entries[FZN_RPC_LOG_SHOW_PAGE_MAX]; /* most-recent-first */
	size_t count;
} fzn_rpc_log_show_resp_t;

#define FZN_RPC_LOCATION_SHOW_RESP_MAX 64

/*
 * Why a host that was asked to sample is not sampling.
 *
 * A CODE RATHER THAN A SENTENCE, because three surfaces render it and a
 * string on the wire would be the daemon writing their text. NONE is 0 so it
 * is also the answer for a host that was never asked -- "no reason" and "not
 * asked" are the same state, and a reason beside `configured = 0` would read
 * as a fault.
 */
typedef enum fzn_rpc_location_stopped {
	FZN_RPC_LOCATION_STOPPED_NONE = 0,
	/* The source could not be opened: gpsd is not running, or is not at the
	 * configured host and port. By far the common case. */
	FZN_RPC_LOCATION_STOPPED_SOURCE = 1,
	/* No timer could be registered, so nothing would ever tick. Rare, and it
	 * means the daemon's timer table was full at startup. */
	FZN_RPC_LOCATION_STOPPED_TIMER = 2,
	/*
	 * The sampler is running and the source is not answering: the socket to
	 * gpsd is not open, or the WATCH has not been acknowledged.
	 *
	 * THIS IS THE COMMON ONE, and the first draft of this enum did not have
	 * it. A gpsd source is created without touching the network, so a host
	 * pointed at a port where nothing listens creates its source, registers
	 * its timer, ticks happily and receives nothing -- and a status built on
	 * "did the source get created" answered `sampling: yes` throughout. The
	 * distinction is between a sampler that could not START and one that is
	 * running and getting nothing, and only the second is reachable by
	 * misconfiguring a port.
	 */
	FZN_RPC_LOCATION_STOPPED_UNREACHABLE = 3,
} fzn_rpc_location_stopped_t;

typedef struct fzn_rpc_location_status_resp {
	/* What location.enabled says. Carried as well as `sampling` rather than
	 * being left to the client to fetch separately, because the whole point
	 * is the COMPARISON, and two values read at two moments can disagree for
	 * a reason that is not the one being reported. */
	uint8_t configured;
	/* Whether the sampler is running with a source. */
	uint8_t sampling;
	uint8_t stopped_reason; /* an fzn_rpc_location_stopped; meaningful where
	                           configured && !sampling */
	uint32_t interval_s;
	/* host:port of the LIVE connection, empty when there is none. The
	 * configured host and port are readable from config; this is the one the
	 * open socket actually goes to, which is what a config change is checked
	 * against. */
	char source[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t source_len;
} fzn_rpc_location_status_resp_t;

/*
 * How precisely a shared track is served to one peer (geolocation.md sec 10:
 * "the one data type where deliberately coarsening is a useful feature"). Held
 * per peer alongside the share grant, applied at send time in
 * fzn_rpc_core_handle_location_relay_frame, and marked with FZN_RPC_LOCATION_FLAG_COARSE
 * so the recipient can tell a degraded fix from a precise one. EXACT is 0 so an
 * older peer record -- and a bare `--enable` -- decodes to full precision, the
 * behaviour before this existed.
 */
typedef enum fzn_rpc_location_precision {
	FZN_RPC_LOCATION_PRECISION_EXACT = 0,  /* served verbatim */
	FZN_RPC_LOCATION_PRECISION_COARSE = 1, /* rounded to a ~1 km grid */
	FZN_RPC_LOCATION_PRECISION_REGION = 2, /* rounded to a ~10 km grid */
} fzn_rpc_location_precision_t;
#define FZN_RPC_LOCATION_PRECISION_MAX 2

/*
 * One fix as it crosses the control channel. Fields are carried
 * individually rather than as the packed 19-byte record: the wire format
 * here is the local IPC channel, whose job is to be decodable by a
 * frontend, not to be compact. Re-using the storage packing would couple a
 * client to the on-disk layout and force it to duplicate the codec.
 */
typedef struct fzn_rpc_location_show_entry {
	uint64_t seq;
	int32_t lat_e7;
	int32_t lon_e7;
	uint32_t utc_s;
	int16_t alt_m;
	uint16_t bearing_deg; /* 0..359, already decoded from the stored byte */
	uint32_t acc_e_m;     /* metres, already decoded from the log scale */
	uint32_t acc_n_m;
	uint32_t acc_v_m;
	uint8_t has_alt;
	uint8_t has_bearing;
	uint8_t is_coarse;
} fzn_rpc_location_show_entry_t;

typedef struct fzn_rpc_location_show_resp {
	fzn_rpc_location_show_entry_t entries[FZN_RPC_LOCATION_SHOW_RESP_MAX]; /* most-recent-first */
	size_t count;
	uint64_t high_water_seq; /* newest seq held for this origin, 0 if none */
	/*
	 * The last ANSWER this host received from that peer (project.md sec
	 * 101). A peer that shares with us and has nothing new answers with no
	 * fixes rather than staying silent, so "answered with none" and "never
	 * answered" -- a friend with no GPS yet, and one who does not share or
	 * is offline -- are now different reports. Only for a peer's own track:
	 * a sibling's is not a friend's Nearby row.
	 *
	 * On the wire after the entries: u8 answered, then when 1, u64
	 * answered_at (the daemon's wall clock) and u16 answered_fixes.
	 */
	uint8_t answered;
	uint64_t answered_at;
	uint16_t answered_fixes;
} fzn_rpc_location_show_resp_t;

#define FZN_RPC_CONFIG_KEY_MAX 96
#define FZN_RPC_CONFIG_VALUE_MAX 192
#define FZN_RPC_CONFIG_SUMMARY_MAX 96
#define FZN_RPC_CONFIG_UNIT_MAX 8
#define FZN_RPC_CONFIG_SCHEMA_PAGE_MAX 1024

/* A SETTING AS THE NODE DECLARES IT, in `state/schema.h`'s words (sec 1098;
 * sec 906): its type a fzn_schema_type_t, where it may stand FZN_SCHEMA_ESTATE
 * and FZN_SCHEMA_HOST, its flags FZN_SCHEMA_RESTART .. FZN_SCHEMA_ADVERTISED.
 * The client's own older model -- bool, int or string, an applies, a
 * distribution -- was a translation that lost a duration, an address, the
 * safe direction and the advertised flag. `min` and `max` hold for a COUNT and
 * a DURATION (seconds), and bound a TEXT's or ADDRESS's length. */
typedef struct fzn_rpc_config_schema_entry {
	char key[FZN_RPC_CONFIG_KEY_MAX + 1];
	size_t key_len;
	fzn_schema_type_t type;
	unsigned scopes;
	unsigned flags;
	int64_t min, max;
	char unit[FZN_RPC_CONFIG_UNIT_MAX + 1];
	size_t unit_len;
	char default_value[FZN_RPC_CONFIG_VALUE_MAX + 1];
	size_t default_value_len;
	char summary[FZN_RPC_CONFIG_SUMMARY_MAX + 1];
	size_t summary_len;
} fzn_rpc_config_schema_entry_t;

typedef struct fzn_rpc_config_schema_resp {
	fzn_rpc_config_schema_entry_t entries[FZN_RPC_CONFIG_SCHEMA_PAGE_MAX];
	size_t count;
	/* Set when the prefix matched more settings than a page holds, so a
	 * client can tell "that is everything" from "ask for a narrower
	 * subtree" instead of silently showing a partial tree. */
	uint8_t truncated;
} fzn_rpc_config_schema_resp_t;

/* prefix selects a subtree ("location"); empty means everything that fits. */
typedef struct fzn_rpc_config_get_resp {
	char value[FZN_RPC_CONFIG_VALUE_MAX + 1];
	size_t value_len;
	/* WHERE THE VALUE STANDS: FZN_SCHEMA_HOST, set for this host;
	 * FZN_SCHEMA_ESTATE, set for every host of the user; 0, the default. A
	 * FLAG's value is the node's word, `on` or `off`. */
	unsigned set_at;
	/*
	 * 1 when the setting is SENSITIVE and the value has been withheld
	 * (configuration.md sec 8.3). `value` is then empty and says nothing
	 * about what is stored; `configured` is what a client should render.
	 *
	 * Redacting rather than refusing outright, because a credential field
	 * has to be able to show "configured" versus "not set" to be usable at
	 * all -- a client that cannot tell those apart can only ask the user to
	 * re-enter a secret blind, every time.
	 */
	uint8_t redacted;
	uint8_t configured; /* meaningful only when redacted: is a value set? */
} fzn_rpc_config_get_resp_t;


/* BLAKE2b-256, per project.md sec 11. Declared here rather than beside the
 * blob commands further down because a group can pin a blob, so the group
 * section names it first. */
#define FZN_RPC_BLOB_HASH_LEN 32

typedef struct fzn_rpc_group_create_resp {
	uint8_t chat_id[32];
} fzn_rpc_group_create_resp_t;

typedef struct fzn_rpc_group_member_entry {
	uint8_t root_pubkey[32];
	char address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t address_len;
	char name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t name_len;
	/*
	 * How many of this host's lines the member has said it holds, the furthest
	 * of its hosts (fuzznet sec 911, by fzn_rpc_group_water). A floor: a host
	 * that took them through another member says nothing here until it next
	 * asks. `heard` 0 is no word at all, which is not none held.
	 */
	uint64_t acked_seq;
	int heard;
	/* 1 when the roster marks the member an admin, who may change who is in
	 * the group (fuzznet sec 626). */
	int admin;
} fzn_rpc_group_member_entry_t;

typedef struct fzn_rpc_group_show_resp {
	uint8_t chat_id[32];
	char group_name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t group_name_len;
	uint64_t epoch;
	uint64_t timestamp;
	fzn_rpc_group_member_entry_t *members; /* sized as fzn_rpc_peer_list_resp_t's are */
	size_t member_room;
	size_t member_count;
	int is_admin; /* 1 if this host holds the group's own signing key */
	/* The highest seq THIS host has sent to the group, so a reader can see
	 * how far behind each member is rather than only where they are. 0 if
	 * this host has sent nothing. */
	uint64_t own_high_seq;
	/* This user's root key, read with the roster: a nameless member who is
	 * this user is told apart from one who is no contact without asking the
	 * node again for each (fzn_rpc_group_nameless_label). */
	uint8_t self_root[32];
} fzn_rpc_group_show_resp_t;

typedef struct fzn_rpc_group_list_entry {
	char name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t name_len;
	uint8_t chat_id[32];
	int is_admin;
	size_t member_count;
	uint64_t lines; /* how many it holds: unchanged, nothing new to read */
} fzn_rpc_group_list_entry_t;

/* A named object: living_room_lamp = on, an estate's, set on one host and read on
 * another (fuzznet sec 948). `allowed` is `on|off`, or `*` for any word; `value`
 * and `by` are empty until one is set. */
#define FZN_RPC_OBJECT_NAME_MAX 32
#define FZN_RPC_OBJECT_VALUE_MAX 64
typedef struct fzn_rpc_object {
	char name[FZN_RPC_OBJECT_NAME_MAX + 1];
	char value[FZN_RPC_OBJECT_VALUE_MAX + 1];
	char by[65];
	char allowed[512];
	uint64_t at_ms;
} fzn_rpc_object_t;

typedef struct fzn_rpc_object_list_resp {
	fzn_rpc_object_t *entries; /* sized as fzn_rpc_peer_list_resp_t's are */
	size_t count;
	size_t room;
} fzn_rpc_object_list_resp_t;

typedef struct fzn_rpc_group_list_resp {
	fzn_rpc_group_list_entry_t *entries; /* sized as fzn_rpc_peer_list_resp_t's are */
	size_t room;
	size_t count;
} fzn_rpc_group_list_resp_t;

/* Local history read (part D groundwork, built alongside part C since
 * it's what makes live send/receive locally verifiable) -- pure local
 * store read, core/src/group_history_internal.h. peer_name empty means
 * "show my own sent messages" (this host's own user_pubkey), same
 * "defaults to the asker's own identity" idiom log_relay's own
 * origin_name already uses. */
#define FZN_RPC_GROUP_HISTORY_SHOW_PAGE_MAX 50 /* per-response cap on the control channel,
                                               independent of the larger internal storage
                                               capacity (FZN_RPC_GROUP_HISTORY_CACHE_MAX_ENTRIES,
                                               core/src/group_history_internal.h) -- same
                                               relationship FZN_RPC_LOG_RELAY_SHOW_PAGE_MAX has to
                                               FZN_RPC_LOG_RELAY_CACHE_MAX_ENTRIES */

typedef struct fzn_rpc_group_history_entry {
	uint64_t seq;
	/*
	 * When the SENDER said it sent this, in unix seconds; 0 for a line
	 * stored before the field existed.
	 *
	 * `seq` orders ONE sender's stream and nothing else -- a group's history
	 * is kept per sender, so two members' seq 1 describe unrelated moments.
	 * A client showing the conversation merges every member's stream, and
	 * this is the only key the members share. project.md sec 66 has the
	 * measurement that found the view was showing one person's half.
	 *
	 * Authenticated where it is set: it travels inside MSG_PUSH's sealed
	 * text, so a relay handing the frame on cannot rewrite it, and
	 * HISTORY_LINES carries it too so a line recovered by catch-up sorts
	 * where it was sent rather than where it landed.
	 *
	 * It is the sender's CLAIM and carries their clock's errors. Nothing
	 * else is shared between members to order by.
	 */
	uint64_t stime;
	char text[FZN_RPC_PEER_TEXT_MAX + 1];
	size_t text_len;
} fzn_rpc_group_history_entry_t;

typedef struct fzn_rpc_group_history_show_resp {
	fzn_rpc_group_history_entry_t entries[FZN_RPC_GROUP_HISTORY_SHOW_PAGE_MAX]; /* most-recent-first */
	size_t count;
	uint64_t high_water_seq;
} fzn_rpc_group_history_show_resp_t;

/*
 * Unread in one member's stream in a group (sec 177): a group's history
 * is a stream per sender, numbered, so a position is the last number read,
 * and what is numbered after it is unread. Counted over the page the daemon
 * answers, so a stream far ahead counts at most a page.
 */
size_t fzn_rpc_group_unread_since(const fzn_rpc_group_history_entry_t *entries, size_t count,
                              uint64_t read_seq);

typedef struct fzn_rpc_host_join_request_resp {
	uint8_t blob[FZN_RPC_JOIN_REQUEST_BLOB_LEN];
	size_t blob_len;
} fzn_rpc_host_join_request_resp_t;

typedef struct fzn_rpc_host_join_approve_resp {
	uint8_t blob[FZN_RPC_JOIN_APPROVAL_BLOB_LEN];
	size_t blob_len;
	/* What the approver actually minted, which may be a strict subset of
	 * what was asked for -- a delegate can only pass on capabilities it
	 * holds itself. Reported explicitly so the caller can name the
	 * difference; see fzn_rpc_host_join_approve. */
	uint8_t conferred[FZN_RPC_JOIN_GRANT_MAX];
	size_t conferred_count;
	/* Whether the joining host was actually recorded as a sibling. Reported
	 * for the same reason `conferred` is: the approval can succeed while this
	 * quietly does not happen -- a name already taken by another device, an
	 * address never supplied -- and without it the two hosts never appear in
	 * each other's registries, so a capability revocation can never reach the
	 * new one. Failing the join over a registry entry would be worse, but so
	 * is saying nothing. */
	uint8_t registered;
} fzn_rpc_host_join_approve_resp_t;

typedef struct fzn_rpc_host_join_install_resp {
	fzn_rpc_host_create_resp_t host;
	/* Whether the APPROVER was recorded as this host's sibling. Zero is
	 * ordinary rather than an error -- an approval that carried no address
	 * cannot be registered against, and the join itself is unaffected -- but
	 * until the two hosts appear in each other's registries a capability
	 * revocation can never travel between them, so it decides whether the
	 * caller says so. */
	uint8_t registered;
} fzn_rpc_host_join_install_resp_t;

typedef struct fzn_rpc_cap_grant_resp {
	uint8_t chain_blob[FZN_RPC_CAP_CHAIN_BLOB_LEN];
	size_t chain_blob_len;
} fzn_rpc_cap_grant_resp_t;

typedef struct fzn_rpc_cap_list_entry {
	fzn_rpc_capability_type_t type;
	int valid; /* live-reverified, not a trusted stored flag -- same discipline
	              as fzn_rpc_status's cross_signed */
	/* Reported separately from `valid` rather than folded into it. A chain
	 * that fails to verify and one that was deliberately revoked are
	 * different facts, and an operator asking why a host stopped working
	 * needs to be told which -- collapsing them would leave cap-show naming
	 * the wrong cause (project.md sec 14). */
	int revoked;
	int hop_count;
	uint64_t expires_at; /* FZN_RPC_CAP_NO_EXPIRY (0) when the grant never lapses,
	                        which is the default */
} fzn_rpc_cap_list_entry_t;

typedef struct fzn_rpc_cap_list_resp {
	fzn_rpc_cap_list_entry_t entries[FZN_RPC_CAP_TYPE_COUNT]; /* at most one per fzn_rpc_capability_type_t */
	size_t count;
} fzn_rpc_cap_list_resp_t;

/*
 * One grant this host has issued, as the audit reports it.
 *
 * ISSUED, NOT IN FORCE. A grant is minted and handed over; the granter never
 * learns whether it was installed, and reporting it as in force would be the
 * invention project.md sec 81 names. `revoked` is the one thing this host
 * does know about it afterwards, and it is joined in at read time from the
 * revocation store rather than written into the grant record -- two writers
 * of one fact drift, and the revocation store is the one that owns it.
 */
typedef struct fzn_rpc_cap_granted_entry {
	fzn_rpc_capability_type_t type;
	uint8_t grantee_pubkey[32];
	uint64_t expires_at; /* FZN_RPC_CAP_NO_EXPIRY (0) when it never lapses */
	uint64_t granted_at;
	uint8_t revoked; /* joined from the revocation store at read time */
} fzn_rpc_cap_granted_entry_t;

typedef struct fzn_rpc_cap_granted_resp {
	fzn_rpc_cap_granted_entry_t entries[FZN_RPC_GRANT_LIST_MAX]; /* newest first */
	size_t count;
} fzn_rpc_cap_granted_resp_t;

typedef struct fzn_rpc_sibling_entry {
	char name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t name_len;
	uint8_t host_pubkey[32];
	char address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t address_len;
	int valid; /* 0 or 1 -- live-reverified at response-encode time, never a
	              trusted stored flag (same discipline as fzn_rpc_status's
	              cross_signed and fzn_rpc_cap_list_entry_t's valid). The
	              sibling's prekey_pk is never exposed here, internal only
	              (core/src/sibling_internal.h's fzn_rpc_sibling_channel_info). */
} fzn_rpc_sibling_entry_t;

typedef struct fzn_rpc_sibling_list_resp {
	fzn_rpc_sibling_entry_t entries[FZN_RPC_SIBLING_LIST_MAX];
	size_t count;
} fzn_rpc_sibling_list_resp_t;

typedef struct fzn_rpc_card_show_resp {
	uint8_t card_blob[FZN_RPC_CONTACT_CARD_BLOB_LEN];
	size_t card_blob_len;
} fzn_rpc_card_show_resp_t;

typedef struct fzn_rpc_peer_request_send_resp {
	uint8_t target_host_pubkey[32]; /* decoded from card_blob, echoed once verified --
	                                    same pattern fzn_rpc_peer_add_resp_t already uses */
} fzn_rpc_peer_request_send_resp_t;

typedef struct fzn_rpc_pending_request_entry {
	uint8_t requester_host_pubkey[32];
	char proposed_display_name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t proposed_display_name_len;
	char address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t address_len;
	uint64_t received_at;
} fzn_rpc_pending_request_entry_t;

typedef struct fzn_rpc_peer_request_list_resp {
	fzn_rpc_pending_request_entry_t entries[FZN_RPC_PEER_REQUEST_MAX];
	size_t count;
} fzn_rpc_peer_request_list_resp_t;

typedef struct fzn_rpc_peer_request_approve_resp {
	uint8_t host_pubkey[32]; /* echoed, matches fzn_rpc_peer_add_resp_t/fzn_rpc_sibling_add_resp_t */
} fzn_rpc_peer_request_approve_resp_t;

/*
 * The reference: root AND content key. The root alone names the ciphertext
 * and is what a peer is asked for; without the key it decrypts to nothing.
 * Both are returned so the pair can be handed to someone out of band --
 * which for the private tier is the ONLY way it ever travels, since a
 * private blob is not discoverable by id.
 */
typedef struct fzn_rpc_blob_add_resp {
	uint8_t root[FZN_RPC_BLOB_HASH_LEN];
	uint8_t key[32];
	uint64_t leaf_count;
	uint64_t byte_len;
} fzn_rpc_blob_add_resp_t;

/*
 * `known` distinguishes "this host has never heard of that root" from "it
 * holds none of it yet" -- a transfer that has been started but has received
 * nothing is not the same as a typo in the root, and reporting both as zero
 * would make the second impossible to diagnose.
 *
 * `range_count` is how many entries the canonical have-set occupies, which
 * is what the wire actually costs. Reported because it is the number that
 * says whether a transfer is fragmenting.
 */
typedef struct fzn_rpc_blob_status_resp {
	uint64_t leaf_count;
	uint64_t leaves_held;
	uint64_t byte_len;
	uint32_t range_count;
	uint8_t known;
	uint8_t complete;
	/*
	 * Which tier this host STORED it under -- FZN_RPC_BLOB_TIER_PUBLIC,
	 * FZN_RPC_BLOB_TIER_PRIVATE, or 0 for unknown.
	 *
	 * READ BACK FROM THE STORE, not echoed from whatever the caller asked
	 * for. The tier has been persisted since blobs existed, as byte 0 of the
	 * key record keyed by root, and nothing ever reported it: the field
	 * appeared only in fzn_rpc_blob_add_req_t, so it was write-only from every
	 * client's point of view. That is not a theoretical gap. The ncurses
	 * client passed a bare 1 -- which is PUBLIC -- while its own comment
	 * said "private", from 2026-08-07 until 2026-09-20, and every file it
	 * sent for six weeks got a content-derived key any other holder of the
	 * same bytes could compute. Nothing displayed the tier, so nothing could
	 * have shown it.
	 *
	 * An ECHO would not have caught that either, which is why this is served
	 * from the stored record: a response built from the request agrees with
	 * the request by construction and says nothing about what was written.
	 *
	 * 0 IS A REAL ANSWER AND NOT A DEFAULT. A blob pulled from a peer
	 * arrived as a reference and this host holds no key record for it, so it
	 * has no tier here to report; neither constant is 0, so the unknown case
	 * cannot be confused with either. A client must not render 0 as "public"
	 * -- that is the reassuring direction, and it is the one the incident
	 * above went in.
	 *
	 * Appended last on the wire, so a response from a newer daemon decodes in
	 * an older client with tier 0 rather than failing -- the same discipline
	 * location-share's precision follows.
	 */
	uint8_t tier;
} fzn_rpc_blob_status_resp_t;

typedef struct fzn_rpc_blob_export_resp {
	uint64_t byte_len;
} fzn_rpc_blob_export_resp_t;

typedef struct fzn_rpc_blob_fetch_resp {
	uint32_t transfer_id;
} fzn_rpc_blob_fetch_resp_t;

typedef struct fzn_rpc_blob_scrub_resp {
	uint64_t leaf_count;
	uint64_t checked;
	uint64_t dropped;
	uint64_t next_index;
	uint8_t done;
} fzn_rpc_blob_scrub_resp_t;

/* How many hosts of an estate one status response names: a person's devices. */
#define FZN_RPC_MANIFEST_FANOUT_MAX 1024

typedef struct fzn_rpc_config_status_row {
	char name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t name_len;
	uint64_t acked;
} fzn_rpc_config_status_row_t;

typedef struct fzn_rpc_config_status_resp {
	uint64_t local_seq;
	fzn_rpc_config_status_row_t rows[FZN_RPC_MANIFEST_FANOUT_MAX];
	size_t count;
} fzn_rpc_config_status_resp_t;

/* Matches FZN_RPC_OUTBOX_MAX, which core/src/outbox_internal.h owns and this
 * file cannot see. control_codec.c carries a _Static_assert that they agree,
 * so a change to the outbox bound is a build error here rather than a
 * silently truncated answer. */
#define FZN_RPC_DELIVERY_LIST_MAX 8192

typedef struct fzn_rpc_delivery_entry {
	/* 16 spelled out rather than named, as fzn_rpc_outbox_due_entry_t's already
	 * is: the commitment's length belongs to the wire format. */
	uint8_t commitment[16];
	char peer_name[FZN_RPC_PEER_NAME_MAX + 1];
	size_t peer_name_len;
	/* 0 = nobody has it yet; 1 = the recipient has it and their own realm
	 * has not finished with it. Settled never appears -- see above. */
	uint8_t delivered;
	uint64_t first_sent;
	uint64_t attempts;
} fzn_rpc_delivery_entry_t;

typedef struct fzn_rpc_delivery_list_resp {
	fzn_rpc_delivery_entry_t entries[FZN_RPC_DELIVERY_LIST_MAX];
	size_t count;
} fzn_rpc_delivery_list_resp_t;

typedef struct fzn_rpc_sticker_list_entry {
	uint8_t root[32];
	/*
	 * The content key, carried so a client can SEND from a saved collection
	 * without the user retyping what saving was supposed to remember.
	 *
	 * Travels but is not PRINTED: `sticker-list` shows name, root and date.
	 * A key on screen ends up in a scrollback, a screenshot or a paste, and
	 * nothing about listing your own packs needs it visible. The socket is
	 * 0600 and local-only, and blob-export already takes a key across it, so
	 * carrying it here discloses nothing new.
	 */
	uint8_t key[32];
	char name[48 + 1];
	size_t name_len;
	uint64_t saved_at;
} fzn_rpc_sticker_list_entry_t;

#define FZN_RPC_NOTES_SUBCMD_SHARE 5
#define FZN_RPC_NOTES_SUBCMD_UNSHARE 6
/*
 * How much text a note carries over the socket.
 *
 * These are smaller than they look like they should be, and the reason is a
 * hard one: a tree node body is 470 bytes (fuzznet's record body minus its own
 * header), and the note header takes 28 of that. control_codec.c
 * _Static_asserts that title and text together still fit.
 *
 * sec 22 records the consequence -- anything longer goes to the blob layer,
 * which is the ORDINARY path rather than an escape hatch. These caps are what
 * a note can hold INLINE, not what a note can be.
 */
#define FZN_RPC_NOTES_TITLE_MAX 100
/* What a listing keeps of a note's labels; a node holds up to 1024 bytes
 * (fuzznet's FZN_NOTE_LABELS_MAX), read whole by fzn_rpc_note_meta. */
#define FZN_RPC_NOTES_LABELS_SHOWN 128
#define FZN_RPC_NOTES_LABELS_MAX 1024
/* fuzznet's FZN_NOTE_TEXT_MAX: about forty thousand words. */
#define FZN_RPC_NOTES_TEXT_MAX (256 * 1024)

typedef struct fzn_rpc_notes_add_resp {
	/* The new node's id, so a client can immediately make it a parent. */
	uint8_t id[32];
	/*
	 * 1 when skip_if_exists matched and `id` names the note that was ALREADY
	 * there rather than one just written.
	 *
	 * Reported rather than silent, because "imported 400" and "imported 0,
	 * 400 already here" are different facts and a user running an importer
	 * twice needs to be told which happened. A silent skip is the shape sec
	 * 22 spent this whole section avoiding.
	 */
	uint8_t existed;
} fzn_rpc_notes_add_resp_t;

/*
 * An edit names the note and carries what replaces its title and text.
 *
 * NO PARENT FIELD, DELIBERATELY. An edit keeps the node where it is: sec 22's
 * tree refuses to resolve competing parents, so a verb that could both rewrite
 * content and move a node would make every edit a potential reparenting race
 * for no reason a user asked for. Moving a note wants its own verb, whenever
 * something needs one.
 */
/*
 * Which fields this edit actually sets. An absent one is PRESERVED, not
 * cleared, and that is the whole reason this byte exists: without it
 * `notes-edit --id X --title "New"` would silently wipe the body, which is
 * the exact silent loss sec 22 and the importer both refuse. A user who
 * means to empty a note's text says so with an explicit empty --text.
 */
#define FZN_RPC_NOTES_EDIT_TITLE 0x01u
#define FZN_RPC_NOTES_EDIT_TEXT 0x02u
/*
 * MOVE TO THE TRASH, OR BACK OUT OF IT.
 *
 * FZN_RPC_NOTE_FLAG_TRASHED existed, was decoded, was carried across the wire and
 * was set by nothing -- so notes-empty-trash was built with no way to put
 * anything into the trash it emptied. Found while writing the scenario for
 * the emptying, which is the only thing that would have found it: every unit
 * test set the flag by hand.
 *
 * TWO BITS RATHER THAN ONE WITH A VALUE, because an edit says which fields it
 * touches and an absent field means "leave it". A single TRASH bit could only
 * ever set, and untrashing is what a person does the moment they empty the
 * wrong thing -- which is exactly when they need it to work.
 */
#define FZN_RPC_NOTES_EDIT_TRASH 0x04u
#define FZN_RPC_NOTES_EDIT_UNTRASH 0x08u

/* The set an edit may name, in one place. Both the encoder and the decoder
 * refuse a bit outside it, and they must refuse the same bits -- spelling the
 * mask out at each of the four sites is how they stop agreeing. */
#define FZN_RPC_NOTES_EDIT_FIELDS_KNOWN                                    \
	(FZN_RPC_NOTES_EDIT_TITLE | FZN_RPC_NOTES_EDIT_TEXT | FZN_RPC_NOTES_EDIT_TRASH | \
	 FZN_RPC_NOTES_EDIT_UNTRASH)

typedef struct fzn_rpc_notes_show_resp {
	uint8_t id[32];
	uint8_t parent[32];
	char title[FZN_RPC_NOTES_TITLE_MAX + 1];
	size_t title_len;
	char text[FZN_RPC_NOTES_TEXT_MAX + 1];
	size_t text_len;
	uint64_t created_at_ms;
	uint64_t edited_at_ms;
	uint16_t content_type;
	uint8_t flags;
	int reachable;
	int contested;
} fzn_rpc_notes_show_resp_t;

/*
 * Publish a subtree to a contact, or stop.
 *
 * ONE PAIR PER REQUEST rather than a set, because sharing is a thing a person
 * does deliberately and one at a time, and a batch verb would make "share
 * everything with everyone" a single typo.
 */
/*
 * What `notes-empty-trash` answers with. `queued` is how many purges were
 * started; `pending` is how many are still collecting sign-off, including
 * ones from earlier runs. Two numbers because they answer different
 * questions: what just happened, and what is still outstanding.
 */
typedef struct fzn_rpc_library_add_req {
	uint8_t root[32];
	uint8_t content_key[32];
	uint64_t size;
	uint64_t duration_ms;
	char name[256];
	size_t name_len;
	char kind[65];
	size_t kind_len;
} fzn_rpc_library_add_req_t;

typedef struct fzn_rpc_library_list_entry {
	uint8_t root[32];
	char name[256];
	size_t name_len;
	char kind[65];
	size_t kind_len;
	uint64_t size;
	uint64_t duration_ms;
	/* How many of this user's hosts claim to hold it, and whether this one
	 * is among them -- sec 24's availability, which is what decides whether
	 * playing needs a transfer at all. */
	uint16_t holders;
	uint8_t held_here;
	/* This build could not read the description; the file is still listed,
	 * because a hidden file is one nobody can play. */
	uint8_t unreadable;
	/* Whether holders, held_here and size were read. A listing reads them for
	 * every row from two node listings since 2026-11-09; until then it was two
	 * requests a file, so a listing asked for the first FZN_RPC_LIBRARY_DETAIL_ROWS
	 * and a view for the rest (fzn_rpc_library_detail, which still serves). */
	uint8_t detail;
} fzn_rpc_library_list_entry_t;

#define FZN_RPC_LIBRARY_DETAIL_ROWS 256u

/* The most files any listing can have -- one per claim at most, so the claim
 * store's bound (FZN_RPC_LIBRARY_MAX, asserted equal in library_service.c). What
 * a client gathers its pages into. */
typedef struct fzn_rpc_library_list_all {
	fzn_rpc_library_list_entry_t *entries; /* sized as fzn_rpc_peer_list_resp_t's are */
	size_t room;
	size_t count;
} fzn_rpc_library_list_all_t;
/*
 * Playing a file (sec 24): a bounded slice of plaintext, from an offset the
 * caller names.
 *
 * A SLICE PER REQUEST, AND THE LOOP LIVES IN THE CLIENT. The same shape as
 * blob-scrub and for the same reason: each request is bounded so the daemon
 * stays responsive to everybody else, and a long read becomes many short
 * ones. It is also what makes this a stream rather than a copy -- the caller
 * consumes each slice as it arrives, which is what sec 24 says playback is.
 *
 * THE DAEMON KEEPS NO CURSOR, so the offset is in the request. A player that
 * paused, or seeked, or died and came back says where it wants to be; a
 * position held daemon-side would be state belonging to a client whose
 * lifetime the daemon cannot see.
 */
#define FZN_RPC_LIBRARY_PLAY_MAX_SLICE 8192u

typedef struct fzn_rpc_library_play_resp {
	/* What the description claims the whole file is. */
	uint64_t size;
	/* How much can be played from the START right now -- the contiguous
	 * prefix, which is NOT the amount held: a host with the second half of a
	 * file holds half of it and can play none of it. */
	uint64_t playable;
	uint8_t complete;
	/*
	 * The read caught up with the fetch. Not an error: sec 6 puts a library
	 * player in copy-stream, so the answer is wait and ask again, never skip
	 * ahead and never substitute. `data_len` is 0 when this is set.
	 */
	uint8_t underrun;
	/* Empty with underrun clear means end of file. */
	uint8_t data[FZN_RPC_LIBRARY_PLAY_MAX_SLICE];
	size_t data_len;
} fzn_rpc_library_play_resp_t;

/*
 * One file and every host claiming it (sec 24).
 *
 * WHY THE LIST IS NOT ENOUGH, which is the whole reason this exists. The
 * listing reports holders as a COUNT, and a count answers "is this here
 * somewhere" while the question a person actually has is "which of my hosts
 * has it, so I can go and fetch it from one". Availability is the metadata
 * that makes this subsystem worth having; a number is the part of it that
 * cannot be acted on.
 *
 * FZN_RPC_LIBRARY_SUBCMD_SHOW was defined when the subsystem was written and for
 * a long time nothing encoded, decoded or dispatched it, while
 * fzn_rpc_library_show sat tested and never called from production. An interface
 * is only as wired as its least-used method, and a complete looking one
 * attracts less suspicion than an obviously unfinished one. All three
 * clients ask it now; the CLI's `library-show` was the last, 2026-09-27.
 */
#define FZN_RPC_LIBRARY_SHOW_HOLDERS_MAX 32

typedef struct fzn_rpc_library_show_resp {
	uint8_t root[32];
	char name[256];
	size_t name_len;
	char kind[65];
	size_t kind_len;
	uint64_t size;
	uint64_t duration_ms;
	/* How many claim it, which may exceed what fits below -- the same
	 * distinction the store makes, kept rather than flattened. */
	uint16_t holders;
	uint8_t held_here;
	uint8_t unreadable;
	uint8_t holder_keys[FZN_RPC_LIBRARY_SHOW_HOLDERS_MAX][32];
	size_t holder_count;
} fzn_rpc_library_show_resp_t;

typedef struct fzn_rpc_notes_empty_trash_resp {
	size_t queued;
	size_t pending;
} fzn_rpc_notes_empty_trash_resp_t;

/*
 * What `notes-share` answers with: the subcommand, and how much of the
 * subtree this host could not publish.
 *
 * A RESPONSE OF ITS OWN rather than a wider notes-ok, because unshare answers
 * with the same command byte and has nothing to count -- and a payload whose
 * length depends on which subcommand it echoes is the shape that gets
 * mis-decoded later.
 */
typedef struct fzn_rpc_notes_share_resp {
	uint8_t sub_cmd;
	size_t withheld;
} fzn_rpc_notes_share_resp_t;

#define FZN_RPC_NOTES_SHARES_LIST_MAX 4096u

typedef struct fzn_rpc_notes_shares_entry {
	uint8_t subtree[32];
	char peer[FZN_RPC_PEER_NAME_MAX + 1];
	size_t peer_len;
	/*
	 * The sharing host's key on an incoming row, all-zero on an outgoing one.
	 *
	 * IT IS THE ONLY WAY A RECIPIENT CAN READ WHAT WAS SHARED WITH THEM, which
	 * is why it is on the row rather than left to a lookup. `notes-list` and
	 * `notes-show` take `--from KEY` and there is no other listing; without
	 * this field the daemon held the key, the CLI told the user to use it, and
	 * nothing anywhere printed one. A share arrived and could not be opened.
	 *
	 * `peer` carries a contact name when the key resolves to one and is empty
	 * when it does not, so a client shows the name and reads with the key. The
	 * two can disagree in a way that matters: a person has several hosts (sec
	 * 3) and only the paired one is in the peer list, so a share from their
	 * other host is nameless and still perfectly readable. Never derive the
	 * key from the name.
	 */
	uint8_t issuer[32];
	/*
	 * On an OUTGOING row, how many notes under this subtree are not being
	 * published because another of this user's hosts wrote them. Zero on an
	 * incoming row, which is somebody else's business to count.
	 *
	 * IT IS ON THE LISTING AND NOT ONLY ON THE SHARE, because a share is
	 * live: a folder that was whole when it was published becomes partial the
	 * moment the user writes into it from their other host, and a warning
	 * given once at share time would have expired without saying so. That is
	 * the failure sec 22 names -- a folder that silently stops updating is
	 * one nobody notices.
	 */
	size_t withheld;
	/* 1 when this row is a subtree somebody shared WITH us rather than one we
	 * publish. The two travel in one listing because a user asking "what is
	 * shared" means both, and a client that showed only outgoing would let
	 * somebody forget what they are receiving. */
	int incoming;
	/*
	 * On an OUTGOING row: whether it goes to a GROUP, and whether that group
	 * share catches up a member who joins later (sec 22's opt-in). Zero on an
	 * incoming row. Read back because it is consent that cannot be undone:
	 * a flag nobody can see is one a client can get wrong unnoticed, which
	 * the ncurses client did -- it sent backfill on every share until
	 * 2026-09-28 (project.md sec 105).
	 */
	uint8_t to_group;
	uint8_t backfill;
} fzn_rpc_notes_shares_entry_t;

typedef struct fzn_rpc_notes_shares_resp {
	fzn_rpc_notes_shares_entry_t entries[FZN_RPC_NOTES_SHARES_LIST_MAX];
	size_t count;
	int truncated;
} fzn_rpc_notes_shares_resp_t;

typedef struct fzn_rpc_notes_list_entry {
	uint8_t id[32];
	uint8_t parent[32];
	char title[FZN_RPC_NOTES_TITLE_MAX + 1];
	size_t title_len;
	uint64_t order;
	uint16_t content_type;
	uint8_t flags; /* FZN_RPC_NOTE_FLAG_* -- pinned, archived, trashed, blob */
	int reachable; /* 0 or 1 -- see the banner */
	int contested; /* 0 or 1 -- see the banner */
	/* A node's labels for it (fuzznet sec 869), NUL between two, kept to
	 * FZN_RPC_NOTES_LABELS_SHOWN bytes for a listing and labels_cut set past
	 * it; fzn_rpc_note_meta reads them whole. */
	char labels[FZN_RPC_NOTES_LABELS_SHOWN];
	size_t labels_len;
	int labels_cut;
} fzn_rpc_notes_list_entry_t;

/* Matches FZN_RPC_NOTES_MAX; control_codec.c static-asserts they agree. */

typedef struct fzn_rpc_notes_list_resp {
	fzn_rpc_notes_list_entry_t *entries; /* sized as fzn_rpc_peer_list_resp_t's are */
	size_t room;
	size_t count;
	/*
	 * Reported rather than silent, because a contested subtree is listed
	 * once per surviving parent claim -- so an output sized for the quiet
	 * case is sized wrong exactly when a user is confused and looking.
	 */
	int truncated;
} fzn_rpc_notes_list_resp_t;

/*
 * How to read a row's key.
 *
 * DEFINED HERE, not in the daemon that fills it in, because it crosses the
 * wire: a value a client must interpret is part of the control contract, and
 * one defined privately in the daemon would be a number the GUI had to
 * hard-code and could not be checked against.
 */
typedef enum fzn_rpc_meter_key_kind {
	FZN_RPC_METER_KEY_NONE = 0, /* the peer is the whole answer -- chat */
	FZN_RPC_METER_KEY_BLOB = 1, /* a content root; hex, nameable from a conversation */
	FZN_RPC_METER_KEY_NAME = 2, /* text, already human-readable -- a group */
} fzn_rpc_meter_key_kind_t;

/*
 * One (subsystem, peer, key) row.
 *
 * THE SUBSYSTEM IS PART OF THE IDENTITY, not a label on it: chat with a peer
 * and a file transfer with the same peer are different traffic answering
 * different questions, and a display that summed them could not tell a busy
 * conversation from a busy download.
 *
 * The KEY is that subsystem's second question -- a blob root for a file, a
 * name for a group, nothing at all for chat, where the peer is the whole
 * answer. `key_kind` says which, and travels WITH the key rather than being
 * inferred from the subsystem, so a subsystem that grows a second kind later
 * is obviously missing rather than silently misread.
 */
typedef struct fzn_rpc_transfer_entry {
	uint8_t subsystem; /* the frame's own cmd byte */
	uint8_t key_kind;  /* an fzn_rpc_meter_key_kind: none | blob root | name */
	uint8_t key[FZN_RPC_BLOB_HASH_LEN];
	size_t key_len;
	char peer_address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t peer_address_len;
	uint64_t bytes_down;
	uint64_t bytes_up;
	uint64_t rate_down; /* bytes per second over the last sampling interval */
	uint64_t rate_up;
	uint64_t first_seen; /* seconds, the daemon's clock */
	uint64_t last_seen;
	/* What a fuzznetd node calls the traffic (its sec 685), filled by the
	 * client there in place of `subsystem`. */
	char family[24];
} fzn_rpc_transfer_entry_t;

#define FZN_RPC_TRANSFER_LIST_MAX 1024

/*
 * Per-subsystem totals, over every row of that subsystem's meter.
 *
 * `evicted_*` is separate from `bytes_*` rather than folded into it, and the
 * reason is the same one that keeps them out of a rate. A meter evicts its
 * least recently active row when full, which loses those bytes from every sum
 * computed over rows: a display adding rows up would report a total that
 * SHRINKS as traffic continues, and nothing on screen would say why. So
 * eviction adds into these instead of discarding, and a subsystem's true total
 * is `bytes_* + evicted_*`. Kept per subsystem rather than per peer because
 * the row that would have carried the attribution is precisely the one being
 * dropped: "these bytes were chat, to someone we no longer track" is the
 * honest claim, and inventing a peer for them would not be.
 *
 * `rate_*` sums the rows only. A rate is about now, and a row that is gone has
 * nothing to say about now.
 */
/* 16: a fuzznetd node meters up to sixteen families (its sec 685). */
#define FZN_RPC_TRANSFER_SUBSYSTEM_MAX 16

typedef struct fzn_rpc_transfer_subsystem {
	uint8_t subsystem;
	uint64_t bytes_down; /* over every row, not just the ones sent */
	uint64_t bytes_up;
	uint64_t rate_down; /* rows only -- see above */
	uint64_t rate_up;
	uint16_t rows; /* rows the daemon holds for this subsystem */
	uint64_t evicted_down;
	uint64_t evicted_up;
	char family[24]; /* as fzn_rpc_transfer_entry_t's */
} fzn_rpc_transfer_subsystem_t;

#define FZN_RPC_TRANSFER_HOST_MAX 48

typedef struct fzn_rpc_transfer_host {
	char peer_address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t peer_address_len;
	uint64_t bytes_down;
	uint64_t bytes_up;
	uint64_t rate_down;
	uint64_t rate_up;
	uint16_t rows; /* rows the daemon holds for this host */
} fzn_rpc_transfer_host_t;

typedef struct fzn_rpc_transfer_list_resp {
	fzn_rpc_transfer_entry_t entries[FZN_RPC_TRANSFER_LIST_MAX];
	size_t count;

	/* Rows the daemon holds across every subsystem. Equal to `count` unless
	 * the frame ran out of room, and greater than it exactly when a display
	 * must say so. u16 like every other count here, and it cannot overflow
	 * one: the daemon's own bound is FZN_RPC_METERS_MAX * FZN_RPC_METER_ROWS_MAX,
	 * asserted against this in daemon/traffic_meter.h. */
	uint16_t rows_total;

	fzn_rpc_transfer_subsystem_t subsystems[FZN_RPC_TRANSFER_SUBSYSTEM_MAX];
	size_t subsystem_count;

	fzn_rpc_transfer_host_t hosts[FZN_RPC_TRANSFER_HOST_MAX];
	size_t host_count;
	uint16_t hosts_total; /* distinct peers held, counted past the bound */
} fzn_rpc_transfer_list_resp_t;

/*
 * Transport tags, as a bitmask because one address may speak several.
 *
 * These are the values the manifest's transport_bitmask has always carried
 * -- it was a declared-but-uninterpreted byte until these were pinned, which
 * is why they are fixed here rather than renumbered freely: an existing
 * manifest's bytes must keep meaning what they meant.
 */
#define FZN_RPC_TRANSPORT_UDP 0x01
/*
 * 0x02 is BURNT, not free. It was FZN_RPC_TRANSPORT_SCTP, and sec 7's "Why not
 * SCTP" records why that was dropped. Left as a hole rather than reused,
 * because a manifest written while it existed may still carry the bit set,
 * and silently reinterpreting it as some future transport would make an old
 * host's declaration mean something it never said.
 */
/* Reserved so the numbering is fixed before anything speaks them; sec 1's
 * link list. Nothing dispatches on these. */
#define FZN_RPC_TRANSPORT_RADIO 0x04
#define FZN_RPC_TRANSPORT_LOCAL 0x08
/*
 * LAN one-to-many between a user's own hosts. A RESEARCH DIRECTION rather
 * than a plan (sec 7, "Research direction: LAN broadcast and multicast") --
 * for once the protocol and software have matured, not something to design
 * toward now.
 *
 * Two bits rather than one because their availability genuinely differs per
 * network: plenty filter multicast while passing broadcast, and plenty do
 * the reverse, so they would have to be measurable separately, which for
 * this table means separate links.
 *
 * Numbered here only so the question is settled and a future transport does
 * not take these values by accident. Neither is spoken, and note that
 * one-to-many does not fit this table's point-to-point cost model at all: it
 * answers "what does it cost to reach this peer", not "this one send covers
 * these three".
 */
#define FZN_RPC_TRANSPORT_BROADCAST 0x10
#define FZN_RPC_TRANSPORT_MULTICAST 0x20

/*
 * Names one transport tag, for a display.
 *
 * IN CORE, BESIDE THE VALUES, rather than in each of the three surfaces that
 * needs it. A tag rendered as `0x01` is a mark nobody can decode, and three
 * private tables mapping the same bytes is how the CLI and the two clients
 * come to disagree about what a peer advertised.
 *
 * Takes ONE bit, because that is what a link row carries: a manifest entry
 * declaring several becomes several rows, which is the link table's own model.
 *
 * An unrecognised tag is written as its HEX VALUE rather than as the word
 * "unknown". A peer controls this byte, 0x02 is burnt and the high bits are
 * unallocated, so what a reader needs is which byte arrived -- and a display
 * that flattens every unknown tag to one word cannot tell an old host from a
 * malformed one. Returns `out`.
 */
const char *fzn_rpc_transport_name(uint8_t transport, char *out, size_t cap);

/* One link: one transport over one address. A peer advertising two
 * addresses, or one address reachable two ways, is several rows -- which is
 * the table's own model rather than a flattening done here. */
typedef struct fzn_rpc_link_entry {
	char address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t address_len;
	uint8_t transport; /* exactly one FZN_RPC_TRANSPORT_* bit */
	/* What the far end DECLARED about its own address. A prior, not
	 * evidence, and carried beside the measurements rather than folded into
	 * them so a reader can see the two disagree. */
	uint8_t metric;
	uint32_t rtt_ms;  /* smoothed; meaningful where replied > 0 */
	uint32_t sent;    /* probes attempted since the counters were reset */
	uint32_t replied; /* of those, answered */
	uint32_t consecutive_failures;
	uint32_t cost; /* fzn_rpc_link_cost, as of this response */
	uint8_t outstanding;   /* an attempt is out and unanswered */
	uint8_t in_use;
	uint64_t since_attempt_ms; /* meaningful where sent > 0 */
	uint64_t since_success_ms; /* meaningful where replied > 0 */
	/* 0 means UNLIMITED, which is every link's state until something
	 * configures otherwise -- so a display must not render an unlimited link
	 * as one that has spent all of nothing. */
	uint64_t budget_limit;
	uint64_t budget_spent; /* this window's, rolled */
	uint64_t budget_window_ms;
} fzn_rpc_link_entry_t;

/* The table's own bound (FZN_RPC_LINK_MAX in link_internal.h), restated here
 * because this header is the contract and link_internal.h is not shipped to
 * a client. control_codec.c asserts the two agree, so raising one without
 * the other is a build error rather than a response that silently drops
 * links. */
#define FZN_RPC_LINK_LIST_MAX 1024

typedef struct fzn_rpc_link_list_resp {
	fzn_rpc_link_entry_t entries[FZN_RPC_LINK_LIST_MAX];
	size_t count;
} fzn_rpc_link_list_resp_t;

#define FZN_RPC_ADDR_OBSERVE_LIST_MAX 8

typedef struct fzn_rpc_addr_observed_entry {
	/* Who reported it -- the peer's own address, so a reader can tell which
	 * of several answers came from where. */
	char reporter[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t reporter_len;
	/* What that peer says this host looks like from outside. */
	char address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t address_len;
	uint64_t observed_at; /* seconds, the daemon's clock */
} fzn_rpc_addr_observed_entry_t;

typedef struct fzn_rpc_addr_observe_resp {
	fzn_rpc_addr_observed_entry_t entries[FZN_RPC_ADDR_OBSERVE_LIST_MAX];
	size_t count;
	/* Probes this call sent. Zero means nothing was asked -- no registered
	 * peer had a usable address -- which is a different state from "asked and
	 * nobody answered" and must not read the same. */
	uint16_t probes_sent;
} fzn_rpc_addr_observe_resp_t;

typedef struct fzn_rpc_lan_seen_entry {
	char address[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t address_len;
	uint64_t seen_at;
} fzn_rpc_lan_seen_entry_t;

#define FZN_RPC_LAN_DISCOVER_LIST_MAX 16

typedef struct fzn_rpc_lan_discover_resp {
	fzn_rpc_lan_seen_entry_t entries[FZN_RPC_LAN_DISCOVER_LIST_MAX];
	size_t count;
	/* 1 when a probe actually went out. Zero means it could not -- no
	 * identity, or no discovery address configured -- which is a different
	 * state from "probed and nobody is there". */
	uint8_t probed;
} fzn_rpc_lan_discover_resp_t;

/* `probe` broadcasts; without it this only reports who has already answered.
 * See the addr-observe note above for why a display must be able to read
 * without asking. */
typedef struct fzn_rpc_identity_reset_resp {
	uint64_t files; /* how many were removed */
} fzn_rpc_identity_reset_resp_t;

typedef struct fzn_rpc_identity_backup_resp {
	uint64_t files;  /* how many were copied */
	uint64_t bytes;  /* how much, so the caller has a figure to check */
} fzn_rpc_identity_backup_resp_t;

typedef struct fzn_rpc_relay_peer_entry {
	char peer[FZN_RPC_PEER_ADDRESS_MAX + 1];
	size_t peer_len;
	uint64_t bytes_used;
	uint64_t refused;
} fzn_rpc_relay_peer_entry_t;

#define FZN_RPC_RELAY_STATUS_LIST_MAX 1024

typedef struct fzn_rpc_relay_status_resp {
	fzn_rpc_relay_peer_entry_t entries[FZN_RPC_RELAY_STATUS_LIST_MAX];
	size_t count;
	uint8_t enabled;
	uint64_t quota_bytes; /* per peer per window; 0 = unlimited */
	uint64_t window_s;
} fzn_rpc_relay_status_resp_t;

#endif /* FZN_RPC_CONTROL_H */
