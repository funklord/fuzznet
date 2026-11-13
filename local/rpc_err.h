#ifndef FZN_RPC_ERRORS_H
#define FZN_RPC_ERRORS_H

typedef enum fzn_rpc_err {
	FZN_RPC_OK = 0,
	FZN_RPC_ERR_MALFORMED = -1,
	FZN_RPC_ERR_UNSUPPORTED_VERSION = -2,
	FZN_RPC_ERR_UNKNOWN_MSG_TYPE = -3,
	FZN_RPC_ERR_BUFFER_TOO_SMALL = -4,
	FZN_RPC_ERR_IDENTITY_EXISTS = -5,
	FZN_RPC_ERR_NO_IDENTITY = -6,
	FZN_RPC_ERR_HOST_EXISTS = -7,
	FZN_RPC_ERR_NO_HOST = -8,
	FZN_RPC_ERR_STORAGE_IO = -9,
	FZN_RPC_ERR_ENTROPY = -10,
	FZN_RPC_ERR_CROSS_SIGN_INVALID = -11,
	FZN_RPC_ERR_INVALID_HOST_NAME = -12,
	FZN_RPC_ERR_PREKEY_EXISTS = -13,
	FZN_RPC_ERR_NO_PREKEY = -14,
	FZN_RPC_ERR_PEER_EXISTS = -15,
	FZN_RPC_ERR_NO_PEER = -16,
	FZN_RPC_ERR_INVALID_PEER_NAME = -17,
	FZN_RPC_ERR_PREKEY_SIG_INVALID = -18,
	FZN_RPC_ERR_PEER_FRAME_MALFORMED = -19,
	FZN_RPC_ERR_COMMITMENT_MISMATCH = -20,
	FZN_RPC_ERR_SEND_FAILED = -21,
	FZN_RPC_ERR_NO_PEER_TRANSPORT = -22,
	FZN_RPC_ERR_JOIN_REQUEST_SIG_INVALID = -23,
	FZN_RPC_ERR_JOIN_HOST_MISMATCH = -24,
	FZN_RPC_ERR_NOT_AUTHORIZED = -25,
	FZN_RPC_ERR_CAPABILITY_CHAIN_INVALID = -26,
	FZN_RPC_ERR_INVALID_SIBLING_NAME = -27,
	FZN_RPC_ERR_SIBLING_EXISTS = -28,
	FZN_RPC_ERR_SIBLING_IS_SELF = -29,
	FZN_RPC_ERR_HOST_PROOF_WRONG_USER = -30,
	/* Contact card's OWN fields (signature over the whole card, malformed
	 * lengths) -- NOT for failures inside its embedded host_proof_bundle,
	 * which propagate FZN_RPC_ERR_CROSS_SIGN_INVALID/FZN_RPC_ERR_CAPABILITY_CHAIN_INVALID
	 * unchanged instead (same "don't collapse a lower layer's specific error
	 * into a generic one" discipline fzn_rpc_identity_verify_host_proof already
	 * follows -- see core/src/peer_pair_internal.h). */
	FZN_RPC_ERR_CONTACT_CARD_INVALID = -31,
	/* The trailing transcription checksum (Base58Check, or the contact
	 * card's own embedded one) didn't match -- deliberately distinct from
	 * FZN_RPC_ERR_MALFORMED/FZN_RPC_ERR_CONTACT_CARD_INVALID so a caller can say
	 * "mistyped?" specifically rather than a generic parse failure. */
	FZN_RPC_ERR_CHECKSUM_MISMATCH = -32,
	FZN_RPC_ERR_PEER_REQUEST_EXISTS = -33,
	FZN_RPC_ERR_NO_PEER_REQUEST = -34,
	/* Manifest's own fields (signature, structure) -- see
	 * core/src/manifest_internal.h. No embedded proof bundle in this blob
	 * (unlike the contact card), so no lower-layer error to propagate
	 * unchanged. */
	FZN_RPC_ERR_MANIFEST_INVALID = -35,
	/* Not yet configured (fzn_rpc_manifest_set hasn't run on this host/mesh
	 * yet -- MANIFEST_SHOW) or nothing cached for that peer yet
	 * (MANIFEST_PEER_SHOW) -- same "not yet configured" meaning
	 * FZN_RPC_ERR_NO_PREKEY/FZN_RPC_ERR_NO_HOST already use for their own subsystems. */
	FZN_RPC_ERR_NO_MANIFEST = -36,
	/* A sibling with no prekey: sibling-add given no prekey_record blob, or
	 * a record left by the plaintext mode dropped 2026-10-29 -- every frame
	 * between hosts is sealed, so such a host is added again with its key. */
	FZN_RPC_ERR_SIBLING_NO_KEY_MATERIAL = -37,
	/* log-relay-show for an origin with nothing cached yet -- matches the
	 * existing FZN_RPC_ERR_NO_MANIFEST/FZN_RPC_ERR_NO_PREKEY "not configured yet"
	 * precedent. core/src/log_relay_internal.h. */
	FZN_RPC_ERR_NO_LOG_RELAY_CACHE = -38,

	/* Group chat (project.md sec 6/5) -- core/src/group_internal.h. */
	FZN_RPC_ERR_INVALID_GROUP_NAME = -39,
	FZN_RPC_ERR_GROUP_EXISTS = -40,
	FZN_RPC_ERR_NO_GROUP = -41,
	/* Roster blob's own signature/structure failed to verify -- mirrors
	 * FZN_RPC_ERR_MANIFEST_INVALID, no embedded proof bundle to propagate a
	 * lower-layer error from. */
	FZN_RPC_ERR_GROUP_ROSTER_INVALID = -42,
	FZN_RPC_ERR_GROUP_MEMBER_EXISTS = -43,
	FZN_RPC_ERR_NO_GROUP_MEMBER = -44,
	/* group-history-show for a (chat, sender) with nothing cached yet --
	 * matches FZN_RPC_ERR_NO_LOG_RELAY_CACHE's own precedent.
	 * core/src/group_history_internal.h. */
	FZN_RPC_ERR_NO_GROUP_HISTORY_CACHE = -45,
	/* No chain key has ever been received from this sender within this
	 * group yet -- core/src/group_ratchet_internal.h. */
	FZN_RPC_ERR_GROUP_NO_CHAIN_KEY = -46,
	/* The stream type passed for an operation is unsupported by this
	 * backend, or disagrees with what the stream on disk was created as.
	 * Reinterpreting existing entries under a different framing would
	 * silently corrupt them, so this is refused rather than guessed --
	 * see fzn_rpc_stream_type_t in core/src/core.h. */
	FZN_RPC_ERR_STREAM_TYPE = -47,
	/* A compare-and-swap write lost: the value changed since the caller read
	 * it (configuration.md sec 8.1). Distinct from a malformed request --
	 * the caller did nothing wrong, its view was simply stale, and it can
	 * re-read and retry. */
	FZN_RPC_ERR_CONFLICT = -48,
	/* A manifest's derivation_version is one this build does not implement,
	 * so its content hash cannot be recomputed and the statement cannot be
	 * checked (configuration.md sec 8.2.3). Deliberately NOT
	 * FZN_RPC_ERR_MANIFEST_INVALID: "my code is older than the host that signed
	 * this" and "this manifest is tampered with or diverged" are completely
	 * different things to tell a user, and only one of them is true on an
	 * ordinary staggered upgrade. */
	FZN_RPC_ERR_MANIFEST_DERIVATION_UNSUPPORTED = -49,
	/* An address that cannot be what the caller meant -- currently only
	 * "you told a peer to reach you at the peer's own address", which is
	 * always a mistake and used to fail silently. Distinct from a malformed
	 * one: the string is fine, the claim is not. */
	FZN_RPC_ERR_INVALID_PEER_ADDRESS = -50,
	/* Asked for a revocation this host does not hold -- matches the
	 * FZN_RPC_ERR_NO_MANIFEST/FZN_RPC_ERR_NO_LOG_RELAY_CACHE "nothing cached for
	 * that yet" precedent. Deliberately NOT the same as "not revoked":
	 * this is only ever returned by the load-for-forwarding path, and
	 * fzn_rpc_capability_is_revoked answers the authorization question with a
	 * plain 0 rather than an error. core/src/capability_internal.h. */
	FZN_RPC_ERR_NO_REVOCATION = -51,

	/* The sender's hold-until-delivered store is full (project.md sec 9,
	 * FZN_RPC_OUTBOX_MAX). Distinct from a storage failure: nothing is wrong, this
	 * host is simply holding as much undelivered mail as it will, and sec 9's
	 * "never give up" means the fix is delivery or a human, not eviction. */
	FZN_RPC_ERR_OUTBOX_FULL = -52,
	/* No outbox entry matches an arriving ack's commitment -- already retired,
	 * or never sent from here. Harmless, and worth telling apart from an ack
	 * whose proof is wrong. */
	FZN_RPC_ERR_NO_SUCH_MESSAGE = -53,
	/* This contact was registered on ANOTHER of this user's hosts and reached
	 * here by peer_sync, so the contact has never met this host and would
	 * drop anything it sent -- their registry pins one host per contact.
	 * Distinct from FZN_RPC_ERR_NO_PEER, which means "who?": here the contact is
	 * known, addressable, and simply not reachable FROM HERE yet. Refusing
	 * beats the silent alternative, which was reporting a successful send for
	 * a message guaranteed to be dropped at the far end. */
	FZN_RPC_ERR_PEER_NOT_OURS = -54,
	/* The hand-off queue is full (core/src/delegate_internal.h,
	 * FZN_RPC_DELEGATE_QUEUE_MAX). Deliberately its own code rather than
	 * FZN_RPC_ERR_OUTBOX_FULL: they are different stores waiting on different
	 * things, and only one of them is waiting on another of this user's own
	 * devices -- which is a thing the user can go and switch on, and worth
	 * saying so. */
	FZN_RPC_ERR_DELEGATE_QUEUE_FULL = -55,
	/* A frontend gave up waiting for the daemon's reply (control.h's
	 * FZN_RPC_REQUEST_TIMEOUT_S). Unlike every other code here this one is never
	 * sent by a daemon and never appears in an FZN_RPC_CMD_ERROR frame -- it is
	 * produced locally, by the caller, about a reply that did not arrive.
	 * Distinct from FZN_RPC_ERR_STORAGE_IO, which the request path returned for
	 * every failure before this existed: "the daemon is wedged" and "the
	 * socket broke" send a user to entirely different places. */
	FZN_RPC_ERR_TIMEOUT = -56,
	/* An X25519 exchange produced the all-zero shared secret, which happens
	 * exactly when the public key on the other side has small order. Monocypher
	 * 4's crypto_x25519 returns void and signals nothing, so this was ours to
	 * detect while this tree did its own key agreement; that is fuzznet's now
	 * and nothing here returns it. */
	FZN_RPC_ERR_DEGENERATE_KEY = -57,
	/* This host already holds FZN_RPC_NOTES_MAX note nodes. A refused put rather
	 * than a silent drop, because the alternative -- discarding the newest
	 * node -- would look to the user exactly like a note they typed and lost,
	 * and would look to another host like a node it published that never
	 * arrived. The bound is a property of the index blob being read and
	 * rewritten whole; see core/src/notes_store_internal.h. */
	FZN_RPC_ERR_TOO_MANY_NOTES = -58,
	/* An edit named a note this host has never seen. Distinct from
	 * FZN_RPC_ERR_STORAGE_IO, which fzn_rpc_notes_get returns for a claim that is
	 * absent from a store that should hold it: this one means the id itself
	 * is unknown, which is a client naming a note that does not exist rather
	 * than a store disagreeing with its own index. A user who mistypes an id
	 * should be told that, not told the disk is unhappy. */
	FZN_RPC_ERR_NO_SUCH_NOTE = -59,
	/* This host's own AEAD backend refused while sealing a frame. Distinct
	 * from FZN_RPC_ERR_PEER_FRAME_MALFORMED and from FZN_RPC_ERR_MALFORMED, and the
	 * distinction is about where to send whoever reads it: those two mean
	 * bytes that arrived are wrong, so the next person goes and reads the
	 * wire. This one means the local crypto seam declined on a frame this
	 * host was building, before anything was sent -- nothing was on the
	 * network and reading it would find nothing. fuzznet's
	 * FZN_SEAL_ERR_AEAD, which arrived as a new enumerator in 43aed04 and
	 * would otherwise have fallen into the default arm of the switch in
	 * fzn_rpc_peer_seal_msg and been reported as a malformed frame. Their
	 * fzn_seal_build wipes the whole frame before returning it, so there is
	 * no half-sealed buffer to inspect either. */
	FZN_RPC_ERR_SEAL_BACKEND = -60,

	/*
	 * The bytes are not here YET -- a playback read that has caught up with
	 * the fetch. Distinct from every other refusal because the caller's
	 * response is different: not retry, not repair, but wait and read again.
	 * fzn_rpc_blob_read answers FZN_RPC_ERR_NO_MANIFEST for an incomplete blob, and
	 * a player cannot act on that -- it cannot tell a file that is arriving
	 * from one that will never arrive.
	 */
	FZN_RPC_ERR_UNDERRUN = -61,

	/*
	 * Not a "host:port" this host can send to -- above all, a port outside 1
	 * to 65535. Its own code because the resolver would otherwise wrap the
	 * port modulo 65536 and send somewhere else without complaint
	 * (project.md sec 135, udp_address.h).
	 */
	FZN_RPC_ERR_BAD_ADDRESS = -62,

	/*
	 * No sibling host is registered under that name. Its own code because the
	 * sibling loader answers FZN_RPC_ERR_STORAGE_IO for a missing record -- its
	 * contract, since through the index the two are one fault -- and a typed
	 * name that is simply wrong was told "storage I/O error" (sec 141).
	 */
	FZN_RPC_ERR_NO_SIBLING = -63,

	/*
	 * The contact exists but this host holds no verified identity for them:
	 * they were added from a bare prekey rather than through a peer request,
	 * so there is no root key to name them by. A group names its members by
	 * that key, so it cannot take them. Its own code because the group verbs
	 * answered FZN_RPC_ERR_NO_PEER -- "who?" -- about a contact listed one line
	 * above (project.md sec 142).
	 */
	FZN_RPC_ERR_PEER_UNVERIFIED = -64,

	/*
	 * The contact's host key is this host's own: somebody added this host's
	 * own prekey as a peer, so no session can be established with it. Its
	 * own code because fuzznet reports it as FZN_SESSION_ERR_SELF and the
	 * seal folded that into FZN_RPC_ERR_MALFORMED, so every send to such a
	 * contact said "malformed message" (project.md sec 144).
	 */
	FZN_RPC_ERR_PEER_IS_SELF = -65,

	/*
	 * A note whose content this build cannot open -- a newer version, a
	 * field larger than it keeps. Refused on edit, because an edit keeps
	 * what it does not name by copying it, and what cannot be read would be
	 * copied as nothing and signed as the newest version (sec 146).
	 */
	FZN_RPC_ERR_NOTE_UNREADABLE = -66,
	/*
	 * A host's contact, group or group-membership limit reached (sec 166).
	 * These were all FZN_RPC_ERR_BUFFER_TOO_SMALL, which named an implementation
	 * detail and told the person nothing about what to do.
	 */
	FZN_RPC_ERR_TOO_MANY_PEERS = -67,
	FZN_RPC_ERR_TOO_MANY_GROUPS = -68,
	FZN_RPC_ERR_GROUP_FULL = -69,
	/* The saved sticker collection limit (sec 167). It borrowed
	 * FZN_RPC_ERR_OUTBOX_FULL, so a full collection list was reported as
	 * "holding as many undelivered messages as it will". */
	FZN_RPC_ERR_TOO_MANY_STICKERS = -70,
	/* The library's claim limit (sec 167), which borrowed
	 * FZN_RPC_ERR_TOO_MANY_NOTES and so said "notes" about files. */
	FZN_RPC_ERR_LIBRARY_FULL = -71,
	/* A pin's keys cannot be owed: the outbox of keys members have not yet
	 * acknowledged is full (sec 180). It said "buffer too small", after the
	 * pin had been recorded, so the file was pinned and nobody was owed. */
	FZN_RPC_ERR_KEYS_OWED_FULL = -72,
	/* A fix handed to this host while location.enabled is off. Refused
	 * rather than kept: switching location off has to mean nothing of the
	 * user's position is recorded, whoever is supplying it. */
	FZN_RPC_ERR_LOCATION_OFF = -73,
} fzn_rpc_err_t;

/* Short, stable, human-readable string for an fzn_rpc_err_t. Never NULL. */
const char *fzn_rpc_err_str(int err);

#endif /* FZN_RPC_ERRORS_H */
