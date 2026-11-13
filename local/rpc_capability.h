#ifndef FZN_RPC_CAPABILITY_H
#define FZN_RPC_CAPABILITY_H

/*
 * Capability types for the delegation-chain model (project.md sec 3/12,
 * "Multi-host: capability delegation, not a fixed root device"). A small
 * fixed byte enum, defined fine-grained from the start even though the CLI
 * stays coarse for now -- retrofitting a typed field into an already-
 * deployed signed capability grant is exactly the kind of wire-format churn
 * this project has already paid to avoid twice (the cmd-space unification,
 * and host_record's signer_pubkey field).
 *
 * FZN_RPC_CAP_ADMIN is the ENTITLEMENT TO GRANT: a non-root host may mint a
 * capability for another host only if it holds CAP_ADMIN *and* the type it
 * is handing over. Those are two different questions -- "may you pass
 * anything on at all" and "do you have this particular thing to pass" --
 * and for a while only the second was asked, which left CAP_ADMIN gating
 * nothing and let any host promote any other host to its own capability
 * set.
 *
 * It is still NOT a cross-type "master granter". A capability chain is
 * single-typed by construction (capability_type sits inside each hop's
 * signed region, and hop linkage requires grantor == previous hop's
 * grantee), so an admin holder cannot mint a type it does not itself hold,
 * and only the root (holding "identity" directly) can originate hop 0 of a
 * brand-new type for someone else. That ceiling is deliberate: it is what
 * keeps one compromised admin host from being equivalent to the root.
 * See core/src/capability_internal.h for the full mint/install/verify
 * contract.
 */
#include <stdint.h>

typedef enum fzn_rpc_capability_type {
	FZN_RPC_CAP_ADMIN = 1,
	FZN_RPC_CAP_HOST_MANAGE = 2,
	/* Enforced everywhere content comes to REST: adding a blob, starting a
	 * fetch, an inbound direct message, and a group MSG_PUSH or
	 * HISTORY_LINES. Reading back and serving what is already held are not
	 * gated -- the capability governs taking on custody, not what to do with
	 * custody already taken, and refusing to read out would strand data
	 * rather than protect it. For the same reason a group ROSTER_PUSH and
	 * CHAIN_KEY pass ungated: membership and key material are not content.
	 * A chat refusal is invisible to the sender (neither chat path has an
	 * acknowledgement), so the receiving daemon logs it explicitly --
	 * see project.md sec 3. */
	FZN_RPC_CAP_STORE = 3,
	/* Enforced: a SIBLING asking this host to forward its traffic
	 * (daemon/ipc_server.c's relay path). A peer holds none of our
	 * capabilities, so relaying for one is gated by the operator's opt-in
	 * instead. */
	FZN_RPC_CAP_RELAY = 4,
	/* May originate content AS THIS USER: a 1:1 message, a group message.
	 * Enforced in core rather than in the daemon's command handlers, so no
	 * frontend can reach a send path around it.
	 *
	 * Added because the four types above did not, between them, make sec 3's
	 * "a stolen host holding none of these leaks nothing" true. They govern
	 * what a host may KEEP, ADMINISTER or FORWARD, and none of them governs
	 * what it may SAY. A linked host holding nothing could still send
	 * messages that every contact would attribute to the user -- verified by
	 * doing it, not by reading for it. Impersonation is a worse theft
	 * consequence than reading whatever the device already had, and it was
	 * entirely ungoverned.
	 *
	 * Deliberately NOT about receiving: that is CAP_STORE's business. A host
	 * can legitimately hold one and not the other -- an archival node that
	 * keeps everything and says nothing wants store without send. */
	FZN_RPC_CAP_SEND = 5,
	/* May change WHO THIS USER IS CONNECTED TO: adding a peer, initiating or
	 * approving a pairing request, creating a group, adding or removing a
	 * member. The other half of the impersonation hole CAP_SEND closed --
	 * found by the same probe, which showed a host holding nothing could
	 * still add peers and create groups.
	 *
	 * Kept separate from CAP_SEND rather than folded into one "may act as
	 * the user" type because the damage has a different lifetime, and that
	 * is the distinction worth being able to express. A message sent from a
	 * stolen phone is a message: bounded, visible, over. A peer added on one
	 * is an identity the user goes on trusting after the device is gone, and
	 * a group member added is someone who keeps receiving. One is an event,
	 * the other is a persistent change to the trust graph.
	 *
	 * Rejecting a pending pairing request is deliberately NOT gated: it
	 * removes a relationship that does not exist yet, and a host unable to
	 * decline junk would be worse off, not safer. Nor is contact-card-show,
	 * which only exports this host's own credential -- soliciting a pairing
	 * request is useless without the approval this type governs. */
	FZN_RPC_CAP_PEER_MANAGE = 6,
	/*
	 * fuzznet's own capabilities, which a fuzznetd node holds and grants and
	 * fzpd has no type for: member, the one a joined device lives on, share
	 * and retention. Only client/calls.c's node mapping makes them, so a
	 * client can name what a node holds rather than leave it out, which hid
	 * a joined device's member and made it look as if it held nothing
	 * (fuzznet's live_fzp.py found it, 2026-10-23).
	 *
	 * NUMBERED APART from fzpd's 1 to 6 on purpose. FZN_RPC_CAP_TYPE_COUNT and
	 * every fzpd loop over the types never meet them, so an fzpd host never
	 * lists them as INVALID. And fzn_rpc_capability_type_is_known refuses them,
	 * so no fzpd frame can carry one.
	 */
	FZN_RPC_CAP_NODE_MEMBER = 0x41,
	FZN_RPC_CAP_NODE_SHARE = 0x42,
	FZN_RPC_CAP_NODE_RETENTION = 0x43,
} fzn_rpc_capability_type_t;

/* How many types the enum above defines. Sizes every "at most one entry per
 * type" array, and bounds how many grants one join approval can carry.
 *
 * It exists because three separate places had independently hardcoded 4 --
 * the type list fzn_rpc_capability_list walks, fzn_rpc_cap_list_resp_t's entries,
 * and FZN_RPC_JOIN_GRANT_MAX -- and a fifth type would have silently truncated
 * whichever of them was missed rather than failing to build. Keep it in step
 * with the enum; core/test/capability_test.c asserts every type the enum
 * defines is actually reported by cap-show, which is what catches the array
 * in capability.c drifting out of step with this number. */
#define FZN_RPC_CAP_TYPE_COUNT 6

/* The human-facing name of a capability type -- what the CLI accepts on
 * --type and prints in cap-show, and what a GUI should label it. Never NULL:
 * an unrecognized byte reads as "unknown" rather than crashing a display
 * path.
 *
 * Here rather than duplicated per frontend for the same reason
 * fzn_rpc_capability_type_is_known is: two copies drift, and a type added to the
 * enum then shows up under one name in one client and a different one (or
 * none) in another. Distinct from cap_storage_key's "cap_admin" spelling,
 * which is an on-disk key and not for reading. */
const char *fzn_rpc_capability_type_name(uint8_t v);
#endif /* FZN_RPC_CAPABILITY_H */
