#ifndef FZN_RPC_PEER_LIMITS_H
#define FZN_RPC_PEER_LIMITS_H

#include <stddef.h>

/* Bounds on the strings and text a peer relationship carries. */

/* A local label for a peer, chosen by this user and never sent as identity. */
#define FZN_RPC_PEER_NAME_MAX 32

/* How long an address string may be ("host:port", opaque to core -- never
 * parsed here). */
#define FZN_RPC_PEER_ADDRESS_MAX 64

/*
 * Is this address string safe to keep and to print?
 *
 * OPAQUE IS NOT THE SAME AS UNCONSTRAINED, and every wire parser here had
 * taken it as though it were: each checked the LENGTH against the bound above
 * and copied the bytes verbatim. An address arriving from a peer could
 * therefore hold any byte at all, a newline included, and the daemon logs
 * one -- "%s sees this host at %s" in the address-observe path. A peer able
 * to put a newline in an address can write whatever it likes into this host's
 * log, on its own line, and forge a record of something that never happened.
 *
 * Raised as a class by fuzznet 2026-09-08 from their own local socket work,
 * about a verb rather than an address; they said explicitly that they had not
 * read this tree and were not asserting anything about it. The path above is
 * what the look found.
 *
 * The rule is deliberately about the CHARACTERS and not the grammar. Core
 * does not parse addresses and should not start: a resolver is entitled to
 * accept shapes this tree has not thought of, and refusing an address for not
 * matching host:port would be core deciding something it does not own. What
 * it can say without knowing the grammar is that no address contains a
 * control character, which is the property the log needs.
 */
static inline int fzn_rpc_address_printable(const char *address, size_t len) {
	if (len == 0 || len > FZN_RPC_PEER_ADDRESS_MAX) return 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)address[i];
		/* Control characters and DEL. Anything at or above 0x80 is left
		 * alone: an internationalised host name arrives here as UTF-8 and
		 * refusing it would be this function inventing a grammar. */
		if (c < 0x20 || c == 0x7f) return 0;
	}
	return 1;
}

/*
 * A human-facing label -- a peer's proposed display name, or a contact card's
 * display name -- safe to keep and print. Same control-character rule as
 * fzn_rpc_address_printable and for the same reason: an UNAUTHENTICATED pairing
 * request carries this string, and both clients render it verbatim in the
 * pending-request list the operator reads to decide whom to trust, so a
 * newline or ANSI escape here could forge or hide the pubkey line the
 * decision rests on. Unlike an address, a display name is optional, so an
 * empty one is allowed; UTF-8 (>= 0x80) is left alone, as above.
 */
static inline int fzn_rpc_display_name_printable(const char *name, size_t len) {
	if (len > FZN_RPC_PEER_NAME_MAX) return 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)name[i];
		if (c < 0x20 || c == 0x7f) return 0;
	}
	return 1;
}

/*
 * The port a host listens on when nobody says otherwise.
 *
 * WHY IT IS HERE RATHER THAN IN THE DAEMON THAT BINDS IT. It was a #define in
 * daemon/main.c, and everything else that needed the number wrote 48080 as a
 * literal -- five test fixtures do. That is survivable while only the daemon
 * decides it, and it stopped being true on Android: the GUI starts the daemon
 * through a foreground service, so the GUI has to name the port too, and a
 * second literal there would be a second thing to be wrong.
 *
 * It cost a session already, from the other direction. A host-join-request
 * claimed a port the daemon was not listening on, the far side recorded it,
 * and there is no verb that corrects a sibling's address -- so records were
 * pushed to a closed port for the rest of the day. The symptom read as a
 * network fault; what diagnosed it was a byte counter showing traffic out and
 * none back.
 *
 * Always a high, unprivileged port: the daemon normally runs as an ordinary
 * user, and binding does not need root either way. --peer-port overrides it
 * for running several instances on one machine, a UDP port being a
 * machine-wide resource unlike --state-dir and --socket-path.
 */
#define FZN_RPC_DEFAULT_PEER_PORT 48080

/* The longest message body a single peer datagram carries. peer_wire.h reads
 * this when it sizes a frame; that direction is fine, being the header that
 * changes depending on the one that does not. */
#define FZN_RPC_PEER_TEXT_MAX 512

#endif /* FZN_RPC_PEER_LIMITS_H */
