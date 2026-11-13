/*
 * What the clients say about what a node told them: the names of the things
 * they show, and the counts they keep (control.h).
 */
#include "rpc_types.h"

#include <stdio.h> /* snprintf, for fzn_rpc_transport_name */
#include <string.h>

const char *fzn_rpc_transport_name(uint8_t transport, char *out, size_t cap) {
	const char *name = NULL;
	switch (transport) {
		case FZN_RPC_TRANSPORT_UDP: name = "udp"; break;
		case FZN_RPC_TRANSPORT_RADIO: name = "radio"; break;
		case FZN_RPC_TRANSPORT_LOCAL: name = "local"; break;
		case FZN_RPC_TRANSPORT_BROADCAST: name = "broadcast"; break;
		case FZN_RPC_TRANSPORT_MULTICAST: name = "multicast"; break;
		/*
		 * 0x02 is named rather than left to the hex fallback, because a
		 * reader meeting it needs to know it is a WITHDRAWN tag and not an
		 * unallocated one -- a manifest written while SCTP existed may still
		 * carry the bit, and "0x02" alone reads as a host sending nonsense.
		 */
		case 0x02: name = "0x02 (withdrawn)"; break;
		default: break;
	}
	if (name) {
		snprintf(out, cap, "%s", name);
	} else {
		snprintf(out, cap, "0x%02x", transport);
	}
	return out;
}

size_t fzn_rpc_group_unread_since(const fzn_rpc_group_history_entry_t *entries, size_t count,
                              uint64_t read_seq) {
	size_t n = 0;
	for (size_t i = 0; i < count; i++) n += entries[i].seq > read_seq ? 1 : 0;
	return n;
}

const char *fzn_rpc_capability_type_name(uint8_t v) {
	switch ((fzn_rpc_capability_type_t)v) {
		case FZN_RPC_CAP_ADMIN: return "admin";
		case FZN_RPC_CAP_HOST_MANAGE: return "host-manage";
		case FZN_RPC_CAP_STORE: return "store";
		case FZN_RPC_CAP_RELAY: return "relay";
		case FZN_RPC_CAP_SEND: return "send";
		case FZN_RPC_CAP_PEER_MANAGE: return "peer-manage";
		case FZN_RPC_CAP_NODE_MEMBER: return "member";
		case FZN_RPC_CAP_NODE_SHARE: return "share";
		case FZN_RPC_CAP_NODE_RETENTION: return "retention";
	}
	return "unknown";
}

int fzn_rpc_is_valid_peer_name(const char *name, size_t len) {
	if (len == 0 || len > FZN_RPC_PEER_NAME_MAX) return 0;
	for (size_t i = 0; i < len; i++) {
		char c = name[i];
		int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		         c == '_';
		if (!ok) return 0;
	}
	return 1;
}
