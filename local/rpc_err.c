#include "rpc_err.h"


const char *fzn_rpc_err_str(int err) {
	switch ((fzn_rpc_err_t)err) {
		case FZN_RPC_OK: return "ok";
		case FZN_RPC_ERR_MALFORMED: return "malformed message";
		case FZN_RPC_ERR_UNSUPPORTED_VERSION: return "unsupported protocol version";
		case FZN_RPC_ERR_UNKNOWN_MSG_TYPE: return "unknown message type";
		case FZN_RPC_ERR_BUFFER_TOO_SMALL: return "buffer too small";
		case FZN_RPC_ERR_IDENTITY_EXISTS: return "identity already exists";
		case FZN_RPC_ERR_NO_IDENTITY: return "no identity";
		case FZN_RPC_ERR_HOST_EXISTS: return "host already exists";
		case FZN_RPC_ERR_NO_HOST: return "no host";
		case FZN_RPC_ERR_STORAGE_IO: return "storage I/O error";
		case FZN_RPC_ERR_ENTROPY: return "entropy source failed";
		case FZN_RPC_ERR_CROSS_SIGN_INVALID: return "host cross-sign verification failed";
		case FZN_RPC_ERR_INVALID_HOST_NAME: return "invalid host name";
		case FZN_RPC_ERR_PREKEY_EXISTS: return "prekey already exists";
		case FZN_RPC_ERR_NO_PREKEY: return "no prekey";
		case FZN_RPC_ERR_PEER_EXISTS: return "peer already exists";
		case FZN_RPC_ERR_NO_PEER: return "no such peer";
		/* The three name refusals say the rule (sec 154): a person told only
		 * "invalid" tries another spelling of the same name. */
		case FZN_RPC_ERR_INVALID_PEER_NAME:
			return "invalid contact name -- use 1 to 32 of A-Z, a-z, 0-9 and _";
		case FZN_RPC_ERR_INVALID_PEER_ADDRESS:
			return "that address cannot be right -- --address here is YOUR OWN address, the one "
			       "the peer should reach you at, not theirs";
		case FZN_RPC_ERR_PREKEY_SIG_INVALID: return "prekey signature verification failed";
		case FZN_RPC_ERR_PEER_FRAME_MALFORMED: return "malformed peer frame";
		case FZN_RPC_ERR_COMMITMENT_MISMATCH: return "key commitment mismatch";
		case FZN_RPC_ERR_SEND_FAILED: return "send failed";
		case FZN_RPC_ERR_NO_PEER_TRANSPORT: return "peer transport not available";
		case FZN_RPC_ERR_JOIN_REQUEST_SIG_INVALID: return "host join request signature verification failed";
		case FZN_RPC_ERR_JOIN_HOST_MISMATCH:
			/* Returned by capability install, host-join install AND pairing
			 * approval, so it must describe the shared condition rather than
			 * whichever caller was written first. It said "host join
			 * approval" for all three, which named an operation the user had
			 * not run -- see project.md sec 14 on diagnostics that name the
			 * wrong cause. */
			return "this blob was issued for a different host key than this host's";
		case FZN_RPC_ERR_NOT_AUTHORIZED: return "not authorized -- no identity or required capability";
		case FZN_RPC_ERR_CAPABILITY_CHAIN_INVALID: return "capability chain verification failed";
		case FZN_RPC_ERR_INVALID_SIBLING_NAME:
			return "invalid host name for a sibling -- use 1 to 32 of A-Z, a-z, 0-9 and _";
		case FZN_RPC_ERR_SIBLING_EXISTS: return "sibling host already registered under that name";
		case FZN_RPC_ERR_SIBLING_IS_SELF: return "that host proof is this host's own, not a sibling's";
		case FZN_RPC_ERR_HOST_PROOF_WRONG_USER:
			return "host proof is valid but rooted at a different user";
		case FZN_RPC_ERR_CONTACT_CARD_INVALID: return "contact card verification failed";
		case FZN_RPC_ERR_CHECKSUM_MISMATCH: return "checksum mismatch -- mistyped or mis-scanned?";
		case FZN_RPC_ERR_PEER_REQUEST_EXISTS: return "a pairing request is already pending for that host";
		case FZN_RPC_ERR_NO_PEER_REQUEST: return "no pending pairing request for that host";
		case FZN_RPC_ERR_MANIFEST_INVALID: return "manifest verification failed";
		case FZN_RPC_ERR_NO_MANIFEST: return "no manifest available";
		case FZN_RPC_ERR_SIBLING_NO_KEY_MATERIAL:
			return "this host has no prekey on file: add it with --prekey-blob (from its prekey-show)";
		case FZN_RPC_ERR_NO_LOG_RELAY_CACHE: return "no cached log for that origin yet";
		case FZN_RPC_ERR_INVALID_GROUP_NAME:
			return "invalid group name -- use 1 to 32 of A-Z, a-z, 0-9 and _";
		case FZN_RPC_ERR_GROUP_EXISTS: return "group already registered under that name";
		case FZN_RPC_ERR_NO_GROUP: return "no such group";
		case FZN_RPC_ERR_GROUP_ROSTER_INVALID: return "group roster verification failed";
		case FZN_RPC_ERR_GROUP_MEMBER_EXISTS: return "already a member of that group";
		case FZN_RPC_ERR_NO_GROUP_MEMBER: return "not a member of that group";
		case FZN_RPC_ERR_NO_GROUP_HISTORY_CACHE: return "no cached history for that sender yet";
		case FZN_RPC_ERR_GROUP_NO_CHAIN_KEY: return "no chain key received from that sender yet";
		case FZN_RPC_ERR_STREAM_TYPE: return "stream type unsupported or mismatched";
		case FZN_RPC_ERR_CONFLICT: return "value changed since it was read";
		case FZN_RPC_ERR_MANIFEST_DERIVATION_UNSUPPORTED:
			return "manifest derivation version not implemented by this build";
		case FZN_RPC_ERR_NO_REVOCATION: return "no such revocation held by this host";
		case FZN_RPC_ERR_OUTBOX_FULL:
			return "this host is already holding as many undelivered messages as it will";
		case FZN_RPC_ERR_NO_SUCH_MESSAGE: return "no undelivered message with that identifier";
		case FZN_RPC_ERR_PEER_NOT_OURS:
			return "this contact was added on another of your hosts and has not met this one";
		case FZN_RPC_ERR_DELEGATE_QUEUE_FULL:
			return "this host is already holding as many messages for another of your hosts as it "
			       "will";
		case FZN_RPC_ERR_TIMEOUT: return "the daemon accepted the request and did not answer in time";
		case FZN_RPC_ERR_DEGENERATE_KEY: return "the peer offered a key with no shared secret in it";
		case FZN_RPC_ERR_TOO_MANY_NOTES:
			return "this host is already holding as many notes as it will";
		case FZN_RPC_ERR_NO_SUCH_NOTE: return "no such note";
		case FZN_RPC_ERR_TOO_MANY_PEERS:
			return "this host already has as many contacts as it will hold -- remove one first";
		case FZN_RPC_ERR_TOO_MANY_GROUPS:
			return "this host is already in as many groups as it will hold -- delete one first";
		case FZN_RPC_ERR_GROUP_FULL: return "that group already has as many members as a group may";
		case FZN_RPC_ERR_LIBRARY_FULL:
			return "this host's library already holds as many files as it will";
		case FZN_RPC_ERR_LOCATION_OFF:
			return "location is switched off on this host -- nothing was recorded";
		case FZN_RPC_ERR_NOT_FETCHED:
			return "none of this file is here yet -- fetch it, and it plays as it arrives";
		case FZN_RPC_ERR_KEYS_OWED_FULL:
			return "this host already owes as many file keys to group members who have not "
			       "come online as it will hold -- nothing was pinned";
		case FZN_RPC_ERR_TOO_MANY_STICKERS:
			return "this host already keeps as many sticker collections as it will -- forget one "
			       "first";
		case FZN_RPC_ERR_SEAL_BACKEND:
			return "this host's own encryption backend refused to seal the frame";
		case FZN_RPC_ERR_UNDERRUN:
			return "the fetch has not reached that offset yet";
		case FZN_RPC_ERR_NO_SIBLING: return "no host of yours is registered under that name";
		case FZN_RPC_ERR_NOTE_UNREADABLE:
			return "this host cannot read that note's content (written by a newer "
			       "version?), and editing it here would erase it";
		case FZN_RPC_ERR_PEER_IS_SELF:
			return "that contact has this host's own key -- it was added from this "
			       "host's own prekey, so nothing can be sent to it";
		case FZN_RPC_ERR_PEER_UNVERIFIED:
			return "that contact was added from a prekey and has no verified identity; "
			       "only a contact who came through a peer request can be in a group";
		case FZN_RPC_ERR_BAD_ADDRESS:
			return "not a host:port this host can send to -- the port must be 1 to 65535";
	}
	/* "unknown", as every renderer here says for a code it has none for: the
	 * sweep in wire/test/err_str_test.c reads that word to find the range. */
	return "unknown";
}
