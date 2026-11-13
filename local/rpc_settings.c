/* The words for a declared setting's properties: settings.h. */
#include "rpc_settings.h"

const char *fzn_rpc_setting_type_name(uint8_t type) {
	switch (type) {
		case FZN_RPC_SETTING_BOOL: return "bool";
		case FZN_RPC_SETTING_INT: return "int";
		case FZN_RPC_SETTING_STRING: return "string";
		default: return "unknown";
	}
}

const char *fzn_rpc_setting_applies_name(uint8_t applies) {
	switch (applies) {
		case FZN_RPC_APPLIES_HOST_SELF: return "host_self";
		case FZN_RPC_APPLIES_HOST_NAMED: return "host_named";
		case FZN_RPC_APPLIES_USER: return "user";
		case FZN_RPC_APPLIES_PEER_NAMED: return "peer_named";
		case FZN_RPC_APPLIES_GROUP_NAMED: return "group_named";
		default: return "unknown";
	}
}

const char *fzn_rpc_setting_distribution_name(uint8_t dist) {
	switch (dist) {
		case FZN_RPC_DIST_LOCAL: return "local";
		case FZN_RPC_DIST_SYNCED: return "synced";
		case FZN_RPC_DIST_ADVERTISED: return "advertised";
		default: return "unknown";
	}
}

const char *fzn_rpc_setting_source_name(uint8_t source) {
	switch (source) {
		case FZN_RPC_SOURCE_DEFAULT: return "default";
		case FZN_RPC_SOURCE_CONFIG_FILE: return "config-file";
		case FZN_RPC_SOURCE_CLI_FLAG: return "cli-flag";
		case FZN_RPC_SOURCE_SYNCED: return "synced";
		case FZN_RPC_SOURCE_DEFAULT_AFTER_INVALID: return "default (file value rejected)";
		default: return "unknown";
	}
}
