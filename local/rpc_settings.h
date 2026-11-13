#ifndef FZN_RPC_SETTINGS_H
#define FZN_RPC_SETTINGS_H

#include <stddef.h>
#include <stdint.h>

/*
 * The words the clients use for a setting the node declares (fuzznet sec
 * 686's schema, read by client/calls.c): its type, what it is about, how far
 * it travels, its flags and where its value came from -- what the window's
 * Settings page and `fzp config-show` print.
 *
 * Until 2026-11-10 this was also the clients' own setting registry, judged
 * against an INI file through iniparser: one row a setting, with ranges,
 * defaults, a safe direction and the INI mapping, from fzpd's own config.
 * The node declares, judges and settles its settings now, the safe
 * direction included (fuzznet secs 686, 981, 984), and the registry was
 * kept only to judge five location values the node now judges itself; it
 * went, with config.c and the iniparser it wrapped.
 */

typedef enum fzn_rpc_setting_type {
	FZN_RPC_SETTING_BOOL = 1,
	FZN_RPC_SETTING_INT = 2,
	FZN_RPC_SETTING_STRING = 3,
} fzn_rpc_setting_type_t;

/* What the setting is ABOUT (configuration.md sec 3). Independent of how
 * far it travels -- collapsing the two loses the distinction that makes
 * "configure one host from another" expressible at all. */
typedef enum fzn_rpc_setting_applies {
	FZN_RPC_APPLIES_HOST_SELF = 1,  /* this host only */
	FZN_RPC_APPLIES_HOST_NAMED = 2, /* a specific host, possibly not this one */
	FZN_RPC_APPLIES_USER = 3,       /* the whole identity */
	FZN_RPC_APPLIES_PEER_NAMED = 4, /* one relationship */
	FZN_RPC_APPLIES_GROUP_NAMED = 5,
} fzn_rpc_setting_applies_t;

/* How far it TRAVELS (configuration.md sec 4). */
typedef enum fzn_rpc_setting_distribution {
	FZN_RPC_DIST_LOCAL = 1,      /* never leaves this host */
	FZN_RPC_DIST_SYNCED = 2,     /* replicated across the user's own hosts */
	FZN_RPC_DIST_ADVERTISED = 3, /* observable by peers -- a disclosure, not a preference */
} fzn_rpc_setting_distribution_t;

/* What authority is needed to change it (configuration.md sec 5, project.md
 * sec 3's capability model). A client greys out what the user cannot change;
 * the daemon enforces the same declaration it published. */
typedef enum fzn_rpc_setting_capability {
	FZN_RPC_SETTING_CAP_NONE = 0,
	FZN_RPC_SETTING_CAP_HOST_MANAGE = 1,
	FZN_RPC_SETTING_CAP_ADMIN = 2,
} fzn_rpc_setting_capability_t;

/*
 * Which way a SYNCED conflict resolves when the setting has a safer
 * direction (configuration.md sec 8.1). A conflict is evidence of a fault,
 * not a choice to put to the user -- where one value is safer, taking it
 * beats both "last write wins" and prompting, because it is correct
 * regardless of WHY the hosts disagreed.
 */
#define FZN_RPC_SETTING_FLAG_RESTART_REQUIRED 0x01
#define FZN_RPC_SETTING_FLAG_SENSITIVE 0x02
#define FZN_RPC_SETTING_FLAG_ADVANCED 0x04

/* Where an effective value actually came from (configuration.md sec 6).
 * Reported alongside every read, because the daemon's precedence is
 * otherwise invisible and a user whose config file is overridden has no way
 * to find out why nothing changed. */
typedef enum fzn_rpc_setting_source {
	FZN_RPC_SOURCE_DEFAULT = 1,
	FZN_RPC_SOURCE_CONFIG_FILE = 2,
	FZN_RPC_SOURCE_CLI_FLAG = 3,
	FZN_RPC_SOURCE_SYNCED = 4,
	/* The file DID set this, and the value was rejected as out of range or
	 * unparseable, so the default is in force. Distinct from plain DEFAULT
	 * on purpose: "you wrote something and it was ignored" is exactly what a
	 * user needs told, and silently reporting DEFAULT would hide it. */
	FZN_RPC_SOURCE_DEFAULT_AFTER_INVALID = 5,
} fzn_rpc_setting_source_t;

const char *fzn_rpc_setting_type_name(uint8_t type);
const char *fzn_rpc_setting_applies_name(uint8_t applies);
const char *fzn_rpc_setting_distribution_name(uint8_t dist);
const char *fzn_rpc_setting_source_name(uint8_t source);

#endif /* FZN_RPC_SETTINGS_H */
