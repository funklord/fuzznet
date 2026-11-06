/*
 * WHAT GOES FIRST WHEN THINGS GET HAIRY, project.md sec 917. The holder,
 * 2026-11-06: fuzznet "must remain functional even in the most extreme cases
 * like disk full and memory reaching full", with "a state diagram or priorities
 * for what can go first", which "will also help network congestion
 * decisionmaking".
 *
 * ONE LADDER FOR EVERYTHING. Every kind of data has a rank (`fzn_rank_t`,
 * `persist/persist.h`), and so does every kind of traffic here, and a host is
 * in one of four states. A state names the lowest rank still served:
 *
 *     CALM ---> TIGHT ---> SCARCE ---> SURVIVAL
 *     all       no         no copies,  control and
 *               traces     no traces   identity only
 *
 *     rank              CALM    TIGHT   SCARCE  SURVIVAL
 *     IDENTITY          yes     yes     yes     yes
 *     CONTROL           yes     yes     yes     yes
 *     USER              yes     yes     yes     no
 *     REFETCH           yes     yes     no      no
 *     TRACE             yes     no      no      no
 *
 * HIGH ON IT, the holder's: "capability/permission/rule/config propagation, also
 * commands, logging, and possibly the future shell subsystem". So CONTROL holds
 * grants, revocations, rules and settings as they travel, `call`, and logs: a
 * host in trouble is the host whose logs are wanted. Within logging only the
 * lowest levels go, debug first. A shell, when there is one, belongs here.
 *
 * LOW ON IT, the holder's again: "file transfers, media and group chats". They
 * rank REFETCH or below, as a group's lines are held by every member and a
 * file's pieces by whoever shared it. Streams are the media here, and TRACE.
 *
 * So in the worst state a host still answers who it is and what time it is,
 * takes a revocation, carries grants, rules and settings, serves `call`, keeps
 * its logs and holds its local socket. Everything else comes back by itself
 * when the pressure passes, or was a copy.
 *
 * THE TOP OF THE LADDER IS NOT AN ORDER, the holder's: "For the subsystems that
 * absolutely have to work, we probably need a round-robin scheme, as they are
 * interdependent and all need to work, to avoid priority inversion". A revocation
 * that waits on a log flood, or a rule that waits on a command, is a host whose
 * highest priority is stuck behind its lowest. So what must work is divided into
 * TURN CLASSES, none above another: propagation (grants, rules, settings as they
 * travel), peers (adding and revoking them, the holder's too), commands and
 * logging. `fzn_pressure_turn` shares FZN_PRESSURE_TURNS_PER_S among them: each
 * class active of late is sure of its equal share, and what one leaves unused
 * another may take, so one alone may have it all. A shell, when there is one,
 * is a class of its own.
 *
 * THE RANKS BELOW CONTROL ARE RULES, the holder's "Maybe these priorities should
 * also live in rules?": group chat is low for a network daemon and most of what
 * a chat program is for. `pressure/rank/NAME` is a setting, NAME one of
 * `fzn_pressure_rule_names`, its value trace, copy or user. What must work
 * is out of their reach: a rule that shed rule propagation could never be undone.
 *
 * WHAT MOVES IT, each resource read alone and the worst one winning:
 *
 *     store     writing            CALM
 *               held in RAM        TIGHT,  SCARCE past half the budget,
 *                                  SURVIVAL past 7/8 of it
 *     memory    over 10% free      CALM
 *               10, 5 and 2%       TIGHT, SCARCE, SURVIVAL
 *     network   the caller's word
 *
 * UP AT ONCE, DOWN ONE STEP AT A TIME, after FZN_PRESSURE_CALM_TICKS of being
 * lower: a host at a threshold must not flap, and each step down restarts
 * work that loads what just eased.
 *
 * Nothing here reads a clock, a file or a socket. A daemon feeds it, and asks.
 */
#ifndef FZN_NODE_PRESSURE_H
#define FZN_NODE_PRESSURE_H

#include <stddef.h>
#include <stdint.h>

#include "meter.h"
#include "../persist/persist.h"

typedef enum fzn_pressure_state {
	FZN_PRESSURE_CALM = 0,
	FZN_PRESSURE_TIGHT = 1,
	FZN_PRESSURE_SCARCE = 2,
	FZN_PRESSURE_SURVIVAL = 3
} fzn_pressure_state_t;

#define FZN_PRESSURE_CALM_TICKS 30u

const char *fzn_pressure_state_str(fzn_pressure_state_t state);

typedef struct fzn_pressure_input {
	/* THE STORE: whether a delta is holding rows, and how full it is. */
	int store_held;
	size_t delta_bytes, delta_budget;
	/* MEMORY, kB; 0 for total when it cannot be read, which says nothing. */
	uint64_t mem_available_kb, mem_total_kb;
	/* THE NETWORK: whatever state its caller has measured. CALM for none. */
	fzn_pressure_state_t network;
} fzn_pressure_input_t;

/* The state `in` calls for, this moment. */
fzn_pressure_state_t fzn_pressure_level(const fzn_pressure_input_t *in);

typedef struct fzn_pressure {
	fzn_pressure_state_t state;
	unsigned calm_ticks;
} fzn_pressure_t;

/* ONE TICK, a second or so: the state now. 1 in `*moved` when it changed. */
fzn_pressure_state_t fzn_pressure_step(fzn_pressure_t *p, fzn_pressure_state_t level, int *moved);

/* WHETHER `state` STILL SERVES what is of `rank`. */
int fzn_pressure_admits(fzn_pressure_state_t state, fzn_rank_t rank);

/* THE RANK OF A REQUEST, by the family `node/meter.h` puts it in. */
fzn_rank_t fzn_pressure_family_rank(fzn_meter_family_t family);

/* The same, for one request: a group's lines are chat and rank with the copies,
 * though its acts, in the same family, are who may do what. */
fzn_rank_t fzn_pressure_request_rank(fzn_meter_family_t family, const uint8_t *payload,
                                     size_t len);

/* ---- what a rule may move -------------------------------------------------- */

typedef enum fzn_pressure_ruled {
	FZN_RULED_STREAMS = 0,
	FZN_RULED_RELAY,
	FZN_RULED_FILES,
	FZN_RULED_GROUP_LINES,
	FZN_RULED_NOTES,
	FZN_RULED_MESSAGES,
	FZN_RULED_RECONCILE,
	FZN_RULED_COUNT
} fzn_pressure_ruled_t;

#define FZN_PRESSURE_RULE_PREFIX "pressure/rank/"

/* WHAT THE RULES SAY: 1 in `set` where one stands. Zeroed is the defaults. */
typedef struct fzn_pressure_rules {
	uint8_t set[FZN_RULED_COUNT];
	fzn_rank_t rank[FZN_RULED_COUNT];
} fzn_pressure_rules_t;

/* The word a rule's key ends in. */
const char *fzn_pressure_rule_name(fzn_pressure_ruled_t ruled);

/* A RULE'S VALUE: trace, copy or user, 1 with `*rank`. 0 for anything else, as
 * nothing a rule says reaches CONTROL. */
int fzn_pressure_rule_value(const uint8_t *value, size_t len, fzn_rank_t *rank);

/* `fzn_pressure_request_rank`, under `rules`, which may be NULL. */
fzn_rank_t fzn_pressure_ruled_rank(const fzn_pressure_rules_t *rules, fzn_meter_family_t family,
                                   const uint8_t *payload, size_t len);

/* ---- turns among what must work ------------------------------------------ */

typedef enum fzn_turn_class {
	FZN_TURN_PROPAGATION = 0,
	FZN_TURN_PEERS,
	FZN_TURN_COMMANDS,
	FZN_TURN_LOGGING,
	FZN_TURN_CLASSES
} fzn_turn_class_t;

/* REQUESTS A SECOND shared out once a host is past TIGHT. Below that nothing is
 * turned away. A request is small, so this is far below what a host can do and
 * far above what a control plane needs. */
#define FZN_PRESSURE_TURNS_PER_S 256u

typedef struct fzn_pressure_turns {
	uint64_t second;
	unsigned served[FZN_TURN_CLASSES];
	/* WHO ASKED IN THE LAST SECOND THAT ASKED: who is owed a share this one. */
	unsigned asked[FZN_TURN_CLASSES], asked_before[FZN_TURN_CLASSES];
} fzn_pressure_turns_t;

/* WHICH CLASS A REQUEST TAKES ITS TURN IN, or FZN_TURN_CLASSES for none: below
 * CONTROL it is the ladder's to shed, and time and hello are never turned away. */
fzn_turn_class_t fzn_pressure_turn_class(fzn_meter_family_t family);

/* A TURN FOR `cls` at `now`, seconds: 1 served, 0 not this second. */
int fzn_pressure_turn(fzn_pressure_turns_t *t, fzn_turn_class_t cls, uint64_t now);

#endif /* FZN_NODE_PRESSURE_H */
