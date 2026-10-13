/*
 * A GROUP'S LOG, and the group it says, project.md sec 626: step 5a of sec
 * 608 on the holder's decisions of sec 625.
 *
 * WHAT A GROUP IS: its members (users, by root), its admins (members who
 * may change it), its settings, and the epoch -- a count every change of
 * membership moves, which step 5b turns into the key a line is sealed
 * under. All of it is derived, by `fzn_group_apply`, from the acts of
 * `node/group_act.h` in log order.
 *
 * WHO MAY DO WHAT, and why:
 *
 *   - ANY ADMIN adds or removes a member, and sets a setting. An admin is
 *     not removed as a member until removed as an admin, so a member
 *     removal cannot take the admin set by the side door.
 *   - A MEMBER LEAVES by an act of their own. The last admin may not:
 *     a group nobody may change is a group nobody can repair.
 *   - THE ADMIN SET CHANGES ONLY BY A MAJORITY of its admins (sec 625): an
 *     admin proposes adding or removing one, and other admins approve,
 *     until more than half have. One admin's stolen key can then disrupt
 *     membership, which the others can undo, but cannot take the group.
 *     A change of the admin set ends every open proposal, since the
 *     majority it counted toward is not the majority any more.
 *
 * THE LOG is kept in the store, each act under its group and place
 * (FZN_PERSIST_GROUP_ACT), and the group it derives beside it
 * (FZN_PERSIST_GROUP), so a group is read without a replay. Both core: a
 * log rolled back is a removed member readmitted.
 *
 * TWO ACTS AT ONE PLACE -- two admins acting at once on one head -- fork
 * the log. Every host keeps the one whose hash is lower, which needs no
 * coordination to agree on; the other's later acts go with it, and its
 * signer's host makes it again on the kept head when it learns of the
 * fork (sec 626 says where that stands).
 */
#ifndef FZN_NODE_GROUP_LOG_H
#define FZN_NODE_GROUP_LOG_H

#include <stddef.h>
#include <stdint.h>

#include "group_act.h"
#include "../persist/persist.h"

#define FZN_GROUP_MEMBERS_MAX 256u
#define FZN_GROUP_ADMINS_MAX 16u
#define FZN_GROUP_PROPOSALS_MAX 8u
/* Groups one host holds. */
#define FZN_GROUPS_HELD_MAX 256u

typedef enum fzn_group_log_err {
	FZN_GROUP_LOG_OK = 0,
	FZN_GROUP_LOG_ERR_MALFORMED = -1, /* a null, or a field out of range */
	FZN_GROUP_LOG_ERR_REFUSED = -2,   /* not an act, or its signature does not hold */
	FZN_GROUP_LOG_ERR_NOT_NEXT = -3,  /* it does not follow the log's head */
	FZN_GROUP_LOG_ERR_DENIED = -4,    /* its signer may not make it */
	FZN_GROUP_LOG_ERR_MOOT = -5,      /* it changes nothing: a member added twice */
	FZN_GROUP_LOG_ERR_FULL = -6,      /* past a bound above */
	FZN_GROUP_LOG_ERR_ABSENT = -7,    /* no such group, or no act there */
	FZN_GROUP_LOG_ERR_GAP = -8,       /* acts before it are missing here */
	FZN_GROUP_LOG_ERR_BACKEND = -9    /* the store refused */
} fzn_group_log_err_t;

const char *fzn_group_log_err_str(fzn_group_log_err_t err);

typedef struct fzn_group_proposal {
	uint8_t hash[32]; /* the proposing act's */
	uint8_t kind;     /* ADMIN_ADD or ADMIN_REMOVE */
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t approvals[FZN_GROUP_ADMINS_MAX][FZN_PUBKEY_LEN];
	size_t n_approvals;
} fzn_group_proposal_t;

typedef struct fzn_group {
	uint8_t id[FZN_GROUP_ID_LEN];
	uint32_t seq; /* acts applied: the next act's place */
	uint8_t head[32];
	uint32_t epoch;
	uint8_t backfill;
	uint8_t members[FZN_GROUP_MEMBERS_MAX][FZN_PUBKEY_LEN];
	size_t n_members;
	uint8_t admins[FZN_GROUP_ADMINS_MAX][FZN_PUBKEY_LEN];
	size_t n_admins;
	fzn_group_proposal_t proposals[FZN_GROUP_PROPOSALS_MAX];
	size_t n_proposals;
} fzn_group_t;

/* APPLY `a`, whose hash is `hash`, to `g`: the act already verified. A
 * CREATE starts `g` afresh; any other must follow `g`'s head. `g` is
 * unchanged on any error. Pure: the store is not read. */
fzn_group_log_err_t fzn_group_apply(fzn_group_t *g, const fzn_group_act_t *a,
                                    const uint8_t hash[32]);

int fzn_group_is_member(const fzn_group_t *g, const uint8_t root[FZN_PUBKEY_LEN]);
int fzn_group_is_admin(const fzn_group_t *g, const uint8_t root[FZN_PUBKEY_LEN]);

/* The tools the log needs: to hash and verify an act, and the member
 * capability a signer's proof is for. */
typedef struct fzn_group_log_ops {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
	const fzn_sign_ops_t *sign;
	const fzn_cap_id_t *member;
	/* EACH ACT A FORK DROPS, as its bytes, the one it lost to first: so a
	 * host can make its own again on the kept head (sec 626). NULL when
	 * nobody asks. */
	void (*dropped)(void *ctx, const uint8_t *bytes, size_t len);
	void *dropped_ctx;
} fzn_group_log_ops_t;

/* What an offered act did. */
typedef enum fzn_group_offer {
	FZN_GROUP_OFFER_TAKEN = 1,    /* applied at the head */
	FZN_GROUP_OFFER_HELD = 2,     /* this very act is already in the log */
	FZN_GROUP_OFFER_REPLACED = 3, /* it won a fork: the acts from its place on went */
	FZN_GROUP_OFFER_LOST = 4      /* it lost a fork to the act already there */
} fzn_group_offer_t;

/* OFFER an act's bytes to the log: decoded, verified, and judged as the
 * header says. On REPLACED `*dropped` counts the acts that went. NOT_NEXT,
 * DENIED and MOOT for an act that cannot stand where it says; GAP for one
 * past the head, whose predecessors are to be fetched first. */
fzn_group_log_err_t fzn_group_log_offer(const fzn_group_log_ops_t *ops, const uint8_t *bytes,
                                        size_t len, fzn_group_offer_t *did, size_t *dropped);

fzn_group_log_err_t fzn_group_log_get(const fzn_persist_ops_t *store,
                                      const uint8_t id[FZN_GROUP_ID_LEN], fzn_group_t *out);

/* The act at place `seq` of group `id`, as its bytes. */
fzn_group_log_err_t fzn_group_log_act(const fzn_group_log_ops_t *ops,
                                      const uint8_t id[FZN_GROUP_ID_LEN], uint32_t seq,
                                      uint8_t *out, size_t cap, size_t *len);

/* FILE `g` AS ITS LOG'S DERIVED GROUP, without the acts: what the log does
 * after each act, given to a test or a tool that builds a group by
 * `fzn_group_apply`. A group put this way has no acts to serve, so no other
 * host can learn it from this one. */
fzn_group_log_err_t fzn_group_log_put(const fzn_persist_ops_t *store, const fzn_group_t *g);

/* Every group held, by id, `cap` of them. */
fzn_group_log_err_t fzn_group_log_list(const fzn_persist_ops_t *store,
                                       uint8_t (*ids)[FZN_GROUP_ID_LEN], size_t cap,
                                       size_t *count);

#endif /* FZN_NODE_GROUP_LOG_H */
