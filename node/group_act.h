/*
 * A GROUP ACT, project.md sec 626: one entry of a group's log, step 5a of
 * sec 608 on the holder's decisions of sec 625, laid out as
 * `node/group_act.situ`.
 *
 * A GROUP IS ITS LOG. Every change to it is an act: made, a member added or
 * removed, a member leaving, an admin proposed or removed, a proposal
 * approved, a setting set. Each act names its group, its place in the log
 * and the hash of the act before it, so the log is a chain and a host
 * holding the newest act holds a commitment to every act before it.
 *
 * SIGNED BY A HOST OF A USER, carrying that host's proof -- a
 * `node/contact_devices.h` entry, the user's root and its chain to the host
 * for the member capability. So any of a user's hosts acts for the user,
 * and no group key exists to be lost with a device: what an act is, is the
 * user's (the signer's `owner`), proved by the host that signed it.
 *
 * THE GROUP'S ID is the hash of its create act, whose subject is a random
 * nonce (sec 516): no name, and no two groups alike.
 *
 * What an act MEANS -- whether its signer may make it, whether it follows
 * the log -- is `node/group_log.h`'s. This is the object and its signature.
 */
#ifndef FZN_NODE_GROUP_ACT_H
#define FZN_NODE_GROUP_ACT_H

#include <stddef.h>
#include <stdint.h>

#include "contact_devices.h"
#include "../session/commitment.h" /* fzn_hash_ops_t */

#define FZN_GROUP_ACT_VERSION 1u
#define FZN_GROUP_ID_LEN 32u
#define FZN_GROUP_ACT_HEAD_LEN                                                               \
	(1u + 1u + 1u + 4u + FZN_GROUP_ID_LEN + 32u + FZN_PUBKEY_LEN + 1u + 8u + 8u + 2u)
#define FZN_GROUP_ACT_MAX (FZN_GROUP_ACT_HEAD_LEN + FZN_CONTACT_DEVICE_MAX + FZN_SIG_LEN)

typedef enum fzn_group_act_kind {
	/* The group made; its maker its first member and admin. Subject: a
	 * random nonce. Place 0, and no group or previous act. */
	FZN_GROUP_ACT_CREATE = 1u,
	/* A user added as a member, by an admin. Subject: their root. */
	FZN_GROUP_ACT_ADD = 2u,
	/* A member removed, by an admin. Subject: their root. */
	FZN_GROUP_ACT_REMOVE = 3u,
	/* A member leaving, by themselves. Subject: their own root. */
	FZN_GROUP_ACT_LEAVE = 4u,
	/* A member proposed as an admin, by an admin. Subject: their root. */
	FZN_GROUP_ACT_ADMIN_ADD = 5u,
	/* An admin proposed removed, by an admin. Subject: their root. */
	FZN_GROUP_ACT_ADMIN_REMOVE = 6u,
	/* A proposal approved, by an admin. Subject: the proposal's hash. */
	FZN_GROUP_ACT_APPROVE = 7u,
	/* A setting set, by an admin: `setting` names it, `value` is it. */
	FZN_GROUP_ACT_SET = 8u
} fzn_group_act_kind_t;

/* SETTINGS, by number: a group's settings are few and the library's, so a
 * byte names one. */
typedef enum fzn_group_setting {
	/* A member added later is given the history retention still holds:
	 * 1, the default, or 0, not. sec 625. */
	FZN_GROUP_SETTING_BACKFILL = 1u
} fzn_group_setting_t;

typedef enum fzn_group_act_err {
	FZN_GROUP_ACT_OK = 0,
	FZN_GROUP_ACT_ERR_MALFORMED = -1, /* a null, or a field out of range */
	FZN_GROUP_ACT_ERR_SHAPE = -2,     /* bytes that are not an act */
	FZN_GROUP_ACT_ERR_REFUSED = -3    /* its signature or its signer's proof does not hold */
} fzn_group_act_err_t;

const char *fzn_group_act_err_str(fzn_group_act_err_t err);

typedef struct fzn_group_act {
	uint8_t kind;
	uint32_t seq;                  /* its place in the log; 0 for CREATE */
	uint8_t group[FZN_GROUP_ID_LEN]; /* zero for CREATE */
	uint8_t prev[32];              /* the act before's hash; zero for CREATE */
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t setting;
	uint64_t value;
	uint64_t at; /* seconds, when its signer made it */
	fzn_contact_device_t signer;
	uint8_t sig[FZN_SIG_LEN];
} fzn_group_act_t;

/* SIGN `a` as its signer's host, whose secret is behind `sign`. */
fzn_group_act_err_t fzn_group_act_sign(fzn_group_act_t *a, const fzn_sign_ops_t *sign);

fzn_group_act_err_t fzn_group_act_encode(const fzn_group_act_t *a, uint8_t *out, size_t cap,
                                         size_t *len);
fzn_group_act_err_t fzn_group_act_decode(const uint8_t *bytes, size_t len, fzn_group_act_t *out);

/* WHETHER `a` HOLDS AS ITS SIGNER'S: the signer's proof holds for `member`
 * at the act's own time -- an act is judged as of when it was made, so a
 * log replayed a year on still reads -- and the signer's host signed it. */
fzn_group_act_err_t fzn_group_act_verify(const fzn_group_act_t *a, const fzn_sign_ops_t *sign,
                                         const fzn_cap_id_t *member);

/* THE ACT'S HASH, over its whole encoding, signature included: what the
 * next act names, what an approval names, and for CREATE the group's id. */
fzn_group_act_err_t fzn_group_act_hash(const fzn_group_act_t *a, const fzn_hash_ops_t *hash,
                                       uint8_t out[32]);

#endif /* FZN_NODE_GROUP_ACT_H */
