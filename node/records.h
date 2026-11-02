/*
 * A HOST'S RECORDS: what a program observes and keeps through fuzznet --
 * netcfgd's stations seen and leases handed out -- as the records kind of
 * `node/buckets.h`. project.md sec 814, on the holder's of 2026-10-29
 * (sec 752): a records kind in the existing engine and buckets, and
 * "config options are a kind of record".
 *
 * A RECORD IS A SETTING its own host signs about itself
 * (`state/setting.h`): host scope, about its setter, KEY what was observed
 * in the program's own words (`seen/wlan0/aa-bb-cc-dd-ee-ff`), VALUE what
 * it says, VERSION when it was written, ms. So a record and a setting are
 * one object, and what tells them apart is how each kind resolves:
 *   - a SETTING resolves to one value a cell, the setter's rank choosing
 *     between writers (sec 728), and travels in its setter's estate stream;
 *   - a RECORD keeps every one written, none resolved over another, and is
 *     held in buckets, a month at a time, so a host that observes often
 *     does not grow the estate's journal, and retention can let a month go.
 *
 * ITS BUCKET: subject its setter, the observing host; month the UTC month
 * of its version (`fzn_message_epoch_of`, as every kind's). Its id is the
 * hash of its bytes, as every item's.
 *
 * KEPT ONLY AS ITS SETTER SIGNED IT: a record filed here opens as a
 * setting, is host-scoped about its own setter, and its setter and month
 * are the bucket's. Who may hand one on is the reconcile gate's question,
 * not this module's: whoever does hands on the setter's word.
 *
 * THE VERBS, this node's own user only:
 *
 *     add record KEY VALUE          this host observes: VALUE the rest of the
 *                                   line, %XX undone
 *     list record [HOST] [FROM]     ok FROM SHOWN MORE, then each record held
 *                                   as HOST,KEY,AT,VALUE -- one host's, or
 *                                   every host's; HOST `self` for this one
 */

#ifndef FZN_NODE_RECORDS_H
#define FZN_NODE_RECORDS_H

#include <stddef.h>
#include <stdint.h>

#include "buckets.h"
#include "apply.h"
#include "provision.h"
#include "../local/vocabulary.h"
#include "../chain/authz.h"

typedef struct fzn_node_records {
	const fzn_buckets_t *b;
	const fzn_sign_ops_t *verify;
	/* WRITING: this node, and its clock, ms. NULL on a node that only
	 * keeps others'. */
	const fzn_node_identity_t *id;
	uint64_t (*now_ms)(void);
} fzn_node_records_t;

/* A RECORD'S PLACE: its setter, the month of its version, and the setting
 * it opens as, when `item` (`len` bytes) is a record -- a host-scoped
 * setting about its own setter, signed. 0 otherwise. `s` may be NULL. */
struct fzn_setting;
int fzn_node_records_place(const fzn_node_records_t *nr, const uint8_t *item, size_t len,
                           uint8_t subject[FZN_PUBKEY_LEN], uint32_t *month,
                           struct fzn_setting *s);

/* A RECORD A PEER HANDS ON, filed into (subject, month): APPLIED when kept
 * or already held, REFUSED when it is no record or its place is not the
 * bucket it came in, NOT_SAVED when the store would not take it. The
 * reconcile filer's `file` (`node/reconcile.h`). */
fzn_node_apply_outcome_t fzn_node_records_file(const fzn_node_records_t *nr,
                                               const uint8_t subject[FZN_PUBKEY_LEN],
                                               uint32_t month, const uint8_t *item,
                                               size_t len);

typedef enum fzn_node_records_err {
	FZN_NODE_RECORDS_OK = 0,
	FZN_NODE_RECORDS_MALFORMED = -1, /* a key or value out of shape, or no writer */
	FZN_NODE_RECORDS_BACKEND = -2,   /* not signed, or not kept */
	FZN_NODE_RECORDS_GONE = -3       /* its month was let go here */
} fzn_node_records_err_t;

/* THIS HOST OBSERVES: `key` = `value`, signed now and kept. */
fzn_node_records_err_t fzn_node_records_write(const fzn_node_records_t *nr, const uint8_t *key,
                                              size_t key_len, const uint8_t *value,
                                              size_t value_len);

/*
 * TRIMMED BY THE RULES, sec 815: every record held, of every host, weighed
 * by `rules` (`log/retain.h`, already selected for this node) at `now_ms`.
 * A prune or keep rule reaches a record whose setter is its `source=`, if
 * it names one, and whose key holds its `text=`, if it has one. An AGE
 * limit is the record's own age; a COUNT is its place among the records
 * of its key and host, newest first. A record goes when a prune rule
 * reaching it is past its limit, or a policy drops records, and no keep
 * rule reaching it is within its limit -- as a log segment does (sec 566).
 * A record that goes is let go (`fzn_buckets_let_go`): its id stays in its
 * bucket so a peer still holding it is not fetched from again. `*gone`
 * (may be NULL) is how many went. OK, or BACKEND.
 */
struct fzn_retain_rule;
fzn_node_records_err_t fzn_node_records_trim(const fzn_node_records_t *nr,
                                             const struct fzn_retain_rule *rules, size_t n,
                                             uint64_t now_ms, size_t *gone);

/* The verbs above, as a local handler: 0 for a request that is not one. */
size_t fzn_node_records_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                              char *reply, size_t reply_cap);

#endif /* FZN_NODE_RECORDS_H */
