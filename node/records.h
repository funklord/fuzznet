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
 *     list record [HOST] [under PREFIX] [FROM]
 *                                   ok FROM SHOWN MORE, then each record held
 *                                   as HOST,KEY,AT,VALUE -- one host's, or
 *                                   every host's; HOST `self` for this one;
 *                                   only keys opening with PREFIX, where
 *                                   one is named (sec 861)
 *     get record KEY [HOST]         ok HOST,KEY,AT,VALUE: the newest record
 *                                   of KEY held, of any host or of HOST's
 *                                   (sec 816); `absent` when none is
 *
 * LISTS, sec 854: a list is the records under `list/NAME/`, one key a
 * member, written by any host of the estate and carried as every record
 * is. A member is IN while the newest record of its key -- of every host's,
 * ties by the greater host -- is set, and OUT once that one is a clear
 * (`state/setting.h`'s `set` 0). So a list resolves as a setting does,
 * newest first, the same on every node holding the same records, and
 * keeps the history of its changes as records do. NAME and MEMBER are a
 * key's words without `/`, together at most a key long.
 *
 *     add listed NAME MEMBER [VALUE]   MEMBER in, with VALUE (%XX undone)
 *     remove listed NAME MEMBER        MEMBER out
 *     get listed NAME MEMBER           ok in [VALUE], ok out, or ok absent
 *     list listed NAME [FROM]          ok FROM SHOWN MORE, then MEMBER,VALUE
 *                                      for each member in, by member
 *
 * A LIST IS NEVER TRIMMED AWAY: the record deciding each member is kept
 * whatever the rules say, and only those it supersedes are weighed.
 */

#ifndef FZN_NODE_RECORDS_H
#define FZN_NODE_RECORDS_H

#include <stddef.h>
#include <stdint.h>

#include "buckets.h"
#include "apply.h"
#include "provision.h"
#include "rate.h"
#include "../local/vocabulary.h"
#include "../chain/authz.h"
#include "../state/setting.h"

struct fzn_setting;
typedef struct fzn_node_records {
	const fzn_buckets_t *b;
	const fzn_sign_ops_t *verify;
	/* WRITING: this node, and its clock, ms. NULL on a node that only
	 * keeps others'. */
	const fzn_node_identity_t *id;
	uint64_t (*now_ms)(void);
	/* TOLD OF EACH RECORD A PEER HANDED ON AND KEPT, sec 895. May be NULL. */
	void (*filed)(void *ctx, const struct fzn_setting *s);
	void *filed_ctx;
	/* THE LISTS RESOLVED, kept between reads. May be NULL, and every list
	 * is read from the records each time. */
	struct fzn_node_records_cache *cache;
	/* HELD TO A WINDOW, sec 1049, where set: `add record` past a key's passes
	 * is held, the newest observation standing for the rest, and written by
	 * `fzn_node_records_due`; `held` told the first time a key is held after
	 * passing freely. NULL for none. The node's own objects are gated where
	 * they are set (sec 1037), not here. */
	fzn_rate_t *rate;
	void (*held)(const uint8_t *key, size_t key_len);
} fzn_node_records_t;

/* A KEY'S WINDOW, the gate's floor, sec 1049. */
#define FZN_NODE_RECORDS_EVERY_MS 1000u

/* THE HELD OBSERVATIONS WHOSE WINDOW HAS PASSED at `now_ms`, written: how many. */
size_t fzn_node_records_due(const fzn_node_records_t *nr, uint64_t now_ms);

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
 * it names one, whose key holds its `text=`, if it has one, and one of
 * whose key's `/` words is a member in its `list=`, if it names one (sec
 * 855; the list read as it resolves now). An AGE
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

/*
 * WHAT EVERY HOST'S TRIM WEIGHS BESIDE ITS RULES, sec 963, the holder's
 * 2026-11-09: an object's values, each host's newest alone. A lamp set
 * every minute otherwise grew a record a minute for good, and none of the
 * older ones changes what the object reads (sec 854's deciding record is
 * kept whatever the rules say). A keep rule reaching them keeps more --
 * `keep records text=list/object-value/ count 100` -- as a keep wins over
 * a prune. Written into `out`, at most `room`; how many.
 */
#define FZN_NODE_RECORDS_DEFAULT_RULE "prune records text=list/object-value/ count 1"
size_t fzn_node_records_defaults(struct fzn_retain_rule *out, size_t room);

/* LISTS, sec 854. */
#define FZN_NODE_LIST_PREFIX "list/"
#define FZN_NODE_LIST_PREFIX_LEN 5u

typedef struct fzn_node_list_member {
	char member[FZN_SETTING_KEY_MAX + 1u]; /* NUL-ended */
	size_t member_len;
	uint8_t host[FZN_PUBKEY_LEN]; /* who wrote the deciding record */
	uint64_t at;                  /* its version, ms */
	int in;                       /* 1 in, 0 out */
	uint8_t value[FZN_SETTING_VALUE_MAX];
	size_t value_len;
} fzn_node_list_member_t;

/* A LIST'S MEMBERS AS RESOLVED, kept between reads: resolving reads and
 * opens every record held, so a named object read by a device's poll cost
 * 25 microseconds for each record the host held (sec 950). A record written
 * or filed through a `fzn_node_records_t` holding this cache is taken into
 * the lists held as resolving would; a trim, or a write that failed, empties
 * it.
 *
 * EVERY WRITER OF THE RECORDS GOES THROUGH THIS MODULE, so that is enough: a
 * store written some other way must not share a cache. */
#define FZN_NODE_RECORDS_CACHED 4u
typedef struct fzn_node_records_cached {
	char name[FZN_SETTING_KEY_MAX];
	size_t name_len;
	fzn_node_list_member_t *rows; /* by member */
	size_t n, cap;
	int held;
} fzn_node_records_cached_t;

/* WHERE `list record`'S LAST PAGE ENDED, sec 952: a page is FROM records
 * along, so each began by reading every one before it, and 8000 records read
 * a page at a time took 50 s. The next page asked for starts here instead,
 * while nothing has been written since. */
typedef struct fzn_node_records_page {
	int held;
	uint64_t written; /* the cache's count when it was kept */
	size_t from;      /* the FROM it answers */
	int one;
	uint8_t host[FZN_PUBKEY_LEN];
	uint8_t prefix[FZN_SETTING_KEY_MAX];
	size_t prefix_len; /* 0: none */
	size_t bucket;     /* among `fzn_buckets_list_all`'s, as listed then */
	uint8_t subject[FZN_PUBKEY_LEN];
	uint32_t month;
	uint64_t item; /* the first not shown, in its bucket */
} fzn_node_records_page_t;

typedef struct fzn_node_records_cache {
	fzn_node_records_cached_t lists[FZN_NODE_RECORDS_CACHED];
	size_t next;      /* the one a list not held takes */
	uint64_t written; /* records written, filed or let go through it */
	fzn_node_records_page_t page;
} fzn_node_records_cache_t;

/* What the cache holds let go. It may be used again after. */
void fzn_node_records_cache_free(fzn_node_records_cache_t *cache);

/* THIS HOST CHANGES A LIST: MEMBER `in` (with `value`) or out, signed now
 * and kept. MALFORMED for a name or member out of shape, or a value given
 * with `in` 0. */
fzn_node_records_err_t fzn_node_records_list_change(const fzn_node_records_t *nr,
                                                    const uint8_t *name, size_t name_len,
                                                    const uint8_t *member, size_t member_len,
                                                    int in, const uint8_t *value,
                                                    size_t value_len);

/* EACH MEMBER OF LIST `name` THAT ANY HOLDS A RECORD OF, resolved, to
 * `each` in order of member -- out ones too, `in` 0. 1, or 0 when the
 * records could not be read (and `each` was not called). `each` must not
 * write records. */
int fzn_node_records_list_each(const fzn_node_records_t *nr, const uint8_t *name,
                               size_t name_len,
                               void (*each)(void *ctx, const fzn_node_list_member_t *m),
                               void *ctx);

/* EVERY RECORD HELD WHOSE KEY OPENS WITH `prefix`, of every host's, to `each`,
 * in no order. 1, or 0 when the records could not be read. */
int fzn_node_records_under(const fzn_node_records_t *nr, const uint8_t *prefix, size_t prefix_len,
                           void (*each)(void *ctx, const struct fzn_setting *s), void *ctx);

/* The verbs above, as a local handler: 0 for a request that is not one. */
size_t fzn_node_records_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                              char *reply, size_t reply_cap);

#endif /* FZN_NODE_RECORDS_H */
