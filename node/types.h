/*
 * EVERY REMOTE REQUEST'S HEAD, in one place, sec 674.
 *
 * A request on the remote hop that is not a verb line opens with a version
 * byte and a type byte. Until now each module chose its own and left a
 * comment pointing at the one before -- "types after notes' 22", "after
 * delivery's 28" -- so no file said which numbers were taken, and an
 * extension (`node/daemon.h`) could not be given a range anybody checked.
 * This is that file. `node/test/types_test.c` includes every owner's
 * header and checks each number below against the owner's constant, that
 * no two version-2 types are one, and that none is an extension's.
 *
 * THE VERSION BYTES. Each is below 0x20, so none is ever the first byte
 * of a verb line (`local/vocabulary.h`), which is how the two share one
 * hop:
 *
 *   1  `spool/message.h`, FZN_MSG_VERSION: a text's or a file's spans
 *   2  the shared space below, by notes sync and its followers
 *   3  `log/cause.h`, FZN_CAUSE_VERSION: an envelope naming a request's
 *      causes, around any other
 *   4  `log/gather.h`, FZN_GATHER_VERSION: a host's log lines
 *   5  `record/exchange.h`, FZN_EXCHANGE_VERSION: the journal
 *   6  `node/reconcile.h`, FZN_RECONCILE_VERSION: reconciliation
 *
 * Each of 1 and 3 to 6 has a type space of its own, its owner's.
 */
#ifndef FZN_NODE_TYPES_H
#define FZN_NODE_TYPES_H

#define FZN_TYPES_VERSION_SPOOL 1u
#define FZN_TYPES_VERSION_SHARED 2u
#define FZN_TYPES_VERSION_CAUSE 3u
#define FZN_TYPES_VERSION_GATHER 4u
#define FZN_TYPES_VERSION_EXCHANGE 5u
#define FZN_TYPES_VERSION_RECONCILE 6u

/* VERSION 2'S TYPES, by owner:
 *
 *    1..10, 15..22  `notes/sync.h`, fzn_notes_sync_type
 *   11, 12          `node/members.h`
 *   13, 14          retired in sec 519, never reused
 *   23..28, 33, 34  `node/messages.h`
 *   29..32, 53..60  `node/contact_devices.h`: 57..60 since sec 1005 (49..52
 *                   from sec 781, which sec 853's CALL and sec 932's SESSION
 *                   took again unseen), a contact's revocations and estate
 *                   records; 53, 54 since sec 782, those records passed
 *                   between members; 55, 56 since sec 783, a key's act log
 *   35, 37..52, 61  fuzznetd's own, here
 *   36              never allocated
 *
 * fuzznetd's own were `#define`s inside `node/daemon.c`; they live here,
 * where the rest can be seen beside them. */
#define FZN_TYPE_RELAY 35u
#define FZN_TYPE_INTRODUCE 37u
#define FZN_TYPE_NOTIFY 38u
#define FZN_TYPE_GROUP_SYNC 39u
#define FZN_TYPE_GROUP_ACTS 40u
#define FZN_TYPE_GROUP_LINES_SYNC 41u
#define FZN_TYPE_GROUP_LINES 42u
#define FZN_TYPE_STREAM_QUERY 43u
#define FZN_TYPE_STREAM_RECORDS 44u
#define FZN_TYPE_FILE_REFS_WANT 45u
#define FZN_TYPE_FILE_REFS 46u
/* A PEER'S CLOCK ASKED, and answered, sec 719 (`node/clocks.h`): the one
 * request a node answers whatever its expiry says, so that two clocks
 * already too far apart for anything else can still be measured. */
#define FZN_TYPE_TIME_ASK 47u
#define FZN_TYPE_TIME 48u
/* A CALL OF A NAMED PROCEDURE, and its answer, sec 853: version 2,
 * the type, the name's length (1 to 32), the name, the arguments; the
 * answer the type, a status (`FZN_CALL_*`) and the procedure's bytes. */
#define FZN_TYPE_CALL 49u
#define FZN_TYPE_CALLED 50u
/* A SESSION ASKED FOR, and granted, sec 932 (`wire/session_frame.h`): version 2,
 * the type, and the body that file gives. An ask is answered whatever its
 * expiry, as a device's first frame goes before it knows the time, and kept out
 * of the replay window, as a replayed one reaches nothing (`node/sessions.h`). */
#define FZN_TYPE_SESSION_ASK 51u
#define FZN_TYPE_SESSION_GRANT 52u
/* A SESSION'S WAYS ASKED OF A RELAY, sec 1045: version 2, the type, the other
 * end's key, the asker's handle and the other end's, 4 bytes each. Answered
 * `ok` or `denied WHY`. */
#define FZN_TYPE_RELAY_SESSION 53u
#define FZN_RELAY_SESSION_LEN (2u + 32u + 4u + 4u)
/* A CALL'S WORD, sec 1019 (`node/live.h`): said in a session, never answered. */
#define FZN_TYPE_LIVE 61u
#define FZN_CALL_OK 0u
#define FZN_CALL_UNKNOWN 1u
#define FZN_CALL_DENIED 2u
#define FZN_CALL_FAILED 3u
#define FZN_CALL_NAME_MAX 32u

/* THE EXTENSIONS' RANGE, sec 674: version 2's types 128 to 191, which
 * fuzznet allocates none of. A daemon's extension answers requests of
 * these types (`node/daemon.h`'s `remote`), and fuzznet hands it nothing
 * else. Each one an extension uses is to be listed here with its owner
 * all the same, so that when it moves into fuzznet it keeps its number
 * and peers on either side of the move still agree (sec 672). 192 to 255
 * are left unallocated for whatever needs a range next.
 *
 * In use, by owner:
 *   128  netcfgd: a request, one line of netcfgd's local vocabulary
 *   129  netcfgd: its answer, `ok TOTAL FROM COUNT DIGEST`, a newline and
 *        COUNT bytes -- DIGEST the FNV-1a 64 of the whole status the
 *        page was cut from, 16 lower-case hex -- or `denied`/`malformed`/
 *        `error` and a sentence
 * (netcfgd's decision 0311 and its 10.689; inbox 2026-11-03 20:00 and
 * 20:23, secs 853, 867.) */
#define FZN_TYPES_EXTENSION_FIRST 128u
#define FZN_TYPES_EXTENSION_LAST 191u
#define FZN_TYPES_NETCFGD_REQUEST 128u
#define FZN_TYPES_NETCFGD_ANSWER 129u

#endif /* FZN_NODE_TYPES_H */
