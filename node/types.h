/*
 * EVERY REMOTE REQUEST'S HEAD, in one place, sec 674.
 *
 * A request on the remote hop that is not a verb line opens with a CMD byte
 * and a SUBCMD byte (sec 1085: a version and a type until then; the CMDs are
 * `wire/cmd.h`'s). Until now each module chose its own and left a
 * comment pointing at the one before -- "types after notes' 22", "after
 * delivery's 28" -- so no file said which numbers were taken, and an
 * extension (`node/daemon.h`) could not be given a range anybody checked.
 * This is that file. `node/test/types_test.c` includes every owner's
 * header and checks each number below against the owner's constant, that
 * no two SUBCMDs of one CMD are one, and that none is an extension's.
 *
 * THE CMD BYTES, `wire/cmd.h`. Each is below 0x20, so none is ever the first
 * byte of a verb line (`local/vocabulary.h`), which is how the two share one
 * hop. Each CMD has a SUBCMD space of its own; within a CMD no two are one,
 * and types_test checks it. The SUBCMDs keep the numbers they had as types in
 * family 2, so most owners changed only byte 0 (sec 1085):
 *
 *   1  FILES: `spool/message.h`'s spans 1..4; file references 45, 46
 *   2  retired in sec 1087: a grab-bag until sec 1085 split it
 *   3  CAUSE: `log/cause.h`, an envelope naming a request's causes
 *   4  GATHER: `log/gather.h`, a host's log lines
 *   5  retired: the journal's exchange before sec 1047, its digest 16 bits
 *   6  RECONCILE: `node/reconcile.h`
 *   7  EXCHANGE: `record/exchange.h`, the journal, since sec 1047
 *   8  NOTES: `notes/sync.h`, 1..10, 15..22 (13, 14 retired in sec 519)
 *   9  MEMBERS: `node/members.h`, 11, 12
 *  10  MESSAGES: `node/messages.h`, 23..28, 33, 34 and the holds
 *  11  CONTACTS: `node/contact_devices.h`, 29..32, 53..60, 63, 64
 *  12  REACH: here, 35, 37, 38, 62, 66..69
 *  13  GROUPS: here, 39..42
 *  14  STREAMS: here, 43, 44
 *  15  TIME: here, 47, 48
 *  16  RRPC: here, 49, 50
 *  17  SESSION: here, 51, 52
 *  18  CALL: `node/live.h`, the call's kind 1..10 (`node/call.situ`)
 *  19  STATUS: `wire/status.h`, the code 0..6 (`wire/status.situ`)
 *  20  EXTENSION: every SUBCMD the extension's
 */
#ifndef FZN_NODE_TYPES_H
#define FZN_NODE_TYPES_H

#include "../wire/status.h"


/* fuzznetd's own SUBCMDs, which were `#define`s inside `node/daemon.c`, live
 * here where the rest can be seen beside them; their CMDs are above. */
#define FZN_SUBCMD_REACH_RELAY 35u
#define FZN_SUBCMD_REACH_INTRODUCE 37u
#define FZN_SUBCMD_REACH_NOTIFY 38u
#define FZN_SUBCMD_GROUPS_SYNC 39u
#define FZN_SUBCMD_GROUPS_ACTS 40u
#define FZN_SUBCMD_GROUPS_LINES_SYNC 41u
#define FZN_SUBCMD_GROUPS_LINES 42u
#define FZN_SUBCMD_STREAMS_QUERY 43u
#define FZN_SUBCMD_STREAMS_RECORDS 44u
#define FZN_SUBCMD_FILES_REFS_WANT 45u
#define FZN_SUBCMD_FILES_REFS 46u
/* A PEER'S CLOCK ASKED, and answered, sec 719 (`node/clocks.h`): the one
 * request a node answers whatever its expiry says, so that two clocks
 * already too far apart for anything else can still be measured. */
#define FZN_SUBCMD_TIME_ASK 47u
#define FZN_SUBCMD_TIME_REPLY 48u
/* A CALL OF A NAMED PROCEDURE, and its answer, sec 853: version 2,
 * the type, the name's length (1 to 32), the name, the arguments; the
 * answer the type, a status (`FZN_CALL_*`) and the procedure's bytes. */
#define FZN_SUBCMD_RRPC_ASK 49u
#define FZN_SUBCMD_RRPC_RESULT 50u
/* A SESSION ASKED FOR, and granted, sec 932 (`wire/session_frame.h`): version 2,
 * the type, and the body that file gives. An ask is answered whatever its
 * expiry, as a device's first frame goes before it knows the time, and kept out
 * of the replay window, as a replayed one reaches nothing (`node/sessions.h`). */
#define FZN_SUBCMD_SESSION_ASK 51u
#define FZN_SUBCMD_SESSION_GRANT 52u
/* A SESSION'S WAYS ASKED OF A RELAY, sec 1045 -- 62 since sec 1064; it took 53,
 * contact devices' KEPT_ESTATE, unseen: version 2, the type, the other
 * end's key, the asker's handle and the other end's, 4 bytes each. Answered
 * `ok` or `denied WHY`. */
#define FZN_SUBCMD_REACH_RELAY_SESSION 62u
/* AN ADDRESS AND A PORT, sec 1077 and 1081: where an introduced host said hello
 * from, INTRODUCE's answer, and where an asker was seen from, ADDRESS_ASK's. */
#define FZN_SUBCMD_REACH_ADDRESS 66u
/* WHERE THIS ASKER WAS SEEN FROM, sec 621 and 1081: two bytes, answered ADDRESS. */
#define FZN_SUBCMD_REACH_ADDRESS_ASK 67u
/* THE ROUTING MANIFEST ASKED, sec 611 and 1081: two bytes, answered ROUTING or a
 * STATUS denied where a contact asks and the user does not advertise. */
#define FZN_SUBCMD_REACH_ROUTING_ASK 68u
/* THE MANIFEST: its two head bytes, then fzn_routing_encode's bytes. */
#define FZN_SUBCMD_REACH_ROUTING 69u
#define FZN_RELAY_SESSION_LEN (2u + 32u + 4u + 4u)
#define FZN_RRPC_OK 0u
#define FZN_RRPC_UNKNOWN 1u
#define FZN_RRPC_DENIED 2u
#define FZN_RRPC_FAILED 3u
#define FZN_RRPC_NAME_MAX 32u

/* THE EXTENSION'S SUBCMDS, sec 674 and 1085: under FZN_CMD_EXTENSION every one
 * is the extension's, and fuzznet hands it nothing else (`node/daemon.h`'s
 * `remote`). Each one an extension uses is listed here with its owner all the
 * same, so that when it moves into fuzznet it keeps its number and peers on
 * either side of the move still agree (sec 672). Until sec 1085 the range was
 * family 2's types 128 to 191, and those in use kept their numbers.
 *
 * In use, by owner:
 *   128  netcfgd: a request, one line of netcfgd's local vocabulary
 *   129  netcfgd: its answer, `ok TOTAL FROM COUNT DIGEST`, a newline and
 *        COUNT bytes -- DIGEST the FNV-1a 64 of the whole status the
 *        page was cut from, 16 lower-case hex -- or `denied`/`malformed`/
 *        `error` and a sentence
 * (netcfgd's decision 0311 and its 10.689; inbox 2026-11-03 20:00 and
 * 20:23, secs 853, 867.) */
#define FZN_TYPES_NETCFGD_REQUEST 128u
#define FZN_TYPES_NETCFGD_ANSWER 129u

#endif /* FZN_NODE_TYPES_H */
