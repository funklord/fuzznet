/*
 * THE CMD, byte 0 of every message one host says to another: a category,
 * project.md sec 1085, the holder's -- "very clear categories of what they
 * do", named CMD_* and SUBCMD_*. Byte 1 is the SUBCMD within it, owned by the
 * module that speaks the category (node/types.h lists them all).
 *
 * In wire/ so any layer names its own category: notes and the log gatherer
 * sit below the node. Every code is one byte, so a category is chosen for
 * clarity alone (sec 1061 measured that a shorter code buys nothing here).
 *
 * 2 was a grab-bag family until sec 1085 split it, and is retired with the
 * last of it (sec 1085 stage 3); 5 was the journal's exchange before sec 1047,
 * retired, never reused.
 */
#ifndef FZN_WIRE_CMD_H
#define FZN_WIRE_CMD_H

#define FZN_CMD_FILES 1u     /* spool's transfers, and file references */
#define FZN_CMD_SHARED 2u    /* the call and STATUS, until sec 1085 stage 3 */
#define FZN_CMD_CAUSE 3u     /* the envelope naming a request's causes */
#define FZN_CMD_GATHER 4u    /* a member gathering a host's log */
#define FZN_CMD_RECONCILE 6u /* the journal reconciled */
#define FZN_CMD_EXCHANGE 7u  /* the journal exchanged */
#define FZN_CMD_NOTES 8u     /* notes sync */
#define FZN_CMD_MEMBERS 9u   /* the estate's members */
#define FZN_CMD_MESSAGES 10u /* lines, their keys, delivery and holdings */
#define FZN_CMD_CONTACTS 11u /* a contact's devices and records */
#define FZN_CMD_REACH 12u    /* relays, introductions, addresses, manifests */
#define FZN_CMD_GROUPS 13u   /* groups and their lines */
#define FZN_CMD_STREAMS 14u  /* a stream's records fetched */
#define FZN_CMD_TIME 15u     /* a peer's clock asked */
#define FZN_CMD_RRPC 16u     /* a registered remote procedure, by name */
#define FZN_CMD_SESSION 17u  /* a session asked for and granted */
#define FZN_CMD_EXTENSION 20u /* the extension's, every SUBCMD its own */

#endif /* FZN_WIRE_CMD_H */
