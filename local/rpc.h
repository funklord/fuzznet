#ifndef FZN_RPC_CLIENT_CALLS_H
#define FZN_RPC_CLIENT_CALLS_H

#include <stddef.h>
#include <stdint.h>

#include "rpc_types.h"
#include "../messages/attachment.h" /* fuzznet's file reference, a line's attachment */
#include "../sticker/pack.h" /* fuzznet's sticker reference and manifest, which a node's stickers fill */
#include "rpc_sticker_read.h"   /* fzn_rpc_sticker_manifest_release, for fzn_rpc_sticker_manifest */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Typed calls to the node (project.md sec 281), one function per request,
 * for both clients.
 *
 * WHY. Each client hand-encoded its requests -- 247 sites across 85 kinds --
 * and decoded the answers itself, and the two turned a refusal into words
 * differently. The cut-over to fuzznetd (sec 271, fuzznet sec 608 step 7)
 * rewrites what every request is; with the requests behind these functions
 * it rewrites them here, once, and the widgets do not change.
 *
 * WHAT A CALL DOES. Asks the node one verb -- a line to fuzznetd's local
 * socket and a line back -- and reads the answer into `out`. FZN_RPC_OK, or the
 * failure's code with `c->error` saying why in words: the node's own where it
 * gave some, otherwise what went wrong getting an answer at all.
 */
/* Answers a node's request in place of a socket: `reply` takes the reply line
 * and `*reply_len` its length, as fuzznetd would send it. For what must reach
 * no node at all -- the store listing's demo -- and for a test's scripted
 * node; FZN_RPC_OK, or a negative fzn_rpc_err_t if there is no answer. */
typedef int (*fzn_rpc_answer_t)(void *ctx, const char *verb, const char *arg, size_t arg_len,
                                 uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* Room for fuzznetd's longest reply, which calls.c asserts. */
#define FZN_RPC_REPLY_MAX 16384

typedef struct fzn_rpc_call {
	/* The last failure, in words; empty after a success. */
	char error[256];
	/* The last failure's code, 0 after a success. */
	int error_code;
	/* Whether the last call got a well-formed answer back, refusal or not:
	 * "the daemon is there and said no" and "nothing answered" want
	 * different things from a person. */
	int answered;
	/* Whether the daemon ACCEPTED it and only its answer did not parse: the
	 * work was done and the report of it was lost. A caller may want to say
	 * that differently from "no" -- emptying the trash, say, has started
	 * erasing either way. Never set for a refusal or a broken frame. */
	int unreadable;
	/* Whether the last `set` was taken and HELD rather than written: a value
	 * changed faster than the node stores and carries it is answered `ok
	 * held`, and the newest held value is written about a second later, the
	 * ones before it dropped (fuzznet sec 1037). A read straight after still
	 * shows the last written value, so a caller says the chosen value is on
	 * its way rather than reading back and appearing to have lost it. */
	int held;
	/* The reply, here rather than on each caller's stack. */
	uint8_t resp[FZN_RPC_REPLY_MAX];
	/* Where fuzznetd answers (sec 284). A path rather than a descriptor: fuzznet's client
	 * opens one connection per request, and fuzznetd restarts in place on
	 * a join, so a held descriptor would go stale. */
	char node_socket[108];
	/* Set, it answers every request and no socket is opened. */
	fzn_rpc_answer_t answer;
	void *answer_ctx;
} fzn_rpc_t;

void fzn_rpc_init(fzn_rpc_t *c);

int fzn_rpc_status(fzn_rpc_t *c, fzn_rpc_status_resp_t *out);
/* Named objects (fuzznet sec 948). `values` is the allowed words, space
 * separated, empty for any word. `get` leaves *found 0 for an object not there. */
int fzn_rpc_object_add(fzn_rpc_t *c, const char *name, const char *values);
int fzn_rpc_object_set(fzn_rpc_t *c, const char *name, const char *value);
int fzn_rpc_object_get(fzn_rpc_t *c, const char *name, fzn_rpc_object_t *out, int *found);
int fzn_rpc_object_list(fzn_rpc_t *c, fzn_rpc_object_list_resp_t *out);
int fzn_rpc_object_remove(fzn_rpc_t *c, const char *name);

/* What waits to cross and whether the rounds drain it (fuzznet sec 966):
 * `get sync-load`. LOAD is the last round's length as a share of its period,
 * per cent; VERDICT `ok`, `busy` (every round took its whole period) or
 * `growing` (a queue the rounds do not drain), which the holder wants said to
 * the person as a sign to write better rules. Each queue -- files, file-bytes,
 * asks, round-ms today -- its value now, peak and mean over sixteen rounds,
 * and its trend word. More queues are meant to come; past FZN_RPC_SYNC_QUEUES_MAX
 * the rest are not read. */
#define FZN_RPC_SYNC_QUEUES_MAX 16
typedef struct fzn_rpc_sync_queue {
	char name[24];
	uint64_t now, peak, mean;
	char trend[16]; /* `steady`, `growing`, as the node says it */
} fzn_rpc_sync_queue_t;
typedef struct fzn_rpc_sync_load {
	uint64_t load_pct;
	char verdict[16];
	fzn_rpc_sync_queue_t queues[FZN_RPC_SYNC_QUEUES_MAX];
	size_t count;
} fzn_rpc_sync_load_t;
int fzn_rpc_sync_load(fzn_rpc_t *c, fzn_rpc_sync_load_t *out);
/* What to tell a person about a verdict, or NULL when it is `ok`. */
const char *fzn_rpc_sync_load_advice(const fzn_rpc_sync_load_t *v);

/* A list's room, given back; a static one held for the program's life need not. */
void fzn_rpc_peer_list_release(fzn_rpc_peer_list_resp_t *v);
void fzn_rpc_group_list_release(fzn_rpc_group_list_resp_t *v);
void fzn_rpc_group_show_release(fzn_rpc_group_show_resp_t *v);
void fzn_rpc_notes_list_release(fzn_rpc_notes_list_resp_t *v);
void fzn_rpc_library_list_release(fzn_rpc_library_list_all_t *v);
int fzn_rpc_peer_list(fzn_rpc_t *c, fzn_rpc_peer_list_resp_t *out);
/* Whether location is shared with each contact, filled into a list read above:
 * one listing, of who holds the stream. */
void fzn_rpc_peer_shares(fzn_rpc_t *c, fzn_rpc_peer_list_resp_t *out);
int fzn_rpc_group_list(fzn_rpc_t *c, fzn_rpc_group_list_resp_t *out);
/* What to call a group member the roster gives no name, member `i` of `v`:
 * a member is named by this user's contact for it, so a nameless row is this
 * user or somebody who is not a contact. Who this user is was read with the
 * roster: asking the node once per row cost a request for every member of a
 * group of strangers (2026-11-10). Static text. */
const char *fzn_rpc_group_nameless_label(const fzn_rpc_group_show_resp_t *v, size_t i);
int fzn_rpc_group_show(fzn_rpc_t *c, const char *group, size_t group_len,
                        fzn_rpc_group_show_resp_t *out);
/* The same with `chat_id` left unread, for a caller walking a listing that has it:
 * finding it costs a listing, so a walk of every group cost groups squared. */
int fzn_rpc_group_members(fzn_rpc_t *c, const char *group, size_t group_len,
                           fzn_rpc_group_show_resp_t *out);
/* What each member of `out`, read by fzn_rpc_group_show, holds of this host's
 * lines, and how many it has written: asked apart, a roster wanting it and most
 * readers of a group not. */
int fzn_rpc_group_water(fzn_rpc_t *c, const char *group, size_t group_len,
                         fzn_rpc_group_show_resp_t *out);
/* A group's lines, newest first, at most `cap`, in one walk of the group: every
 * sender, a member with no contact here too. `seq` is the line's send time in
 * milliseconds, what a read mark compares. */
typedef struct fzn_rpc_group_line {
	fzn_rpc_inbox_entry_t line;
	uint64_t seq;
} fzn_rpc_group_line_t;
int fzn_rpc_group_lines(fzn_rpc_t *c, const char *group, size_t group_len, fzn_rpc_group_line_t *out,
                         size_t cap, size_t *count);
/* `peer` NULL or empty asks for this host's own stream. */
int fzn_rpc_group_history_show(fzn_rpc_t *c, const char *group, size_t group_len,
                                const char *peer, size_t peer_len,
                                fzn_rpc_group_history_show_resp_t *out);

/* ---- step 2 (sec 281): files, config, siblings, pairing, sending ---- */

/* Delete this device's copy of the file `root` (`remove file ROOT`): its
 * bytes go, and with them what this host said of it in the catalogue (fuzznet
 * sec 1009 -- a holder is a host describing the file), so the library lists
 * it while another device still does. Other devices' copies stay, and it can
 * be fetched again from one. One device at a time, as the holder scoped
 * deletion (project.md sec 181's context). Refused while a transfer of it
 * runs, and when nothing of it is here. */
int fzn_rpc_file_remove(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN]);
/* Who may fetch a stored file from this node (fuzznet sec 493): `to` a
 * contact's name, `@NAME` a group, or NULL for every contact at once (`set
 * file ROOT public|private`); `share` 0 takes it back (`revoke file`). A
 * file shared is fetchable by its reference; who holds the reference is
 * still the sender's to decide. */
int fzn_rpc_file_share(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], const char *to,
                        int share);
/* Whom the file is shared with (`get file ROOT shares`, fuzznet sec 1016):
 * every contact, a contact or a group, each by its key or id and this host's
 * name for it -- empty for one no longer a contact or group. `*out` is
 * grown by the call and kept. A share is taken back by fzn_rpc_file_share
 * with the key as 64 hex, whichever kind it is. */
typedef struct fzn_rpc_file_share {
	uint8_t kind; /* FZN_RPC_FILE_SHARE_EVERYONE, _CONTACT or _GROUP */
	uint8_t key[32];
	char name[FZN_RPC_PEER_NAME_MAX + 1];
} fzn_rpc_file_share_t;
#define FZN_RPC_FILE_SHARE_EVERYONE 0
#define FZN_RPC_FILE_SHARE_CONTACT 1
#define FZN_RPC_FILE_SHARE_GROUP 2
int fzn_rpc_file_shares(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                         fzn_rpc_file_share_t **out, size_t *room, size_t *count);
/* What one contact may fetch from this node (`get file shared CONTACT`,
 * fuzznet sec 1028): every file held that it may -- by name, through a
 * group it is in, or as everyone -- by root. `*roots` grown and kept. */
typedef uint8_t fzn_rpc_root_t[FZN_RPC_BLOB_HASH_LEN];
int fzn_rpc_file_shared_with(fzn_rpc_t *c, const char *contact, fzn_rpc_root_t **roots, size_t *room,
                              size_t *count);
int fzn_rpc_blob_status(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                         fzn_rpc_blob_status_resp_t *out);
int fzn_rpc_blob_fetch(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                        fzn_rpc_blob_fetch_resp_t *out);
/* The same by the file's whole reference, as a message names one: fetched
 * from whoever holds it, by the root, key and size (sec 284). */
/* FROM WHERE A PLAYER IS (fuzznet sec 998): `fetch file REF at OFFSET`
 * sets the file's playhead, so the fetch asks from the leaf holding
 * `offset` and wraps to the rest; asked again while the file arrives it is
 * a seek. The reference is the one this node holds for `root`. */
int fzn_rpc_blob_fetch_at(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], uint64_t offset);
int fzn_rpc_blob_fetch_ref(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                            const uint8_t key[32], uint64_t size, fzn_rpc_blob_fetch_resp_t *out);
/* `key` NULL exports a blob this host can open without being told one. */
int fzn_rpc_blob_export(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], const uint8_t *key,
                         const char *path, size_t path_len, fzn_rpc_blob_export_resp_t *out);
int fzn_rpc_blob_add(fzn_rpc_t *c, const char *path, size_t path_len, uint8_t tier,
                      fzn_rpc_blob_add_resp_t *out);
/* `instance` NULL or empty for a key with no instance. */
int fzn_rpc_config_get(fzn_rpc_t *c, const char *key, size_t key_len, fzn_rpc_config_get_resp_t *out);
int fzn_rpc_sibling_list(fzn_rpc_t *c, fzn_rpc_sibling_list_resp_t *out);
int fzn_rpc_peer_request_list(fzn_rpc_t *c, fzn_rpc_peer_request_list_resp_t *out);
int fzn_rpc_card_show(fzn_rpc_t *c, const char *display_name, size_t display_name_len,
                       fzn_rpc_card_show_resp_t *out);
/* An empty acknowledgement: FZN_RPC_OK means the daemon took it. `via` NULL or
 * empty sends directly. */
int fzn_rpc_message_send(fzn_rpc_t *c, const char *peer, size_t peer_len, const char *text,
                          size_t text_len);
/* An empty acknowledgement, as message_send. */
int fzn_rpc_group_send(fzn_rpc_t *c, const char *group, size_t group_len, const char *text,
                        size_t text_len);

/* ---- step 3 (sec 281): library, transfers, deliveries, config, probes ---- */

/* One slice of a library file from `offset`, at most `want` bytes; a one-byte
 * read is the status probe, since size, playable and complete come back
 * whatever the slice holds. */
int fzn_rpc_library_play(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], uint64_t offset,
                          uint16_t want, fzn_rpc_library_play_resp_t *out);
int fzn_rpc_library_show(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN],
                          fzn_rpc_library_show_resp_t *out);
/*
 * The whole listing, page by page (sec 167), into `out`. Bounded by the most
 * a library holds, in case a daemon keeps saying "more" without moving. On a
 * failure part way, `out` holds the pages that did arrive.
 */
int fzn_rpc_library_list(fzn_rpc_t *c, fzn_rpc_library_list_all_t *out);
/* Rows `from` on, `count` of them, given what the listing left out. */
int fzn_rpc_library_detail(fzn_rpc_t *c, fzn_rpc_library_list_all_t *list, size_t from, size_t count);
/* An empty acknowledgement: FZN_RPC_OK means it is catalogued. */
int fzn_rpc_library_add(fzn_rpc_t *c, const fzn_rpc_library_add_req_t *entry);
int fzn_rpc_transfer_list(fzn_rpc_t *c, fzn_rpc_transfer_list_resp_t *out);
int fzn_rpc_delivery_list(fzn_rpc_t *c, fzn_rpc_delivery_list_resp_t *out);
/* `instance` and `expected` NULL or empty where there is none. On FZN_RPC_OK,
 * *restart_required (NULL ok) says whether the value waits for a restart. */
int fzn_rpc_config_set(fzn_rpc_t *c, const char *key, size_t key_len, const char *value,
                        size_t value_len, const char *expected, size_t expected_len,
                        int *restart_required);
/* `probe` 0 only reports who has already answered; 1 also asks again. */
int fzn_rpc_lan_discover(fzn_rpc_t *c, int probe, fzn_rpc_lan_discover_resp_t *out);
int fzn_rpc_addr_observe(fzn_rpc_t *c, int probe, fzn_rpc_addr_observe_resp_t *out);
int fzn_rpc_relay_status(fzn_rpc_t *c, fzn_rpc_relay_status_resp_t *out);
/* One bounded slice of a scrub from piece `from`; `out` says where to go on. */
int fzn_rpc_blob_scrub(fzn_rpc_t *c, const uint8_t root[FZN_RPC_BLOB_HASH_LEN], uint64_t from,
                        fzn_rpc_blob_scrub_resp_t *out);

/* ---- step 4 (sec 281): notes ---- */

/* `parent` and `from` are 32 bytes each, zero for the root and for this
 * host's own notes. */
int fzn_rpc_notes_list(fzn_rpc_t *c, const uint8_t parent[32], const uint8_t from[32],
                        int from_group, fzn_rpc_notes_list_resp_t *out);
int fzn_rpc_notes_show(fzn_rpc_t *c, const uint8_t id[32], const uint8_t from[32],
                        int from_group, fzn_rpc_notes_show_resp_t *out);
/* Whether the group called `group` has a notebook with anything at its top,
 * asked by name: by chat id each ask reads the group listing, so a walk of
 * every group was groups squared. A group nobody shares in is not held. */
int fzn_rpc_group_notebook_held(fzn_rpc_t *c, const char *group, size_t group_len, int *held);
int fzn_rpc_notes_add(fzn_rpc_t *c, const uint8_t parent[32], const char *title,
                       size_t title_len, const char *text, size_t text_len,
                       uint64_t created_at_ms, int skip_if_exists, uint16_t content_type,
                       fzn_rpc_notes_add_resp_t *out);
/*
 * An export imported whole by a node (fuzznet sec 440's `add import PARENT
 * PATH`): a KNotes `.ics`, a Keep note's `.json` or a Takeout directory of
 * them, read by fuzznetd itself -- the same user, so the path is a file
 * both can open, made absolute here. Into `parent`, zero for the top.
 * The node takes an import a page of notes at a time (fuzznet sec 991), so
 * the host answers between pages; this asks page after page until it says
 * it is done, and the counts are the sum. `refused_titles` holds each refused
 * note as `REASON: TITLE`, one a line -- unparsed, too-long, failed or
 * pending (fuzznet sec 982) -- as far as there is room; the counts are all
 * of them. `pending` counts refused notes that import again once their
 * content is held, `attached` notes imported whose files stayed in the
 * export (sec 985).
 */
typedef struct fzn_rpc_notes_import_resp {
	size_t imported, already, undated, refused, pending, attached;
	char refused_titles[4096];
	size_t refused_titles_len;
} fzn_rpc_notes_import_resp_t;
int fzn_rpc_notes_import(fzn_rpc_t *c, const uint8_t parent[32], const char *path,
                          size_t path_len, fzn_rpc_notes_import_resp_t *out);
/* An empty acknowledgement. `fields` is FZN_RPC_NOTES_EDIT_*; the strings are
 * read only for the fields named. */
/* A FILE IN A FOLDER (fuzznet sec 1000): a note of type ATTACHMENT whose
 * text is the file's reference -- root, key and length -- so a folder of
 * them, shared, is a folder of files a contact browses and fetches. The key
 * travels in the note: sharing such a folder shares a lasting capability to
 * fetch its files. fzn_rpc_notes_attach writes one under `parent` for a file
 * already put (fzn_rpc_blob_add); fzn_rpc_note_ref reads one back, from
 * this user's tree or, `from` not NULL, from the tree a sharer with that key
 * shares -- or, `from_group`, the group with that chat id, whichever of its
 * sharers holds the note -- for fzn_rpc_blob_fetch_ref and
 * fzn_rpc_blob_export. */
int fzn_rpc_notes_attach(fzn_rpc_t *c, const uint8_t parent[32], const uint8_t root[32],
                          const uint8_t key[32], uint64_t length, const char *title,
                          size_t title_len, uint8_t id[32]);
int fzn_rpc_note_ref(fzn_rpc_t *c, const uint8_t id[32], const uint8_t *from, int from_group,
                      uint8_t root[32], uint8_t key[32], uint64_t *length);
/* A note's labels on a node (fuzznet sec 869): NUL between two labels, and
 * its colour, 0xRRGGBBAA with 0 unset. */
int fzn_rpc_note_meta(fzn_rpc_t *c, const uint8_t id[32], char *labels, size_t cap, size_t *len,
                       uint32_t *colour);
int fzn_rpc_note_labels_set(fzn_rpc_t *c, const uint8_t id[32], const char *labels, size_t len);
int fzn_rpc_notes_edit(fzn_rpc_t *c, const uint8_t id[32], uint8_t fields, const char *title,
                        size_t title_len, const char *text, size_t text_len);
int fzn_rpc_notes_share(fzn_rpc_t *c, const uint8_t subtree[32], const char *peer,
                         size_t peer_len, int to_group, int backfill,
                         fzn_rpc_notes_share_resp_t *out);
/* A call of its own because its answer is a different shape: an empty
 * acknowledgement, where a share answers with what it withheld. One
 * function for both decoded an unshare's answer as a share's and failed
 * every unshare the daemon had already done. */
int fzn_rpc_notes_unshare(fzn_rpc_t *c, const uint8_t subtree[32], const char *peer,
                           size_t peer_len, int to_group);
int fzn_rpc_notes_shares(fzn_rpc_t *c, fzn_rpc_notes_shares_resp_t *out);
int fzn_rpc_notes_empty_trash(fzn_rpc_t *c, fzn_rpc_notes_empty_trash_resp_t *out);

/* ---- step 5 (sec 281): groups, pairing, siblings ---- */

int fzn_rpc_group_create(fzn_rpc_t *c, const char *group, size_t group_len,
                          fzn_rpc_group_create_resp_t *out);
/* Empty acknowledgements, these three. */
int fzn_rpc_group_add_member(fzn_rpc_t *c, const char *group, size_t group_len,
                              const char *peer, size_t peer_len);
int fzn_rpc_group_remove_member(fzn_rpc_t *c, const char *group, size_t group_len,
                                 const char *peer, size_t peer_len);
int fzn_rpc_group_delete(fzn_rpc_t *c, const char *group, size_t group_len);
/* Make a member an admin (`make` 1) or no longer one (0): `add|remove admin
 * GROUP CONTACT`, an admin's to ask. A PROPOSAL until a majority of the
 * group's admins asks the same (fuzznet secs 627, 1012): `*needed` is then
 * how many must, `*approvals` how many have, and both 0 when it took. */
int fzn_rpc_group_admin(fzn_rpc_t *c, const char *group, size_t group_len, const char *peer,
                         size_t peer_len, int make, size_t *approvals, size_t *needed);
/* CALLS (fuzznet secs 1017-1028): live audio and video between contacts'
 * hosts, the media opaque to the node -- codec and jitter buffer are the
 * client's. A call is rung (`add call CONTACT[,CONTACT...] KINDS`), answered,
 * declined or hung up (`set call ID ...`) and listed while it lives (`list
 * call`); of several, the caller's host is the hub. An id is 16 hex. */
#define FZN_RPC_ID_HEX 16
#define FZN_RPC_AUDIO 1u
#define FZN_RPC_VIDEO 2u
enum { FZN_RPC_RINGING_IN = 1, FZN_RPC_RINGING_OUT = 2, FZN_RPC_UP = 3 };
typedef struct fzn_rpc_entry {
	char id[FZN_RPC_ID_HEX + 1];
	uint8_t state; /* FZN_RPC_RINGING_IN, _RINGING_OUT or _UP */
	uint8_t kinds; /* FZN_RPC_AUDIO | FZN_RPC_VIDEO */
	/* The other end's user (fuzznet sec 1040): at the callee the caller,
	 * at the caller the first user it rang. has_user 0 where the host
	 * cannot say, or a node from before it said. */
	uint8_t has_user;
	uint8_t user[32];
} fzn_rpc_entry_t;
/* The contact whose user is USER, by name, into NAME; 0 when none is. */
int fzn_rpc_user_name(fzn_rpc_t *c, const uint8_t user[32], char *name, size_t cap);
#define FZN_RPC_CALLS_MAX 64
/* `who`: a contact's name, or several joined by commas. */
int fzn_rpc_ring(fzn_rpc_t *c, const char *who, size_t who_len, uint8_t kinds,
                  char id[FZN_RPC_ID_HEX + 1]);
/* `what`: "answer", "decline" or "hangup". */
int fzn_rpc_respond(fzn_rpc_t *c, const char *id, const char *what);
int fzn_rpc_calls(fzn_rpc_t *c, fzn_rpc_entry_t *out, size_t cap, size_t *count);
/* WHY A CALL ENDED, `get call ID` (fuzznet sec 1082): the node keeps a call
 * it ended for 30 s with its reason, so a client that saw one leave `list
 * call` can say why. REASON receives the node's word -- declined, hung-up,
 * no-answer, busy, gone, unreachable or ended -- or "" while the call is
 * still live. An error, the node's words, when it knows no such call. */
#define FZN_RPC_REASON_MAX 24
int fzn_rpc_ended(fzn_rpc_t *c, const char *id, char *reason, size_t cap);
/* REASON as a person reads it; the word itself for one this client does not
 * know, so a reason fuzznet adds later is still said. */
const char *fzn_rpc_ended_words(const char *reason);
/* A CALL'S MEDIA, opaque to the node (fuzznet sec 1020): a frame on STREAM,
 * numbered SEQ, captured at AT (the sender's own ms), said once and never
 * resent. A request is at most 512 bytes and the media goes as hex, so a
 * frame here is one piece of at most FZN_RPC_FRAME_MAX bytes. `*sent` 0 is
 * the node's `ok lost`: not said, and not to be said again. */
#define FZN_RPC_FRAME_MAX 200
int fzn_rpc_frame_add(fzn_rpc_t *c, const char *id, uint8_t stream, uint32_t seq, uint32_t at,
                       const uint8_t *media, size_t len, int *sent);
/* The frames kept of a call from `from` on (the node keeps its last 64), as
 * many as one reply holds; `*next` is where to ask next. A frame that came
 * in pieces is listed a piece a row, as kept. */
typedef struct fzn_rpc_frame {
	uint8_t stream;
	uint32_t seq, at;
	uint16_t piece, pieces;
	uint16_t sender; /* 0 the caller; a participant its number */
	uint8_t media[512]; /* a reply is 1024 bytes, so a piece in it is less */
	size_t len;
} fzn_rpc_frame_t;
int fzn_rpc_frames(fzn_rpc_t *c, const char *id, uint64_t from, fzn_rpc_frame_t *out,
                    size_t cap, size_t *count, uint64_t *next);
/* A call's quality on `stream` (`get call ID quality`, fuzznet secs 1021,
 * 1026): what the other end reported of this one's frames -- received, lost,
 * jitter in ms, and the AT of the newest it had and how long ago, from which
 * the round trip is now - last_at - held_ms on this sender's own clock --
 * and what this end measured of theirs. A `have_` 0 is not yet known. */
typedef struct fzn_rpc_quality {
	int have_sent, have_received;
	uint64_t sent_received, sent_lost, sent_jitter, last_at, held_ms;
	uint64_t received, lost, jitter;
} fzn_rpc_quality_t;
int fzn_rpc_quality(fzn_rpc_t *c, const char *id, uint8_t stream, fzn_rpc_quality_t *out);
/* Whether a member added later gets what retention still holds of the group,
 * earlier lines and files alike (fuzznet sec 625): an admin's, on by default. */
int fzn_rpc_group_earlier(fzn_rpc_t *c, const char *group, size_t group_len, int on);
int fzn_rpc_group_earlier_get(fzn_rpc_t *c, const char *group, size_t group_len, int *on);
/* This node's retention rules, as fuzznet writes them: `prune|keep PROGRAM|*
 * ... age|size|count N[unit]` (its log/retain.h). What is kept decides what
 * remains for anyone to read later, by age or size or both. The list is the
 * node's answer, one rule a line, in `text`. */
int fzn_rpc_retention_add(fzn_rpc_t *c, const char *rule, size_t rule_len);
int fzn_rpc_retention_remove(fzn_rpc_t *c, const char *rule, size_t rule_len);
int fzn_rpc_retention_list(fzn_rpc_t *c, char *text, size_t cap, size_t *text_len);
/*
 * A fuzznet contact card, `FZC1:` and base32 (fuzznet sec 617), read for
 * what it says rather than added: its shape checked, and the name it offers
 * and where it says its host is written out (`address` as `HOST:PORT`, or
 * the first seed's where the host gives none). Not VERIFIED: that needs the
 * node's member capability, so the node checks the signature when the card
 * is added, and refuses a forged one in its own words. FZN_RPC_OK, or
 * FZN_RPC_ERR_MALFORMED for text that is not such a card.
 */
int fzn_rpc_node_card_read(const char *text, size_t text_len, char *name, size_t name_cap,
                       char *address, size_t address_cap);
int fzn_rpc_peer_request_send(fzn_rpc_t *c, const uint8_t *card_blob, size_t card_blob_len,
                               const char *local_name, size_t local_name_len,
                               const char *proposed_display_name,
                               size_t proposed_display_name_len,
                               fzn_rpc_peer_request_send_resp_t *out);
int fzn_rpc_peer_request_approve(fzn_rpc_t *c, const uint8_t requester_host_pubkey[32],
                                  const char *name, size_t name_len,
                                  fzn_rpc_peer_request_approve_resp_t *out);
/* Empty acknowledgements, these four. */
int fzn_rpc_peer_request_reject(fzn_rpc_t *c, const uint8_t requester_host_pubkey[32]);
/* A contact given another name by its key, which is how two sharing a name
 * come apart: a name two contacts hold is refused where it is used (fuzznet
 * sec 893). The name reaches every device of this user. */
int fzn_rpc_peer_rename(fzn_rpc_t *c, const uint8_t key[32], const char *name, size_t name_len);
int fzn_rpc_peer_remove(fzn_rpc_t *c, const char *name, size_t name_len);
int fzn_rpc_sibling_set_address(fzn_rpc_t *c, const char *name, size_t name_len,
                                 const char *address, size_t address_len);
int fzn_rpc_sibling_remove(fzn_rpc_t *c, const char *name, size_t name_len);

/* ---- step 6 (sec 281): capabilities ---- */

int fzn_rpc_cap_list(fzn_rpc_t *c, fzn_rpc_cap_list_resp_t *out);
int fzn_rpc_cap_granted(fzn_rpc_t *c, fzn_rpc_cap_granted_resp_t *out);
/* `out` carries the chain to hand the grantee. */
int fzn_rpc_cap_grant(fzn_rpc_t *c, fzn_rpc_capability_type_t type,
                       const uint8_t grantee_pubkey[32], uint64_t expires_in_seconds,
                       fzn_rpc_cap_grant_resp_t *out);
/* An empty acknowledgement. */
int fzn_rpc_cap_install(fzn_rpc_t *c, fzn_rpc_capability_type_t type, const uint8_t *chain_blob,
                         size_t chain_blob_len);
/* An empty acknowledgement. */
/* A whole host revoked, on a fuzznetd node: fuzznet's `revoke peer KEY`
 * (its secs 376 and 497). fuzznet has one capability per service rather
 * than the clients' typed set, so a node revokes the host, not one capability of
 * it, and the vote travels by itself -- there is no code to carry. The
 * vote draws a line in the host's log: what it did up to `cut` is kept,
 * or nothing when `keeps_nothing`. `already` when a vote was held, its
 * line left where it was. */
typedef struct fzn_rpc_host_revoke_resp {
	int already;
	int keeps_nothing;
	uint8_t cut[32];
} fzn_rpc_host_revoke_resp_t;
int fzn_rpc_host_revoke(fzn_rpc_t *c, const uint8_t host_pubkey[32], fzn_rpc_host_revoke_resp_t *out);
/* The vote withdrawn, `remove revocation KEY`: the host's grant is
 * honoured again, and one whose pairing was removed is paired again. */
int fzn_rpc_host_unrevoke(fzn_rpc_t *c, const uint8_t host_pubkey[32]);

/* ---- step 7 (sec 281): identity, hosts, prekeys ---- */

/* A device joined by one code read off a host's screen (fuzznet sec 896).
 * `invite` writes this node's code, FZI1: text a QR holds, good for ten
 * minutes. `join` hands one to this node and waits about ten seconds for it to
 * serve under the host's identity, a client's thread being held meanwhile:
 * *joined 1 then, and 0 while the node is still asking, which it goes on doing
 * for five minutes. */
int fzn_rpc_device_invite(fzn_rpc_t *c, char *code, size_t cap);
/* Whether this host's user is asked before a device joins by a code, the host
 * setting invite/confirm (fuzznet sec 896): off lets in whoever holds the code.
 * With it on a device waits, named by the event `invite`: `waiting` lists them,
 * and `answer` lets one in or turns it away. */
int fzn_rpc_device_confirm_get(fzn_rpc_t *c, int *on);
int fzn_rpc_device_confirm_set(fzn_rpc_t *c, int on);
int fzn_rpc_device_waiting(fzn_rpc_t *c, uint8_t (*keys)[32], size_t cap, size_t *count);
int fzn_rpc_device_answer(fzn_rpc_t *c, const uint8_t key[32], int let_in);
int fzn_rpc_device_join(fzn_rpc_t *c, const char *code, size_t code_len, int *joined);

/* What was decided apart (fuzznet sec 895): each side of a subject whose hosts
 * disagree, one row a side, a subject's rows together. What stands is the
 * setting's; a fork only says. `settle` makes the change again, which is what
 * closes one: a contact's name by that contact, anything else by its setting. */
#define FZN_RPC_FORK_SUBJECT_MAX 64
#define FZN_RPC_FORK_VALUE_MAX 256
typedef struct fzn_rpc_fork_side {
	char subject[FZN_RPC_FORK_SUBJECT_MAX + 1];
	char value[FZN_RPC_FORK_VALUE_MAX + 1];
	uint8_t host[32];
	uint64_t at;
} fzn_rpc_fork_side_t;
int fzn_rpc_fork_list(fzn_rpc_t *c, fzn_rpc_fork_side_t *sides, size_t cap, size_t *count);
int fzn_rpc_fork_settle(fzn_rpc_t *c, const char *subject, const char *value);
/* What a person is shown for a subject: a contact's name as "the name of X",
 * a contact being known here by key and the subject holding half of one. */
void fzn_rpc_fork_subject_label(fzn_rpc_t *c, const char *subject, char *out, size_t cap);

int fzn_rpc_identity_generate(fzn_rpc_t *c, fzn_rpc_identity_generate_resp_t *out);
int fzn_rpc_identity_reset(fzn_rpc_t *c, const uint8_t user_pubkey[32],
                        fzn_rpc_identity_reset_resp_t *out);
int fzn_rpc_identity_backup(fzn_rpc_t *c, const char *dir, size_t dir_len,
                         fzn_rpc_identity_backup_resp_t *out);
int fzn_rpc_host_create(fzn_rpc_t *c, const char *host_name, size_t host_name_len,
                     fzn_rpc_host_create_resp_t *out);
int fzn_rpc_host_join_request(fzn_rpc_t *c, const char *host_name, size_t host_name_len,
                           const char *address, size_t address_len,
                           fzn_rpc_host_join_request_resp_t *out);
int fzn_rpc_host_join_approve(fzn_rpc_t *c, const uint8_t *request_blob, size_t request_blob_len,
                           const char *own_address, size_t own_address_len,
                           fzn_rpc_host_join_approve_resp_t *out);
int fzn_rpc_host_join_install(fzn_rpc_t *c, const uint8_t *approval_blob, size_t approval_blob_len,
                           fzn_rpc_host_join_install_resp_t *out);
int fzn_rpc_prekey_show(fzn_rpc_t *c, fzn_rpc_prekey_show_resp_t *out);

/* ---- step 8 (sec 281): the rest ---- */

int fzn_rpc_log_show(fzn_rpc_t *c, fzn_rpc_log_show_resp_t *out);
int fzn_rpc_link_list(fzn_rpc_t *c, fzn_rpc_link_list_resp_t *out);
int fzn_rpc_location_status(fzn_rpc_t *c, fzn_rpc_location_status_resp_t *out);
/* Every contact whose position this host holds, with the newest fix, from one
 * walk of the listing, sorted by name. Asked a contact at a time, each ask
 * walked the whole listing, stopping at 64 pages -- so a page of many sharers
 * cost sharers times the listing, and a sharer past those pages showed no
 * position at all (2026-11-10). `*out` is grown by the call and kept for the
 * next. */
typedef struct fzn_rpc_location_latest {
	char name[FZN_RPC_PEER_NAME_MAX + 1];
	fzn_rpc_location_show_entry_t fix;
} fzn_rpc_location_latest_t;
int fzn_rpc_location_latest(fzn_rpc_t *c, fzn_rpc_location_latest_t **out, size_t *room,
                             size_t *count);
/* The fix of `name` in what fzn_rpc_location_latest read, or NULL. */
const fzn_rpc_location_show_entry_t *fzn_rpc_location_latest_find(const fzn_rpc_location_latest_t *v,
                                                          size_t count, const char *name);
int fzn_rpc_location_show(fzn_rpc_t *c, const char *origin, size_t origin_len,
                           fzn_rpc_location_show_resp_t *out);
int fzn_rpc_location_fetch(fzn_rpc_t *c, const char *target, size_t target_len);
/*
 * Hands this host a fix it measured itself -- the platform's location
 * service, or a pin dropped by hand. *recorded says whether it was kept (0:
 * less accurate than the host accepts). FZN_RPC_ERR_LOCATION_OFF while location
 * is switched off. On a fuzznetd node it is `add location`, which keeps
 * what it is given, so *recorded is 1 there.
 */
struct fzn_location_fix; /* location/location.h's fix */
int fzn_rpc_location_record(fzn_rpc_t *c, const struct fzn_location_fix *fix, int *recorded);
int fzn_rpc_config_schema(fzn_rpc_t *c, const char *prefix, size_t prefix_len,
                           fzn_rpc_config_schema_resp_t *out);
int fzn_rpc_config_status(fzn_rpc_t *c, const char *key, size_t key_len, const char *instance,
                           size_t instance_len, fzn_rpc_config_status_resp_t *out);
/*
 * Peers whose clocks disagree with this node's by more than a request lives
 * (fuzznet sec 717's `list clock`), for a notice a person will see where a
 * log line would go unread. One row a peer:
 * - `ahead` 0 when its frames arrive already expired (its clock behind
 *   this node's, or this one ahead), 1 when past this node's horizon;
 * - `seconds` by how much, as last measured;
 * - `at` when last seen, epoch seconds by the node's clock.
 * A row not seen for ten minutes is gone, which is when a notice goes.
 *
 * Rows are allocated to fit; release with fzn_rpc_clock_list_release, after a failure
 * too.
 */
typedef struct fzn_rpc_clock_row {
	uint8_t key[32];
	int ahead;
	uint64_t seconds;
	uint64_t at;
} fzn_rpc_clock_row_t;
typedef struct fzn_rpc_clock_list {
	fzn_rpc_clock_row_t *rows;
	size_t count;
} fzn_rpc_clock_list_t;
int fzn_rpc_clock_list(fzn_rpc_t *c, fzn_rpc_clock_list_t *out);
void fzn_rpc_clock_list_release(fzn_rpc_clock_list_t *l);

/*
 * Whether this node's own clock is right, against the median of the user's
 * other devices' clocks (fuzznet sec 719's `get clock`). It is what says
 * WHICH device is off: a peer listed above disagrees with this one, but only
 * the estate's vote says whose clock to set.
 * - `offset_ms`: the estate's time less this node's; positive when this
 *   node's clock is behind.
 * - `devices`: how many other devices of the user's were measured within
 *   the last ten minutes. Contacts never vote.
 * - `state`: WRONG past a minute from the median, measured against at
 *   least two other devices; UNSURE with fewer, since one other device
 *   cannot say which of the two is off.
 */
typedef enum { FZN_RPC_CLOCK_RIGHT = 0, FZN_RPC_CLOCK_WRONG = 1, FZN_RPC_CLOCK_UNSURE = 2 } fzn_rpc_clock_state_t;
typedef struct fzn_rpc_clock_estate {
	int64_t offset_ms;
	uint32_t devices;
	fzn_rpc_clock_state_t state;
} fzn_rpc_clock_estate_t;
int fzn_rpc_clock_get(fzn_rpc_t *c, fzn_rpc_clock_estate_t *out);
/* Every collection this user keeps, oldest first, which has no limit since
 * 2026-10-23: read a page at a time, into entries
 * allocated to fit. Release with fzn_rpc_sticker_packs_release, after a
 * failure too. */
typedef struct fzn_rpc_sticker_packs {
	fzn_rpc_sticker_list_entry_t *entries;
	size_t count;
} fzn_rpc_sticker_packs_t;
int fzn_rpc_sticker_list(fzn_rpc_t *c, fzn_rpc_sticker_packs_t *out);
void fzn_rpc_sticker_packs_release(fzn_rpc_sticker_packs_t *p);
int fzn_rpc_sticker_forget(fzn_rpc_t *c, const uint8_t root[32]);

/*
 * Stickers on a fuzznetd node (sec 284), fuzznet secs 679-682: a pack is a
 * file of the node's, read through its verbs rather than opened here, since
 * a node's packs are fuzznet's layout and not the zip core reads. PACK is a
 * saved pack's root as 64 hex, or the 144 hex of any held pack's file
 * reference (root, key, length).
 */
/* fuzznet's pack has no count cap since its sec 836, nor core's reader; a
 * LINE emoji set runs to a few hundred. A longer pack is said, not read
 * as unreadable. */
#define FZN_RPC_NODE_STICKER_ITEMS_MAX 1024
typedef struct fzn_rpc_node_sticker_item {
	uint64_t id;
	uint8_t type;  /* an fzn_sticker_type_t: fuzznet's numbers are the same */
	uint16_t flags;
	uint16_t text_limit; /* characters the sender's words may run to; 0 for no box */
	/* The box and its paint (fuzznet sec 864), in the main rendition's
	 * pixels, whose size is main_w by main_h: all 0 from a node before it. */
	uint16_t text_x, text_y, text_w, text_h;
	uint32_t text_fill, text_ink; /* 0xRRGGBBAA, 0 for none */
	uint16_t text_turn;           /* 0..359, clockwise */
	uint16_t main_w, main_h;
	char description[129];
	size_t description_len;
} fzn_rpc_node_sticker_item_t;
typedef struct fzn_rpc_node_sticker_items_resp {
	fzn_rpc_node_sticker_item_t entries[FZN_RPC_NODE_STICKER_ITEMS_MAX];
	size_t count;
	int overflow; /* more rows than entries: said, not read as unreadable */
} fzn_rpc_node_sticker_items_resp_t;
/* The stickers a pack holds, `list sticker PACK`. */
int fzn_rpc_sticker_items(fzn_rpc_t *c, const char *pack, size_t pack_len,
                           fzn_rpc_node_sticker_items_resp_t *out);
/* The text a message carries for one, `get sticker PACK ID`: an `fzn:`
 * reference, into `text` (NUL-ended) of `cap` bytes. */
int fzn_rpc_sticker_reference(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                               char *text, size_t cap, size_t *text_len);
/* The same for a sticker that carries the sender's words (a message or name
 * sticker), `get sticker PACK ID text WORDS` (fuzznet sec 830): the words go
 * in the reference, and the node refuses them for a sticker with no text
 * box. */
int fzn_rpc_sticker_reference_words(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                                     const char *words, size_t words_len, char *text, size_t cap,
                                     size_t *text_len);
/* One rendition drawn to a NEW file at `path` (made absolute here), `get
 * sticker PACK ID ROLE PATH`: the role asked for or the nearest the
 * sticker has. The answer is its format (an fzn_sticker_format_t), width
 * and height. */
typedef struct fzn_rpc_node_sticker_drawn {
	uint8_t format;
	uint16_t width, height;
} fzn_rpc_node_sticker_drawn_t;
int fzn_rpc_sticker_draw(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                          uint8_t role, const char *path, size_t path_len,
                          fzn_rpc_node_sticker_drawn_t *out);
/* A pack built from the spec at `spec_path` and the files beside it, and
 * saved, `put sticker SPEC`: its root, and `*host_only` 1 when this host
 * may not set the estate's settings and saved it for itself alone. */
int fzn_rpc_sticker_put(fzn_rpc_t *c, const char *spec_path, size_t spec_path_len,
                         uint8_t root[32], int *host_only);

/* A pack as a file: written to `path`, with its id, the hash of its art, in
 * *pack_id (NULL for none wanted); and a file written so, on this or any node,
 * held and kept in the user's collection. The node checks what it keeps. */
int fzn_rpc_sticker_file_write(fzn_rpc_t *c, const uint8_t root[32], const char *path,
                                size_t path_len, uint64_t *pack_id);
int fzn_rpc_sticker_file_keep(fzn_rpc_t *c, const char *path, size_t path_len, uint8_t root[32],
                               int *host_only);

/* A pack this host holds -- one a message named and the node fetched --
 * kept in the user's collection, `add sticker REF` (fuzznet sec 683): REF
 * its whole file reference as 144 hex, its name read from the pack. The
 * answer is put's. */
int fzn_rpc_sticker_keep(fzn_rpc_t *c, const char *ref, size_t ref_len, uint8_t root[32],
                          int *host_only);


/* A sticker reference in a message's text, `fzn:` or `fzp:` (fuzznet sec
 * 680: `fzn:` is written, both are read), into core's struct and the pack's
 * length -- 0 for `fzp:`, which names none. FZN_RPC_OK, or FZN_RPC_ERR_MALFORMED
 * for text that is no reference. */
int fzn_rpc_sticker_ref_read(const char *text, size_t text_len, fzn_sticker_ref_t *out,
                         uint64_t *length);
/* A file reference in a message's text is fuzznet's: fzn_attachment_parse
 * (messages/attachment.h), `fzn:file/` or `fzp:file/`. */
/*
 * A file this node holds sent as an attachment, to a contact or, with
 * `is_group`, a group: `add message WHO out ID attach ROOT NAME`. fuzznet
 * writes the reference from the key it keeps and the file's length, and
 * grants the file to the conversation as the line goes out, so the client
 * neither formats nor grants.
 */
int fzn_rpc_message_attach(fzn_rpc_t *c, const char *to, size_t to_len, int is_group,
                            const uint8_t root[32], const char *name, size_t name_len);
/* The PACK a node reads a referenced pack by: its whole file reference as
 * 144 hex, root then key then length big-endian. */
void fzn_rpc_sticker_pack_word(const fzn_sticker_ref_t *ref, uint64_t length, char out[145]);
/* A node's pack as core's manifest, from `list sticker PACK`: ids, types,
 * flags and descriptions, and no renditions, which the node draws. Its
 * entries are allocated to fit: release with fzn_rpc_sticker_manifest_release
 * (client/sticker_read.h), after a failure too. */
int fzn_rpc_sticker_manifest(fzn_rpc_t *c, const char *pack, size_t pack_len,
                              fzn_sticker_manifest_t *out);
/* One rendition's bytes, at most `max` of them, drawn by the node to a
 * temporary file that is read and removed: *art the caller frees, and
 * *format an fzn_sticker_format_t. */
int fzn_rpc_sticker_art(fzn_rpc_t *c, const char *pack, size_t pack_len, uint64_t id,
                         uint8_t role, size_t max, uint8_t **art, size_t *art_len,
                         uint8_t *format);
/* `*reaches_siblings` (NULL ok): whether the change reaches this user's other
 * hosts, which is what location-share answers. */
int fzn_rpc_location_share(fzn_rpc_t *c, const char *peer, size_t peer_len, int enable,
                            uint8_t precision, int *reaches_siblings);
/*
 * Every stored inbox line, newest first -- one contact's when `peer_len` is
 * not 0 -- gathered page by page (sec 171) into `out`, at most `cap`.
 * Bounded by the most the inbox stores, in case a daemon keeps saying "more"
 * without moving. On a failure part way, *count is what did arrive.
 */
/* A conversation's read position, held by the node and synced between this
 * user's devices, the newest written winning (fuzznet sec 528; the holder,
 * 2026-10-08: read state moves into fuzznet, and clients keep none).
 * fzn_rpc_message_read sets it at the line whose id is `id`, the inbox's
 * `commitment`; fzn_rpc_message_unread counts the lines in above it, every
 * line in when there is none, `*more` 1 when the count is a floor. A group
 * is `@` and its 64-hex id, which no rename moves (fuzznet secs 647, 1084). */
int fzn_rpc_message_read(fzn_rpc_t *c, const char *peer, size_t peer_len, const uint8_t id[16]);
int fzn_rpc_message_unread(fzn_rpc_t *c, const char *peer, size_t peer_len, size_t *count,
                            int *more);
int fzn_rpc_inbox_lines(fzn_rpc_t *c, const char *peer, size_t peer_len, fzn_rpc_inbox_entry_t *out,
                         size_t cap, size_t *count);
/* EVERY CONVERSATION'S COUNT IN ONE REPLY, `list message unread [FROM]`
 * (fuzznet sec 1084): `key` is a contact's root key, or a group's id; a
 * conversation with nothing unread is listed too, with count 0. Gathered
 * page by page into `out`, at most `cap`; `*total` is how many the node
 * has, so a caller sees when `cap` cut it short. */
typedef struct {
	uint8_t key[32];
	size_t count;
	int more; /* the count is a floor */
} fzn_rpc_unread_entry_t;
int fzn_rpc_unread_all(fzn_rpc_t *c, fzn_rpc_unread_entry_t *out, size_t cap, size_t *count,
                        size_t *total);

/* ---- the node (sec 284) ---- */

/*
 * These reach fuzznetd's local verbs through fuzznet's own client (fuzznet
 * sec 364), so the request grammar is stated once, in fuzznet, and not again
 * here.
 */

/* Where fuzznetd answers, or NULL / "" for none, or "default" for fuzznet's
 * own default socket (`fzn_socket_default_path`, its sec 663). A path too
 * long for a unix socket is refused here by leaving none set, and returns
 * -1. */
int fzn_rpc_set_node_socket(fzn_rpc_t *c, const char *path);

/*
 * One request to fuzznetd: `verb SP arg LF`, or `verb LF` when `arg` is
 * NULL. FZN_RPC_OK with *rest and *rest_len the reply after its `ok` -- pointing
 * into c->resp, valid until the next call -- or the failure with c->error
 * saying why, as every call here does:
 *   - a refusal (`denied`, `unsupported`, `error`, `malformed`) is answered,
 *     and its words are the daemon's;
 *   - no daemon, a timeout or a broken socket is not answered, and says so.
 */
int fzn_rpc_node(fzn_rpc_t *c, const char *verb, const char *arg, size_t arg_len,
                  const char **rest, size_t *rest_len);

/* The reply half alone: maps one reply line, without its terminator, onto
 * the call's result. Exposed so the mapping is tested without a daemon. */
int fzn_rpc_node_reply(fzn_rpc_t *c, const char *reply, size_t len, const char **rest,
                        size_t *rest_len);

#ifdef __cplusplus
}
#endif

/*
 * fuzznetd's events (sec 284 step 4, fuzznet sec 609): a connection that
 * asked `get events` and was answered `ok events`, which fuzznetd then
 * writes one line a change, `event SUBJECT NAME` -- SUBJECT `message`,
 * `note`, `request`, `catalog`, `estate` or `routing`, NAME the item in hex
 * or `-` for the whole subject. Thin, as the clients' events are: an event says
 * what to read again, and the read is the authority.
 */
typedef struct fzn_rpc_node_events {
	int fd;
	char buf[256];
	size_t len;
	/* Why the last open did not subscribe: fuzznetd's own words when it
	 * answered with a refusal (as sec 667's follower did, before sec 669
	 * passed its events through), or ours when it could not be asked. Empty after a subscription. */
	char why[160];
} fzn_rpc_node_events_t;

/* Subscribe at `path`. 0 with `ev->fd` open, -1 when fuzznetd is not there
 * or did not take it (it holds at most FZN_NODE_EVENTS_MAX subscribers). */
int fzn_rpc_node_events_open(fzn_rpc_node_events_t *ev, const char *path);
/* After the fd polls readable, call until it returns 0: 1 with the next
 * event in `subject` and `name` (more may be buffered behind it, which a
 * poll would not report), 0 when no whole line is here yet, -1 when the
 * subscription ended -- read everything again and subscribe anew. */
int fzn_rpc_node_events_next(fzn_rpc_node_events_t *ev, char *subject, size_t subject_cap, char *name,
                         size_t name_cap);
void fzn_rpc_node_events_close(fzn_rpc_node_events_t *ev);

#endif /* FZN_RPC_CLIENT_CALLS_H */
