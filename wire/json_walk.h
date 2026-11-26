/*
 * JSON WALKED THROUGH SITU'S VIEWS, project.md sec 1469: a document framed
 * and validated by the generated `fzn_json` (media/json.situ), then each
 * member of an object or element of an array handed to a callback, in
 * order -- each run walked once, each entry measured where it begins, as
 * the generated `_entries_at` counts from the first on every call and so
 * walks a run quadratically. A string's escapes are the caller's to read:
 * situ frames a string and does not say what it spells.
 */
#ifndef FZN_JSON_WALK_H
#define FZN_JSON_WALK_H

#include <stddef.h>
#include <stdint.h>

/* situ's message and view, named and not defined here: an installed
 * header includes no generated one, so a caller that walks includes
 * `wire/generated/json.h` itself and holds the structs. */
struct situ_msg;
struct situ_view;

/* THE ONE VALUE at the start of `len` bytes of `text`, framed and
 * validated, into `out`; `msg` is the caller's and must outlive `out`.
 * Bytes past the value are not read. 1, or 0 for no whole JSON value --
 * its depth bounded by the schema's. */
int fzn_json_walk_frame(const char *text, size_t len, struct situ_msg *msg, struct situ_view *out);

/* EACH MEMBER of an object value: its key as framed (escapes not read),
 * and its value. An empty object has none. 1, or 0 where `value` is no
 * object or `each` returns 0. */
int fzn_json_walk_members(const struct situ_view *value,
                          int (*each)(const char *key, size_t key_len, const struct situ_view *held, void *ctx),
                          void *ctx);

/* EACH ELEMENT of an array value, likewise. */
int fzn_json_walk_elements(const struct situ_view *value, int (*each)(const struct situ_view *held, void *ctx),
                           void *ctx);

/* A STRING VALUE's framed characters, escapes as written: 1 with them in
 * `*chars`, `*len`, or 0 for a value that is no string. */
int fzn_json_walk_string(const struct situ_view *value, const char **chars, size_t *len);

/* A NUMBER VALUE's own bytes, as written, blanks after it not counted: 1,
 * or 0 for a value that is no number. Read by the caller, to its own
 * precision. */
int fzn_json_walk_number(const struct situ_view *value, const char **text, size_t *len);

/* Whether a member's framed key is `want`. */
int fzn_json_walk_key_is(const char *key, size_t len, const char *want);

#endif /* FZN_JSON_WALK_H */
