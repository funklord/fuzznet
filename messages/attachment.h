/*
 * A FILE SENT IN A CONVERSATION, sec 794: the reference a line's text
 * carries, fuzznet's since the holder's word of 2026-10-31 ("fuzznet owns
 * the attachment reference"), where it was fuzzypickles' own token.
 *
 *     fzn:file/<root hex>/<key hex>/<size> <name>
 *
 * It rides the ordinary text field, as a sticker's reference does (sec
 * 679): so it inherits delivery, settlement, a group's sealing and the
 * buckets, and a client that knows nothing of it still shows a line that
 * says what was sent and how big it is. fuzzypickles' `fzp:file/...`, the
 * same grammar under its own scheme, is still read, so an attachment
 * already sent still resolves; only `fzn:` is written.
 *
 * THE FILE IS NOT FETCHED FOR BEING NAMED. A file can be a gigabyte, and
 * fetching every one anybody sends spends the receiver's bandwidth and
 * disk for them; the size is in the reference so a client can ask first.
 * It is the SENDER'S CLAIM -- a fetch checks the blob's own tree, so a lie
 * fails the fetch -- and a client shows it as one.
 *
 * THE NAME IS FOR DISPLAY AND FOR A DEFAULT, NEVER A PATH TO WRITE: 1 to
 * 64 bytes, no `/` or `\`, no control byte or 0x7f, no leading dot, no
 * space at either end. One that breaks any of those is refused, not
 * cleaned: a name altered unseen is a file saved under something its
 * sender never wrote. The size has no leading zero, so a file has one
 * spelling.
 */
#ifndef FZN_MESSAGES_ATTACHMENT_H
#define FZN_MESSAGES_ATTACHMENT_H

#include <stddef.h>
#include <stdint.h>

#define FZN_ATTACHMENT_ROOT_LEN 32u
#define FZN_ATTACHMENT_KEY_LEN 32u
#define FZN_ATTACHMENT_NAME_MAX 64u
/* "fzn:file/", two hex fields and their separators, at most twenty digits
 * of size, a space and the name: within a line's 512 bytes. */
#define FZN_ATTACHMENT_REF_MAX (9u + 64u + 1u + 64u + 1u + 20u + 1u + FZN_ATTACHMENT_NAME_MAX)

typedef struct fzn_attachment {
	uint8_t root[FZN_ATTACHMENT_ROOT_LEN];
	uint8_t key[FZN_ATTACHMENT_KEY_LEN];
	uint64_t size; /* the sender's claim */
	char name[FZN_ATTACHMENT_NAME_MAX + 1u];
	size_t name_len;
} fzn_attachment_t;

/* `fzn:file/...` into `out`, NUL ended: 1 with `*len`, or 0 for a name
 * this format does not carry or a room too small. */
int fzn_attachment_format(const fzn_attachment_t *a, char *out, size_t cap, size_t *len);

/* `fzn:file/...` or fuzzypickles' `fzp:file/...` back: 1, or 0 for
 * anything not a whole, well-formed reference -- the text is then the
 * ordinary message it is. Every attachment a client shows passes here. */
int fzn_attachment_parse(const char *text, size_t len, fzn_attachment_t *out);

#endif /* FZN_MESSAGES_ATTACHMENT_H */
