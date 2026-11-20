/* The sticker packs in binary: stickers_binary.h, sec 1172. */
#include "stickers_binary.h"

#include <stdint.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/stickers_local.h"
#include "../wire/generated/stickers_local_build.h"
#include "../wire/status.h"
#include "../local/vocabulary.h"
#include "../sticker/pack.h"
#include "../local/escape.h"

#include <stdio.h>

static int status(fzn_node_stickers_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_stickers_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const fzn_node_sticker_pack_t *p)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_STICKERS_BINARY_MAX], out[FZN_NODE_STICKERS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = p->name_len <= FZN_STICKER_NAME_MAX
	        && fzn_stickers_local_pack_row_build(row, sizeof(row), p->root, p->length, (uint8_t)(p->held ? 1 : 0),
	                                             (uint8_t)(p->estate ? 1 : 0), (const uint8_t *)p->name,
	                                             (uint32_t)p->name_len, &row_len)
	                   == SITU_OK
	        && fzn_stickers_local_message_build_pack_row(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

/* ONE STICKER AS A ROW, sec 1248. */
static void item_one(void *ctx, const struct fzn_sticker_entry *e, unsigned main_w, unsigned main_h)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_STICKERS_BINARY_MAX], out[FZN_NODE_STICKERS_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = e->description_len <= FZN_STICKER_DESC_MAX
	        && fzn_stickers_local_item_row_build(row, sizeof(row), e->id, e->type, e->flags, e->text_limit, e->text_x,
	                                             e->text_y, e->text_w, e->text_h, e->text_fill, e->text_ink,
	                                             e->text_turn, (uint16_t)main_w, (uint16_t)main_h,
	                                             (const uint8_t *)e->description, (uint32_t)e->description_len,
	                                             &row_len)
	                   == SITU_OK
	        && fzn_stickers_local_message_build_item_row(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

/* A PACK KEPT OR LET GO, sec 1248: through the verbs' own handler, as
 * `add sticker REF` and `remove sticker ROOT`, so every check is theirs;
 * kept, its root said as a row. Never malformed for a refusal. */
static int pack_write(const fzn_node_stickers_t *st, situ_view_t v, fzn_node_stickers_put_t put, void *put_ctx)
{
	static char reply[512];
	static char arg[16 + 2u * 72u + 1100u];
	fzn_request_t req;
	situ_view_t b;
	const uint8_t *bytes;
	uint8_t made[32];
	size_t i, r, n = 0, want;
	const int built = fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_PUT;
	const int keep = built || fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_KEEP;

	memset(&req, 0, sizeof(req));
	/* A PACK FROM A FILE, sec 1308: a spec built, or a pack file kept, as
	 * `put sticker PATH`; its root is the verb's answer's. */
	if (built) {
		const uint8_t *path;
		size_t path_len;

		if (fzn_stickers_local_message_body_put_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
		path = fzn_stickers_local_put_ask_path_ptr(b);
		path_len = fzn_stickers_local_put_ask_path_len_get(b);
		if (path[0] != '/' || memchr(path, ' ', path_len) || memchr(path, '\n', path_len)
		    || memchr(path, '\r', path_len))
			return status(put, put_ctx, FZN_STATUS_ERROR, "a path not absolute, or holding a space or a line break");
		n = (size_t)snprintf(arg, sizeof(arg), "sticker %.*s", (int)path_len, (const char *)path);
		req.parsed = FZN_VERB_PUT;
		bytes = made;
	} else if (keep) {
		uint8_t raw[72];

		if (fzn_stickers_local_message_body_keep_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
		memcpy(raw, fzn_stickers_local_keep_ask_root_ptr(b), 32);
		memcpy(raw + 32, fzn_stickers_local_keep_ask_key_ptr(b), 32);
		for (i = 0; i < 8u; i++)
			raw[64 + i] = (uint8_t)(fzn_stickers_local_keep_ask_length_get(b) >> (56u - 8u * i));
		bytes = raw;
		want = 72u;
		n = (size_t)snprintf(arg, sizeof(arg), "sticker ");
		for (i = 0; i < want; i++)
			n += (size_t)snprintf(arg + n, sizeof(arg) - n, "%02x", bytes[i]);
		req.parsed = FZN_VERB_ADD;
	} else {
		if (fzn_stickers_local_message_body_forget_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
		bytes = fzn_stickers_local_pack_ask_root_ptr(b);
		n = (size_t)snprintf(arg, sizeof(arg), "sticker ");
		for (i = 0; i < 32u; i++)
			n += (size_t)snprintf(arg + n, sizeof(arg) - n, "%02x", bytes[i]);
		req.parsed = FZN_VERB_REMOVE;
	}
	req.arg = (const uint8_t *)arg;
	req.arg_len = n;
	r = fzn_node_stickers_local((void *)(uintptr_t)st, FZN_ORIGIN_SAME_USER, &req, reply, sizeof(reply));
	while (r && (reply[r - 1u] == '\n' || reply[r - 1u] == '\r'))
		reply[--r] = '\0';
	if (r < 2u || memcmp(reply, "ok", 2u) != 0 || (r > 2u && reply[2] != ' '))
		return status(put, put_ctx,
		              r > 7u && memcmp(reply, "denied ", 7u) == 0 ? FZN_STATUS_DENIED : FZN_STATUS_ERROR,
		              memchr(reply, ' ', r) ? (const char *)memchr(reply, ' ', r) + 1 : "the pack would not change");
	/* KEPT: `ok ROOT` for the estate, `ok ROOT host` for this host alone. */
	if (built) {
		for (i = 0; i < 32u; i++) {
			int hi = r >= 3u + 64u ? reply[3 + 2 * i] : -1, lo = r >= 3u + 64u ? reply[4 + 2 * i] : -1;

			hi = hi >= '0' && hi <= '9' ? hi - '0' : hi >= 'a' && hi <= 'f' ? hi - 'a' + 10 : -1;
			lo = lo >= '0' && lo <= '9' ? lo - '0' : lo >= 'a' && lo <= 'f' ? lo - 'a' + 10 : -1;
			if (hi < 0 || lo < 0)
				return status(put, put_ctx, FZN_STATUS_ERROR, "the verb's answer did not read");
			made[i] = (uint8_t)(hi << 4 | lo);
		}
	}
	if (keep) {
		uint8_t row[40], out[56];
		uint32_t row_len = 0, m = 0;

		if (fzn_stickers_local_kept_row_build(row, sizeof(row), bytes, (uint8_t)(strstr(reply, " host") ? 0 : 1),
		                                      &row_len)
		            != SITU_OK
		    || fzn_stickers_local_message_build_kept(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len, &m)
		               != SITU_OK
		    || !put(put_ctx, out, m))
			return 0;
	}
	return status(put, put_ctx, FZN_STATUS_OK, NULL);
}

/* THE STICKER ASKED, `sticker PACK ID` as the verb takes it, into `arg`:
 * its length. */
static size_t sticker_arg(situ_view_t s, char *arg, size_t cap)
{
	size_t n, i;

	n = (size_t)snprintf(arg, cap, "sticker ");
	for (i = 0; i < 32u; i++)
		n += (size_t)snprintf(arg + n, cap - n, "%02x", fzn_stickers_local_sticker_ask_root_ptr(s)[i]);
	if (fzn_stickers_local_sticker_ask_has_key_get(s)) {
		for (i = 0; i < 32u; i++)
			n += (size_t)snprintf(arg + n, cap - n, "%02x", fzn_stickers_local_sticker_ask_key_ptr(s)[i]);
		n += (size_t)snprintf(arg + n, cap - n, "%016llx",
		                      (unsigned long long)fzn_stickers_local_sticker_ask_length_get(s));
	}
	n += (size_t)snprintf(arg + n, cap - n, " %llu", (unsigned long long)fzn_stickers_local_sticker_ask_id_get(s));
	return n < cap ? n : 0u;
}

/* A REFERENCE, OR A RENDITION OR SOUND WRITTEN, sec 1304: through the verb's
 * own handler, `get sticker PACK ID [text WORDS]` or `get sticker PACK ID
 * ROLE PATH`, so every check stays the verb's; its answer as a row and ok,
 * or a STATUS in its words, never malformed. */
static int sticker_read(const fzn_node_stickers_t *st, situ_view_t v, fzn_node_stickers_put_t put, void *put_ctx)
{
	static const char *const ROLES[] = { "thumb", "inline", "main", "popup", "sound" };
	static char reply[FZN_STICKER_REF_SENT_MAX + 64u];
	static char arg[2u * 32u + 2u * 32u + 64u + 3u * FZN_STICKER_TEXT_MAX + 1100u];
	const int reference = fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_REFERENCE;
	situ_view_t b, s;
	fzn_request_t req;
	size_t n, r;

	if ((reference ? fzn_stickers_local_message_body_reference_view(v, &b)
	               : fzn_stickers_local_message_body_art_view(v, &b))
	            != SITU_OK
	    || (reference ? fzn_stickers_local_reference_ask_sticker_view(b, &s)
	                  : fzn_stickers_local_art_ask_sticker_view(b, &s))
	               != SITU_OK
	    || !(n = sticker_arg(s, arg, sizeof(arg))))
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
	if (reference && fzn_stickers_local_reference_ask_words_len_get(b)) {
		size_t e = 0;

		n += (size_t)snprintf(arg + n, sizeof(arg) - n, " text ");
		(void)fzn_escape(fzn_stickers_local_reference_ask_words_ptr(b), fzn_stickers_local_reference_ask_words_len_get(b),
		                 arg + n, sizeof(arg) - n - 1u, &e);
		n += e;
	} else if (!reference) {
		const size_t path_len = fzn_stickers_local_art_ask_path_len_get(b);
		const uint8_t *path = fzn_stickers_local_art_ask_path_ptr(b);

		if (memchr(path, ' ', path_len) || memchr(path, '\n', path_len) || memchr(path, '\r', path_len))
			return status(put, put_ctx, FZN_STATUS_ERROR, "a path holding a space or a line break");
		n += (size_t)snprintf(arg + n, sizeof(arg) - n, " %s %.*s",
		                      ROLES[fzn_stickers_local_art_ask_role_get(b) - 1u], (int)path_len, (const char *)path);
	}
	if (n >= sizeof(arg))
		return status(put, put_ctx, FZN_STATUS_ERROR, "the request would not fit");
	memset(&req, 0, sizeof(req));
	req.parsed = FZN_VERB_GET;
	req.arg = (const uint8_t *)arg;
	req.arg_len = n;
	r = fzn_node_stickers_local((void *)(uintptr_t)st, FZN_ORIGIN_SAME_USER, &req, reply, sizeof(reply));
	while (r && (reply[r - 1u] == '\n' || reply[r - 1u] == '\r'))
		reply[--r] = '\0';
	if (r < 3u || memcmp(reply, "ok ", 3u) != 0)
		return status(put, put_ctx,
		              r > 7u && memcmp(reply, "denied ", 7u) == 0 ? FZN_STATUS_DENIED : FZN_STATUS_ERROR,
		              memchr(reply, ' ', r) ? (const char *)memchr(reply, ' ', r) + 1 : "the sticker would not read");
	{
		uint8_t row[FZN_STICKER_REF_SENT_MAX + 8u], out[FZN_STICKER_REF_SENT_MAX + 16u];
		uint32_t row_len = 0, m = 0;
		situ_err_t err;

		if (reference) {
			err = fzn_stickers_local_referenced_row_build(row, sizeof(row), (const uint8_t *)reply + 3, (uint32_t)(r - 3u),
			                                              &row_len);
			if (err == SITU_OK)
				err = fzn_stickers_local_message_build_referenced(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row,
				                                                  row_len, &m);
		} else {
			unsigned long long f = 0, wd = 0, ht = 0;
			const int sound = fzn_stickers_local_art_ask_role_get(b) == 5u;

			if (sound ? sscanf(reply + 3, "%llu", &f) != 1 : sscanf(reply + 3, "%llu %llu %llu", &f, &wd, &ht) != 3)
				return status(put, put_ctx, FZN_STATUS_ERROR, "the verb's answer did not read");
			err = fzn_stickers_local_drawn_row_build(row, sizeof(row), (uint8_t)(sound ? 0u : f), (uint16_t)wd,
			                                         (uint16_t)ht, sound ? (uint64_t)f : 0u, &row_len);
			if (err == SITU_OK)
				err = fzn_stickers_local_message_build_drawn(out, sizeof(out), (uint8_t)FZN_CMD_STICKERS, row, row_len,
				                                             &m);
		}
		if (err != SITU_OK || !put(put_ctx, out, m))
			return 0;
	}
	return status(put, put_ctx, FZN_STATUS_OK, NULL);
}

int fzn_node_stickers_binary(const fzn_node_stickers_t *st, const uint8_t *msg, size_t len,
                             fzn_node_stickers_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };

	if (!put)
		return 0;
	if (!st || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no stickers here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_stickers_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_stickers_local_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
	if (fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_KEEP
	    || fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_FORGET
	    || fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_PUT)
		return pack_write(st, v, put, put_ctx);
	if (fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_REFERENCE
	    || fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_ART)
		return sticker_read(st, v, put, put_ctx);
	/* ONE PACK'S STICKERS, sec 1248: a row each, then ok; no such pack, or
	 * one not here whole, refused in words. */
	if (fzn_stickers_local_message_op_get(v) == FZN_STICKERS_LOCAL_OP_ITEMS) {
		situ_view_t b;
		int r;

		if (fzn_stickers_local_message_body_items_view(v, &b) != SITU_OK)
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
		r = fzn_node_stickers_items(st, fzn_stickers_local_pack_ask_root_ptr(b), item_one, &w);
		if (r <= 0)
			return status(put, put_ctx, FZN_STATUS_ERROR,
			              r < 0 ? "that pack is not here whole, or is no pack" : "no such pack is saved");
		return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	if (fzn_stickers_local_message_op_get(v) != FZN_STICKERS_LOCAL_OP_PACKS)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a stickers request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_stickers_each(st, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the packs did not list");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
