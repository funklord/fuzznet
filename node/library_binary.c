/* The library in binary: library_binary.h, sec 1174. */
#include "library_binary.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/files_local.h"
#include "../wire/generated/files_local_build.h"
#include "../wire/status.h"

/* A label's name, as `add catalog` writes it. */
static int named(const fzn_catalog_assertion_t *a, const char *name, size_t name_len)
{
	return a->name_len == name_len && memcmp(a->name, name, name_len) == 0;
}

/* A duration in milliseconds, as decimal digits and nothing else. */
static int decimal(const uint8_t *p, size_t len, uint64_t *out)
{
	uint64_t v = 0;
	size_t i;

	if (!len || len > 20u)
		return 0;
	for (i = 0; i < len; i++) {
		uint64_t d;

		if (p[i] < '0' || p[i] > '9')
			return 0;
		d = (uint64_t)(p[i] - '0');
		if (v > (UINT64_MAX - d) / 10u)
			return 0;
		v = v * 10u + d;
	}
	*out = v;
	return 1;
}

/* ONE FILE'S ROW from its claims, `set` the `n` of them in the order taken. */
static void row_of(const fzn_catalog_assertion_t *set, size_t n, const uint8_t root[32],
                   const uint8_t *host, fzn_node_library_file_t file, void *file_ctx,
                   fzn_node_library_row_t *r)
{
	size_t holders = 0, k, j;
	int claimed = 0, whole = 0;
	uint64_t length = 0;
	uint16_t arriving = 0;

	memset(r, 0, sizeof(*r));
	memcpy(r->root, root, 32u);
	for (k = 0; k < n; k++) {
		const fzn_catalog_assertion_t *a = &set[k];
		int seen = 0;

		if (!a->live)
			continue;
		if (named(a, "name", 4u) && !r->name_len && a->value_len) {
			r->name_len = a->value_len < sizeof(r->name) ? a->value_len : sizeof(r->name);
			memcpy(r->name, a->value, r->name_len);
		} else if (named(a, "kind", 4u) && !r->kind_len && a->value_len) {
			r->kind_len = a->value_len < sizeof(r->kind) ? a->value_len : sizeof(r->kind);
			memcpy(r->kind, a->value, r->kind_len);
		} else if (named(a, "duration", 8u) && !r->duration_ms) {
			uint64_t ms = 0;

			if (decimal(a->value, a->value_len, &ms))
				r->duration_ms = ms;
		}
		/* A HOLDER IS THE ISSUER OF A HOLDER CLAIM (C8, sec 1189), by its
		 * first eight bytes, counted once: `fzn_catalog_holders`' rule,
		 * which `get catalog` answers by. A claim made under another
		 * capability names the file without saying where its bytes are. */
		if (a->issuer_len < 8u || a->capability != FZN_CATALOG_CAP_HOLDER)
			continue;
		for (j = 0; j < k && !seen; j++)
			seen = set[j].live && set[j].capability == FZN_CATALOG_CAP_HOLDER
			       && set[j].issuer_len >= 8u && memcmp(set[j].issuer, a->issuer, 8u) == 0;
		if (!seen)
			holders++;
		if (memcmp(a->issuer, host, 8u) == 0)
			claimed = 1;
	}
	r->holders = (uint16_t)(holders > 0xffffu ? 0xffffu : holders);
	if (!file || !file(file_ctx, root, &length, &whole, &arriving))
		return;
	r->size = length;
	/* HELD HERE IS THE BYTES, NOT THE CLAIM (local/rpc.c's one-file path
	 * says why): whole here and unclaimed, this host is a holder too. */
	if (whole) {
		r->held_here = 1;
		if (!claimed && r->holders < 0xffffu)
			r->holders++;
	} else {
		r->arriving = arriving ? arriving : 1u;
	}
}

int fzn_node_library_each(const fzn_node_catalog_t *cat, const uint8_t *host,
                          fzn_node_library_file_t file, void *file_ctx,
                          fzn_node_library_each_t each, void *each_ctx)
{
	fzn_catalog_assertion_t *set = NULL;
	size_t cap = 0, i;
	int ok = 1;

	if (!cat || !host || !each)
		return 0;
	for (i = 0; i < cat->count && ok; i++) {
		const fzn_node_catalog_entry_t *e = &cat->entries[i];
		fzn_node_library_row_t row;
		size_t j, n;
		int earlier = 0;

		if (!e->live)
			continue;
		/* THE FILE'S FIRST LIVE CLAIM opens its row: any earlier one live,
		 * and the row was given there. */
		for (j = e->same_entity; j != SIZE_MAX && j < i && !earlier; j = cat->entries[j].same_entity)
			earlier = cat->entries[j].live;
		if (earlier)
			continue;
		n = fzn_node_catalog_count_of(cat, e->entity);
		if (n > cap) {
			fzn_catalog_assertion_t *more = realloc(set, n * sizeof(*set));

			if (!more) {
				ok = 0;
				break;
			}
			set = more;
			cap = n;
		}
		n = fzn_node_catalog_assertions(cat, e->entity, set, n);
		row_of(set, n, e->entity, host, file, file_ctx, &row);
		each(each_ctx, &row);
	}
	free(set);
	return ok;
}

static int status(fzn_node_library_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_library_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const fzn_node_library_row_t *r)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_LIBRARY_BINARY_MAX], out[FZN_NODE_LIBRARY_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = fzn_files_local_library_row_build(row, sizeof(row), r->root, r->size, r->duration_ms,
	                                          r->holders, r->held_here, r->arriving, r->kind,
	                                          (uint32_t)r->kind_len, r->name, (uint32_t)r->name_len,
	                                          &row_len)
	                == SITU_OK
	        && fzn_files_local_message_build_library_row(out, sizeof(out), (uint8_t)FZN_CMD_FILES, row,
	                                                     row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

int fzn_node_library_one(const fzn_node_catalog_t *cat, const uint8_t root[32], const uint8_t *host,
                         fzn_node_library_file_t file, void *file_ctx, fzn_node_library_row_t *row)
{
	fzn_catalog_assertion_t *set;
	size_t n, k;
	int live = 0;

	if (!cat || !root || !host || !row)
		return -1;
	n = fzn_node_catalog_count_of(cat, root);
	if (!n)
		return 0;
	set = malloc(n * sizeof(*set));
	if (!set)
		return -1;
	n = fzn_node_catalog_assertions(cat, root, set, n);
	for (k = 0; k < n && !live; k++)
		live = set[k].live != 0;
	/* RETRACTED THROUGHOUT is not in the library, as the listing gives no
	 * row for it. */
	if (live)
		row_of(set, n, root, host, file, file_ctx, row);
	free(set);
	return live;
}

/* ONE FILE'S ROW, sec 1190: as the listing gives it, then ok. */
static int answer_one(const fzn_node_catalog_t *cat, const uint8_t *host, fzn_node_library_file_t file,
                      void *file_ctx, situ_view_t v, struct rows *w)
{
	situ_view_t body;
	fzn_node_library_row_t row;
	int found;

	if (fzn_files_local_message_body_library_file_view(v, &body) != SITU_OK)
		return status(w->put, w->ctx, FZN_STATUS_MALFORMED, "not a library request");
	found = fzn_node_library_one(cat, fzn_files_local_library_file_root_ptr(body), host, file, file_ctx,
	                             &row);
	if (found < 0)
		return status(w->put, w->ctx, FZN_STATUS_ERROR, "the library did not list");
	if (!found)
		return status(w->put, w->ctx, FZN_STATUS_ERROR, "that file is not in the library");
	row_one(w, &row);
	return w->ok && status(w->put, w->ctx, FZN_STATUS_OK, NULL);
}

/* ---- the music and photo catalogues, sec 1449 ---------------------------- */

/* The first live value of `name` among a file's claims, or none. */
static size_t word_of(const fzn_catalog_assertion_t *set, size_t n, const char *name, const uint8_t **value)
{
	size_t k, len = strlen(name);

	for (k = 0; k < n; k++)
		if (set[k].live && named(&set[k], name, len) && set[k].value_len) {
			*value = set[k].value;
			return set[k].value_len < 255u ? set[k].value_len : 255u;
		}
	*value = NULL;
	return 0;
}

/* The leading digits of a value as a number, at most `max`: "3/12" is 3,
 * "1961-06-25" is 1961. 0 for none, or one past `max`. */
static uint32_t leading(const uint8_t *p, size_t len, uint32_t max)
{
	uint32_t v = 0;
	size_t i;

	for (i = 0; i < len && i < 10u && p[i] >= '0' && p[i] <= '9'; i++)
		v = v * 10u + (uint32_t)(p[i] - '0');
	return i && i < 10u && v <= max ? v : 0u;
}

/* "N/M"'s M, as `leading` reads N. */
static uint32_t total_of(const uint8_t *p, size_t len, uint32_t max)
{
	const uint8_t *slash = p ? memchr(p, '/', len) : NULL;

	return slash ? leading(slash + 1, len - (size_t)(slash + 1 - p), max) : 0u;
}

/* A kind's family: "audio/flac" begins "audio/". */
static int kind_is(const uint8_t *kind, size_t len, const char *family)
{
	size_t f = strlen(family);

	return len > f && memcmp(kind, family, f) == 0;
}

/* `place`'s "LAT,LON" in ten-millionths of a degree: 1, or 0 where it is no
 * place. */
static int place_of(const uint8_t *p, size_t len, int32_t *lat, int32_t *lon)
{
	char text[64], *comma, *end;
	double a, b;

	if (!p || !len || len >= sizeof(text))
		return 0;
	memcpy(text, p, len);
	text[len] = '\0';
	if (!(comma = strchr(text, ',')))
		return 0;
	*comma = '\0';
	a = strtod(text, &end);
	if (end == text || *end)
		return 0;
	b = strtod(comma + 1, &end);
	if (end == comma + 1 || *end || !(a >= -90.0 && a <= 90.0) || !(b >= -180.0 && b <= 180.0))
		return 0;
	*lat = (int32_t)(a * 1e7 + (a < 0 ? -0.5 : 0.5));
	*lon = (int32_t)(b * 1e7 + (b < 0 ? -0.5 : 0.5));
	return 1;
}

/* ONE FILE'S MUSIC ROW, or its photo row, from its claims and the library
 * row they make: 1 when it is one, written; 0 when it is not; -1 when the
 * row would not write. Music is a kind of `audio/`, or no kind and an
 * artist or an album; a photo a kind of `image/`, or no kind and a time
 * taken or a camera; and a phone's video, a kind of `video/`, among the
 * photographs as a phone's own gallery has it (sec 1460). */
static int media_row(const fzn_catalog_assertion_t *set, size_t n, const fzn_node_library_row_t *r, unsigned op,
                     struct rows *w)
{
	static uint8_t row[16u * 1024u], out[16u * 1024u + 8u];
	const uint8_t *v[14];
	size_t l[14];
	uint32_t row_len = 0, out_len = 0;
	int ok;

	if (op == FZN_FILES_LOCAL_OP_MUSIC) {
		/* AND WHAT ITS HOST HEARD, sec 1462: 6 to 11 as the row carries them,
		 * each held to its field's bound -- a value past it is no value. */
		static const char *names[14] = { "title", "artist", "album", "album_artist", "genre",
			                         "composer", "bpm", "key", "beat", "loudness", "peak",
			                         "acoustid", "musicbrainz_recording", "track" };
		static const size_t most[14] = { 255u, 255u, 255u, 255u, 255u, 255u, 16u, 16u, 16u, 16u, 16u, 36u, 36u, 255u };
		const uint8_t *disc, *year;
		size_t disc_len, year_len, i;

		for (i = 0; i < 14u; i++)
			if ((l[i] = word_of(set, n, names[i], &v[i])) > most[i])
				l[i] = 0;
		if (r->kind_len ? !kind_is(r->kind, r->kind_len, "audio/") : !l[1] && !l[2])
			return 0;
		disc_len = word_of(set, n, "disc", &disc);
		year_len = word_of(set, n, "year", &year);
		ok = fzn_files_local_music_row_build(
		             row, sizeof(row), r->root, r->duration_ms, r->holders, r->held_here,
		             (uint16_t)leading(v[13], l[13], 0xffffu), (uint16_t)total_of(v[13], l[13], 0xffffu),
		             (uint16_t)leading(disc, disc_len, 0xffffu), (uint16_t)total_of(disc, disc_len, 0xffffu),
		             (uint16_t)leading(year, year_len, 0xffffu), v[0], (uint32_t)l[0], v[1], (uint32_t)l[1], v[2],
		             (uint32_t)l[2], v[3], (uint32_t)l[3], v[4], (uint32_t)l[4], v[5], (uint32_t)l[5], v[6],
		             (uint32_t)l[6], v[7], (uint32_t)l[7], v[8], (uint32_t)l[8], v[9], (uint32_t)l[9], v[10],
		             (uint32_t)l[10], v[11], (uint32_t)l[11], v[12], (uint32_t)l[12], r->name, (uint32_t)r->name_len,
		             &row_len)
		             == SITU_OK
		     && fzn_files_local_message_build_music_row(out, sizeof(out), (uint8_t)FZN_CMD_FILES, row, row_len,
		                                                &out_len)
		                == SITU_OK;
	} else {
		const uint8_t *taken, *camera, *place, *width, *height, *orientation;
		size_t taken_len = word_of(set, n, "taken", &taken), camera_len = word_of(set, n, "camera", &camera);
		size_t place_len = word_of(set, n, "place", &place), width_len = word_of(set, n, "width", &width);
		size_t height_len = word_of(set, n, "height", &height);
		size_t orientation_len = word_of(set, n, "orientation", &orientation);
		int32_t lat = 0, lon = 0;
		int where, video = r->kind_len && kind_is(r->kind, r->kind_len, "video/");

		if (r->kind_len ? !kind_is(r->kind, r->kind_len, "image/") && !video : !taken_len && !camera_len)
			return 0;
		if (taken_len > 19u)
			taken_len = 0;
		where = place_of(place, place_len, &lat, &lon);
		ok = fzn_files_local_photo_row_build(
		             row, sizeof(row), r->root, r->size, r->holders, r->held_here,
		             leading(width, width_len, 0x7fffffffu), leading(height, height_len, 0x7fffffffu),
		             (uint8_t)leading(orientation, orientation_len, 8u), (uint8_t)video,
		             video ? r->duration_ms : 0u, (uint8_t)where, lat, lon, taken,
		             (uint32_t)taken_len, camera, (uint32_t)camera_len, r->name, (uint32_t)r->name_len, &row_len)
		             == SITU_OK
		     && fzn_files_local_message_build_photo_row(out, sizeof(out), (uint8_t)FZN_CMD_FILES, row, row_len,
		                                                &out_len)
		                == SITU_OK;
	}
	return ok && w->put(w->ctx, out, out_len) ? 1 : -1;
}

/* Every file that is music, or every photograph, a row each, then ok. */
static int answer_media(const fzn_node_catalog_t *cat, const uint8_t *host, fzn_node_library_file_t file,
                        void *file_ctx, unsigned op, struct rows *w)
{
	fzn_catalog_assertion_t *set = NULL;
	size_t cap = 0, i;
	int ok = 1;

	for (i = 0; i < cat->count && ok; i++) {
		const fzn_node_catalog_entry_t *e = &cat->entries[i];
		fzn_node_library_row_t row;
		size_t j, n;
		int earlier = 0;

		if (!e->live)
			continue;
		for (j = e->same_entity; j != SIZE_MAX && j < i && !earlier; j = cat->entries[j].same_entity)
			earlier = cat->entries[j].live != 0;
		if (earlier)
			continue;
		n = fzn_node_catalog_count_of(cat, e->entity);
		if (n > cap) {
			fzn_catalog_assertion_t *more = realloc(set, n * sizeof(*set));

			if (!more) {
				ok = 0;
				break;
			}
			set = more;
			cap = n;
		}
		n = fzn_node_catalog_assertions(cat, e->entity, set, n);
		row_of(set, n, e->entity, host, file, file_ctx, &row);
		ok = media_row(set, n, &row, op, w) >= 0;
	}
	free(set);
	if (!ok)
		return status(w->put, w->ctx, FZN_STATUS_ERROR, "the catalogue did not list");
	return status(w->put, w->ctx, FZN_STATUS_OK, NULL);
}

int fzn_node_library_binary(const fzn_node_catalog_t *cat, const uint8_t *host,
                            fzn_node_library_file_t file, void *file_ctx, const uint8_t *msg,
                            size_t len, fzn_node_library_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };
	unsigned op;

	if (!put)
		return 0;
	if (!cat || !host || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no library here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_files_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_files_local_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a library request");
	op = (unsigned)fzn_files_local_message_op_get(v);
	if (op == FZN_FILES_LOCAL_OP_LIBRARY_FILE)
		return answer_one(cat, host, file, file_ctx, v, &w);
	if (op == FZN_FILES_LOCAL_OP_MUSIC || op == FZN_FILES_LOCAL_OP_PHOTOS)
		return answer_media(cat, host, file, file_ctx, op, &w);
	if (op != FZN_FILES_LOCAL_OP_LIBRARY)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a library request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_library_each(cat, host, file, file_ctx, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the library did not list");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}

int fzn_node_file_binary(fzn_node_file_here_get_t get, void *get_ctx, const uint8_t *msg, size_t len,
                         fzn_node_library_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v, body;
	fzn_node_file_here_t here;
	uint8_t row[64], out[64 + 8];
	uint32_t row_len = 0, n = 0;
	int found;

	if (!put)
		return 0;
	if (!get || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no files here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_files_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_files_local_message_validate(v) != SITU_OK
	    || fzn_files_local_message_op_get(v) != FZN_FILES_LOCAL_OP_FILE
	    || fzn_files_local_message_body_file_view(v, &body) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a file's asking");
	memset(&here, 0, sizeof(here));
	found = get(get_ctx, fzn_files_local_file_root_ptr(body), &here);
	if (found < 0)
		return status(put, put_ctx, FZN_STATUS_ERROR, "the file's state would not read");
	/* NOT HERE IS AN ANSWER, not a failure: no row, then ok. */
	if (!found)
		return status(put, put_ctx, FZN_STATUS_OK, NULL);
	if (fzn_files_local_file_row_build(row, sizeof(row), here.held, here.total, here.length, here.state,
	                                   here.to_everyone, here.shares, here.busy, &row_len)
	            != SITU_OK
	    || fzn_files_local_message_build_file_row(out, sizeof(out), (uint8_t)FZN_CMD_FILES, row, row_len, &n)
	               != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_ERROR, "the file's state would not write");
	return put(put_ctx, out, n) && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
