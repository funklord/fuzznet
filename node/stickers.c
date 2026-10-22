#define _POSIX_C_SOURCE 200809L

#include "stickers.h"

#include "../local/escape.h"
#include "../sticker/pack.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_PREFIX "sticker/"
#define KEY_PREFIX_LEN 8u
/* 28 BYTES OF THE ROOT, 56 hex: the setting key's 64 less the prefix. */
#define KEY_ROOT_BYTES 28u
#define KEY_LEN (KEY_PREFIX_LEN + 2u * KEY_ROOT_BYTES)
#define REF_HEX (2u * FZN_NODE_FILE_REF_LEN)
/* The longest spec read: a person's text, never a library. */
#define SPEC_MAX (64u * 1024u)

static const char HEX[] = "0123456789abcdef";

static void hex_of(const uint8_t *b, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		out[2u * i] = HEX[b[i] >> 4];
		out[2u * i + 1u] = HEX[b[i] & 15u];
	}
	out[2u * n] = '\0';
}

static int unhex(const uint8_t *in, size_t n, uint8_t *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		int v = in[i] >= '0' && in[i] <= '9'   ? in[i] - '0'
		        : in[i] >= 'a' && in[i] <= 'f' ? in[i] - 'a' + 10
		                                       : -1;

		if (v < 0)
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)(v << 4);
		else
			out[i / 2u] = (uint8_t)(out[i / 2u] | v);
	}
	return 1;
}

static int next_word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *n)
{
	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	if (!*left)
		return 0;
	*w = *at;
	while (*left && **at != ' ') {
		(*at)++;
		(*left)--;
	}
	*n = (size_t)(*at - *w);
	return 1;
}

static void cell_key(const uint8_t root[FZN_BLOB_HASH_LEN], uint8_t key[KEY_LEN])
{
	char hex[2u * KEY_ROOT_BYTES + 1u];

	memcpy(key, KEY_PREFIX, KEY_PREFIX_LEN);
	hex_of(root, KEY_ROOT_BYTES, hex);
	memcpy(key + KEY_PREFIX_LEN, hex, 2u * KEY_ROOT_BYTES);
}

/* A CELL's VALUE read: its reference, and its name escaped, `name` NUL
 * ended. 1, or 0 for one of no such shape. */
static int read_value(const uint8_t *v, size_t n, fzn_node_file_ref_t *ref, char *name,
                      size_t name_cap)
{
	uint8_t raw[FZN_NODE_FILE_REF_LEN];

	if (n < REF_HEX + 1u || v[REF_HEX] != ' ' || n - REF_HEX - 1u >= name_cap
	    || !unhex(v, REF_HEX, raw) || !fzn_node_file_ref_read(raw, ref))
		return 0;
	memcpy(name, v + REF_HEX + 1u, n - REF_HEX - 1u);
	name[n - REF_HEX - 1u] = '\0';
	return 1;
}

int fzn_node_stickers_saved(const fzn_node_stickers_t *st, const uint8_t root[FZN_BLOB_HASH_LEN],
                            fzn_node_file_ref_t *ref)
{
	uint8_t key[KEY_LEN], value[FZN_SETTING_VALUE_MAX];
	char name[FZN_SETTING_VALUE_MAX];
	fzn_setting_rank_t rank;
	size_t len = 0;

	if (!st || !st->settings || !root || !ref)
		return 0;
	cell_key(root, key);
	/* THE ESTATE'S FIRST, then this host's own. */
	if ((st->settings->estate
	     && fzn_node_settings_get(st->settings, FZN_SCOPE_ESTATE, st->settings->estate, key,
	                              sizeof(key), value, &len, &rank)
	     && read_value(value, len, ref, name, sizeof(name)))
	    || (st->host
	        && fzn_node_settings_get(st->settings, FZN_SCOPE_HOST, st->host, key, sizeof(key),
	                                 value, &len, &rank)
	        && read_value(value, len, ref, name, sizeof(name))))
		return memcmp(ref->root, root, FZN_BLOB_HASH_LEN) == 0;
	return 0;
}

/* ---- reading and writing whole files ---------------------------------- */

/* `path`'s bytes, at most `max`, into a buffer the caller frees: NULL for a
 * file absent, unreadable or longer. */
static uint8_t *slurp(const char *path, size_t max, size_t *len)
{
	struct stat sb;
	uint8_t *buf;
	size_t got = 0;
	FILE *f = fopen(path, "rb");

	if (!f)
		return NULL;
	if (fstat(fileno(f), &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size < 0
	    || (uint64_t)sb.st_size > max || !(buf = malloc(sb.st_size ? (size_t)sb.st_size : 1u))) {
		(void)fclose(f);
		return NULL;
	}
	while (got < (size_t)sb.st_size) {
		size_t n = fread(buf + got, 1u, (size_t)sb.st_size - got, f);

		if (!n)
			break;
		got += n;
	}
	(void)fclose(f);
	if (got != (size_t)sb.st_size) {
		free(buf);
		return NULL;
	}
	*len = got;
	return buf;
}

/* A NEW FILE AT `path`, made exclusively, holding `len` bytes: 1, or 0
 * with nothing left behind. */
static int spill(const char *path, const uint8_t *bytes, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	size_t at = 0;

	if (fd < 0)
		return 0;
	while (at < len) {
		ssize_t n = write(fd, bytes + at, len - at);

		if (n <= 0) {
			(void)close(fd);
			(void)unlink(path);
			return 0;
		}
		at += (size_t)n;
	}
	if (close(fd) != 0) {
		(void)unlink(path);
		return 0;
	}
	return 1;
}

/* A WORKING NAME in the files' own directory, this process's. */
static void scratch_path(const fzn_node_stickers_t *st, char *out, size_t cap)
{
	static unsigned n;

	(void)snprintf(out, cap, "%s/.sticker.%ld.%u", st->files->dir, (long)getpid(), n++);
}

/* THE PACK `ref` NAMES, read whole into a buffer the caller frees, and
 * opened into `m`: NULL when it is not held, or is no pack. */
static uint8_t *pack_of(const fzn_node_stickers_t *st, const fzn_node_file_ref_t *ref,
                        fzn_sticker_manifest_t *m, const uint8_t **data, size_t *data_len)
{
	char path[FZN_NODE_FILES_DIR_MAX + 48u];
	uint8_t *bytes;
	size_t len = 0;

	if (ref->length > FZN_STICKER_PACK_MAX_LEN)
		return NULL;
	scratch_path(st, path, sizeof(path));
	if (fzn_node_files_export(st->files, ref, path) != FZN_NODE_FILES_OK)
		return NULL;
	bytes = slurp(path, FZN_STICKER_PACK_MAX_LEN, &len);
	(void)unlink(path);
	if (bytes && !fzn_sticker_pack_open(bytes, len, m, data, data_len)) {
		free(bytes);
		return NULL;
	}
	return bytes;
}

/* ---- the verbs -------------------------------------------------------- */

#define REPLY(...) ((size_t)snprintf(reply, cap, __VA_ARGS__))

/* PACK, a saved pack's 64-hex root or any pack's 144-hex reference, into
 * `ref`: 1, or 0. */
static int pack_named(const fzn_node_stickers_t *st, const uint8_t *w, size_t n,
                      fzn_node_file_ref_t *ref)
{
	uint8_t raw[FZN_NODE_FILE_REF_LEN];

	if (n == 2u * FZN_BLOB_HASH_LEN && unhex(w, n, raw))
		return fzn_node_stickers_saved(st, raw, ref);
	return n == REF_HEX && unhex(w, n, raw) && fzn_node_file_ref_read(raw, ref);
}

/* SAVED: `REF NAME`, the name escaped, the estate's cell or this host's --
 * `ok ROOT`, or `ok ROOT host`. */
static size_t save_pack(const fzn_node_stickers_t *st, const fzn_node_file_ref_t *ref,
                        const char *pack_name, size_t pack_name_len, char *reply, size_t cap)
{
	char root_hex[2u * FZN_BLOB_HASH_LEN + 1u], ref_hex[REF_HEX + 1u];
	char name[3u * FZN_STICKER_NAME_MAX + 1u];
	uint8_t key[KEY_LEN], raw[FZN_NODE_FILE_REF_LEN], value[FZN_SETTING_VALUE_MAX];
	size_t name_len = 0, value_len;
	fzn_node_settings_err_t serr;

	fzn_node_file_ref_write(ref, raw);
	hex_of(raw, sizeof(raw), ref_hex);
	(void)fzn_escape((const uint8_t *)pack_name, pack_name_len, name, sizeof(name) - 1u,
	                 &name_len);
	name[name_len] = '\0';
	value_len = (size_t)snprintf((char *)value, sizeof(value), "%s %s", ref_hex, name);
	cell_key(ref->root, key);
	hex_of(ref->root, FZN_BLOB_HASH_LEN, root_hex);
	/* A NAME THAT ESCAPES PAST A SETTING'S VALUE is refused, never cut: a
	 * name of 48 bytes escapes to as many as 144. */
	if (value_len >= sizeof(value))
		return REPLY("error the pack %s is here, and its name is too long to save escaped\n",
		             root_hex);
	serr = st->settings->estate
	       ? fzn_node_settings_write(st->settings, FZN_SCOPE_ESTATE, st->settings->estate, key,
	                                 sizeof(key), 1, value, value_len)
	       : FZN_NODE_SETTINGS_REFUSED;
	if (serr == FZN_NODE_SETTINGS_OK)
		return REPLY("ok %s\n", root_hex);
	if (serr != FZN_NODE_SETTINGS_REFUSED || !st->host
	    || fzn_node_settings_write(st->settings, FZN_SCOPE_HOST, st->host, key, sizeof(key), 1,
	                               value, value_len)
	               != FZN_NODE_SETTINGS_OK)
		return REPLY("error the pack %s is here, and would not save\n", root_hex);
	return REPLY("ok %s host\n", root_hex);
}

/* `add sticker REF`, sec 683: a pack held here -- one a message named and
 * the sweep fetched -- saved by its whole reference, its name read from the
 * pack. Receiving never saves; this is the user's deliberate keep. */
static size_t add_sticker(const fzn_node_stickers_t *st, const uint8_t *w, size_t n,
                          char *reply, size_t cap)
{
	static fzn_sticker_manifest_t m;
	uint8_t raw[FZN_NODE_FILE_REF_LEN];
	fzn_node_file_ref_t ref;
	const uint8_t *data;
	size_t data_len;
	uint8_t *bytes;

	if (n != REF_HEX || !unhex(w, n, raw) || !fzn_node_file_ref_read(raw, &ref))
		return REPLY("malformed add sticker REF, the pack's reference in 144 hex\n");
	if (!(bytes = pack_of(st, &ref, &m, &data, &data_len)))
		return REPLY("error that pack is not here whole, or is no pack\n");
	free(bytes);
	return save_pack(st, &ref, m.name, m.name_len, reply, cap);
}

static size_t put_sticker(const fzn_node_stickers_t *st, const uint8_t *w, size_t n,
                          char *reply, size_t cap)
{
	static fzn_sticker_manifest_t m;
	static const uint8_t *art[FZN_STICKER_PER_PACK_MAX][FZN_STICKER_RENDITIONS_MAX];
	static uint32_t art_len[FZN_STICKER_PER_PACK_MAX][FZN_STICKER_RENDITIONS_MAX];
	static const uint8_t *sound[FZN_STICKER_PER_PACK_MAX];
	static uint32_t sound_len[FZN_STICKER_PER_PACK_MAX];
	static uint8_t *owned[FZN_STICKER_PER_PACK_MAX * (FZN_STICKER_RENDITIONS_MAX + 1u)];
	char spec_path[1024], dir[1024], file[1024 + FZN_STICKER_PATH_MAX + 2u], err[160];
	char scratch[FZN_NODE_FILES_DIR_MAX + 48u];
	size_t n_owned = 0, spec_len = 0, pack_len = 0, i, r;
	uint64_t total = 0;
	uint8_t *spec, *pack = NULL;
	const char *slash, *why = NULL;
	fzn_node_file_ref_t ref;

	if (n >= sizeof(spec_path) || w[0] != '/')
		return REPLY("malformed the spec's path is absolute\n");
	memcpy(spec_path, w, n);
	spec_path[n] = '\0';
	if (!(spec = slurp(spec_path, SPEC_MAX, &spec_len)))
		return REPLY("error the spec would not read\n");
	if (!fzn_sticker_spec_parse((const char *)spec, spec_len, &m, err, sizeof(err))) {
		free(spec);
		return REPLY("malformed the spec: %s\n", err);
	}
	free(spec);
	slash = strrchr(spec_path, '/');
	(void)snprintf(dir, sizeof(dir), "%.*s", (int)(slash - spec_path), spec_path);
	memset(sound, 0, sizeof(sound));
	memset(sound_len, 0, sizeof(sound_len));
	/* EVERY FILE THE SPEC NAMES, beside it -- its paths cannot climb out
	 * (`fzn_sticker_path_ok`) -- read, the whole bounded by a pack's. */
	for (i = 0; i < m.count && !why; i++) {
		fzn_sticker_entry_t *e = &m.entries[i];

		for (r = 0; r <= e->rendition_count && !why; r++) {
			const char *p = r < e->rendition_count ? e->renditions[r].path : e->audio_path;
			size_t got = 0;
			uint8_t *bytes;

			if (r == e->rendition_count && !e->audio_path_len)
				break;
			(void)snprintf(file, sizeof(file), "%s/%s", dir, p);
			if (!(bytes = slurp(file, FZN_STICKER_PACK_MAX_LEN - total, &got)) || !got) {
				free(bytes);
				why = p;
				break;
			}
			owned[n_owned++] = bytes;
			total += got;
			if (r < e->rendition_count) {
				art[i][r] = bytes;
				art_len[i][r] = (uint32_t)got;
			} else {
				sound[i] = bytes;
				sound_len[i] = (uint32_t)got;
			}
		}
	}
	if (!why
	    && fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                              (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                              (const uint8_t *const *)sound, sound_len, NULL, 0, &pack_len)
	    && (pack = malloc(pack_len))
	    && !fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                               (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                               (const uint8_t *const *)sound, sound_len, pack, pack_len,
	                               &pack_len)) {
		free(pack);
		pack = NULL;
	}
	for (i = 0; i < n_owned; i++)
		free(owned[i]);
	if (why)
		return REPLY("error %s would not read beside the spec\n", why);
	if (!pack)
		return REPLY("malformed the pack would not build: a description repeated, a sound "
		             "or a box missing\n");
	/* PUT AS ANY FILE IS, from a working name in the files' directory. */
	scratch_path(st, scratch, sizeof(scratch));
	if (!spill(scratch, pack, pack_len)) {
		free(pack);
		return REPLY("error the pack would not write\n");
	}
	free(pack);
	if (fzn_node_files_put(st->files, scratch, &ref) != FZN_NODE_FILES_OK) {
		(void)unlink(scratch);
		return REPLY("error the pack would not be put\n");
	}
	(void)unlink(scratch);
	return save_pack(st, &ref, m.name, m.name_len, reply, cap);
}

struct listing {
	const fzn_node_stickers_t *st;
	char *reply;
	size_t cap, at, count;
	int over;
};

static void list_one(void *ctx, const fzn_setting_t *s, fzn_setting_rank_t rank)
{
	struct listing *l = ctx;
	fzn_node_file_ref_t ref;
	char name[FZN_SETTING_VALUE_MAX], root_hex[2u * FZN_BLOB_HASH_LEN + 1u];
	uint64_t held_len = 0;
	int held, k;

	(void)rank;
	if (!s->set || s->key_len != KEY_LEN || memcmp(s->key, KEY_PREFIX, KEY_PREFIX_LEN) != 0)
		return;
	if (s->scope == FZN_SCOPE_ESTATE
	    && (!l->st->settings->estate
	        || memcmp(s->about, l->st->settings->estate, FZN_PUBKEY_LEN) != 0))
		return;
	if (s->scope == FZN_SCOPE_HOST
	    && (!l->st->host || memcmp(s->about, l->st->host, FZN_PUBKEY_LEN) != 0))
		return;
	if (s->scope != FZN_SCOPE_ESTATE && s->scope != FZN_SCOPE_HOST)
		return;
	if (!read_value(s->value, s->value_len, &ref, name, sizeof(name)))
		return;
	held = fzn_node_files_held(l->st->files, ref.root, &held_len) == FZN_NODE_FILES_OK;
	hex_of(ref.root, FZN_BLOB_HASH_LEN, root_hex);
	k = snprintf(l->reply + l->at, l->cap - l->at, " %s,%llu,%s,%d,%s", root_hex,
	             (unsigned long long)ref.length, name, held,
	             s->scope == FZN_SCOPE_ESTATE ? "estate" : "host");
	if (k < 0 || (size_t)k >= l->cap - l->at) {
		l->over = 1;
		return;
	}
	l->at += (size_t)k;
	l->count++;
}

static size_t list_saved(const fzn_node_stickers_t *st, char *reply, size_t cap)
{
	static char rows[16384];
	struct listing l;

	memset(&l, 0, sizeof(l));
	l.st = st;
	l.reply = rows;
	l.cap = sizeof(rows);
	rows[0] = '\0';
	if (fzn_node_settings_each(st->settings, list_one, &l) != FZN_NODE_SETTINGS_OK)
		return REPLY("error the settings would not list\n");
	if (l.over)
		return REPLY("error the list does not fit a reply\n");
	{
		int k = snprintf(reply, cap, "ok %zu%s\n", l.count, rows);

		if (k < 0 || (size_t)k >= cap)
			return REPLY("error the list does not fit a reply\n");
		return (size_t)k;
	}
}

static size_t list_pack(const fzn_node_stickers_t *st, const fzn_node_file_ref_t *ref,
                        char *reply, size_t cap)
{
	static fzn_sticker_manifest_t m;
	const uint8_t *data;
	size_t data_len, i, at;
	uint8_t *bytes = pack_of(st, ref, &m, &data, &data_len);

	if (!bytes)
		return REPLY("error that pack is not here whole, or is no pack\n");
	at = REPLY("ok %zu", m.count);
	for (i = 0; i < m.count && at < cap; i++) {
		char desc[3u * FZN_STICKER_DESC_MAX + 1u];
		size_t d = 0;

		(void)fzn_escape((const uint8_t *)m.entries[i].description, m.entries[i].description_len,
		                 desc, sizeof(desc) - 1u, &d);
		desc[d] = '\0';
		at += (size_t)snprintf(reply + at, cap - at, " %u,%u,%u,%s", (unsigned)m.entries[i].id,
		                       (unsigned)m.entries[i].type, (unsigned)m.entries[i].flags, desc);
	}
	free(bytes);
	if (at + 1u >= cap)
		return REPLY("error the list does not fit a reply\n");
	return at + (size_t)snprintf(reply + at, cap - at, "\n");
}

static const fzn_sticker_entry_t *entry_of(const fzn_sticker_manifest_t *m, unsigned long id)
{
	size_t i;

	for (i = 0; i < m->count; i++)
		if (m->entries[i].id == id)
			return &m->entries[i];
	return NULL;
}

static int id_of(const uint8_t *w, size_t n, unsigned long *id)
{
	size_t i;

	if (!n || n > 5u)
		return 0;
	*id = 0;
	for (i = 0; i < n; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		*id = *id * 10u + (unsigned long)(w[i] - '0');
	}
	return *id <= 0xffffu;
}

static size_t get_sticker(const fzn_node_stickers_t *st, const fzn_node_file_ref_t *ref,
                          const uint8_t **at, size_t *left, char *reply, size_t cap)
{
	static const char *const ROLES[] = { "thumb", "inline", "main", "popup" };
	static fzn_sticker_manifest_t m;
	const fzn_sticker_entry_t *e;
	const fzn_sticker_rendition_t *x;
	const uint8_t *w, *data;
	size_t n, data_len, i;
	unsigned long id;
	uint8_t *bytes;

	if (!next_word(at, left, &w, &n) || !id_of(w, n, &id))
		return REPLY("malformed get sticker PACK ID [ROLE PATH]\n");
	if (!(bytes = pack_of(st, ref, &m, &data, &data_len)))
		return REPLY("error that pack is not here whole, or is no pack\n");
	if (!(e = entry_of(&m, id))) {
		free(bytes);
		return REPLY("error that pack has no sticker %lu\n", id);
	}
	/* THE REFERENCE, what a message carries. */
	if (!next_word(at, left, &w, &n)) {
		fzn_sticker_ref_t sr;
		char text[FZN_STICKER_REF_MAX + 1u];
		size_t len = 0;

		memset(&sr, 0, sizeof(sr));
		memcpy(sr.root, ref->root, FZN_BLOB_HASH_LEN);
		memcpy(sr.key, ref->key, FZN_STICKER_KEY_LEN);
		sr.length = ref->length;
		sr.id = e->id;
		memcpy(sr.description, e->description, e->description_len);
		sr.description_len = e->description_len;
		free(bytes);
		if (!fzn_sticker_ref_format(&sr, text, sizeof(text), &len))
			return REPLY("error the reference would not write\n");
		return REPLY("ok %s\n", text);
	}
	/* A RENDITION, written out for a client to draw. */
	for (i = 0; i < 4u && !(n == strlen(ROLES[i]) && memcmp(w, ROLES[i], n) == 0); i++)
		;
	{
		const uint8_t *p;
		size_t p_len;
		char path[1024];

		if (i == 4u || !next_word(at, left, &p, &p_len) || *left || p_len >= sizeof(path)
		    || p[0] != '/') {
			free(bytes);
			return REPLY("malformed get sticker PACK ID ROLE PATH, ROLE thumb, inline, main "
			             "or popup, PATH absolute\n");
		}
		memcpy(path, p, p_len);
		path[p_len] = '\0';
		x = fzn_sticker_pick(e, (fzn_sticker_role_t)(i + 1u));
		if (!x || !spill(path, data + x->offset, x->len)) {
			free(bytes);
			return REPLY("error the rendition would not write: %s\n",
			             errno == EEXIST ? "the path exists" : "the path is not writable");
		}
		free(bytes);
		return REPLY("ok %u %u %u\n", (unsigned)x->format, (unsigned)x->width,
		             (unsigned)x->height);
	}
}

static size_t remove_sticker(const fzn_node_stickers_t *st, const uint8_t *w, size_t n,
                             char *reply, size_t cap)
{
	uint8_t root[FZN_BLOB_HASH_LEN], key[KEY_LEN], value[FZN_SETTING_VALUE_MAX];
	fzn_setting_rank_t rank;
	size_t len = 0;
	int any = 0;

	if (n != 2u * FZN_BLOB_HASH_LEN || !unhex(w, n, root))
		return REPLY("malformed remove sticker ROOT\n");
	cell_key(root, key);
	/* EACH CELL THAT HOLDS IT, cleared: the estate's, and this host's. */
	if (st->settings->estate
	    && fzn_node_settings_get(st->settings, FZN_SCOPE_ESTATE, st->settings->estate, key,
	                             sizeof(key), value, &len, &rank)) {
		if (fzn_node_settings_write(st->settings, FZN_SCOPE_ESTATE, st->settings->estate, key,
		                            sizeof(key), 0, NULL, 0u) != FZN_NODE_SETTINGS_OK)
			return REPLY("error this host may not change the estate's stickers\n");
		any = 1;
	}
	if (st->host
	    && fzn_node_settings_get(st->settings, FZN_SCOPE_HOST, st->host, key, sizeof(key), value,
	                             &len, &rank)) {
		if (fzn_node_settings_write(st->settings, FZN_SCOPE_HOST, st->host, key, sizeof(key), 0,
		                            NULL, 0u) != FZN_NODE_SETTINGS_OK)
			return REPLY("error the pack would not be forgotten\n");
		any = 1;
	}
	return any ? REPLY("ok\n") : REPLY("error no such pack is saved\n");
}

size_t fzn_node_stickers_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t cap)
{
	const fzn_node_stickers_t *st = ctx;
	const uint8_t *at = request->arg, *subject, *w;
	size_t left = request->arg_len, subject_len, n;
	fzn_node_file_ref_t ref;

	if (!at || !next_word(&at, &left, &subject, &subject_len) || subject_len != 7u
	    || memcmp(subject, "sticker", 7u) != 0)
		return 0;
	if (request->parsed != FZN_VERB_PUT && request->parsed != FZN_VERB_LIST
	    && request->parsed != FZN_VERB_GET && request->parsed != FZN_VERB_REMOVE
	    && request->parsed != FZN_VERB_ADD)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return REPLY("denied stickers are this node's own user's\n");
	if (!st || !st->files || !st->settings)
		return REPLY("error this node keeps no stickers\n");
	if (request->parsed == FZN_VERB_LIST && !next_word(&at, &left, &w, &n))
		return list_saved(st, reply, cap);
	if (request->parsed == FZN_VERB_LIST && left == 0u)
		return pack_named(st, w, n, &ref) ? list_pack(st, &ref, reply, cap)
		                                  : REPLY("error no such pack\n");
	if (request->parsed == FZN_VERB_LIST)
		return REPLY("malformed list sticker [PACK]\n");
	if (!next_word(&at, &left, &w, &n))
		return REPLY("malformed %s sticker ...\n", request->parsed == FZN_VERB_PUT   ? "put"
		                                           : request->parsed == FZN_VERB_GET ? "get"
		                                           : request->parsed == FZN_VERB_ADD ? "add"
		                                                                              : "remove");
	if (request->parsed == FZN_VERB_PUT)
		return left ? REPLY("malformed put sticker SPEC\n") : put_sticker(st, w, n, reply, cap);
	if (request->parsed == FZN_VERB_ADD)
		return left ? REPLY("malformed add sticker REF\n") : add_sticker(st, w, n, reply, cap);
	if (request->parsed == FZN_VERB_REMOVE)
		return left ? REPLY("malformed remove sticker ROOT\n")
		            : remove_sticker(st, w, n, reply, cap);
	if (!pack_named(st, w, n, &ref))
		return REPLY("error no such pack\n");
	return get_sticker(st, &ref, &at, &left, reply, cap);
}
