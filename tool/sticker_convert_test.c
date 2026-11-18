/*
 * THE OLD-PACK CONVERTER, sec 1278: `tool/sticker_convert.c` run on packs
 * of each old version, made here from a current one.
 *
 * A version 4 or 3 pack within their caps has a 5's layout, so it comes
 * back byte for byte as the 5 it was made from; a 2 has no pack id and no
 * paint, and comes back as that 5 too when its paint was none, its id
 * taken from its art; a 1, written by hand, comes back a pack the reader
 * opens. A 4 holding more than a 4 could is refused, a 5 is left alone,
 * and a file that is no pack is refused.
 *
 * Retired with the converter: this file and its Makefile lines go too.
 */
#define _POSIX_C_SOURCE 200809L
#include "../sticker/pack.h"
#include "../session/hash_monocypher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures, checks;

#define CHECK(cond, what)                                                                    \
	do {                                                                                     \
		checks++;                                                                            \
		if (!(cond)) {                                                                       \
			failures++;                                                                      \
			fprintf(stderr, "  FAIL sticker_convert_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                                    \
	} while (0)

static char tool[1024], dir[64], in_path[128], out_path[128];
static uint8_t got[8192];
static size_t got_len;

/* RUN THE CONVERTER on `len` bytes: its exit status, the output read back
 * into `got` (none, `got_len` 0, when it wrote nothing). */
static int run(const uint8_t *bytes, size_t len)
{
	char cmd[1400];
	FILE *f;
	int rc;

	(void)unlink(out_path);
	got_len = 0;
	f = fopen(in_path, "wb");
	if (!f || fwrite(bytes, 1u, len, f) != len || fclose(f) != 0)
		return -1;
	(void)snprintf(cmd, sizeof(cmd), "'%s' '%s' '%s' >/dev/null 2>&1", tool, in_path, out_path);
	rc = system(cmd);
	if ((f = fopen(out_path, "rb"))) {
		got_len = fread(got, 1u, sizeof(got), f);
		(void)fclose(f);
	}
	return rc == -1 ? -1 : WEXITSTATUS(rc);
}

int main(int argc, char **argv)
{
	static const char SPEC[] = "name old cats\nsticker 3 static\nkeyword hello there\n"
	                           "description a cat\nmain png 8 8 art/a.png\n"
	                           "sticker 9 animated\nmain png 8 8 art/b.png\n";
	static fzn_sticker_entry_t room[2], back_room[2];
	fzn_sticker_manifest_t m = { "", 0, 0, room, 2u, 0, 0 }, back = { "", 0, 0, back_room, 2u, 0, 0 };
	const uint8_t *art[2][FZN_STICKER_RENDITIONS_MAX] = { { (const uint8_t *)"AAAAAAA" },
	                                                       { (const uint8_t *)"BBBBBBBBB" } };
	const uint32_t art_len[2][FZN_STICKER_RENDITIONS_MAX] = { { 7u }, { 9u } };
	const uint8_t *sound[2] = { NULL, NULL };
	const uint32_t sound_len[2] = { 0u, 0u };
	uint8_t pack[4096], old[4096], scratch[64];
	const uint8_t *data;
	size_t len = 0, data_len, n, at;
	fzn_hash_ops_t hash;
	char err[96], *slash;
	uint64_t id = 0;

	(void)argc;
	fzn_hash_monocypher_init(&hash);
	(void)snprintf(tool, sizeof(tool), "%s", argv[0]);
	slash = strrchr(tool, '/');
	(void)snprintf(slash ? slash + 1 : tool, sizeof(tool) - (size_t)(slash ? slash + 1 - tool : 0),
	               "sticker_convert");
	(void)snprintf(dir, sizeof(dir), "/tmp/fzn-convert-test-XXXXXX");
	if (!mkdtemp(dir)) {
		fprintf(stderr, "  FAIL sticker_convert_test.c: no scratch directory\n");
		return 1;
	}
	(void)snprintf(in_path, sizeof(in_path), "%s/in", dir);
	(void)snprintf(out_path, sizeof(out_path), "%s/out", dir);

	CHECK(fzn_sticker_spec_parse(SPEC, sizeof(SPEC) - 1u, &m, err, sizeof(err)), err);
	CHECK(fzn_sticker_pack_id(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                          (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                          (const uint8_t *const *)sound, sound_len, &hash, scratch,
	                          sizeof(scratch), &id),
	      "fixture: the pack's id");
	m.id = id;
	CHECK(fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                             (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                             (const uint8_t *const *)sound, sound_len, pack, sizeof(pack), &len),
	      "fixture: a current pack");

	/* 4 AND 3: the same layout, so the same bytes back. */
	memcpy(old, pack, len);
	for (old[0] = 4u; old[0] >= 3u; old[0]--)
		CHECK(run(old, len) == 0 && got_len == len && !memcmp(got, pack, len),
		      "a version 4 or 3 pack did not come back as the 5 it was");
	/* 2: no pack id after the version, no paint after each box -- the
	 * layout's ten bytes each sticker, after its box's five numbers. */
	{
		const size_t head = 1u + 8u + 8u + 1u + m.name_len + 4u;
		size_t from = 1u + 8u, i;

		old[0] = 2u;
		n = 1u;
		memcpy(old + n, pack + from, head - from);
		n += head - from;
		from = head;
		for (i = 0; i < m.count; i++) {
			const fzn_sticker_entry_t *e = &room[i];
			size_t k, box = 8u + 8u + 1u + 2u + 1u + e->description_len + 1u;

			for (k = 0; k < e->keyword_count; k++)
				box += 1u + e->keyword_lens[k];
			box += 10u;
			memcpy(old + n, pack + from, box);
			n += box;
			from += box + 10u;
			at = 4u + 4u + 1u + e->rendition_count * 14u;
			memcpy(old + n, pack + from, at);
			n += at;
			from += at;
		}
		memcpy(old + n, pack + from, len - from);
		n += len - from;
		CHECK(run(old, n) == 0 && got_len == len && !memcmp(got, pack, len),
		      "a version 2 pack did not come back as the 5 it was, its id from its art");
	}
	/* 1, BY HAND: a 16-bit id, a description, one rendition. */
	{
		static const uint8_t V1[] = {
			1u, 1u, 'p', 1u,
			0x01u, 0x02u, FZN_STICKER_STATIC, 0u, 0u, 1u, 'd', 0u,
			0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
			0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
			1u, FZN_STICKER_MAIN, FZN_STICKER_PNG, 0u, 1u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u,
			0u, 0u, 0u, 2u, 'x', 'y',
		};

		CHECK(run(V1, sizeof(V1)) == 0 && got[0] == FZN_STICKER_VERSION
		              && fzn_sticker_pack_open(got, got_len, &back, &data, &data_len)
		              && back.count == 1u && back_room[0].id == 0x0102u && back.id != 0u
		              && data_len == 2u && data[0] == 'x',
		      "a version 1 pack did not come back as a current one");
	}
	/* A 4 PAST A 4's CAPS is no 4; a 5 is left; nothing is refused. */
	{
		room[0].keyword_count = 129u;
		for (n = 0; n < 129u; n++) {
			room[0].keywords[n][0] = (char)('a' + n % 26u);
			room[0].keyword_lens[n] = 1u;
		}
		CHECK(fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
		                             (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
		                             (const uint8_t *const *)sound, sound_len, old, sizeof(old),
		                             &n),
		      "fixture: a pack of 129 phrases");
		old[0] = 4u;
		CHECK(run(old, n) == 1 && got_len == 0u, "a version 4 pack of 129 phrases was converted");
	}
	CHECK(run(pack, len) == 0 && got_len == 0u, "a current pack was written again");
	CHECK(run((const uint8_t *)"name not a pack\n", 16u) == 1 && got_len == 0u,
	      "a file that is no pack was converted");

	(void)unlink(in_path);
	(void)unlink(out_path);
	CHECK(rmdir(dir) == 0, "the scratch directory did not go");
	if (failures) {
		fprintf(stderr, "sticker_convert_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("sticker_convert_test: all %d checks passed\n", checks);
	return 0;
}
