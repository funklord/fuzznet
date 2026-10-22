/* sticker/pack.h, sec 680: a spec parsed, built into a pack and opened back;
 * every refusal fuzzypickles' decoder kept; the spec written and read back
 * unchanged; references in both schemes; which fields a kind has; and the
 * rendition picked when the one asked for is missing. */
#include "../pack.h"

#include "../../wire/bytes.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL sticker_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static const char SPEC[] =
        "# cats\n"
        "name  cats and their moods\n"
        "sticker 1 static\n"
        "description a ginger cat waving hello\n"
        "keyword wave\n"
        "keyword hello there\n"
        "inline png 128 128 art/wave.png\n"
        "thumb  png  64  64 art/wave-thumb.png\n"
        "\n"
        "sticker 2 animated big sound\r\n"
        "description the same cat spinning very fast\n"
        "main lottie 320 320 art/spin.json\n"
        "sound art/spin.ogg\n"
        "sticker 7 message\n"
        "description a cat holding a sign\n"
        "main png 240 240 art/sign.png\n"
        "text 12 10 20 200 40\n";

static fzn_sticker_manifest_t m, back;
static const uint8_t *art[FZN_STICKER_PER_PACK_MAX][FZN_STICKER_RENDITIONS_MAX];
static uint32_t art_len[FZN_STICKER_PER_PACK_MAX][FZN_STICKER_RENDITIONS_MAX];
static const uint8_t *sound[FZN_STICKER_PER_PACK_MAX];
static uint32_t sound_len[FZN_STICKER_PER_PACK_MAX];
static uint8_t pack[4096];
static size_t pack_len;

/* EACH FILE A SPEC NAMES as a few bytes saying which it is. */
static void fill_art(const fzn_sticker_manifest_t *mm)
{
	static uint8_t bytes[FZN_STICKER_PER_PACK_MAX][FZN_STICKER_RENDITIONS_MAX + 1u][8];
	size_t i, r;

	memset(art, 0, sizeof(art));
	memset(art_len, 0, sizeof(art_len));
	memset(sound, 0, sizeof(sound));
	memset(sound_len, 0, sizeof(sound_len));
	for (i = 0; i < mm->count; i++) {
		for (r = 0; r < mm->entries[i].rendition_count; r++) {
			memset(bytes[i][r], (int)('A' + i * 8u + r), sizeof(bytes[i][r]));
			art[i][r] = bytes[i][r];
			art_len[i][r] = (uint32_t)(5u + r);
		}
		if (mm->entries[i].audio_path_len) {
			memset(bytes[i][FZN_STICKER_RENDITIONS_MAX], 'z', 8u);
			sound[i] = bytes[i][FZN_STICKER_RENDITIONS_MAX];
			sound_len[i] = 8u;
		}
	}
}

static int build(const fzn_sticker_manifest_t *mm)
{
	fill_art(mm);
	return fzn_sticker_pack_build(mm, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                              (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                              (const uint8_t *const *)sound, sound_len, pack, sizeof(pack),
	                              &pack_len);
}

static void test_a_spec_built_and_opened(void)
{
	char err[96];
	const uint8_t *data;
	size_t data_len, need = 0;
	const fzn_sticker_rendition_t *x;

	CHECK(fzn_sticker_spec_parse(SPEC, sizeof(SPEC) - 1u, &m, err, sizeof(err)), err);
	CHECK(m.count == 3u && m.name_len == 20u && memcmp(m.name, "cats and their moods", 20u) == 0,
	      "the pack name or count is wrong");
	CHECK(m.entries[0].keyword_count == 2u && m.entries[0].keyword_lens[1] == 11u
	              && m.entries[0].rendition_count == 2u
	              && m.entries[0].renditions[1].role == FZN_STICKER_THUMB,
	      "sticker 1's keywords or renditions are wrong");
	CHECK(m.entries[1].type == FZN_STICKER_ANIMATED
	              && m.entries[1].flags == (FZN_STICKER_FLAG_BIG | FZN_STICKER_FLAG_SOUND)
	              && strcmp(m.entries[1].audio_path, "art/spin.ogg") == 0,
	      "a CR-ended sticker line, its flags or its sound were misread");
	CHECK(m.entries[2].text_limit == 12u && m.entries[2].text_h == 40u, "the text box was misread");
	fill_art(&m);
	CHECK(fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                             (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                             (const uint8_t *const *)sound, sound_len, NULL, 0, &need)
	              && need > 0u,
	      "the pack's length was not answered");
	CHECK(build(&m) && pack_len == need, "the pack did not build at the length it said");
	CHECK(pack[0] == FZN_STICKER_VERSION, "the version is not first");
	CHECK(fzn_sticker_pack_open(pack, pack_len, &back, &data, &data_len), "the pack did not open");
	CHECK(back.count == 3u && back.entries[2].id == 7u
	              && back.entries[1].audio_len == 8u && data_len == 5u + 6u + 5u + 8u + 5u,
	      "what opened is not what was built");
	/* EACH RENDITION WHERE ITS BYTES ARE. */
	x = &back.entries[0].renditions[1];
	CHECK(x->len == 6u && data[x->offset] == 'B' && data[x->offset + x->len - 1u] == 'B',
	      "sticker 1's second rendition is not its own bytes");
	CHECK(data[back.entries[1].audio_offset] == 'z', "sticker 2's sound is not its own bytes");
	CHECK(back.entries[0].renditions[0].path_len == 0u, "a pack carried a spec's path");
}

static void test_what_opening_refuses(void)
{
	fzn_sticker_manifest_t bent;
	const uint8_t *data;
	size_t data_len;
	uint8_t copy[4096];

	CHECK(build(&m), "fixture: the pack");
	memcpy(copy, pack, pack_len);
	copy[0] = 2u;
	CHECK(!fzn_sticker_pack_open(copy, pack_len, &back, &data, &data_len), "version 2 opened");
	CHECK(!fzn_sticker_pack_open(pack, pack_len - 1u, &back, &data, &data_len)
	              && !fzn_sticker_pack_open(pack, pack_len + 1u, &back, &data, &data_len),
	      "a pack cut short, or with a byte after it, opened");

	/* EACH RULE, BY BUILDING WHAT BREAKS IT: building opens what it built. */
	bent = m;
	bent.entries[1].id = 1u;
	CHECK(!build(&bent), "two stickers with one id built");
	bent = m;
	memcpy(bent.entries[1].description, bent.entries[0].description, sizeof(bent.entries[0].description));
	bent.entries[1].description_len = bent.entries[0].description_len;
	CHECK(!build(&bent), "two stickers with one description built");
	bent = m;
	bent.entries[1].audio_path_len = 0;
	CHECK(!build(&bent), "a sound flag with no sound built");
	bent = m;
	bent.entries[2].text_w = 0;
	CHECK(!build(&bent), "a message sticker with no box built");
	bent = m;
	bent.entries[0].type = FZN_STICKER_EMOJI;
	bent.entries[0].flags = FZN_STICKER_FLAG_BIG;
	CHECK(!build(&bent), "a big emoji built");
	bent = m;
	bent.entries[0].flags = 0x0008u;
	CHECK(!build(&bent), "an unknown flag built");
	bent = m;
	bent.entries[0].type = 8u;
	CHECK(!build(&bent), "an unknown type built");
	bent = m;
	bent.entries[0].description[3] = '\n';
	CHECK(!build(&bent), "a description with a line break built");
	bent = m;
	bent.entries[0].renditions[0].width = 0;
	CHECK(!build(&bent), "a rendition with no width built");

	/* A RANGE PAST THE DATA, written by hand: offset of sticker 1's first
	 * rendition moved beyond the data area. Built again first: a refused
	 * build above has written into the buffer before refusing. */
	CHECK(build(&m), "fixture: the pack again");
	{
		size_t at = 1u + 1u + m.name_len + 1u + 2u + 1u + 2u + 1u + m.entries[0].description_len
		            + 1u + (1u + 4u) + (1u + 11u) + 10u + 8u + 1u + 6u;

		memcpy(copy, pack, pack_len);
		fzn_put_be32(copy + at, 0x00ffffffu);
		CHECK(fzn_sticker_pack_open(pack, pack_len, &back, &data, &data_len)
		              && !fzn_sticker_pack_open(copy, pack_len, &back, &data, &data_len),
		      "a rendition past the data area opened");
	}
}

static void test_the_spec_round_trips(void)
{
	static char text[4096], again[4096];
	char err[96];
	size_t len = 0, len2 = 0;
	fzn_sticker_manifest_t bent;

	CHECK(fzn_sticker_spec_format(&m, text, sizeof(text), &len, err, sizeof(err)), err);
	CHECK(fzn_sticker_spec_parse(text, len, &back, err, sizeof(err)), err);
	CHECK(fzn_sticker_spec_format(&back, again, sizeof(again), &len2, err, sizeof(err))
	              && len2 == len && memcmp(text, again, len) == 0,
	      "the spec written, read and written again changed");
	CHECK(strstr(text, "sticker 2 animated sound big\n") != NULL,
	      "the flags were not written in table order");
	bent = m;
	bent.entries[0].description[0] = ' ';
	CHECK(!fzn_sticker_spec_format(&bent, text, sizeof(text), &len, err, sizeof(err))
	              && strstr(err, "sticker 1: the description begins or ends with a space"),
	      "a value the text cannot carry back was written, or the refusal named nothing");
	/* A KIND THAT DOES NOT USE ITS BOX KEEPS IT. */
	bent = m;
	bent.entries[2].type = FZN_STICKER_STATIC;
	CHECK(fzn_sticker_spec_format(&bent, text, sizeof(text), &len, err, sizeof(err))
	              && fzn_sticker_spec_parse(text, len, &back, err, sizeof(err))
	              && back.entries[2].text_limit == 12u,
	      "a box its kind does not use was not kept");
}

static int spec_refused(const char *spec, const char *want)
{
	char err[160];

	return !fzn_sticker_spec_parse(spec, strlen(spec), &back, err, sizeof(err))
	       && strstr(err, want) != NULL;
}

static void test_what_a_spec_refuses(void)
{
	CHECK(spec_refused("sticker 1 static\n", "line 1: the pack has no name")
	              || spec_refused("sticker 1 static\n", "no name"),
	      "a spec with no name was taken");
	CHECK(spec_refused("name x\ndescription y\n", "line 2: line comes before any sticker"),
	      "a line before any sticker was taken");
	CHECK(spec_refused("name x\nsticker 1 static\nsticker 1 animated\n",
	                   "line 3: two stickers share one id"),
	      "a repeated id was taken");
	CHECK(spec_refused("name x\nsticker 1 wobbly\n", "line 2: unknown sticker type")
	              && spec_refused("name x\nsticker 1 static loud\n", "unknown flag")
	              && spec_refused("name x\nsticker 1 static\nmain gif 1 1 a.gif\n",
	                              "unknown image format")
	              && spec_refused("name x\nsticker 1 static\nsideways png 1 1 a\n",
	                              "unknown keyword"),
	      "an unknown type, flag, format or keyword was taken");
	CHECK(spec_refused("name x\nsticker 1 static\nmain png 0 1 a.png\n", "width and a height")
	              && spec_refused("name x\nsticker 1 static\ntext 1 2 3\n", "text needs"),
	      "a sizeless rendition or a short text line was taken");
	/* A PATH ABOVE THE SPEC, or absolute: an import reads these files. */
	CHECK(spec_refused("name x\nsticker 1 static\nmain png 1 1 ../etc/passwd\n",
	                   "not inside the spec's directory")
	              && spec_refused("name x\nsticker 1 static\nmain png 1 1 /etc/passwd\n",
	                              "not inside")
	              && spec_refused("name x\nsticker 1 static\nsound a/../../b\n", "not inside")
	              && spec_refused("name x\nsticker 1 static\nmain png 1 1 .hidden\n",
	                              "not inside"),
	      "a path outside the spec's directory was taken");
	CHECK(fzn_sticker_path_ok("art/a.png", 9u) && !fzn_sticker_path_ok("a\\b", 3u)
	              && !fzn_sticker_path_ok("c:x", 3u),
	      "a path's rule is wrong");
}

static void test_references(void)
{
	fzn_sticker_ref_t ref, got;
	char text[FZN_STICKER_REF_MAX + 1u];
	size_t len = 0, i;

	memset(&ref, 0, sizeof(ref));
	for (i = 0; i < FZN_STICKER_ROOT_LEN; i++) {
		ref.root[i] = (uint8_t)i;
		ref.key[i] = (uint8_t)(0xf0u + (i & 15u));
	}
	ref.id = 65535u;
	ref.length = 4321u;
	memcpy(ref.description, "a cat, waving", 13u);
	ref.description_len = 13u;
	CHECK(fzn_sticker_ref_format(&ref, text, sizeof(text), &len)
	              && strncmp(text, "fzn:sticker/000102", 18u) == 0 && len == strlen(text),
	      "a reference was not written as fzn:sticker");
	CHECK(strstr(text, "/4321/65535 a cat, waving") != NULL,
	      "the length and the id are not where the reference says");
	CHECK(fzn_sticker_ref_parse(text, len, &got) && got.id == 65535u && got.length == 4321u
	              && memcmp(got.root, ref.root, 32u) == 0 && memcmp(got.key, ref.key, 32u) == 0
	              && got.description_len == 13u && memcmp(got.description, "a cat, waving", 13u) == 0,
	      "a reference did not read back");
	/* FUZZYPICKLES' SCHEME, read as one of these: no length in it, so 0. */
	{
		char old[FZN_STICKER_REF_MAX + 1u];
		const char *cut = strstr(text, "/4321/");
		size_t head = (size_t)(cut - text), n;

		memcpy(old, text, head);
		memcpy(old + head, cut + 5, len - head - 5u);
		n = len - 5u;
		old[2] = 'p';
		CHECK(fzn_sticker_ref_parse(old, n, &got) && got.id == 65535u && got.length == 0u
		              && got.description_len == 13u,
		      "an fzp:sticker reference was not read, with no length");
		old[2] = 'n';
		CHECK(!fzn_sticker_ref_parse(old, n, &got), "an fzn reference with no length was read");
	}
	text[2] = 'q';
	CHECK(!fzn_sticker_ref_parse(text, len, &got), "an unknown scheme was read");
	text[2] = 'n';
	/* A LENGTH PAST 64 BITS, or of 0. */
	{
		char big[FZN_STICKER_REF_MAX + 32u];
		const char *cut = strstr(text, "/4321/");
		size_t head = (size_t)(cut - text);
		int n;

		n = snprintf(big, sizeof(big), "%.*s/18446744073709551616/%s", (int)head, text, cut + 6);
		CHECK(n > 0 && !fzn_sticker_ref_parse(big, (size_t)n, &got),
		      "a length past 64 bits was read");
		n = snprintf(big, sizeof(big), "%.*s/0/%s", (int)head, text, cut + 6);
		CHECK(n > 0 && !fzn_sticker_ref_parse(big, (size_t)n, &got), "a length of 0 was read");
	}
	/* WHAT IS NO REFERENCE. */
	CHECK(!fzn_sticker_ref_parse("fzn:sticker/", 12u, &got)
	              && !fzn_sticker_ref_parse(text, len - 13u - 1u, &got),
	      "a reference with nothing after its scheme, or no description, was read");
	{
		char bent[FZN_STICKER_REF_MAX + 1u];

		memcpy(bent, text, len);
		bent[len - 2u] = '\n';
		CHECK(!fzn_sticker_ref_parse(bent, len, &got), "a description with a line break was read");
		memcpy(bent, text, len);
		bent[20] = 'G';
		CHECK(!fzn_sticker_ref_parse(bent, len, &got), "a root that is not hex was read");
	}
	CHECK(!fzn_sticker_ref_parse("fzn:sticker/00/00/1 x", 21u, &got), "short fields were read");
	ref.description_len = 0;
	CHECK(!fzn_sticker_ref_format(&ref, text, sizeof(text), &len),
	      "a reference with no description was written");
	ref.description_len = 13u;
	ref.length = 0;
	CHECK(!fzn_sticker_ref_format(&ref, text, sizeof(text), &len),
	      "a reference with no length was written");
}

static void test_kinds_and_picks(void)
{
	fzn_sticker_entry_t e;

	CHECK(fzn_sticker_field_applies(FZN_STICKER_STATIC, 0, FZN_STICKER_FIELD_DESCRIPTION)
	              && !fzn_sticker_field_applies(FZN_STICKER_STATIC, 0, FZN_STICKER_FIELD_AUDIO)
	              && fzn_sticker_field_applies(FZN_STICKER_STATIC, FZN_STICKER_FLAG_SOUND,
	                                           FZN_STICKER_FIELD_AUDIO)
	              && fzn_sticker_field_applies(FZN_STICKER_NAMED, 0, FZN_STICKER_FIELD_TEXT_LIMIT)
	              && !fzn_sticker_field_applies(FZN_STICKER_POPUP, 0, FZN_STICKER_FIELD_TEXT_BOX)
	              && !fzn_sticker_field_applies(FZN_STICKER_ANIMATED, 0,
	                                            FZN_STICKER_FIELD_FLAG_ANIMATED)
	              && !fzn_sticker_field_applies(FZN_STICKER_EMOJI, 0, FZN_STICKER_FIELD_FLAG_BIG)
	              && fzn_sticker_field_applies(FZN_STICKER_POPUP, 0, FZN_STICKER_FIELD_ROLE_POPUP)
	              && !fzn_sticker_field_applies(FZN_STICKER_STATIC, 0,
	                                            (fzn_sticker_field_t)99),
	      "a kind's fields are wrong");
	memset(&e, 0, sizeof(e));
	e.rendition_count = 2u;
	e.renditions[0].role = FZN_STICKER_POPUP_ART;
	e.renditions[1].role = FZN_STICKER_MAIN;
	CHECK(fzn_sticker_pick(&e, FZN_STICKER_POPUP_ART) == &e.renditions[0]
	              && fzn_sticker_pick(&e, FZN_STICKER_THUMB) == &e.renditions[1],
	      "the rendition asked for, or the nearest, was not picked");
	e.rendition_count = 0;
	CHECK(fzn_sticker_pick(&e, FZN_STICKER_MAIN) == NULL, "an entry with nothing gave something");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_a_spec_built_and_opened();
	test_what_opening_refuses();
	test_the_spec_round_trips();
	test_what_a_spec_refuses();
	test_references();
	test_kinds_and_picks();
	test_the_suite_can_tell_pass_from_fail();

	printf("sticker_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
