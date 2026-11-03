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

/* ROOM FOR STICKERS, the caller's since sec 702. */
#define ROOM 80u

static fzn_sticker_entry_t m_room[ROOM], back_room[ROOM], bent_room[ROOM];
static fzn_sticker_manifest_t m = { "", 0, 0, m_room, ROOM, 0 },
                              back = { "", 0, 0, back_room, ROOM, 0 };
static const uint8_t *art[ROOM][FZN_STICKER_RENDITIONS_MAX];
static uint32_t art_len[ROOM][FZN_STICKER_RENDITIONS_MAX];
static const uint8_t *sound[ROOM];
static uint32_t sound_len[ROOM];

/* `m` copied into room of its own, so bending the copy leaves `m` alone. */
static fzn_sticker_manifest_t copy_of(const fzn_sticker_manifest_t *from)
{
	fzn_sticker_manifest_t to = *from;

	memcpy(bent_room, from->entries, from->count * sizeof(from->entries[0]));
	to.entries = bent_room;
	to.cap = ROOM;
	return to;
}
static uint8_t pack[4096];
static size_t pack_len;

/* EACH FILE A SPEC NAMES as a few bytes saying which it is. */
static void fill_art(const fzn_sticker_manifest_t *mm)
{
	static uint8_t bytes[ROOM][FZN_STICKER_RENDITIONS_MAX + 1u][8];
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
	copy[0] = 3u;
	CHECK(!fzn_sticker_pack_open(copy, pack_len, &back, &data, &data_len), "version 3 opened");
	CHECK(!fzn_sticker_pack_open(pack, pack_len - 1u, &back, &data, &data_len)
	              && !fzn_sticker_pack_open(pack, pack_len + 1u, &back, &data, &data_len),
	      "a pack cut short, or with a byte after it, opened");

	/* EACH RULE, BY BUILDING WHAT BREAKS IT: building opens what it built. */
	bent = copy_of(&m);
	bent.entries[1].id = 1u;
	CHECK(!build(&bent), "two stickers with one id built");
	bent = copy_of(&m);
	memcpy(bent.entries[1].description, bent.entries[0].description, sizeof(bent.entries[0].description));
	bent.entries[1].description_len = bent.entries[0].description_len;
	/* DESCRIPTIONS MAY REPEAT since sec 702, and may be left out. */
	CHECK(build(&bent), "two stickers with one description did not build");
	bent = copy_of(&m);
	bent.entries[0].description_len = 0;
	CHECK(build(&bent) && fzn_sticker_pack_open(pack, pack_len, &back, &data, &data_len)
	              && back.entries[0].description_len == 0u,
	      "a sticker with no description did not build and open");
	bent = copy_of(&m);
	bent.entries[0].id = 0;
	CHECK(!build(&bent), "a sticker with id 0 built");
	bent = copy_of(&m);
	bent.entries[1].audio_path_len = 0;
	CHECK(!build(&bent), "a sound flag with no sound built");
	bent = copy_of(&m);
	bent.entries[2].text_w = 0;
	CHECK(!build(&bent), "a message sticker with no box built");
	bent = copy_of(&m);
	bent.entries[0].type = FZN_STICKER_EMOJI;
	bent.entries[0].flags = FZN_STICKER_FLAG_BIG;
	CHECK(!build(&bent), "a big emoji built");
	bent = copy_of(&m);
	bent.entries[0].flags = 0x0008u;
	CHECK(!build(&bent), "an unknown flag built");
	bent = copy_of(&m);
	bent.entries[0].type = 8u;
	CHECK(!build(&bent), "an unknown type built");
	bent = copy_of(&m);
	bent.entries[0].description[3] = '\n';
	CHECK(!build(&bent), "a description with a line break built");
	bent = copy_of(&m);
	bent.entries[0].renditions[0].width = 0;
	CHECK(!build(&bent), "a rendition with no width built");

	/* TWO OF ONE ID, written by hand, since a build refuses them before it
	 * opens anything: sticker 7's id made 2. */
	CHECK(build(&m), "fixture: the pack, for its ids");
	{
		static const uint8_t SEVEN[] = { 0, 0, 0, 0, 0, 0, 0, 7u, 0, 0, 0, 0, 0, 0, 0, 0,
		                                 FZN_STICKER_MESSAGE };
		size_t k, found = 0;

		memcpy(copy, pack, pack_len);
		for (k = 0; k + sizeof(SEVEN) <= pack_len; k++)
			if (memcmp(copy + k, SEVEN, sizeof(SEVEN)) == 0) {
				copy[k + 7u] = 2u;
				found++;
			}
		CHECK(found == 1u && !fzn_sticker_pack_open(copy, pack_len, &back, &data, &data_len),
		      "a pack holding two stickers of one id opened");
	}

	/* A RANGE PAST THE DATA, written by hand: offset of sticker 1's first
	 * rendition moved beyond the data area. Built again first: a refused
	 * build above has written into the buffer before refusing. */
	CHECK(build(&m), "fixture: the pack again");
	{
		size_t at = 1u + 8u + 1u + m.name_len + 4u + 8u + 8u + 1u + 2u + 1u
		            + m.entries[0].description_len + 1u + (1u + 4u) + (1u + 11u) + 10u + 8u + 1u
		            + 6u;

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
	bent = copy_of(&m);
	bent.entries[0].description[0] = ' ';
	CHECK(!fzn_sticker_spec_format(&bent, text, sizeof(text), &len, err, sizeof(err))
	              && strstr(err, "sticker 1: the description begins or ends with a space"),
	      "a value the text cannot carry back was written, or the refusal named nothing");
	/* A KIND THAT DOES NOT USE ITS BOX KEEPS IT. */
	bent = copy_of(&m);
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
	/* NO TEXT IS REFUSED. Its end, `text + len`, was once reckoned before
	 * the check, arithmetic on a null pointer that cppcheck named. gcc's
	 * UBSan did not report that order here, so this holds the refusal,
	 * not the fix. */
	{
		static fzn_sticker_manifest_t none;
		char why[64];

		CHECK(!fzn_sticker_spec_parse(NULL, 5u, &none, why, sizeof(why)),
		      "a spec with no text was taken");
	}
	/* NO NAME, NO DESCRIPTION AND NO ID are all taken since sec 702. */
	{
		static const char BARE[] = "sticker static\nmain png 1 1 a.png\n";
		char why[96];

		CHECK(fzn_sticker_spec_parse(BARE, sizeof(BARE) - 1u, &back, why, sizeof(why))
		              && back.count == 1u && back.name_len == 0u && back.entries[0].id == 0u,
		      "a spec with no name, description or id was refused");
	}
	CHECK(spec_refused("sticker 0 static\n", "a sticker id is a number")
	              && spec_refused("sticker 18446744073709551616 static\n",
	                              "a sticker id is a number")
	              && spec_refused("sticker 07 static\n", "a sticker id is a number"),
	      "an id of 0, past 64 bits or with a leading zero was taken");
	CHECK(spec_refused("line_package x\n", "line_package needs")
	              && spec_refused("sticker 1 static\nline_id 0\n", "line_id needs"),
	      "LINE's ids, malformed, were taken");
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
	ref.id = 18446744073709551615u;
	ref.length = 4321u;
	memcpy(ref.description, "a cat, waving", 13u);
	ref.description_len = 13u;
	CHECK(fzn_sticker_ref_format(&ref, text, sizeof(text), &len)
	              && strncmp(text, "fzn:sticker/000102", 18u) == 0 && len == strlen(text),
	      "a reference was not written as fzn:sticker");
	CHECK(strstr(text, "/4321/18446744073709551615 a cat, waving") != NULL,
	      "the length and the id are not where the reference says");
	CHECK(fzn_sticker_ref_parse(text, len, &got) && got.id == UINT64_MAX && got.length == 4321u
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
		CHECK(fzn_sticker_ref_parse(old, n, &got) && got.id == UINT64_MAX && got.length == 0u
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
		/* ONE SPELLING: no leading zero in the length or the id; an id of
		 * 0 is still one digit. */
		n = snprintf(big, sizeof(big), "%.*s/04321/%s", (int)head, text, cut + 6);
		CHECK(n > 0 && !fzn_sticker_ref_parse(big, (size_t)n, &got),
		      "a length with a leading zero was read");
		n = snprintf(big, sizeof(big), "%.*s/4321/07 a cat, waving", (int)head, text);
		CHECK(n > 0 && !fzn_sticker_ref_parse(big, (size_t)n, &got),
		      "an id with a leading zero was read");
		n = snprintf(big, sizeof(big), "%.*s/4321/0 a cat, waving", (int)head, text);
		CHECK(n > 0 && !fzn_sticker_ref_parse(big, (size_t)n, &got), "an id of 0 was read");
		n = snprintf(big, sizeof(big), "%.*s/4321/18446744073709551616 a cat, waving", (int)head,
		             text);
		CHECK(n > 0 && !fzn_sticker_ref_parse(big, (size_t)n, &got),
		      "an id past 64 bits was read");
	}
	/* WHAT IS NO REFERENCE. */
	CHECK(!fzn_sticker_ref_parse("fzn:sticker/", 12u, &got)
	              && !fzn_sticker_ref_parse(text, len - 13u, &got),
	      "a reference with nothing after its scheme, or a space and no description, was read");
	/* NO DESCRIPTION, sec 702: the reference ends at the id. */
	CHECK(fzn_sticker_ref_parse(text, len - 13u - 1u, &got) && got.id == UINT64_MAX
	              && got.description_len == 0u,
	      "a reference ending at its id was not read");
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
	CHECK(fzn_sticker_ref_format(&ref, text, sizeof(text), &len)
	              && strcmp(text + len - 21u, "/18446744073709551615") == 0,
	      "a reference with no description was not written ending at its id");
	ref.description_len = 13u;
	ref.id = 0;
	CHECK(!fzn_sticker_ref_format(&ref, text, sizeof(text), &len),
	      "a reference with id 0 was written");
	ref.id = 5u;
	ref.length = 0;
	CHECK(!fzn_sticker_ref_format(&ref, text, sizeof(text), &len),
	      "a reference with no length was written");
}

/* A STICKER'S WORDS, sec 830: in fuzzypickles' form, `:TEXT` after the id,
 * one spelling each, and only words a person could have typed. */
static void test_a_references_words(void)
{
	fzn_sticker_ref_t ref, got;
	char text[FZN_STICKER_REF_MAX + 1u], bent[FZN_STICKER_REF_MAX + 1u];
	size_t len = 0, i;

	memset(&ref, 0, sizeof(ref));
	for (i = 0; i < FZN_STICKER_ROOT_LEN; i++)
		ref.root[i] = ref.key[i] = (uint8_t)i;
	ref.id = 7u;
	ref.length = 99u;
	memcpy(ref.description, "a sign", 6u);
	ref.description_len = 6u;
	memcpy(ref.text, "Hej d\xc3\xa5!", 8u);
	ref.text_len = 8u;
	CHECK(fzn_sticker_ref_format(&ref, text, sizeof(text), &len)
	              && strstr(text, "/99/7:Hej%20d%C3%A5%21 a sign") != NULL,
	      "a sticker's words were not written escaped after its id");
	CHECK(fzn_sticker_ref_parse(text, len, &got) && got.text_len == 8u
	              && memcmp(got.text, "Hej d\xc3\xa5!", 8u) == 0 && got.id == 7u
	              && got.description_len == 6u,
	      "a sticker's words did not read back");
	/* ONE SPELLING: a lower-case escape, an escaped plain byte, a raw byte
	 * that is escaped, and no words after the colon are each refused. */
	{
		static const char *const BENT[][2] = {
			{ "%C3%A5", "%c3%a5" }, { "Hej", "%48ej" }, { "%21", "!" }, { "Hej%20d%C3%A5%21", "" },
			{ "%21", "%07" }, { "%C3%A5", "%C3" },
		};

		for (i = 0; i < sizeof(BENT) / sizeof(BENT[0]); i++) {
			char *at;

			memcpy(bent, text, len + 1u);
			at = strstr(bent, BENT[i][0]);
			if (!at)
				continue;
			memmove(at + strlen(BENT[i][1]), at + strlen(BENT[i][0]),
			        strlen(at + strlen(BENT[i][0])) + 1u);
			memcpy(at, BENT[i][1], strlen(BENT[i][1]));
			CHECK(!fzn_sticker_ref_parse(bent, strlen(bent), &got),
			      "words in another spelling, or no client could draw, were read as a "
			      "reference");
		}
	}
	/* WORDS NOBODY TYPED: a control character, and bytes that are not UTF-8,
	 * neither written nor read. */
	memcpy(ref.text, "a\x07b", 3u);
	ref.text_len = 3u;
	CHECK(!fzn_sticker_ref_format(&ref, text, sizeof(text), &len),
	      "words holding a control character were written");
	ref.text[0] = (char)0xc3;
	ref.text_len = 1u;
	CHECK(!fzn_sticker_ref_format(&ref, text, sizeof(text), &len),
	      "words cut inside a character were written");
	/* AT MOST 84 BYTES, and a reference no longer than a message. */
	memset(ref.text, 'w', FZN_STICKER_TEXT_MAX);
	ref.text_len = FZN_STICKER_TEXT_MAX;
	CHECK(fzn_sticker_ref_format(&ref, text, sizeof(text), &len)
	              && len <= FZN_STICKER_REF_SENT_MAX && fzn_sticker_ref_parse(text, len, &got)
	              && got.text_len == FZN_STICKER_TEXT_MAX,
	      "the longest plain words did not make a reference, or it read back short");
	/* Every byte escaped, and the longest length, id and description:
	 * 518 bytes. */
	ref.length = UINT64_MAX;
	ref.id = UINT64_MAX;
	memset(ref.text, ' ', FZN_STICKER_TEXT_MAX);
	memset(ref.description, 'd', FZN_STICKER_DESC_MAX);
	ref.description_len = FZN_STICKER_DESC_MAX;
	CHECK(!fzn_sticker_ref_format(&ref, text, sizeof(text), &len),
	      "a reference longer than a message was written");
	/* FUZZYPICKLES' FORM WITH WORDS is read too. */
	{
		const char *fzp = "fzp:sticker/"
		                  "0000000000000000000000000000000000000000000000000000000000000000/"
		                  "0000000000000000000000000000000000000000000000000000000000000000/"
		                  "3:hi%20there a wave";

		CHECK(fzn_sticker_ref_parse(fzp, strlen(fzp), &got) && got.id == 3u && got.length == 0u
		              && got.text_len == 8u && memcmp(got.text, "hi there", 8u) == 0,
		      "fuzzypickles' reference with words was not read");
	}
}

/* THE DIGESTS a BLAKE2b-256 gives the fixture's art, from Python's hashlib:
 * sticker 1's renditions end to end, and sticker 2's rendition then its
 * sound. A hash that is not one of these is asked something else. */
static const uint8_t DIGEST_1[32] = {
	0x8a, 0x05, 0x76, 0xf0, 0xe8, 0x2a, 0xd9, 0xad, 0x7a, 0x3c, 0xa0, 0x56, 0x81, 0xc1, 0x16, 0x05,
	0x7e, 0x07, 0xf3, 0x8a, 0x82, 0x40, 0x5e, 0xb8, 0xce, 0x90, 0x9c, 0x23, 0x4d, 0x90, 0xc1, 0x4e,
};
static const uint8_t DIGEST_2[32] = {
	0xc0, 0x2b, 0xf1, 0xfb, 0x8b, 0x19, 0xf7, 0x94, 0x18, 0x59, 0x3a, 0x72, 0x0b, 0x30, 0xfd, 0x08,
	0x66, 0xdb, 0xc2, 0x41, 0x84, 0x6b, 0x01, 0x25, 0xee, 0xbb, 0xa7, 0xd8, 0x19, 0x6f, 0x10, 0x24,
};
static int hashed_wrong, hash_zero;

static int fixture_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	if (out_len != 32u)
		return 0;
	if (hash_zero) {
		memset(out, 0, 32u);
		return 1;
	}
	if (in_len == 11u && memcmp(in, "AAAAABBBBBB", 11u) == 0)
		memcpy(out, DIGEST_1, 32u);
	else if (in_len == 13u && memcmp(in, "IIIIIzzzzzzzz", 13u) == 0)
		memcpy(out, DIGEST_2, 32u);
	else {
		hashed_wrong++;
		return 0;
	}
	return 1;
}

/* AN ID FROM THE ART, sec 702, as fuzzypickles derives it: the first 8
 * bytes of BLAKE2b-256 over the renditions in order and then the sound,
 * big endian; a given id kept, and 0 made 1. */
static void test_ids_from_the_art(void)
{
	fzn_sticker_manifest_t d;
	fzn_hash_ops_t h = { fixture_hash, NULL };
	uint8_t scratch[64];

	d = copy_of(&m);
	d.entries[0].id = 0;
	d.entries[1].id = 0;
	fill_art(&d);
	CHECK(fzn_sticker_derive_ids(&d, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                             (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                             (const uint8_t *const *)sound, sound_len, &h, scratch,
	                             sizeof(scratch))
	              && hashed_wrong == 0,
	      "the ids were not derived, or from bytes other than the art in order");
	CHECK(d.entries[0].id == 0x8a0576f0e82ad9adu && d.entries[1].id == 0xc02bf1fb8b19f794u
	              && d.entries[2].id == 7u,
	      "a derived id is not the digest's first 8 bytes, or a given one moved");
	CHECK(build(&d), "a pack of derived ids did not build");
	d.entries[0].id = 0;
	CHECK(!fzn_sticker_derive_ids(&d, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                              (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                              (const uint8_t *const *)sound, sound_len, &h, scratch, 10u),
	      "art past the scratch was hashed");
	hash_zero = 1;
	CHECK(fzn_sticker_derive_ids(&d, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                             (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                             (const uint8_t *const *)sound, sound_len, &h, scratch,
	                             sizeof(scratch))
	              && d.entries[0].id == 1u,
	      "a digest opening with 8 zero bytes did not make id 1");
	hash_zero = 0;
}

/* NO CAP OF 64, sec 702: seventy stickers built and opened, and a reader
 * with too little room told the room it needs, never handed part of it. */
static void test_more_than_64(void)
{
	static char spec[ROOM * 64u];
	fzn_sticker_entry_t few[3];
	fzn_sticker_manifest_t small = { "", 0, 0, few, 3u, 0 };
	const uint8_t *data;
	size_t data_len, at = 0, i;
	char err[96];
	static uint8_t big[16384];
	size_t big_len = 0;

	for (i = 0; i < 70u; i++)
		at += (size_t)snprintf(spec + at, sizeof(spec) - at,
		                       "sticker %zu static\nmain png 1 1 a%zu.png\n", i + 1u, i);
	CHECK(fzn_sticker_spec_parse(spec, at, &m, err, sizeof(err)) && m.count == 70u, err);
	CHECK(!fzn_sticker_spec_parse(spec, at, &small, err, sizeof(err))
	              && FZN_STICKER_TOO_SMALL(&small) && small.count == 70u,
	      "a spec past the room was taken, or did not say the room it needs");
	fill_art(&m);
	CHECK(fzn_sticker_pack_build(&m, (const uint8_t *const(*)[FZN_STICKER_RENDITIONS_MAX])art,
	                             (const uint32_t(*)[FZN_STICKER_RENDITIONS_MAX])art_len,
	                             (const uint8_t *const *)sound, sound_len, big, sizeof(big),
	                             &big_len),
	      "seventy stickers did not build");
	CHECK(fzn_sticker_pack_open(big, big_len, &back, &data, &data_len) && back.count == 70u
	              && back.entries[69].id == 70u,
	      "seventy stickers did not open");
	CHECK(!fzn_sticker_pack_open(big, big_len, &small, &data, &data_len)
	              && FZN_STICKER_TOO_SMALL(&small) && small.count == 70u,
	      "a pack past the room opened, or did not say the room it needs");
	/* A SPEC WRONG AFTER ITS FIRST STICKER, read with too little room, is
	 * wrong, not short of room. */
	CHECK(!fzn_sticker_spec_parse("sticker 1 static\nsticker 2 static\nsideways\n", 41u,
	                              &small, err, sizeof(err))
	              && !FZN_STICKER_TOO_SMALL(&small),
	      "a spec refused for what it says was answered as wanting room");
	big[0] = 9u;
	CHECK(!fzn_sticker_pack_open(big, big_len, &small, &data, &data_len)
	              && !FZN_STICKER_TOO_SMALL(&small),
	      "no pack at all was answered as wanting room");
	/* `m` back to the fixture, for the tests after. */
	CHECK(fzn_sticker_spec_parse(SPEC, sizeof(SPEC) - 1u, &m, err, sizeof(err)), err);
}

/* VERSION 1, still read: 16-bit ids, a count of one byte, LINE's ids
 * absent. One sticker, written by hand. */
static void test_version_1_read(void)
{
	static const uint8_t V1[] = {
		1u, 1u, 'p', 1u,
		0x01u, 0x02u, FZN_STICKER_STATIC, 0u, 0u, 1u, 'd', 0u,
		0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
		0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
		1u, FZN_STICKER_MAIN, FZN_STICKER_PNG, 0u, 1u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u,
		0u, 0u, 0u, 2u, 'x', 'y',
	};
	const uint8_t *data;
	size_t data_len;

	CHECK(fzn_sticker_pack_open(V1, sizeof(V1), &back, &data, &data_len) && back.count == 1u
	              && back.entries[0].id == 0x0102u && back.line_package == 0u
	              && back.name_len == 1u && data_len == 2u,
	      "a version 1 pack was not read");
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
	test_a_references_words();
	test_ids_from_the_art();
	test_more_than_64();
	test_version_1_read();
	test_kinds_and_picks();
	test_the_suite_can_tell_pass_from_fail();

	printf("sticker_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
