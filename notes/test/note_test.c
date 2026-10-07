/* note_test -- the note body format, ported from fuzzypickles'
 * core/test/notes_test.c at b419405 with its cases intact, and the blob
 * reference sec 422 gives TEXT_IS_BLOB. */

#include "../note.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL note_test.c:%d: %s\n", line, what);
}

#define CHECK(cond) check_at((cond) ? 1 : 0, __LINE__, #cond)

/* Encode a note and parse it straight back, which most of these need. */
static fzn_note_err_t round_trip(const fzn_note_t *in, uint8_t *buf, size_t cap, size_t *len,
                                 fzn_note_t *out)
{
	fzn_note_err_t err = fzn_note_content(in, buf, cap, len);
	if (err != FZN_NOTE_OK) return err;
	return fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, *len, out);
}

static void test_a_note_survives_the_round_trip(void)
{
	uint8_t buf[512];
	size_t len = 0;
	fzn_note_t in, out;

	memset(&in, 0, sizeof in);
	in.title = (const uint8_t *)"Shopping";
	in.title_len = 8;
	in.text = (const uint8_t *)"milk and bread";
	in.text_len = 14;
	in.labels = (const uint8_t *)"home\0errands";
	in.labels_len = 12;
	in.colour = 0xFFAA0080u;
	in.created_at_ms = 1756000000000ull;
	in.edited_at_ms = 1756000060000ull;
	in.flags = FZN_NOTE_FLAG_PINNED;

	CHECK(round_trip(&in, buf, sizeof buf, &len, &out) == FZN_NOTE_OK);
	CHECK(len == FZN_NOTE_HEADER_LEN + 8 + 14 + 12);

	CHECK(out.version == FZN_NOTE_VERSION);
	CHECK(out.flags == FZN_NOTE_FLAG_PINNED);
	CHECK(out.colour == 0xFFAA0080u);
	CHECK(out.created_at_ms == 1756000000000ull);
	CHECK(out.edited_at_ms == 1756000060000ull);
	CHECK(out.title_len == 8 && memcmp(out.title, "Shopping", 8) == 0);
	CHECK(out.text_len == 14 && memcmp(out.text, "milk and bread", 14) == 0);
	CHECK(out.labels_len == 12);
}

/*
 * THE PARTITION CHECK, which is the only thing making three variable fields
 * safe against `record/`'s one-variable rule.
 *
 * Both directions matter and they fail for different reasons: lengths that
 * sum SHORT describe bytes nobody owns, and lengths that sum LONG describe
 * bytes past the end. One equality refuses both, and this is the test that
 * says so rather than trusting the comment.
 */
static void test_lengths_must_tile_the_body_exactly(void)
{
	uint8_t buf[512];
	size_t len = 0;
	fzn_note_t in, out;

	memset(&in, 0, sizeof in);
	in.title = (const uint8_t *)"t";
	in.title_len = 1;
	in.text = (const uint8_t *)"body";
	in.text_len = 4;

	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_OK);

	/* A gap: text_len one short, so one byte belongs to nobody. */
	buf[FZN_NOTE_OFF_TEXT_LEN + 1] = 3;
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_ERR_PARTITION);

	/* An overrun: text_len one long, so the field runs past the end. */
	buf[FZN_NOTE_OFF_TEXT_LEN + 1] = 5;
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_ERR_PARTITION);

	/* Restored, to show the buffer itself was fine all along. */
	buf[FZN_NOTE_OFF_TEXT_LEN + 1] = 4;
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_OK);

	/* And a truncated body, which is the same check from the other side. */
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len - 1, &out) == FZN_NOTE_ERR_PARTITION);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, FZN_NOTE_HEADER_LEN - 1, &out) ==
	      FZN_NOTE_ERR_SHORT);
}

/*
 * AN UNKNOWN TYPE PARSES AND IS NOT REFUSED, which is the rule most likely to
 * be got wrong and the one that costs a user their notes when it is.
 *
 * A host that refused what it could not name would drop a newer host's nodes
 * on every sync. So an unrecognised type must still yield a readable header
 * -- the layout is this one until a version says otherwise -- while
 * fzn_note_type_known reports honestly that we do not know it.
 */
static void test_an_unknown_type_is_readable_and_not_refused(void)
{
	uint8_t buf[512];
	size_t len = 0;
	fzn_note_t in, out;

	memset(&in, 0, sizeof in);
	in.title = (const uint8_t *)"from a newer host";
	in.title_len = 17;

	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);

	CHECK(!fzn_note_type_known(0x0777));
	CHECK(fzn_note_open(0x0777, buf, len, &out) == FZN_NOTE_OK);
	CHECK(out.title_len == 17 && memcmp(out.title, "from a newer host", 17) == 0);

	/* The types we do know, so the predicate is not vacuously false. */
	CHECK(fzn_note_type_known(FZN_NOTE_TYPE_NOTE));
	CHECK(fzn_note_type_known(FZN_NOTE_TYPE_LIST));
	CHECK(fzn_note_type_known(FZN_NOTE_TYPE_FOLDER));
	CHECK(fzn_note_type_known(FZN_NOTE_TYPE_ATTACHMENT));
}

/*
 * The reserved type is the one value that must not be meaningful: an all-zero
 * body header would otherwise decode as a valid node of a valid type.
 */
static void test_the_reserved_type_is_refused(void)
{
	uint8_t zeros[64];
	fzn_note_t out;

	memset(zeros, 0, sizeof zeros);
	CHECK(!fzn_note_type_known(FZN_NOTE_TYPE_NONE));
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NONE, zeros, sizeof zeros, &out) == FZN_NOTE_ERR_TYPE);

	/* And it is refused BEFORE the version, so an all-zero buffer cannot
	 * reach the layout at all. */
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, zeros, sizeof zeros, &out) == FZN_NOTE_ERR_VERSION);
}

static void test_an_unknown_version_is_refused(void)
{
	uint8_t buf[512];
	size_t len = 0;
	fzn_note_t in, out;

	memset(&in, 0, sizeof in);
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_OK);

	buf[FZN_NOTE_OFF_VERSION] = 2;
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_ERR_VERSION);
}

/*
 * A blob reference of the wrong width names nothing, so it is refused rather
 * than shown -- on both sides, because the decoder cannot tell a truncated
 * reference from an honest one and the encoder is where it has to be stopped.
 * The width is the reference's (root, key and length), not the 32-byte id
 * fuzzypickles' layout reserved and never wrote: that width is now refused.
 */
static void test_a_blob_reference_must_be_a_reference(void)
{
	uint8_t buf[512];
	uint8_t id[FZN_NOTE_BLOB_REF_LEN];
	size_t len = 0;
	fzn_note_t in, out;

	memset(id, 0xAB, sizeof id);
	memset(&in, 0, sizeof in);
	in.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	in.text = id;
	in.text_len = sizeof id;

	CHECK(round_trip(&in, buf, sizeof buf, &len, &out) == FZN_NOTE_OK);
	CHECK(out.text_len == FZN_NOTE_BLOB_REF_LEN);
	CHECK((out.flags & FZN_NOTE_FLAG_TEXT_IS_BLOB) != 0);

	/* The old 32-byte id is no reference. */
	in.text_len = 32;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_ERR_BLOB_LEN);

	/* The encoder refuses a short one. */
	in.text_len = 8;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_ERR_BLOB_LEN);

	/* And so does the decoder, when the flag is set after the fact. */
	in.flags = 0;
	in.text_len = 8;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	buf[FZN_NOTE_OFF_FLAGS] = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_ERR_BLOB_LEN);
}

/*
 * Labels are NUL-SEPARATED and not NUL-terminated, so an empty field is no
 * labels rather than one empty one, and a trailing NUL would mean a real
 * empty label at the end. Getting that boundary wrong is how a label list
 * grows a phantom entry every time it round-trips.
 */
static void test_labels_are_separated_not_terminated(void)
{
	uint8_t buf[512];
	size_t len = 0;
	fzn_note_t in, out;
	const uint8_t *label = NULL;
	size_t label_len = 0;

	memset(&in, 0, sizeof in);
	CHECK(round_trip(&in, buf, sizeof buf, &len, &out) == FZN_NOTE_OK);
	CHECK(fzn_note_label_count(&out) == 0);
	CHECK(fzn_note_label(&out, 0, &label, &label_len) == FZN_NOTE_ERR_SHORT);

	in.labels = (const uint8_t *)"home";
	in.labels_len = 4;
	CHECK(round_trip(&in, buf, sizeof buf, &len, &out) == FZN_NOTE_OK);
	CHECK(fzn_note_label_count(&out) == 1);
	CHECK(fzn_note_label(&out, 0, &label, &label_len) == FZN_NOTE_OK);
	CHECK(label_len == 4 && memcmp(label, "home", 4) == 0);

	in.labels = (const uint8_t *)"home\0errands\0trip";
	in.labels_len = 17;
	CHECK(round_trip(&in, buf, sizeof buf, &len, &out) == FZN_NOTE_OK);
	CHECK(fzn_note_label_count(&out) == 3);
	CHECK(fzn_note_label(&out, 1, &label, &label_len) == FZN_NOTE_OK);
	CHECK(label_len == 7 && memcmp(label, "errands", 7) == 0);
	CHECK(fzn_note_label(&out, 2, &label, &label_len) == FZN_NOTE_OK);
	CHECK(label_len == 4 && memcmp(label, "trip", 4) == 0);
	CHECK(fzn_note_label(&out, 3, &label, &label_len) == FZN_NOTE_ERR_SHORT);

	/* A trailing NUL IS a real empty label -- the separator semantics, said
	 * out loud, so nobody later "fixes" it into a terminator. */
	in.labels = (const uint8_t *)"home\0";
	in.labels_len = 5;
	CHECK(round_trip(&in, buf, sizeof buf, &len, &out) == FZN_NOTE_OK);
	CHECK(fzn_note_label_count(&out) == 2);
	CHECK(fzn_note_label(&out, 1, &label, &label_len) == FZN_NOTE_OK);
	CHECK(label_len == 0);
}

static void test_a_checklist_walks_and_refuses_a_truncated_item(void)
{
	uint8_t buf[512];
	uint8_t items[64];
	size_t len = 0, cursor = 0, n = 0;
	fzn_note_t in, out;
	fzn_note_item_t item;

	/* "milk" unchecked, then "bread" checked. */
	n = 0;
	items[n++] = 0;
	items[n++] = 0;
	items[n++] = 4;
	memcpy(items + n, "milk", 4);
	n += 4;
	items[n++] = FZN_NOTE_ITEM_FLAG_CHECKED;
	items[n++] = 0;
	items[n++] = 5;
	memcpy(items + n, "bread", 5);
	n += 5;

	memset(&in, 0, sizeof in);
	in.text = items;
	in.text_len = n;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_LIST, buf, len, &out) == FZN_NOTE_OK);

	cursor = 0;
	CHECK(fzn_note_item_next(&out, &cursor, &item) == FZN_NOTE_OK);
	CHECK(item.flags == 0 && item.text_len == 4 && memcmp(item.text, "milk", 4) == 0);
	CHECK(fzn_note_item_next(&out, &cursor, &item) == FZN_NOTE_OK);
	CHECK(item.flags == FZN_NOTE_ITEM_FLAG_CHECKED && item.text_len == 5);
	CHECK(memcmp(item.text, "bread", 5) == 0);
	/* A clean end, which is how a caller stops. */
	CHECK(fzn_note_item_next(&out, &cursor, &item) == FZN_NOTE_ERR_SHORT);

	/* An item claiming more than is there is a truncation, not an end --
	 * the distinction the body-level partition check makes, one level down.
	 * Without it a walk would read past the text into the labels. */
	in.text_len = n - 1;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_LIST, buf, len, &out) == FZN_NOTE_OK);
	cursor = 0;
	CHECK(fzn_note_item_next(&out, &cursor, &item) == FZN_NOTE_OK);
	CHECK(fzn_note_item_next(&out, &cursor, &item) == FZN_NOTE_ERR_PARTITION);
}

/*
 * A note that does not fit is refused rather than truncated, and the boundary
 * is exact on both sides of it -- an off-by-one here is a note silently
 * losing its last character.
 */
static void test_the_content_budget_is_exact(void)
{
	static uint8_t big[1024];
	uint8_t buf[1024];
	size_t len = 0;
	fzn_note_t in;

	memset(big, 'x', sizeof big);
	memset(&in, 0, sizeof in);
	in.text = big;

	in.text_len = FZN_NOTE_CONTENT_MAX;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(len == FZN_NOTE_HEADER_LEN + FZN_NOTE_CONTENT_MAX);

	in.text_len = FZN_NOTE_CONTENT_MAX + 1;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_ERR_LEN);

	/* And a buffer too small is a capacity answer, not a length one: the
	 * note is representable, this caller just did not bring room for it. */
	in.text_len = FZN_NOTE_CONTENT_MAX;
	CHECK(fzn_note_content(&in, buf, FZN_NOTE_HEADER_LEN, &len) == FZN_NOTE_ERR_CAPACITY);
}

/*
 * A length past what its own field can carry is refused by the ENCODER, and
 * THE PROBE HAS TO OVERFLOW `need` OR IT PROVES NOTHING.
 *
 * The first version of this test passed 70000 and asserted FZN_NOTE_ERR_LEN,
 * which it got -- from the budget check, not from the guard it meant to
 * exercise. Any single length above 0xFFFF is also above the 470-byte
 * budget, so that probe could never reach the guard, and deleting the guard
 * left the test green. Found by mutation, and it is the same vacuous shape
 * as a gate over an empty file list: a true assertion answered by the wrong
 * code.
 *
 * What the guard actually stops is the sum WRAPPING. At SIZE_MAX the total
 * `28 + n1 + n2 + n3` overflows to a small number, sails past the budget and
 * the capacity checks, and reaches memcpy with a length nothing bounded.
 * That is the case worth a test, and it is the one only this guard catches.
 */
static void test_a_length_that_would_wrap_the_total_is_refused(void)
{
	uint8_t buf[1024];
	size_t len = 0;
	fzn_note_t in;

	memset(&in, 0, sizeof in);
	in.title = buf; /* a valid pointer; the guard returns before reading it */
	in.title_len = (size_t)-1;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_ERR_LEN);

	/* And the ordinary oversize case still answers, by whichever check
	 * reaches it first -- the point is that it is refused, not truncated. */
	memset(&in, 0, sizeof in);
	in.title = buf;
	in.title_len = 70000; /* 70000 & 0xFFFF == 4464, a different note */
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_ERR_LEN);
}

static void test_error_strings_exist_for_every_code(void)
{
	static const fzn_note_err_t all[] = {
		FZN_NOTE_OK,
		FZN_NOTE_ERR_NULL,
		FZN_NOTE_ERR_SHORT,
		FZN_NOTE_ERR_VERSION,
		FZN_NOTE_ERR_PARTITION,
		FZN_NOTE_ERR_CAPACITY,
		FZN_NOTE_ERR_LEN,
		FZN_NOTE_ERR_BLOB_LEN,
		FZN_NOTE_ERR_TYPE,
	};
	for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
		const char *s = fzn_note_err_str(all[i]);
		CHECK(s != NULL);
		CHECK(strcmp(s, "unknown") != 0);
	}
}


/*
 * WHAT THIS BUILD MAY WRITE IS NARROWER THAN WHAT IT MAY READ, and the two
 * predicates must not drift into each other. The interesting case is
 * ATTACHMENT: known, deliberately not writable, and the only known type for
 * which the two answers differ. A test asserting only "unknown is unwritable"
 * would pass with fzn_note_type_writable replaced by fzn_note_type_known.
 */
static void test_writable_is_narrower_than_known(void)
{
	CHECK(fzn_note_type_known(FZN_NOTE_TYPE_ATTACHMENT) == 1);
	CHECK(fzn_note_type_writable(FZN_NOTE_TYPE_ATTACHMENT) == 0);

	CHECK(fzn_note_type_writable(FZN_NOTE_TYPE_NOTE) == 1);
	CHECK(fzn_note_type_writable(FZN_NOTE_TYPE_LIST) == 1);
	CHECK(fzn_note_type_writable(FZN_NOTE_TYPE_FOLDER) == 1);

	/* The reserved value and a type from a newer host: neither originates here. */
	CHECK(fzn_note_type_writable(FZN_NOTE_TYPE_NONE) == 0);
	CHECK(fzn_note_type_writable(0x4242) == 0);

	/* And the two disagree somewhere, which is what makes them two functions.
	 * Derived rather than asserted at one value, so a later type that made
	 * them identical would fail here rather than pass quietly. */
	{
		int differ = 0;
		for (unsigned t = 0; t <= 0x0005u; t++)
			if (fzn_note_type_known((uint16_t)t) != fzn_note_type_writable((uint16_t)t)) differ++;
		CHECK(differ == 1);
	}
}

/*
 * A FOLDER carrying text would render as a note on one host and a container
 * on another. Checked when this host CREATES one; a folder arriving from a
 * newer host with text is still readable, which the next test pins.
 */
static void test_a_folder_may_not_carry_text_or_labels(void)
{
	fzn_note_t note;

	memset(&note, 0, sizeof note);
	note.title = (const uint8_t *)"Recipes";
	note.title_len = 7;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_FOLDER, &note) == FZN_NOTE_OK);

	note.text = (const uint8_t *)"x";
	note.text_len = 1;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_FOLDER, &note) == FZN_NOTE_ERR_PARTITION);

	note.text_len = 0;
	note.labels = (const uint8_t *)"l";
	note.labels_len = 1;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_FOLDER, &note) == FZN_NOTE_ERR_PARTITION);

	/* The same bytes are fine as a note, so the refusal is about the TYPE
	 * rather than about the fields. Without this the test would pass with
	 * shape_ok refusing every note with text. */
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_NOTE, &note) == FZN_NOTE_OK);
}

/*
 * The shape check must reject a list whose items do not parse, or a LIST is
 * just a NOTE with a different number on it.
 */
static void test_a_list_must_hold_items_that_parse(void)
{
	fzn_note_t note;
	static const uint8_t good[] = {0x00, 0x00, 0x04, 'm', 'i', 'l', 'k',
	                               0x01, 0x00, 0x05, 'b', 'r', 'e', 'a', 'd'};
	static const uint8_t truncated[] = {0x00, 0x00, 0x09, 'm', 'i', 'l', 'k'};

	memset(&note, 0, sizeof note);
	note.text = good;
	note.text_len = sizeof good;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_LIST, &note) == FZN_NOTE_OK);

	note.text = truncated;
	note.text_len = sizeof truncated;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_LIST, &note) == FZN_NOTE_ERR_PARTITION);

	/* An empty checklist is a checklist somebody has not filled in yet. */
	note.text = NULL;
	note.text_len = 0;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_LIST, &note) == FZN_NOTE_OK);
}

/* A flag this build does not know is not one it may originate. */
static void test_an_unknown_flag_is_not_written(void)
{
	fzn_note_t note;
	memset(&note, 0, sizeof note);
	note.flags = 0x80u;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_NOTE, &note) == FZN_NOTE_ERR_TYPE);
	note.flags = FZN_NOTE_FLAG_PINNED;
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_NOTE, &note) == FZN_NOTE_OK);
}

/*
 * THE LONG NOTE, sec 422: a note whose text is past the inline budget is
 * written as a reference to a blob, and the reference -- root, content key,
 * length -- round-trips through a note's content exactly. A note that holds
 * no reference has none to read, and a reference to nothing is refused both
 * ways, since an empty text is inline.
 */
static void test_a_blob_reference_round_trips(void)
{
	static uint8_t long_text[5000];
	uint8_t buf[512], field[FZN_NOTE_BLOB_REF_LEN];
	size_t len = 0;
	fzn_note_blob_ref_t ref, back;
	fzn_note_t in, out;

	memset(long_text, 'x', sizeof long_text);
	memset(&in, 0, sizeof in);
	in.title = (const uint8_t *)"Minutes";
	in.title_len = 7;
	in.text = long_text;
	in.text_len = sizeof long_text;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_ERR_LEN);

	memset(ref.root, 0x11, sizeof ref.root);
	memset(ref.key, 0x22, sizeof ref.key);
	ref.length = sizeof long_text;
	CHECK(fzn_note_blob_ref_write(&ref, field) == FZN_NOTE_OK);
	in.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	in.text = field;
	in.text_len = sizeof field;
	in.labels = (const uint8_t *)"work";
	in.labels_len = 4;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_OK);
	CHECK(fzn_note_blob_ref(&out, &back) == FZN_NOTE_OK);
	CHECK(memcmp(back.root, ref.root, sizeof ref.root) == 0);
	CHECK(memcmp(back.key, ref.key, sizeof ref.key) == 0);
	CHECK(back.length == sizeof long_text);
	CHECK(out.title_len == 7 && out.labels_len == 4);

	/* A note that holds no reference has none to read. */
	in.flags = 0;
	in.text = (const uint8_t *)"short";
	in.text_len = 5;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_OK);
	CHECK(fzn_note_blob_ref(&out, &back) == FZN_NOTE_ERR_BLOB_LEN);

	/* A reference to nothing, refused to write and to read. */
	ref.length = 0;
	CHECK(fzn_note_blob_ref_write(&ref, field) == FZN_NOTE_ERR_BLOB_LEN);
	ref.length = 1;
	CHECK(fzn_note_blob_ref_write(&ref, field) == FZN_NOTE_OK);
	memset(field + FZN_NOTE_REF_OFF_LEN, 0, 8);
	in.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	in.text = field;
	in.text_len = sizeof field;
	CHECK(fzn_note_content(&in, buf, sizeof buf, &len) == FZN_NOTE_OK);
	CHECK(fzn_note_open(FZN_NOTE_TYPE_NOTE, buf, len, &out) == FZN_NOTE_OK);
	CHECK(fzn_note_blob_ref(&out, &back) == FZN_NOTE_ERR_BLOB_LEN);
	CHECK(fzn_note_blob_ref(NULL, &back) == FZN_NOTE_ERR_NULL);
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1);
	failures = before;
	checks -= 1;
}

/* `fzn_note_item_put` is the reader's inverse: what it writes walks back
 * item for item, and what it refuses it writes nothing of. sec 442. */
static void test_an_item_written_walks_back(void)
{
	static uint8_t buf[70000];
	static uint8_t big[0x10000];
	fzn_note_t list;
	fzn_note_item_t item;
	size_t used = 0, cursor = 0;

	CHECK(fzn_note_item_put(buf, sizeof(buf), &used, FZN_NOTE_ITEM_FLAG_CHECKED,
	                        (const uint8_t *)"milk", 4u)
	      == FZN_NOTE_OK);
	CHECK(fzn_note_item_put(buf, sizeof(buf), &used, 0u, NULL, 0u) == FZN_NOTE_OK);
	CHECK(used == 3u + 4u + 3u);
	memset(&list, 0, sizeof(list));
	list.text = buf;
	list.text_len = used;
	CHECK(fzn_note_item_next(&list, &cursor, &item) == FZN_NOTE_OK && item.text_len == 4u
	      && memcmp(item.text, "milk", 4u) == 0 && item.flags == FZN_NOTE_ITEM_FLAG_CHECKED);
	CHECK(fzn_note_item_next(&list, &cursor, &item) == FZN_NOTE_OK && item.text_len == 0u
	      && item.flags == 0u);
	CHECK(fzn_note_item_next(&list, &cursor, &item) == FZN_NOTE_ERR_SHORT);
	/* REFUSED, AND NOTHING WRITTEN: a text a u16 cannot carry, and an item
	 * that does not fit. */
	memset(big, 'b', sizeof(big));
	CHECK(fzn_note_item_put(buf, sizeof(buf), &used, 0u, big, 0x10000u) == FZN_NOTE_ERR_LEN
	      && used == 10u);
	CHECK(fzn_note_item_put(buf, 12u, &used, 0u, (const uint8_t *)"ab", 2u)
	              == FZN_NOTE_ERR_CAPACITY
	      && used == 10u);
	CHECK(fzn_note_item_put(buf, 15u, &used, 0u, (const uint8_t *)"ab", 2u) == FZN_NOTE_OK
	      && used == 15u);
	CHECK(fzn_note_item_put(NULL, 15u, &used, 0u, NULL, 0u) == FZN_NOTE_ERR_NULL);
}

/* ---- version 2, sec 513 --------------------------------------------- */

static fzn_note_meta_t a_meta(void)
{
	fzn_note_meta_t m;
	size_t i;

	memset(&m, 0, sizeof(m));
	m.flags = FZN_NOTE_FLAG_PINNED | FZN_NOTE_FLAG_TRASHED;
	m.colour = 0x11223344u;
	m.created_at_ms = 1000u;
	m.edited_at_ms = 2000u;
	for (i = 0; i < FZN_BLOB_HASH_LEN; i++)
		m.content.root[i] = (uint8_t)(0x40u + i);
	for (i = 0; i < FZN_BLOB_KEY_LEN; i++)
		m.content.key[i] = (uint8_t)(0x80u + i);
	m.content.length = 9u + 5u;
	return m;
}

/* THE META: 94 bytes at the offsets the schema states, read back whole. */
static void test_a_meta_round_trips(void)
{
	fzn_note_meta_t m = a_meta(), back;
	uint8_t b[FZN_NOTE_META_LEN];

	CHECK(fzn_note_meta_write(&m, b) == FZN_NOTE_OK);
	CHECK(b[0] == 2u && b[1] == (FZN_NOTE_FLAG_PINNED | FZN_NOTE_FLAG_TRASHED) && b[2] == 0x11u
	      && b[22] == 0x40u && b[54] == 0x80u && b[93] == 14u);
	CHECK(fzn_note_meta_open(FZN_NOTE_TYPE_NOTE, b, sizeof(b), &back) == FZN_NOTE_OK);
	CHECK(back.flags == m.flags && back.colour == m.colour && back.created_at_ms == 1000u
	      && back.edited_at_ms == 2000u && back.content.length == 14u
	      && memcmp(back.content.root, m.content.root, FZN_BLOB_HASH_LEN) == 0
	      && memcmp(back.content.key, m.content.key, FZN_BLOB_KEY_LEN) == 0);
}

/* WHAT A META REFUSES: the reserved type, a short body, version 1, a
 * trailing byte, a flag it does not know -- TEXT_IS_BLOB among them, since
 * every note is a blob -- and a payload shorter than a payload's header. */
static void test_a_meta_refuses(void)
{
	fzn_note_meta_t m = a_meta(), back;
	uint8_t b[FZN_NOTE_META_LEN + 1u];

	CHECK(fzn_note_meta_write(&m, b) == FZN_NOTE_OK);
	CHECK(fzn_note_meta_open(FZN_NOTE_TYPE_NONE, b, FZN_NOTE_META_LEN, &back)
	      == FZN_NOTE_ERR_TYPE);
	CHECK(fzn_note_meta_open(FZN_NOTE_TYPE_NOTE, b, FZN_NOTE_META_LEN - 1u, &back)
	      == FZN_NOTE_ERR_SHORT);
	CHECK(fzn_note_meta_open(FZN_NOTE_TYPE_NOTE, b, sizeof(b), &back) == FZN_NOTE_ERR_PARTITION);
	b[0] = 1u;
	CHECK(fzn_note_meta_open(FZN_NOTE_TYPE_NOTE, b, FZN_NOTE_META_LEN, &back)
	      == FZN_NOTE_ERR_VERSION);
	b[0] = 2u;
	b[1] = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	CHECK(fzn_note_meta_open(FZN_NOTE_TYPE_NOTE, b, FZN_NOTE_META_LEN, &back) == FZN_NOTE_ERR_TYPE);
	b[1] = 0u;
	b[93] = 8u;
	CHECK(fzn_note_meta_open(FZN_NOTE_TYPE_NOTE, b, FZN_NOTE_META_LEN, &back)
	      == FZN_NOTE_ERR_BLOB_LEN);
	m.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	CHECK(fzn_note_meta_write(&m, b) == FZN_NOTE_ERR_TYPE);
	m.flags = 0u;
	m.content.length = 8u;
	CHECK(fzn_note_meta_write(&m, b) == FZN_NOTE_ERR_BLOB_LEN);
}

/* THE PAYLOAD: title, text and labels round-trip, and the label and item
 * helpers read a payload as they read a version-1 note. */
static void test_a_payload_round_trips(void)
{
	static const uint8_t labels[] = "work\0home";
	static uint8_t items[64];
	uint8_t p[256];
	fzn_note_t n, back;
	const uint8_t *label;
	size_t len = 0, used = 0, label_len = 0, cursor = 0;
	fzn_note_item_t item;

	memset(&n, 0, sizeof(n));
	n.title = (const uint8_t *)"groceries";
	n.title_len = 9u;
	CHECK(fzn_note_item_put(items, sizeof(items), &used, FZN_NOTE_ITEM_FLAG_CHECKED,
	                        (const uint8_t *)"milk", 4u) == FZN_NOTE_OK
	      && fzn_note_item_put(items, sizeof(items), &used, 0u, (const uint8_t *)"eggs", 4u)
	                 == FZN_NOTE_OK);
	n.text = items;
	n.text_len = used;
	n.labels = labels;
	n.labels_len = sizeof(labels) - 1u;
	CHECK(fzn_note_payload_write(&n, p, sizeof(p), &len) == FZN_NOTE_OK
	      && len == 9u + 9u + used + n.labels_len);
	CHECK(p[0] == 1u && p[2] == 9u && p[4] == (uint8_t)n.labels_len && p[8] == (uint8_t)used);
	CHECK(fzn_note_payload_open(p, len, &back) == FZN_NOTE_OK && back.title_len == 9u
	      && memcmp(back.title, "groceries", 9u) == 0 && back.flags == 0u);
	CHECK(fzn_note_label_count(&back) == 2u
	      && fzn_note_label(&back, 1u, &label, &label_len) == FZN_NOTE_OK && label_len == 4u
	      && memcmp(label, "home", 4u) == 0);
	CHECK(fzn_note_item_next(&back, &cursor, &item) == FZN_NOTE_OK && item.text_len == 4u
	      && (item.flags & FZN_NOTE_ITEM_FLAG_CHECKED));
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_LIST, &back) == FZN_NOTE_OK);
	CHECK(fzn_note_shape_ok(FZN_NOTE_TYPE_FOLDER, &back) == FZN_NOTE_ERR_PARTITION);

	/* AN EMPTY NOTE is a header and nothing else, still a payload. */
	memset(&n, 0, sizeof(n));
	CHECK(fzn_note_payload_write(&n, p, sizeof(p), &len) == FZN_NOTE_OK && len == 9u
	      && fzn_note_payload_open(p, len, &back) == FZN_NOTE_OK && back.title_len == 0u);
}

/* WHAT A PAYLOAD REFUSES: lengths that do not tile it, a title or labels
 * past the bounds a listing caches, an unknown version, a short header, and
 * a buffer too small to write into. */
static void test_a_payload_refuses(void)
{
	static uint8_t big[FZN_NOTE_LABELS_MAX + 1u];
	uint8_t p[64];
	fzn_note_t n, back;
	size_t len = 0;

	memset(&n, 0, sizeof(n));
	n.title = (const uint8_t *)"t";
	n.title_len = 1u;
	CHECK(fzn_note_payload_write(&n, p, sizeof(p), &len) == FZN_NOTE_OK && len == 10u);
	CHECK(fzn_note_payload_open(p, len + 1u, &back) == FZN_NOTE_ERR_PARTITION);
	CHECK(fzn_note_payload_open(p, len - 1u, &back) == FZN_NOTE_ERR_PARTITION);
	CHECK(fzn_note_payload_open(p, 8u, &back) == FZN_NOTE_ERR_SHORT);
	p[0] = 2u;
	CHECK(fzn_note_payload_open(p, len, &back) == FZN_NOTE_ERR_VERSION);
	p[0] = 1u;
	p[1] = 0x01u; /* a title of 257 */
	p[2] = 0x01u;
	CHECK(fzn_note_payload_open(p, len, &back) == FZN_NOTE_ERR_LEN);
	n.title = big;
	n.title_len = FZN_NOTE_TITLE_MAX + 1u;
	CHECK(fzn_note_payload_write(&n, p, sizeof(p), &len) == FZN_NOTE_ERR_LEN);
	n.title_len = 0u;
	n.labels = big;
	n.labels_len = FZN_NOTE_LABELS_MAX + 1u;
	CHECK(fzn_note_payload_write(&n, p, sizeof(p), &len) == FZN_NOTE_ERR_LEN);
	n.labels_len = 60u;
	CHECK(fzn_note_payload_write(&n, p, sizeof(p), &len) == FZN_NOTE_ERR_CAPACITY);
}

int main(void)
{
	test_a_note_survives_the_round_trip();
	test_lengths_must_tile_the_body_exactly();
	test_an_unknown_type_is_readable_and_not_refused();
	test_the_reserved_type_is_refused();
	test_an_unknown_version_is_refused();
	test_a_blob_reference_must_be_a_reference();
	test_labels_are_separated_not_terminated();
	test_a_checklist_walks_and_refuses_a_truncated_item();
	test_an_item_written_walks_back();
	test_the_content_budget_is_exact();
	test_a_length_that_would_wrap_the_total_is_refused();
	test_error_strings_exist_for_every_code();
	test_writable_is_narrower_than_known();
	test_a_folder_may_not_carry_text_or_labels();
	test_a_list_must_hold_items_that_parse();
	test_an_unknown_flag_is_not_written();
	test_a_blob_reference_round_trips();
	test_the_suite_can_tell_pass_from_fail();
	test_a_meta_round_trips();
	test_a_meta_refuses();
	test_a_payload_round_trips();
	test_a_payload_refuses();

	printf("note_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
