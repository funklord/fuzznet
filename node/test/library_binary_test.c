/* node library_binary_test -- the library in binary, sec 1174: the join
 * the client did over three text listings, done on the node, rule for rule
 * -- live claims only, the first value of each label, holders by issuer,
 * held here as the bytes and not the claim, arrival while fetched, rows in
 * the order a file first appears -- and the answer a row each then a
 * STATUS ok. */

#include "../library_binary.h"
#include "../../wire/cmd.h"
#include "../../wire/generated/files_local.h"
#include "../../wire/status.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                       \
	do {                                                                                    \
		checks++;                                                                       \
		if (!(cond)) {                                                                  \
			failures++;                                                             \
			fprintf(stderr, "  FAIL library_binary_test.c:%d: %s\n", __LINE__, what); \
		}                                                                               \
	} while (0)

static fzn_node_catalog_t cat;
static uint8_t host_a[32], host_b[32], host_c[32];
static uint64_t seq = 1;

static fzn_catalog_capability_t capability = FZN_CATALOG_CAP_HOLDER;

static void claim(const uint8_t *issuer, const uint8_t *root, const char *name, const char *value,
                  size_t value_len)
{
	fzn_catalog_assertion_t a;
	uint8_t body[1024];
	size_t len = 0;

	memset(&a, 0, sizeof(a));
	a.name = (const uint8_t *)name;
	a.name_len = strlen(name);
	a.value = (const uint8_t *)value;
	a.value_len = value_len;
	a.attr_class = FZN_CATALOG_LABEL;
	a.scope = FZN_CATALOG_ESTATE;
	a.merge = FZN_CATALOG_DISTINCT;
	a.capability = capability;
	CHECK(fzn_catalog_attribute_encode(&a, body, sizeof(body), &len) == FZN_CATALOG_OK
	              && fzn_node_catalog_take(&cat, issuer, root, seq++, FZN_CATALOG_ATTRIBUTE_KIND, body,
	                                       len)
	                         == FZN_NODE_CATALOG_OK,
	      "a claim was not taken");
}

static void say(const uint8_t *issuer, const uint8_t *root, const char *name, const char *value)
{
	claim(issuer, root, name, value, strlen(value));
}

static void retract(const uint8_t *issuer, const uint8_t *root, const char *name)
{
	CHECK(fzn_node_catalog_take(&cat, issuer, root, seq++, FZN_CATALOG_RETRACT_KIND,
	                            (const uint8_t *)name, strlen(name))
	              == FZN_NODE_CATALOG_OK,
	      "a retraction was not taken");
}

/* THE FILES HERE, as fuzznetd's spool would say them. */
struct here {
	uint8_t root[4][32];
	uint64_t length[4];
	int whole[4];
	uint16_t arriving[4];
	size_t n;
};

static int file_here(void *ctx, const uint8_t root[32], uint64_t *length, int *whole,
                     uint16_t *arriving)
{
	const struct here *h = ctx;
	size_t i;

	for (i = 0; i < h->n; i++)
		if (memcmp(h->root[i], root, 32u) == 0) {
			*length = h->length[i];
			*whole = h->whole[i];
			*arriving = h->arriving[i];
			return 1;
		}
	return 0;
}

static fzn_node_library_row_t rows[16];
static size_t n_rows;

static void take_row(void *ctx, const fzn_node_library_row_t *row)
{
	(void)ctx;
	if (n_rows < 16u)
		rows[n_rows] = *row;
	n_rows++;
}

static void list(const uint8_t *host, struct here *h)
{
	n_rows = 0;
	CHECK(fzn_node_library_each(&cat, host, h ? file_here : NULL, h, take_row, NULL),
	      "the walk did not finish");
}

static int is(const fzn_node_library_row_t *r, const uint8_t *s, size_t len, const char *want)
{
	return len == strlen(want) && memcmp(s, want, len) == 0 && r;
}

static void test_labels_take_the_first_live_value(void)
{
	uint8_t song[32];

	memset(song, 0x50, sizeof(song));
	fzn_node_catalog_init(&cat);
	say(host_a, song, "name", "");
	say(host_b, song, "name", "Holiday");
	say(host_c, song, "name", "Later");
	say(host_a, song, "kind", "video");
	say(host_a, song, "duration", "soon");
	say(host_b, song, "duration", "120000");
	list(host_a, NULL);
	CHECK(n_rows == 1u, "one file was not one row");
	CHECK(is(&rows[0], rows[0].name, rows[0].name_len, "Holiday"),
	      "an empty name was taken over the first that says something");
	CHECK(is(&rows[0], rows[0].kind, rows[0].kind_len, "video"), "the kind was lost");
	CHECK(rows[0].duration_ms == 120000u, "a duration that is no number was not passed over");
	retract(host_b, song, "name");
	list(host_a, NULL);
	CHECK(n_rows == 1u && is(&rows[0], rows[0].name, rows[0].name_len, "Later"),
	      "a retracted name still named the file");
	fzn_node_catalog_free(&cat);
}

static void test_holders_are_issuers_and_the_bytes(void)
{
	uint8_t song[32], film[32], twin[32];
	struct here h;

	memset(song, 0x50, sizeof(song));
	memset(film, 0x60, sizeof(film));
	/* A KEY SHARING host_a's FIRST EIGHT BYTES is one holder, as the
	 * client compares them. */
	memcpy(twin, host_a, 32u);
	twin[31] ^= 1u;
	fzn_node_catalog_init(&cat);
	say(host_a, song, "name", "s");
	say(host_a, song, "kind", "audio");
	say(twin, song, "kind", "audio");
	say(host_b, song, "duration", "5");
	say(host_b, film, "name", "f");
	/* A CLAIM UNDER ANOTHER CAPABILITY names the file and holds nothing
	 * (C8, sec 1189): host_c is no holder of the song for it. */
	capability = FZN_CATALOG_CAP_NONE;
	say(host_c, song, "kind", "audio");
	capability = FZN_CATALOG_CAP_HOLDER;
	memset(&h, 0, sizeof(h));
	memcpy(h.root[0], song, 32u);
	h.length[0] = 20000u;
	h.whole[0] = 1;
	memcpy(h.root[1], film, 32u);
	h.length[1] = 1u << 20;
	h.whole[1] = 1;
	h.n = 2u;
	list(host_a, &h);
	CHECK(n_rows == 2u, "two files were not two rows");
	CHECK(rows[0].holders == 2u, "an issuer's labels, or a key's twin, were counted twice");
	CHECK(rows[0].held_here && rows[0].size == 20000u, "a whole file was not held here");
	CHECK(rows[1].held_here && rows[1].holders == 2u,
	      "a file whole here that this host never claimed did not count it a holder");
	list(host_c, &h);
	CHECK(rows[0].holders == 3u, "the bytes here did not make this host a holder");
	/* A CLAIM IS NOT THE BYTES: claimed here and gone, it is not held. */
	h.n = 0u;
	list(host_a, &h);
	CHECK(!rows[0].held_here && rows[0].holders == 2u && rows[0].size == 0u,
	      "this host's claim read as the bytes being here");
	fzn_node_catalog_free(&cat);
}

static void test_arrival_while_fetched(void)
{
	uint8_t song[32], film[32];
	struct here h;

	memset(song, 0x50, sizeof(song));
	memset(film, 0x60, sizeof(film));
	fzn_node_catalog_init(&cat);
	say(host_b, song, "name", "s");
	say(host_b, film, "name", "f");
	memset(&h, 0, sizeof(h));
	memcpy(h.root[0], song, 32u);
	h.length[0] = 1000u;
	h.arriving[0] = 500u;
	memcpy(h.root[1], film, 32u);
	h.length[1] = 7u;
	h.arriving[1] = 0u;
	h.n = 2u;
	list(host_a, &h);
	CHECK(n_rows == 2u && rows[0].arriving == 500u && !rows[0].held_here && rows[0].size == 1000u
	              && rows[0].holders == 1u,
	      "a file being fetched did not say how far");
	CHECK(rows[1].arriving == 1u, "a fetch begun with nothing did not read as begun");
	fzn_node_catalog_free(&cat);
}

static void test_rows_in_the_order_first_live(void)
{
	uint8_t x[32], y[32], z[32];

	memset(x, 0x11, sizeof(x));
	memset(y, 0x22, sizeof(y));
	memset(z, 0x33, sizeof(z));
	fzn_node_catalog_init(&cat);
	say(host_a, x, "name", "x");
	say(host_a, y, "name", "y");
	say(host_a, z, "name", "z");
	say(host_b, x, "kind", "k");
	retract(host_a, x, "name");
	retract(host_a, z, "name");
	list(host_a, NULL);
	/* x's first claim is dead, its next live after y's: as `list catalog`
	 * lists the live ones, and z has none. */
	CHECK(n_rows == 2u && memcmp(rows[0].root, y, 32u) == 0 && memcmp(rows[1].root, x, 32u) == 0,
	      "the rows were not in the order a file first appears live");
	CHECK(n_rows == 2u && rows[1].name_len == 0u && rows[1].holders == 1u,
	      "a dead claim still named or held the file");
	fzn_node_catalog_free(&cat);
}

static void test_long_labels_are_cut(void)
{
	uint8_t song[32];
	char long_name[400], long_kind[100];

	memset(song, 0x50, sizeof(song));
	memset(long_name, 'n', sizeof(long_name));
	memset(long_kind, 'k', sizeof(long_kind));
	fzn_node_catalog_init(&cat);
	claim(host_a, song, "name", long_name, sizeof(long_name));
	claim(host_a, song, "kind", long_kind, sizeof(long_kind));
	list(host_a, NULL);
	CHECK(n_rows == 1u && rows[0].name_len == FZN_NODE_LIBRARY_NAME_MAX
	              && rows[0].kind_len == FZN_NODE_LIBRARY_KIND_MAX,
	      "a long name or kind was not cut to what a row carries");
	fzn_node_catalog_free(&cat);
}

/* THE ANSWER, as the client reads it. */
static uint8_t said[8][FZN_NODE_LIBRARY_BINARY_MAX];
static size_t said_len[8], n_said;

static int put(void *ctx, const uint8_t *msg, size_t len)
{
	(void)ctx;
	if (n_said >= 8u || len > sizeof(said[0]))
		return 0;
	memcpy(said[n_said], msg, len);
	said_len[n_said++] = len;
	return 1;
}

static void test_the_answer_on_the_wire(void)
{
	static const uint8_t ask[] = { FZN_CMD_FILES, FZN_FILES_LOCAL_OP_LIBRARY };
	uint8_t wrong[FZN_NODE_LIBRARY_BINARY_MAX];
	size_t wrong_len = 0;
	uint8_t song[32], copy[FZN_NODE_LIBRARY_BINARY_MAX];
	char long_name[300];
	situ_msg_t m;
	situ_view_t v, b;
	fzn_status_t code;
	const uint8_t *why;
	size_t why_len;

	memset(song, 0x50, sizeof(song));
	memset(long_name, 'n', sizeof(long_name));
	fzn_node_catalog_init(&cat);
	claim(host_b, song, "name", long_name, sizeof(long_name));
	say(host_b, song, "kind", "video");
	say(host_b, song, "duration", "42");
	n_said = 0;
	CHECK(fzn_node_library_binary(&cat, host_a, NULL, NULL, ask, sizeof(ask), put, NULL),
	      "the listing was not answered");
	CHECK(n_said == 2u, "one file was not a row and a STATUS");
	memcpy(copy, said[0], said_len[0]);
	situ_msg_init(&m, copy, (uint32_t)said_len[0]);
	CHECK(fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[0], &v) == SITU_OK
	              && fzn_files_local_message_validate(v) == SITU_OK
	              && fzn_files_local_message_op_get(v) == FZN_FILES_LOCAL_OP_LIBRARY_ROW
	              && fzn_files_local_message_body_library_row_view(v, &b) == SITU_OK,
	      "the row did not read back");
	CHECK(memcmp(fzn_files_local_library_row_root_ptr(b), song, 32u) == 0
	              && fzn_files_local_library_row_name_len(b) == 255u
	              && fzn_files_local_library_row_kind_len(b) == 5u
	              && fzn_files_local_library_row_duration_ms_get(b) == 42u
	              && fzn_files_local_library_row_holders_get(b) == 1u,
	      "the row's fields were not the file's");
	CHECK(fzn_status_read(said[1], said_len[1], &code, &why, &why_len) && code == FZN_STATUS_OK,
	      "the listing did not end with a STATUS ok");
	/* A WHOLE ROW SENT AS A REQUEST, which parses: only its op says it is
	 * no request -- a bare op byte is refused before the op is looked at. */
	wrong_len = said_len[0];
	memcpy(wrong, said[0], wrong_len);
	n_said = 0;
	CHECK(fzn_node_library_binary(&cat, host_a, NULL, NULL, wrong, wrong_len, put, NULL)
	              && n_said == 1u
	              && fzn_status_read(said[0], said_len[0], &code, &why, &why_len)
	              && code == FZN_STATUS_MALFORMED,
	      "a row sent as a request was answered as the listing");
	fzn_node_catalog_free(&cat);
}

/* ONE FILE BY ITS ROOT, sec 1190: its row and ok, as the listing gives it;
 * a root no claim names, and one whose every claim was retracted, refused
 * with no row. */
static void test_one_file_by_its_root(void)
{
	uint8_t song[32], film[32], gone[32], ask[34], copy[FZN_NODE_LIBRARY_BINARY_MAX];
	situ_msg_t m;
	situ_view_t v, b;
	fzn_status_t code;
	const uint8_t *why;
	size_t why_len;
	struct here h;

	memset(song, 0x50, sizeof(song));
	memset(film, 0x60, sizeof(film));
	memset(gone, 0x70, sizeof(gone));
	fzn_node_catalog_init(&cat);
	say(host_b, film, "name", "f");
	say(host_b, song, "name", "s");
	say(host_c, song, "kind", "audio");
	say(host_b, gone, "name", "g");
	retract(host_b, gone, "name");
	memset(&h, 0, sizeof(h));
	memcpy(h.root[0], song, 32u);
	h.length[0] = 7u;
	h.whole[0] = 1;
	h.n = 1u;
	ask[0] = FZN_CMD_FILES;
	ask[1] = FZN_FILES_LOCAL_OP_LIBRARY_FILE;
	memcpy(ask + 2, song, 32u);
	n_said = 0;
	CHECK(fzn_node_library_binary(&cat, host_a, file_here, &h, ask, sizeof(ask), put, NULL) && n_said == 2u,
	      "one file was not a row and a STATUS");
	memcpy(copy, said[0], said_len[0]);
	situ_msg_init(&m, copy, (uint32_t)said_len[0]);
	CHECK(fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[0], &v) == SITU_OK
	              && fzn_files_local_message_op_get(v) == FZN_FILES_LOCAL_OP_LIBRARY_ROW
	              && fzn_files_local_message_body_library_row_view(v, &b) == SITU_OK
	              && memcmp(fzn_files_local_library_row_root_ptr(b), song, 32u) == 0
	              && fzn_files_local_library_row_name_len(b) == 1u
	              && fzn_files_local_library_row_kind_len(b) == 5u
	              && fzn_files_local_library_row_holders_get(b) == 3u
	              && fzn_files_local_library_row_held_here_get(b) == 1u
	              && fzn_files_local_library_row_size_get(b) == 7u,
	      "the file asked was not its own row, as the listing gives it");
	CHECK(fzn_status_read(said[1], said_len[1], &code, &why, &why_len) && code == FZN_STATUS_OK,
	      "one file did not end with a STATUS ok");
	memcpy(ask + 2, gone, 32u);
	n_said = 0;
	CHECK(fzn_node_library_binary(&cat, host_a, file_here, &h, ask, sizeof(ask), put, NULL) && n_said == 1u
	              && fzn_status_read(said[0], said_len[0], &code, &why, &why_len)
	              && code == FZN_STATUS_ERROR,
	      "a file every claim of which was retracted was given a row");
	memset(ask + 2, 0x11, 32u);
	n_said = 0;
	CHECK(fzn_node_library_binary(&cat, host_a, file_here, &h, ask, sizeof(ask), put, NULL) && n_said == 1u
	              && fzn_status_read(said[0], said_len[0], &code, &why, &why_len)
	              && code == FZN_STATUS_ERROR,
	      "a file no claim names was given a row");
	fzn_node_catalog_free(&cat);
}

/* ONE FILE'S STATE, sec 1203: catalogued or not, a row as the state reads
 * and ok; a file not here ok alone; a state that would not read refused;
 * another op refused as no file's asking. */
static int state_found;

static int state_of(void *ctx, const uint8_t root[32], fzn_node_file_here_t *out)
{
	(void)ctx;
	if (root[0] != 0x6d)
		return 0;
	if (state_found < 0)
		return -1;
	out->held = 2u;
	out->total = 3u;
	out->length = 40000u;
	out->state = 1u;
	out->to_everyone = 1u;
	out->shares = 4u;
	out->busy = 1u;
	return 1;
}

static void test_one_files_state(void)
{
	uint8_t ask[34], copy[FZN_NODE_LIBRARY_BINARY_MAX];
	situ_msg_t m;
	situ_view_t v, b;
	fzn_status_t code;
	const uint8_t *why;
	size_t why_len;

	ask[0] = FZN_CMD_FILES;
	ask[1] = FZN_FILES_LOCAL_OP_FILE;
	memset(ask + 2, 0x6d, 32u);
	state_found = 1;
	n_said = 0;
	CHECK(fzn_node_file_binary(state_of, NULL, ask, sizeof(ask), put, NULL) && n_said == 2u
	              && fzn_status_read(said[1], said_len[1], &code, &why, &why_len) && code == FZN_STATUS_OK,
	      "a file's state was not a row and a STATUS ok");
	memcpy(copy, said[0], said_len[0]);
	situ_msg_init(&m, copy, (uint32_t)said_len[0]);
	CHECK(fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[0], &v) == SITU_OK
	              && fzn_files_local_message_validate(v) == SITU_OK
	              && fzn_files_local_message_op_get(v) == FZN_FILES_LOCAL_OP_FILE_ROW
	              && fzn_files_local_message_body_file_row_view(v, &b) == SITU_OK
	              && fzn_files_local_file_row_held_get(b) == 2u && fzn_files_local_file_row_total_get(b) == 3u
	              && fzn_files_local_file_row_length_get(b) == 40000u
	              && fzn_files_local_file_row_state_get(b) == 1u
	              && fzn_files_local_file_row_to_everyone_get(b) == 1u
	              && fzn_files_local_file_row_shares_get(b) == 4u && fzn_files_local_file_row_busy_get(b) == 1u,
	      "the row was not the file's state, every field as read");
	memset(ask + 2, 0x11, 32u);
	n_said = 0;
	CHECK(fzn_node_file_binary(state_of, NULL, ask, sizeof(ask), put, NULL) && n_said == 1u
	              && fzn_status_read(said[0], said_len[0], &code, &why, &why_len) && code == FZN_STATUS_OK,
	      "a file not here was not a STATUS ok alone");
	memset(ask + 2, 0x6d, 32u);
	state_found = -1;
	n_said = 0;
	CHECK(fzn_node_file_binary(state_of, NULL, ask, sizeof(ask), put, NULL) && n_said == 1u
	              && fzn_status_read(said[0], said_len[0], &code, &why, &why_len) && code == FZN_STATUS_ERROR,
	      "a state that would not read was not refused");
	ask[1] = FZN_FILES_LOCAL_OP_LIBRARY_FILE;
	state_found = 1;
	n_said = 0;
	CHECK(fzn_node_file_binary(state_of, NULL, ask, sizeof(ask), put, NULL) && n_said == 1u
	              && fzn_status_read(said[0], said_len[0], &code, &why, &why_len)
	              && code == FZN_STATUS_MALFORMED,
	      "another op was answered as a file's state");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

/* THE MUSIC AND PHOTO CATALOGUES, sec 1449: a song by its kind and one by
 * its words alone, a photograph, and a film that is no music and, since sec
 * 1460, a video among the photographs, its length carried; the rows read
 * back with the catalogue's words turned into numbers -- "3/12", a year
 * from a date, a place in ten-millionths of a degree. */
static void test_music_and_photos(void)
{
	static const uint8_t ask_music[] = { FZN_CMD_FILES, FZN_FILES_LOCAL_OP_MUSIC };
	static const uint8_t ask_photos[] = { FZN_CMD_FILES, FZN_FILES_LOCAL_OP_PHOTOS };
	uint8_t song[32], bare[32], photo[32], film[32], copy[FZN_NODE_LIBRARY_BINARY_MAX];
	situ_msg_t m;
	situ_view_t v, b;
	fzn_status_t code;
	const uint8_t *why;
	size_t why_len;

	memset(song, 0x51, sizeof(song));
	memset(bare, 0x52, sizeof(bare));
	memset(photo, 0x53, sizeof(photo));
	memset(film, 0x54, sizeof(film));
	fzn_node_catalog_init(&cat);
	say(host_a, song, "name", "03 night.mp3");
	say(host_a, song, "kind", "audio/mpeg");
	say(host_a, song, "title", "Night Drive");
	say(host_a, song, "artist", "Svalbard Echo");
	say(host_a, song, "album", "Polar Lights");
	say(host_a, song, "track", "3/12");
	say(host_a, song, "disc", "1");
	say(host_a, song, "year", "2019-05-02");
	say(host_a, song, "duration", "251000");
	say(host_b, song, "bpm", "118.00");
	say(host_b, song, "beat", "0.098");
	say(host_b, song, "loudness", "-9.3");
	say(host_b, song, "peak", "0.981");
	say(host_b, song, "acoustid", "0b1cf1a2-2222-4b4b-8c8c-000000000002");
	say(host_b, song, "musicbrainz_recording", "bbbbbbbb-0000-4000-8000-000000000002-and-more");
	/* ITS COMPANIONS, sec 1472: lyrics named by a root; a video in
	 * capitals and a beatmap a digit short name none. */
	say(host_a, song, "lyrics", "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1");
	say(host_a, song, "video", "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1");
	say(host_a, song, "beatmap", "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a");
	say(host_a, bare, "artist", "Bill Evans");
	say(host_a, photo, "kind", "image/jpeg");
	say(host_a, photo, "taken", "2023-07-14T21:45:30");
	say(host_a, photo, "camera", "Canon EOS 5D");
	say(host_a, photo, "width", "4000");
	say(host_a, photo, "height", "3000");
	say(host_a, photo, "orientation", "6");
	say(host_a, photo, "place", "-33.8650000,20.2250000");
	say(host_a, film, "kind", "video/webm");
	say(host_a, film, "title", "A film");
	say(host_a, film, "duration", "12000");

	n_said = 0;
	CHECK(fzn_node_library_binary(&cat, host_a, NULL, NULL, ask_music, sizeof(ask_music), put, NULL)
	              && n_said == 3u,
	      "two pieces of music were not two rows and a STATUS");
	memcpy(copy, said[0], said_len[0]);
	situ_msg_init(&m, copy, (uint32_t)said_len[0]);
	CHECK(fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[0], &v) == SITU_OK
	              && fzn_files_local_message_validate(v) == SITU_OK
	              && fzn_files_local_message_body_music_row_view(v, &b) == SITU_OK
	              && memcmp(fzn_files_local_music_row_root_ptr(b), song, 32u) == 0
	              && fzn_files_local_music_row_track_get(b) == 3u
	              && fzn_files_local_music_row_track_total_get(b) == 12u
	              && fzn_files_local_music_row_disc_get(b) == 1u
	              && fzn_files_local_music_row_disc_total_get(b) == 0u
	              && fzn_files_local_music_row_year_get(b) == 2019u
	              && fzn_files_local_music_row_duration_ms_get(b) == 251000u
	              && fzn_files_local_music_row_title_len(b) == 11u
	              && memcmp(fzn_files_local_music_row_title_ptr(b), "Night Drive", 11u) == 0
	              && fzn_files_local_music_row_bpm_len(b) == 6u
	              && fzn_files_local_music_row_beat_len(b) == 5u
	              && memcmp(fzn_files_local_music_row_beat_ptr(b), "0.098", 5u) == 0
	              && fzn_files_local_music_row_loudness_len(b) == 4u
	              && fzn_files_local_music_row_peak_len(b) == 5u
	              && fzn_files_local_music_row_acoustid_len(b) == 36u
	              /* past a UUID's 36: no value, not a value cut */
	              && fzn_files_local_music_row_recording_len(b) == 0u
	              && fzn_files_local_music_row_name_len(b) == 12u,
	      "a song's row did not carry its words and their numbers");
	{
		uint8_t lyrics[32];

		memset(lyrics, 0xa1, sizeof(lyrics));
		CHECK(fzn_files_local_music_row_lyrics_len_get(b) == 32u
		              && memcmp(fzn_files_local_music_row_lyrics_ptr(b), lyrics, 32u) == 0
		              && fzn_files_local_music_row_video_len_get(b) == 0u
		              && fzn_files_local_music_row_beatmap_len_get(b) == 0u
		              && fzn_files_local_music_row_tracklist_len_get(b) == 0u,
		      "a song's companions were not its roots, or a value that is no root was one");
	}
	memcpy(copy, said[1], said_len[1]);
	situ_msg_init(&m, copy, (uint32_t)said_len[1]);
	CHECK(fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[1], &v) == SITU_OK
	              && fzn_files_local_message_body_music_row_view(v, &b) == SITU_OK
	              && memcmp(fzn_files_local_music_row_root_ptr(b), bare, 32u) == 0
	              && fzn_files_local_music_row_track_get(b) == 0u && fzn_files_local_music_row_year_get(b) == 0u,
	      "a file of no kind saying an artist was not music");
	CHECK(fzn_status_read(said[2], said_len[2], &code, &why, &why_len) && code == FZN_STATUS_OK,
	      "the music did not end with a STATUS ok");

	n_said = 0;
	CHECK(fzn_node_library_binary(&cat, host_a, NULL, NULL, ask_photos, sizeof(ask_photos), put, NULL)
	              && n_said == 3u,
	      "a photograph and a video were not two rows and a STATUS");
	memcpy(copy, said[0], said_len[0]);
	situ_msg_init(&m, copy, (uint32_t)said_len[0]);
	CHECK(fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[0], &v) == SITU_OK
	              && fzn_files_local_message_validate(v) == SITU_OK
	              && fzn_files_local_message_body_photo_row_view(v, &b) == SITU_OK
	              && memcmp(fzn_files_local_photo_row_root_ptr(b), photo, 32u) == 0
	              && fzn_files_local_photo_row_width_get(b) == 4000u
	              && fzn_files_local_photo_row_height_get(b) == 3000u
	              && fzn_files_local_photo_row_orientation_get(b) == 6u
	              && fzn_files_local_photo_row_place_get(b) == 1u
	              && fzn_files_local_photo_row_latitude_get(b) == -338650000
	              && fzn_files_local_photo_row_longitude_get(b) == 202250000
	              && fzn_files_local_photo_row_taken_len(b) == 19u
	              && fzn_files_local_photo_row_camera_len(b) == 12u
	              && fzn_files_local_photo_row_video_get(b) == 0u
	              && fzn_files_local_photo_row_duration_ms_get(b) == 0u,
	      "a photograph's row did not carry when, where and its size");
	memcpy(copy, said[1], said_len[1]);
	situ_msg_init(&m, copy, (uint32_t)said_len[1]);
	CHECK(fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[1], &v) == SITU_OK
	              && fzn_files_local_message_body_photo_row_view(v, &b) == SITU_OK
	              && memcmp(fzn_files_local_photo_row_root_ptr(b), film, 32u) == 0
	              && fzn_files_local_photo_row_video_get(b) == 1u
	              && fzn_files_local_photo_row_duration_ms_get(b) == 12000u,
	      "a video was not a row among the photographs, marked and its length carried");

	/* A PLACE THAT IS NO PLACE is said as none, not as 0,0. */
	say(host_a, photo, "place", "north,east");
	retract(host_a, photo, "place");
	say(host_a, photo, "place", "95.0,10.0");
	n_said = 0;
	(void)fzn_node_library_binary(&cat, host_a, NULL, NULL, ask_photos, sizeof(ask_photos), put, NULL);
	memcpy(copy, said[0], said_len[0]);
	situ_msg_init(&m, copy, (uint32_t)said_len[0]);
	CHECK(n_said == 3u && fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[0], &v) == SITU_OK
	              && fzn_files_local_message_body_photo_row_view(v, &b) == SITU_OK
	              && fzn_files_local_photo_row_place_get(b) == 0u
	              && fzn_files_local_photo_row_latitude_get(b) == 0,
	      "a latitude past the pole was taken as a place");
	/* A TUNE'S MUSIC VIDEO, sec 1477, is the music's: the film, named as
	 * the song's video, leaves the gallery -- the photograph alone. */
	say(host_a, song, "video", "5454545454545454545454545454545454545454545454545454545454545454");
	n_said = 0;
	(void)fzn_node_library_binary(&cat, host_a, NULL, NULL, ask_photos, sizeof(ask_photos), put, NULL);
	memcpy(copy, said[0], said_len[0]);
	situ_msg_init(&m, copy, (uint32_t)said_len[0]);
	CHECK(n_said == 2u && fzn_files_local_message_view(&m, 0u, (uint32_t)said_len[0], &v) == SITU_OK
	              && fzn_files_local_message_body_photo_row_view(v, &b) == SITU_OK
	              && memcmp(fzn_files_local_photo_row_root_ptr(b), photo, 32u) == 0,
	      "a tune's music video was listed among the photographs");
	fzn_node_catalog_free(&cat);
}

int main(void)
{
	memset(host_a, 0xaa, sizeof(host_a));
	memset(host_b, 0xbb, sizeof(host_b));
	memset(host_c, 0xcc, sizeof(host_c));
	test_the_suite_can_tell_pass_from_fail();
	test_one_files_state();
	test_labels_take_the_first_live_value();
	test_holders_are_issuers_and_the_bytes();
	test_arrival_while_fetched();
	test_rows_in_the_order_first_live();
	test_long_labels_are_cut();
	test_the_answer_on_the_wire();
	test_one_file_by_its_root();
	test_music_and_photos();
	if (failures) {
		fprintf(stderr, "node library_binary_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node library_binary_test: all %d checks passed\n", checks);
	return 0;
}
