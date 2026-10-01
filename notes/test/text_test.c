/* text_test -- a long note's text as a blob: sealed into a spool, opened
 * back, and its state named. sec 423.
 *
 * The hash and the AEAD are blob_test's stubs, copied: what is under test is
 * which leaves land where and under which key, not the cipher. */

#include "../text.h"

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
	fprintf(stderr, "  FAIL text_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	if (!out || !in)
		return 0;

	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

static void stream(const uint8_t *key, const uint8_t *nonce, uint8_t *text, size_t len)
{
	uint64_t h = 0x243f6a8885a308d3ull;
	size_t i;

	for (i = 0; i < FZN_AEAD_KEY_LEN; i++) {
		h ^= key[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++) {
		h ^= nonce[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < len; i++) {
		h ^= (uint64_t)i;
		h *= 0x100000001b3ull;
		text[i] ^= (uint8_t)(h >> 24);
	}
}

static void tag_over(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, const uint8_t *text, size_t text_len,
                     uint8_t tag[FZN_AEAD_TAG_LEN])
{
	uint64_t h = 0xff51afd7ed558ccdull;
	size_t i;

	for (i = 0; i < FZN_AEAD_KEY_LEN; i++) {
		h ^= key[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++) {
		h ^= nonce[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < aad_len; i++) {
		h ^= aad[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < text_len; i++) {
		h ^= text[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < FZN_AEAD_TAG_LEN; i++) {
		h ^= (uint64_t)i + 0x2545f4914f6cdd1dull;
		h *= 0x100000001b3ull;
		tag[i] = (uint8_t)(h >> 40);
	}
}

static int stub_seal(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                     const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len,
                     uint8_t tag[FZN_AEAD_TAG_LEN])
{
	(void)ctx;
	stream(key, nonce, text, text_len);
	tag_over(key, nonce, aad, aad_len, text, text_len, tag);
	return 1;
}

static int stub_open(void *ctx, const uint8_t key[FZN_AEAD_KEY_LEN],
                     const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *aad,
                     size_t aad_len, uint8_t *text, size_t text_len,
                     const uint8_t tag[FZN_AEAD_TAG_LEN])
{
	uint8_t want[FZN_AEAD_TAG_LEN];

	(void)ctx;
	tag_over(key, nonce, aad, aad_len, text, text_len, want);
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	stream(key, nonce, text, text_len);
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };
static const fzn_aead_ops_t AEAD = { stub_seal, stub_open, NULL };

/* A random source that never repeats itself, and one that refuses. */
static uint64_t counter = 1;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)((counter * 131u + i * 7u) >> (i % 8u));
	counter++;
	return 1;
}

static int refuse_fill(void *ctx, uint8_t *out, size_t len)
{
	(void)ctx;
	(void)out;
	(void)len;
	return 0;
}

static const fzn_random_ops_t RNG = { counter_fill, NULL };
static const fzn_random_ops_t NO_RNG = { refuse_fill, NULL };

/* A spool backend over memory, one per host in a case. */
typedef struct mem {
	uint8_t bytes[FZN_NOTE_TEXT_LEAVES_MAX * FZN_BLOB_SEALED_MAX];
} mem_t;

static int mem_read(void *ctx, uint64_t offset, uint8_t *out, size_t len)
{
	mem_t *m = (mem_t *)ctx;

	if (offset > sizeof(m->bytes) || len > sizeof(m->bytes) - offset)
		return 0;
	memcpy(out, m->bytes + offset, len);
	return 1;
}

static int mem_write(void *ctx, uint64_t offset, const uint8_t *bytes, size_t len)
{
	mem_t *m = (mem_t *)ctx;

	if (offset > sizeof(m->bytes) || len > sizeof(m->bytes) - offset)
		return 0;
	memcpy(m->bytes + offset, bytes, len);
	return 1;
}

static int mem_sync(void *ctx)
{
	(void)ctx;
	return 1;
}

static uint8_t text[FZN_NOTE_TEXT_MAX + 1u], back[FZN_NOTE_TEXT_MAX];

static void fill_text(size_t len, uint8_t seed)
{
	size_t i;

	for (i = 0; i < len; i++)
		text[i] = (uint8_t)(seed + i * 31u + (i >> 8));
}

/* SEALED AND OPENED BACK at the leaf boundaries: one byte, a whole leaf, a
 * leaf and a byte, a note's paragraphs, and the bound. */
static void test_a_text_round_trips(void)
{
	static mem_t m;
	static uint8_t present[FZN_NOTE_TEXT_PRESENT_LEN];
	static const size_t lens[] = { 1u, FZN_BLOB_LEAF_SIZE, FZN_BLOB_LEAF_SIZE + 1u, 5000u,
		                       FZN_NOTE_TEXT_MAX };
	fzn_spool_ops_t ops = { mem_read, mem_write, mem_sync, &m };
	size_t i, got;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		fzn_spool_t spool;
		fzn_note_blob_ref_t ref;

		fill_text(lens[i], (uint8_t)i);
		got = 0;
		CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, lens[i], &ops, present,
		                         sizeof(present), &spool, &ref) == FZN_NOTE_OK
		              && ref.length == lens[i] && fzn_spool_complete(&spool),
		      "a text did not seal into a complete spool");
		CHECK(fzn_note_text_open(&HASH, &AEAD, &spool, &ref, back, sizeof(back), &got)
		                      == FZN_NOTE_OK
		              && got == lens[i] && memcmp(back, text, lens[i]) == 0,
		      "a sealed text did not open back to itself");
	}
}

/* A FRESH KEY EVERY TIME: the same text sealed twice is two blobs. */
static void test_every_seal_has_its_own_key(void)
{
	static mem_t m1, m2;
	static uint8_t p1[FZN_NOTE_TEXT_PRESENT_LEN], p2[FZN_NOTE_TEXT_PRESENT_LEN];
	fzn_spool_ops_t o1 = { mem_read, mem_write, mem_sync, &m1 };
	fzn_spool_ops_t o2 = { mem_read, mem_write, mem_sync, &m2 };
	fzn_spool_t s1, s2;
	fzn_note_blob_ref_t r1, r2;

	fill_text(3000u, 7);
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 3000u, &o1, p1, sizeof(p1), &s1, &r1)
	              == FZN_NOTE_OK
	              && fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 3000u, &o2, p2, sizeof(p2),
	                                    &s2, &r2) == FZN_NOTE_OK,
	      "fixture: one text sealed twice");
	CHECK(memcmp(r1.key, r2.key, sizeof(r1.key)) != 0
	              && memcmp(r1.root, r2.root, sizeof(r1.root)) != 0,
	      "two seals of one text shared a key or a root");
}

/* WHAT IS REFUSED: no text, too much, no randomness, and a bitmap too small. */
static void test_the_seal_refuses(void)
{
	static mem_t m;
	static uint8_t present[FZN_NOTE_TEXT_PRESENT_LEN];
	fzn_spool_ops_t ops = { mem_read, mem_write, mem_sync, &m };
	fzn_spool_t spool;
	fzn_note_blob_ref_t ref;

	fill_text(FZN_NOTE_TEXT_MAX + 1u, 1);
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 0u, &ops, present, sizeof(present),
	                         &spool, &ref) == FZN_NOTE_ERR_LEN,
	      "an empty text was sealed, where it belongs inline");
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, FZN_NOTE_TEXT_MAX + 1u, &ops, present,
	                         sizeof(present), &spool, &ref) == FZN_NOTE_ERR_LEN,
	      "a text past the bound was sealed");
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &NO_RNG, text, 100u, &ops, present, sizeof(present),
	                         &spool, &ref) == FZN_NOTE_ERR_CRYPTO,
	      "a text was sealed with no randomness for its key");
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 100u, &ops, present,
	                         FZN_NOTE_TEXT_PRESENT_LEN - 1u, &spool, &ref)
	              == FZN_NOTE_ERR_CAPACITY,
	      "a bitmap too small for the bound was taken");
}

/* WHAT OPENING REFUSES: another blob, another length, an incomplete spool,
 * another key, and too little room. */
static void test_the_open_refuses(void)
{
	static mem_t m, other_m, part_m;
	static uint8_t present[FZN_NOTE_TEXT_PRESENT_LEN], other_p[FZN_NOTE_TEXT_PRESENT_LEN];
	static uint8_t part_p[FZN_NOTE_TEXT_PRESENT_LEN];
	fzn_spool_ops_t ops = { mem_read, mem_write, mem_sync, &m };
	fzn_spool_ops_t other_ops = { mem_read, mem_write, mem_sync, &other_m };
	fzn_spool_ops_t part_ops = { mem_read, mem_write, mem_sync, &part_m };
	fzn_spool_t spool, other, part;
	fzn_note_blob_ref_t ref, other_ref, bent;
	size_t got = 0;

	fill_text(5000u, 3);
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 5000u, &ops, present, sizeof(present),
	                         &spool, &ref) == FZN_NOTE_OK
	              && fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 5000u, &other_ops, other_p,
	                                    sizeof(other_p), &other, &other_ref) == FZN_NOTE_OK,
	      "fixture: two blobs of one length, so only the root tells them apart");
	CHECK(fzn_note_text_open(&HASH, &AEAD, &other, &ref, back, sizeof(back), &got)
	              == FZN_NOTE_ERR_MISMATCH,
	      "another blob's spool opened as this note's text");
	/* ANOTHER LENGTH: with another leaf count, the spool is not the blob;
	 * with the same count, the last leaf will not open at that length. */
	bent = ref;
	bent.length = 3000u;
	CHECK(fzn_note_text_open(&HASH, &AEAD, &spool, &bent, back, sizeof(back), &got)
	              == FZN_NOTE_ERR_MISMATCH,
	      "a reference naming another leaf count opened");
	bent.length = 4999u;
	CHECK(fzn_note_text_open(&HASH, &AEAD, &spool, &bent, back, sizeof(back), &got)
	              == FZN_NOTE_ERR_CRYPTO,
	      "a reference naming another length, same leaf count, opened");
	bent = ref;
	bent.key[0] ^= 1u;
	CHECK(fzn_note_text_open(&HASH, &AEAD, &spool, &bent, back, sizeof(back), &got)
	              == FZN_NOTE_ERR_CRYPTO,
	      "the text opened under another key");
	CHECK(fzn_note_text_open(&HASH, &AEAD, &spool, &ref, back, 4999u, &got)
	              == FZN_NOTE_ERR_CAPACITY,
	      "the text opened into a buffer too small");
	memset(part_p, 0, sizeof(part_p));
	CHECK(fzn_spool_open(&part, ref.root, spool.leaves, part_p, sizeof(part_p), &part_ops)
	              == FZN_SPOOL_OK
	              && fzn_note_text_open(&HASH, &AEAD, &part, &ref, back, sizeof(back), &got)
	                         == FZN_NOTE_ERR_ABSENT,
	      "an empty spool for the blob opened as its text");
}

/* Leaf `i`'s sealed length in a blob of `len` bytes over `leaves` leaves. */
static size_t sealed_len_of(uint64_t i, uint64_t leaves, size_t len)
{
	size_t last = len - (size_t)(leaves - 1u) * FZN_BLOB_LEAF_SIZE;

	return (i + 1u == leaves ? last : (size_t)FZN_BLOB_LEAF_SIZE) + FZN_BLOB_LEAF_OVERHEAD;
}

/* A note whose text is in `field` as a reference, built and opened. */
static int blob_note(const fzn_note_blob_ref_t *ref, uint8_t field[FZN_NOTE_BLOB_REF_LEN],
                     uint8_t *content, size_t cap, fzn_note_t *out)
{
	fzn_note_t in;
	size_t len = 0;

	memset(&in, 0, sizeof(in));
	in.title = (const uint8_t *)"Minutes";
	in.title_len = 7u;
	in.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	in.text = field;
	in.text_len = FZN_NOTE_BLOB_REF_LEN;
	return fzn_note_blob_ref_write(ref, field) == FZN_NOTE_OK
	       && fzn_note_content(&in, content, cap, &len) == FZN_NOTE_OK
	       && fzn_note_open(FZN_NOTE_TYPE_NOTE, content, len, out) == FZN_NOTE_OK;
}

/* THE REQUIREMENT, END TO END, and the state a sibling is in on the way: a
 * 5000-byte note sealed on one host; on another, whose spool fills leaf by
 * leaf as a fetch would fill it, the note is PENDING until the last leaf and
 * HERE after, and its text opens to what was written. */
static void test_a_long_note_reaches_a_sibling(void)
{
	static mem_t mine, theirs;
	static uint8_t p_mine[FZN_NOTE_TEXT_PRESENT_LEN], p_theirs[FZN_NOTE_TEXT_PRESENT_LEN];
	static uint8_t hashes[FZN_NOTE_TEXT_LEAVES_MAX][FZN_BLOB_HASH_LEN];
	fzn_spool_ops_t o_mine = { mem_read, mem_write, mem_sync, &mine };
	fzn_spool_ops_t o_theirs = { mem_read, mem_write, mem_sync, &theirs };
	uint8_t field[FZN_NOTE_BLOB_REF_LEN], content[FZN_TREE_CONTENT_MAX];
	uint8_t sealed[FZN_BLOB_SEALED_MAX], proof[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	fzn_spool_t s_mine, s_theirs;
	fzn_note_blob_ref_t ref, named;
	fzn_note_t note;
	uint64_t i;
	size_t got = 0, len = 0;
	unsigned siblings = 0;
	int pending_until_last = 1;

	fill_text(5000u, 9);
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 5000u, &o_mine, p_mine, sizeof(p_mine),
	                         &s_mine, &ref) == FZN_NOTE_OK
	              && blob_note(&ref, field, content, sizeof(content), &note)
	              && fzn_note_blob_ref(&note, &named) == FZN_NOTE_OK,
	      "fixture: a 5000-byte note on this host");
	CHECK(fzn_note_text_state(&note, &s_mine) == FZN_NOTE_TEXT_HERE,
	      "the writer's own note is not HERE");
	CHECK(fzn_note_text_state(&note, NULL) == FZN_NOTE_TEXT_PENDING,
	      "a host holding no spool for the note's blob did not say PENDING");

	/* THE SIBLING: its spool over the root the note names, filled from the
	 * writer's leaves, each proved as a fetch would prove it. */
	memset(p_theirs, 0, sizeof(p_theirs));
	CHECK(fzn_spool_open(&s_theirs, named.root, s_mine.leaves, p_theirs, sizeof(p_theirs),
	                     &o_theirs) == FZN_SPOOL_OK,
	      "fixture: the sibling's empty spool");
	/* A SLOT IS READ WHOLE, so each leaf's sealed length is the geometry's:
	 * 5000 bytes are four whole leaves and one of 904. */
	for (i = 0; i < s_mine.leaves; i++)
		if (fzn_spool_read(&s_mine, i, sealed, sizeof(sealed), &len) != FZN_SPOOL_OK
		    || fzn_blob_leaf_hash(&HASH, sealed, sealed_len_of(i, s_mine.leaves, 5000u),
		                          hashes[i]) != FZN_BLOB_OK)
			pending_until_last = 0;
	for (i = 0; i < s_mine.leaves; i++) {
		if (fzn_note_text_state(&note, &s_theirs) != FZN_NOTE_TEXT_PENDING)
			pending_until_last = 0;
		len = sealed_len_of(i, s_mine.leaves, 5000u);
		if (fzn_spool_read(&s_mine, i, sealed, sizeof(sealed), &got) != FZN_SPOOL_OK
		    || fzn_blob_proof_build(&HASH, (const uint8_t *)hashes, s_mine.leaves, i, proof,
		                            sizeof(proof), &siblings) != FZN_BLOB_OK
		    || fzn_spool_place(&s_theirs, &HASH, i, sealed, len, proof, siblings)
		               != FZN_SPOOL_OK)
			pending_until_last = 0;
	}
	CHECK(pending_until_last, "the sibling's note was not PENDING until its last leaf landed");
	CHECK(fzn_note_text_state(&note, &s_theirs) == FZN_NOTE_TEXT_HERE,
	      "the sibling's note is not HERE with every leaf");
	CHECK(fzn_note_text_open(&HASH, &AEAD, &s_theirs, &named, back, sizeof(back), &got)
	                      == FZN_NOTE_OK
	              && got == 5000u && memcmp(back, text, 5000u) == 0,
	      "the sibling did not read the text that was written");
}

/* THE STATES: inline, and a reference to nothing is BROKEN, never pending. */
static void test_the_states(void)
{
	static mem_t m;
	static uint8_t present[FZN_NOTE_TEXT_PRESENT_LEN];
	fzn_spool_ops_t ops = { mem_read, mem_write, mem_sync, &m };
	uint8_t field[FZN_NOTE_BLOB_REF_LEN], content[FZN_TREE_CONTENT_MAX], short_content[64];
	fzn_spool_t spool, other;
	fzn_note_blob_ref_t ref, other_ref;
	fzn_note_t note, in;
	size_t len = 0;

	memset(&in, 0, sizeof(in));
	in.text = (const uint8_t *)"milk";
	in.text_len = 4u;
	CHECK(fzn_note_content(&in, short_content, sizeof(short_content), &len) == FZN_NOTE_OK
	              && fzn_note_open(FZN_NOTE_TYPE_NOTE, short_content, len, &note) == FZN_NOTE_OK
	              && fzn_note_text_state(&note, NULL) == FZN_NOTE_TEXT_INLINE,
	      "a short note's text is not INLINE");

	fill_text(2000u, 5);
	CHECK(fzn_note_text_seal(&HASH, &AEAD, &RNG, text, 2000u, &ops, present, sizeof(present),
	                         &spool, &ref) == FZN_NOTE_OK
	              && blob_note(&ref, field, content, sizeof(content), &note),
	      "fixture: a blob note");
	other_ref = ref;
	other = spool;
	other.root[0] ^= 1u;
	CHECK(fzn_note_text_state(&note, &other) == FZN_NOTE_TEXT_PENDING,
	      "a spool for another blob made the note HERE");

	/* A length past the bound names nothing that can arrive. */
	other_ref.length = (uint64_t)FZN_NOTE_TEXT_MAX + 1u;
	CHECK(blob_note(&other_ref, field, content, sizeof(content), &note)
	              && fzn_note_text_state(&note, &spool) == FZN_NOTE_TEXT_BROKEN,
	      "a reference past the bound was not BROKEN");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_a_text_round_trips();
	test_every_seal_has_its_own_key();
	test_the_seal_refuses();
	test_the_open_refuses();
	test_a_long_note_reaches_a_sibling();
	test_the_states();
	test_the_suite_can_tell_pass_from_fail();

	printf("text_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
