/* See qr.h. */

#include "qr.h"

#include <string.h>

/* ---- the tables, which are the part an independent decoder adjudicates ---- */

/* Total codewords -- data plus error correction -- per version, 1..15. */
static const uint16_t TOTAL_CODEWORDS[] = { 0,  26,  44,  70,  100, 134, 172, 196,
                                            242, 292, 346, 404, 466, 532, 581, 655 };

/* Per (version, level): error-correction codewords in every block, the number
 * of blocks in group 1, and the number in group 2. Group 2's blocks each hold
 * one data codeword more than group 1's, which is how the standard divides a
 * count that does not divide evenly. */
struct ec_spec {
	uint8_t ec_per_block;
	uint8_t group1;
	uint8_t group2;
};

static const struct ec_spec EC[FZN_QR_VERSION_MAX + 1u][4] = {
	/* version 0 is unused so the array is indexed by version */
	{ { 0, 0, 0 }, { 0, 0, 0 }, { 0, 0, 0 }, { 0, 0, 0 } },
	{ { 7, 1, 0 }, { 10, 1, 0 }, { 13, 1, 0 }, { 17, 1, 0 } },
	{ { 10, 1, 0 }, { 16, 1, 0 }, { 22, 1, 0 }, { 28, 1, 0 } },
	{ { 15, 1, 0 }, { 26, 1, 0 }, { 18, 2, 0 }, { 22, 2, 0 } },
	{ { 20, 1, 0 }, { 18, 2, 0 }, { 26, 2, 0 }, { 16, 4, 0 } },
	{ { 26, 1, 0 }, { 24, 2, 0 }, { 18, 2, 2 }, { 22, 2, 2 } },
	{ { 18, 2, 0 }, { 16, 4, 0 }, { 24, 4, 0 }, { 28, 4, 0 } },
	{ { 20, 2, 0 }, { 18, 4, 0 }, { 18, 2, 4 }, { 26, 4, 1 } },
	{ { 24, 2, 0 }, { 22, 2, 2 }, { 22, 4, 2 }, { 26, 4, 2 } },
	{ { 30, 2, 0 }, { 22, 3, 2 }, { 20, 4, 4 }, { 24, 4, 4 } },
	{ { 18, 2, 2 }, { 26, 4, 1 }, { 24, 6, 2 }, { 28, 6, 2 } },
	{ { 20, 4, 0 }, { 30, 1, 4 }, { 28, 4, 4 }, { 24, 3, 8 } },
	{ { 24, 2, 2 }, { 22, 6, 2 }, { 26, 4, 6 }, { 28, 7, 4 } },
	{ { 26, 4, 0 }, { 22, 8, 1 }, { 24, 8, 4 }, { 22, 12, 4 } },
	{ { 30, 3, 1 }, { 24, 4, 5 }, { 20, 11, 5 }, { 24, 11, 5 } },
	{ { 22, 5, 1 }, { 24, 5, 5 }, { 30, 5, 7 }, { 24, 11, 7 } },
};

/* Where alignment patterns sit, per version. Version 1 has none; from 2 on
 * the standard gives a coordinate list and a pattern goes at every pair
 * except the three that would sit on a finder. */
/* FOUR COLUMNS, BECAUSE VERSION 14 IS WHERE A FOURTH COORDINATE APPEARS.
 * Three was enough through version 13 and silently wrong from 14, where the
 * pattern at 66 simply went missing -- quirc decoded every version but that
 * one, at all four levels, which is what a per-version table error looks
 * like from outside. A zero ends the list. */
static const uint8_t ALIGN[FZN_QR_VERSION_MAX + 1u][4] = {
	{ 0, 0, 0, 0 },   { 0, 0, 0, 0 },   { 6, 18, 0, 0 },  { 6, 22, 0, 0 },
	{ 6, 26, 0, 0 },  { 6, 30, 0, 0 },  { 6, 34, 0, 0 },  { 6, 22, 38, 0 },
	{ 6, 24, 42, 0 }, { 6, 26, 46, 0 }, { 6, 28, 50, 0 }, { 6, 30, 54, 0 },
	{ 6, 32, 58, 0 }, { 6, 34, 62, 0 }, { 6, 26, 46, 66 }, { 6, 26, 48, 70 },
};

/*
 * Format and version information, DERIVED RATHER THAN TABLED.
 *
 * Both are BCH codes over a handful of data bits, so computing them is ten
 * lines and tabling them is sixty numbers written from memory. The first
 * version of this file tabled both, and the format table was wrong: quirc
 * read level Q out of a code asked for at level L, which is a single row in
 * the wrong order and is invisible to anything that does not decode.
 *
 * A derivation has one thing a table cannot: it is checkable by reading it
 * against the definition, and there is no row to put in the wrong place.
 */

/* The two bits the format carries for each level, which are NOT this enum's
 * order: the standard numbers them M=00, L=01, Q=11, H=10. */
static const unsigned LEVEL_BITS[4] = { 1u, 0u, 3u, 2u };

static unsigned bch(unsigned data, unsigned generator, unsigned data_bits,
                    unsigned total_bits)
{
	/* The generator's degree, which is also how far its top bit sits: to
	 * clear bit `b` the generator shifts left by `b - degree`. Shifting by
	 * anything else leaves a remainder wider than the code -- the first
	 * version used `b - data_bits`, and format(L, 0) came out as 0x6AD01,
	 * a nineteen-bit answer to a fifteen-bit question. */
	unsigned degree = total_bits - data_bits;
	unsigned rem = data << degree;
	unsigned b;

	for (b = total_bits; b > degree; b--)
		if (rem & (1u << (b - 1u)))
			rem ^= generator << ((b - 1u) - degree);

	return (data << degree) | rem;
}

/* 15 bits: five of level and mask, ten of BCH, masked so an all-zero format
 * is not a legal one. */
static uint16_t format_bits(fzn_qr_level_t level, unsigned mask)
{
	unsigned data = (LEVEL_BITS[level] << 3) | mask;

	return (uint16_t)(bch(data, 0x537u, 5u, 15u) ^ 0x5412u);
}

/* 18 bits: six of version and twelve of BCH. Versions 7 and up only. */
static uint32_t version_bits(unsigned version)
{
	return bch(version, 0x1F25u, 6u, 18u);
}

/* ---- GF(256), the field Reed-Solomon works in --------------------------- */

static uint8_t GF_EXP[512];
static uint8_t GF_LOG[256];
static int gf_ready;

static void gf_init(void)
{
	unsigned x = 1u;
	unsigned i;

	if (gf_ready)
		return;
	for (i = 0; i < 255u; i++) {
		GF_EXP[i] = (uint8_t)x;
		GF_LOG[x] = (uint8_t)i;
		x <<= 1;
		/* 0x11D is the QR standard's primitive polynomial. */
		if (x & 0x100u)
			x ^= 0x11Du;
	}
	for (i = 255u; i < 512u; i++)
		GF_EXP[i] = GF_EXP[i - 255u];
	gf_ready = 1;
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
	if (a == 0 || b == 0)
		return 0;
	return GF_EXP[(unsigned)GF_LOG[a] + (unsigned)GF_LOG[b]];
}

/*
 * The generator polynomial for `degree` error-correction codewords.
 *
 * DESCENDING, WITH THE LEADING 1 IMPLICIT, so the array is `degree` long and
 * `poly[j]` is what the remainder loop below multiplies by. The first version
 * stored it the other way round -- constant first, leading coefficient last --
 * and the loop then read `poly[j + 1]`, which skipped the constant term and
 * included the leading one. Every codeword it produced was wrong.
 *
 * IT WAS FOUND BY A PROPERTY AND NOT BY A VECTOR. A Reed-Solomon codeword
 * evaluated at each of the generator's roots is zero, which is true whatever
 * construction produced the generator -- so it tests the thing under
 * suspicion without needing a published example to compare against, and
 * `evidence.md` would not have let a recalled one count anyway. Seven of
 * seven roots were nonzero before and zero after.
 */
static void rs_generator(unsigned degree, uint8_t *poly)
{
	uint8_t root = 1u;
	unsigned i;
	unsigned j;

	memset(poly, 0, degree);
	poly[degree - 1u] = 1u;
	for (i = 0; i < degree; i++) {
		for (j = 0; j < degree; j++) {
			poly[j] = gf_mul(poly[j], root);
			if (j + 1u < degree)
				poly[j] = (uint8_t)(poly[j] ^ poly[j + 1u]);
		}
		root = gf_mul(root, 2u);
	}
}

/* Remainder of `data` divided by the generator: the error-correction block. */
static void rs_encode(const uint8_t *data, unsigned data_len, unsigned ec_len, uint8_t *out)
{
	uint8_t gen[31];
	unsigned i;
	unsigned j;

	rs_generator(ec_len, gen);
	memset(out, 0, ec_len);
	for (i = 0; i < data_len; i++) {
		uint8_t factor = (uint8_t)(data[i] ^ out[0]);

		memmove(out, out + 1, ec_len - 1u);
		out[ec_len - 1u] = 0;
		for (j = 0; j < ec_len; j++)
			out[j] = (uint8_t)(out[j] ^ gf_mul(gen[j], factor));
	}
}

/* ---- the payload -------------------------------------------------------- */

/* QR's alphanumeric set, in its own order: the index IS the value. */
static const char ALNUM[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

static int alnum_value(char c)
{
	const char *at = strchr(ALNUM, c);

	/* `strchr` finds the NUL, which is not a member. */
	if (!at || c == '\0')
		return -1;
	return (int)(at - ALNUM);
}

static int all_alnum(const char *text, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (alnum_value(text[i]) < 0)
			return 0;
	return 1;
}

/* How many bits the character count field takes, which depends on the mode
 * and on which of three version bands the version falls in. */
static unsigned count_bits(unsigned version, int alnum)
{
	if (version <= 9u)
		return alnum ? 9u : 8u;
	if (version <= 26u)
		return alnum ? 11u : 16u;
	return alnum ? 13u : 16u;
}

static unsigned data_codewords(unsigned version, fzn_qr_level_t level)
{
	const struct ec_spec *spec = &EC[version][level];
	unsigned blocks = (unsigned)spec->group1 + (unsigned)spec->group2;

	return TOTAL_CODEWORDS[version] - blocks * spec->ec_per_block;
}

/* Bits the payload needs at this version, mode indicator and count included. */
static unsigned payload_bits(size_t len, unsigned version, int alnum)
{
	unsigned bits = 4u + count_bits(version, alnum);

	if (alnum)
		bits += (unsigned)(len / 2u) * 11u + ((len % 2u) ? 6u : 0u);
	else
		bits += (unsigned)len * 8u;
	return bits;
}

unsigned fzn_qr_version_for(const char *text, size_t text_len, fzn_qr_level_t level)
{
	unsigned version;
	int alnum;

	if (!text || (int)level < 0 || (int)level > 3)
		return 0;
	alnum = all_alnum(text, text_len);
	for (version = 1u; version <= FZN_QR_VERSION_MAX; version++) {
		if (payload_bits(text_len, version, alnum) <=
		    data_codewords(version, level) * 8u)
			return version;
	}

	return 0;
}

/* A bit appender over a caller's byte buffer. */
struct bits {
	uint8_t *buf;
	unsigned used;
};

static void put_bits(struct bits *b, uint32_t value, unsigned n)
{
	unsigned i;

	for (i = n; i > 0; i--) {
		unsigned bit = (value >> (i - 1u)) & 1u;

		if (bit)
			b->buf[b->used >> 3] |= (uint8_t)(0x80u >> (b->used & 7u));
		b->used++;
	}
}

/* ---- the matrix --------------------------------------------------------- */

/* Every module carries its value in bit 0 and whether it is FUNCTION in bit
 * 1. The second is what stops the data walk writing over a finder and what
 * stops the mask flipping one. */
#define M_VALUE 1u
#define M_FIXED 2u

static void set_fixed(uint8_t *m, unsigned size, unsigned x, unsigned y, unsigned value)
{
	if (x >= size || y >= size)
		return;
	m[y * size + x] = (uint8_t)(M_FIXED | (value ? M_VALUE : 0u));
}

static void draw_finder(uint8_t *m, unsigned size, unsigned ox, unsigned oy)
{
	int dx;
	int dy;

	/* The 7x7 pattern plus the one-module separator all round it. */
	for (dy = -1; dy <= 7; dy++) {
		for (dx = -1; dx <= 7; dx++) {
			int on = (dx >= 0 && dx <= 6 && (dy == 0 || dy == 6)) ||
			         (dy >= 0 && dy <= 6 && (dx == 0 || dx == 6)) ||
			         (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4);
			int x = (int)ox + dx;
			int y = (int)oy + dy;

			if (x < 0 || y < 0)
				continue;
			set_fixed(m, size, (unsigned)x, (unsigned)y, (unsigned)on);
		}
	}
}

static void draw_function(uint8_t *m, unsigned size, unsigned version)
{
	unsigned i;
	unsigned a;
	unsigned b;

	draw_finder(m, size, 0, 0);
	draw_finder(m, size, size - 7u, 0);
	draw_finder(m, size, 0, size - 7u);

	/* Timing: alternating modules along row 6 and column 6, BETWEEN the
	 * finders and not across them.
	 *
	 * Running the full width instead is how the first version of this was
	 * wrong, and it is invisible from the outside: the finder's right edge
	 * at row 1 is a dark module and timing at index 1 is light, so the ring
	 * lost one module on each of two sides and the code stopped being
	 * findable at all. quirc reported "0 codes" for every version and
	 * level, which says nothing about where. Printing one and looking at
	 * the corner is what said where. */
	for (i = 8u; i + 8u < size; i++) {
		set_fixed(m, size, i, 6u, (i % 2u) == 0u);
		set_fixed(m, size, 6u, i, (i % 2u) == 0u);
	}

	/* Alignment patterns at every pair of listed coordinates, except the
	 * three that would land on a finder. */
	for (a = 0; a < 4u && ALIGN[version][a]; a++) {
		for (b = 0; b < 4u && ALIGN[version][b]; b++) {
			unsigned cx = ALIGN[version][a];
			unsigned cy = ALIGN[version][b];
			int dx;
			int dy;

			if ((cx <= 8u && cy <= 8u) || (cx <= 8u && cy >= size - 9u) ||
			    (cx >= size - 9u && cy <= 8u))
				continue;
			for (dy = -2; dy <= 2; dy++)
				for (dx = -2; dx <= 2; dx++) {
					int edge = (dx == -2 || dx == 2 || dy == -2 || dy == 2);
					int centre = (dx == 0 && dy == 0);

					set_fixed(m, size, (unsigned)((int)cx + dx),
					          (unsigned)((int)cy + dy),
					          (unsigned)(edge || centre));
				}
		}
	}

	/* Format areas are reserved now and written after masking.
	 *
	 * THE SECOND COPY IS SEVEN CELLS VERTICALLY AND EIGHT HORIZONTALLY --
	 * fifteen between them -- and reserving eight of each takes one cell
	 * too many: the extra one is the dark module. Written that way first,
	 * the reservation cleared it and the dark module was light in every
	 * code this produced. quirc decoded them anyway, because its reader
	 * does not consult that module, so nothing but reading the matrix back
	 * says so. */
	for (i = 0; i <= 8u; i++) {
		if (i != 6u) {
			set_fixed(m, size, i, 8u, 0u);
			set_fixed(m, size, 8u, i, 0u);
		}
	}
	for (i = 0; i < 8u; i++)
		set_fixed(m, size, size - 1u - i, 8u, 0u);
	for (i = 0; i < 7u; i++)
		set_fixed(m, size, 8u, size - 1u - i, 0u);

	/* The dark module, which is always set and always here -- and after the
	 * reservation, so that nothing clears it again. */
	set_fixed(m, size, 8u, size - 8u, 1u);

	/* Version information, versions 7 and up. */
	if (version >= 7u) {
		uint32_t bits = version_bits(version);

		for (i = 0; i < 18u; i++) {
			unsigned bit = (bits >> i) & 1u;

			set_fixed(m, size, i / 3u, size - 11u + (i % 3u), bit);
			set_fixed(m, size, size - 11u + (i % 3u), i / 3u, bit);
		}
	}
}

/* The zigzag: two columns at a time from the right, skipping column 6. */
static void place_data(uint8_t *m, unsigned size, const uint8_t *data, unsigned data_len)
{
	unsigned bit = 0;
	int col;

	for (col = (int)size - 1; col >= 0; col -= 2) {
		int upward;
		int row;

		if (col == 6)
			col--;
		upward = (((int)size - 1 - col) / 2) % 2 == 0;
		for (row = 0; row < (int)size; row++) {
			int y = upward ? (int)size - 1 - row : row;
			int c;

			for (c = 0; c < 2; c++) {
				int x = col - c;
				unsigned at = (unsigned)y * size + (unsigned)x;
				unsigned value = 0;

				if (m[at] & M_FIXED)
					continue;
				if (bit < data_len * 8u)
					value = (data[bit >> 3] >> (7u - (bit & 7u))) & 1u;
				m[at] = (uint8_t)(value ? M_VALUE : 0u);
				bit++;
			}
		}
	}
}

static int mask_bit(unsigned mask, unsigned x, unsigned y)
{
	switch (mask) {
	case 0:
		return ((x + y) % 2u) == 0u;
	case 1:
		return (y % 2u) == 0u;
	case 2:
		return (x % 3u) == 0u;
	case 3:
		return ((x + y) % 3u) == 0u;
	case 4:
		return (((y / 2u) + (x / 3u)) % 2u) == 0u;
	case 5:
		return ((x * y) % 2u + (x * y) % 3u) == 0u;
	case 6:
		return ((((x * y) % 2u) + ((x * y) % 3u)) % 2u) == 0u;
	default:
		return ((((x + y) % 2u) + ((x * y) % 3u)) % 2u) == 0u;
	}
}

static void apply_mask(uint8_t *m, unsigned size, unsigned mask)
{
	unsigned x;
	unsigned y;

	for (y = 0; y < size; y++)
		for (x = 0; x < size; x++)
			if (!(m[y * size + x] & M_FIXED) && mask_bit(mask, x, y))
				m[y * size + x] ^= M_VALUE;
}

static void draw_format(uint8_t *m, unsigned size, fzn_qr_level_t level, unsigned mask)
{
	uint16_t bits = format_bits(level, mask);
	unsigned i;

	/* THE FIRST COPY RUNS DOWN COLUMN 8 AND ALONG ROW 8, AND THE TWO WERE
	 * TRANSPOSED. Written the other way round the bits land in the right
	 * cells for the wrong copy, so a decoder reading either one gets a
	 * level and a mask that were never asked for -- quirc read Q, then M,
	 * out of codes built at L. It is not visible without a decoder,
	 * because the modules are all present and the code still scans as a
	 * code. */
	for (i = 0; i < 15u; i++) {
		unsigned bit = (bits >> i) & 1u;

		/* The copy beside the top-left finder. */
		if (i < 6u)
			set_fixed(m, size, 8u, i, bit);
		else if (i == 6u)
			set_fixed(m, size, 8u, 7u, bit);
		else if (i == 7u)
			set_fixed(m, size, 8u, 8u, bit);
		else if (i == 8u)
			set_fixed(m, size, 7u, 8u, bit);
		else
			set_fixed(m, size, 14u - i, 8u, bit);

		/* And the split copy, which is what makes the format readable
		 * when one corner is damaged. */
		if (i < 8u)
			set_fixed(m, size, size - 1u - i, 8u, bit);
		else
			set_fixed(m, size, 8u, size - 15u + i, bit);
	}
}

/* The standard's four penalties, which decide which mask to keep. */
static unsigned penalty(const uint8_t *m, unsigned size)
{
	unsigned score = 0;
	unsigned dark = 0;
	unsigned x;
	unsigned y;
	unsigned i;

	/* Runs of five or more in a row or column. */
	for (i = 0; i < 2u; i++) {
		for (y = 0; y < size; y++) {
			unsigned run = 1;
			unsigned prev = 2;

			for (x = 0; x < size; x++) {
				unsigned at = i ? (x * size + y) : (y * size + x);
				unsigned v = m[at] & M_VALUE;

				if (v == prev) {
					run++;
					if (run == 5u)
						score += 3u;
					else if (run > 5u)
						score += 1u;
				} else {
					run = 1;
					prev = v;
				}
			}
		}
	}

	/* Two-by-two blocks of one colour. */
	for (y = 0; y + 1u < size; y++) {
		for (x = 0; x + 1u < size; x++) {
			unsigned v = m[y * size + x] & M_VALUE;

			if ((m[y * size + x + 1u] & M_VALUE) == v &&
			    (m[(y + 1u) * size + x] & M_VALUE) == v &&
			    (m[(y + 1u) * size + x + 1u] & M_VALUE) == v)
				score += 3u;
		}
	}

	/* The finder-like 1:1:3:1:1 run, with four light modules one side. */
	for (i = 0; i < 2u; i++) {
		for (y = 0; y < size; y++) {
			unsigned bits = 0;

			for (x = 0; x < size; x++) {
				unsigned at = i ? (x * size + y) : (y * size + x);

				bits = ((bits << 1) | (m[at] & M_VALUE)) & 0x7FFu;
				if (x >= 10u && (bits == 0x5D0u || bits == 0x05Du))
					score += 40u;
			}
		}
	}

	/* And the balance of dark to light. */
	for (y = 0; y < size; y++)
		for (x = 0; x < size; x++)
			if (m[y * size + x] & M_VALUE)
				dark++;
	{
		unsigned total = size * size;
		unsigned percent = dark * 100u / total;
		unsigned k = percent > 50u ? (percent - 50u) / 5u : (50u - percent) / 5u;

		score += k * 10u;
	}

	return score;
}

/* ---- putting it together ------------------------------------------------ */

fzn_qr_err_t fzn_qr_encode(const char *text, size_t text_len, fzn_qr_level_t level,
                           uint8_t *out, size_t out_cap, size_t *size_out)
{
	uint8_t stream[TOTAL_CODEWORDS[FZN_QR_VERSION_MAX]];
	uint8_t interleaved[TOTAL_CODEWORDS[FZN_QR_VERSION_MAX]];
	uint8_t ecbuf[FZN_QR_VERSION_MAX * 4u][31];
	uint8_t work[FZN_QR_MODULES_MAX];
	uint8_t best[FZN_QR_MODULES_MAX];
	struct bits bits;
	unsigned version;
	unsigned size;
	unsigned alnum;
	unsigned data_len;
	unsigned blocks;
	unsigned short_len;
	unsigned at;
	unsigned i;
	unsigned j;
	unsigned mask;
	unsigned best_mask = 0;
	unsigned best_score = 0;
	const struct ec_spec *spec;

	if (!text || !size_out || (int)level < 0 || (int)level > 3)
		return FZN_QR_ERR_MALFORMED;
	if (!out && out_cap > 0)
		return FZN_QR_ERR_MALFORMED;

	version = fzn_qr_version_for(text, text_len, level);
	if (version == 0)
		return FZN_QR_ERR_TOO_LONG;
	size = 17u + 4u * version;
	*size_out = size;
	if (out_cap < (size_t)size * size)
		return FZN_QR_ERR_FULL;

	gf_init();
	alnum = (unsigned)all_alnum(text, text_len);
	spec = &EC[version][level];
	data_len = data_codewords(version, level);

	/* THE BIT STREAM: mode, count, payload, terminator, pad. */
	memset(stream, 0, sizeof(stream));
	bits.buf = stream;
	bits.used = 0;
	put_bits(&bits, alnum ? 2u : 4u, 4u);
	put_bits(&bits, (uint32_t)text_len, count_bits(version, (int)alnum));
	if (alnum) {
		for (i = 0; i + 1u < text_len; i += 2u) {
			unsigned v = (unsigned)alnum_value(text[i]) * 45u +
			             (unsigned)alnum_value(text[i + 1u]);

			put_bits(&bits, v, 11u);
		}
		if (text_len % 2u)
			put_bits(&bits, (uint32_t)alnum_value(text[text_len - 1u]), 6u);
	} else {
		for (i = 0; i < text_len; i++)
			put_bits(&bits, (uint8_t)text[i], 8u);
	}
	/* Up to four zero bits to end the message, then to a byte boundary. */
	for (i = 0; i < 4u && bits.used < data_len * 8u; i++)
		put_bits(&bits, 0, 1u);
	while (bits.used % 8u)
		put_bits(&bits, 0, 1u);
	/* The standard's alternating pad, 0xEC then 0x11, to fill the block. */
	for (i = bits.used / 8u; i < data_len; i++)
		stream[i] = (i - bits.used / 8u) % 2u ? 0x11u : 0xECu;

	/* ERROR CORRECTION, PER BLOCK. Group 2's blocks hold one data codeword
	 * more than group 1's. */
	blocks = (unsigned)spec->group1 + (unsigned)spec->group2;
	short_len = data_len / blocks;
	at = 0;
	for (i = 0; i < blocks; i++) {
		unsigned len = short_len + (i >= spec->group1 ? 1u : 0u);

		rs_encode(stream + at, len, spec->ec_per_block, ecbuf[i]);
		at += len;
	}

	/* INTERLEAVED, which is what spreads a scratch across blocks rather
	 * than destroying one of them. */
	at = 0;
	for (j = 0; j <= short_len; j++) {
		unsigned base = 0;

		for (i = 0; i < blocks; i++) {
			unsigned len = short_len + (i >= spec->group1 ? 1u : 0u);

			if (j < len)
				interleaved[at++] = stream[base + j];
			base += len;
		}
	}
	for (j = 0; j < spec->ec_per_block; j++)
		for (i = 0; i < blocks; i++)
			interleaved[at++] = ecbuf[i][j];

	/* THE MATRIX, once per mask, keeping the least penalised. */
	for (mask = 0; mask < 8u; mask++) {
		unsigned score;

		memset(work, 0, (size_t)size * size);
		draw_function(work, size, version);
		place_data(work, size, interleaved, at);
		apply_mask(work, size, mask);
		draw_format(work, size, level, mask);
		score = penalty(work, size);
		if (mask == 0 || score < best_score) {
			best_score = score;
			best_mask = mask;
			memcpy(best, work, (size_t)size * size);
		}
	}
	(void)best_mask;

	for (i = 0; i < size * size; i++)
		out[i] = (uint8_t)(best[i] & M_VALUE);

	return FZN_QR_OK;
}

const char *fzn_qr_err_str(fzn_qr_err_t err)
{
	switch (err) {
	case FZN_QR_OK:
		return "ok";
	case FZN_QR_ERR_MALFORMED:
		return "malformed argument";
	case FZN_QR_ERR_TOO_LONG:
		return "no version this large would hold it";
	case FZN_QR_ERR_FULL:
		return "no room for the modules";
	}

	return "unknown";
}
