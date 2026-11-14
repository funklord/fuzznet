#include "../hex.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                   \
  do {                                                                \
    if (!(cond)) {                                                    \
      fprintf(stderr, "FAIL hex_test.c:%d: %s\n", __LINE__, #cond);    \
      failures++;                                                     \
    }                                                                 \
  } while (0)

static void test_hex_roundtrip(void) {
	uint8_t data[] = {0x00, 0x01, 0xAB, 0xCD, 0xFF};
	char hex[16];
	fzn_hex_encode(data, sizeof(data), hex);
	CHECK(strcmp(hex, "0001abcdff") == 0);

	uint8_t dec[8];
	CHECK(fzn_hex_decode(hex, dec, sizeof(data)) == 0);
	CHECK(memcmp(dec, data, sizeof(data)) == 0);
}

static void test_hex_decode_rejects_wrong_length(void) {
	uint8_t dec[8];
	CHECK(fzn_hex_decode("abcd", dec, 3) != 0); /* implies 3 bytes, given 2 */
	/* LONGER than asked: the length check alone refuses it, every digit being good. */
	CHECK(fzn_hex_decode("abcdef", dec, 2) != 0);
}

static void test_hex_decode_rejects_invalid_char(void) {
	uint8_t dec[8];
	CHECK(fzn_hex_decode("zzzz", dec, 2) != 0);
	/* A BAD HIGH DIGIT beside a good low one, and the reverse. */
	CHECK(fzn_hex_decode("z0", dec, 1) != 0);
	CHECK(fzn_hex_decode("0z", dec, 1) != 0);
}

static void test_hex_decode_var(void) {
	uint8_t dec[8];
	size_t dec_len;
	CHECK(fzn_hex_decode_var("aabbcc", dec, sizeof(dec), &dec_len) == 0);
	CHECK(dec_len == 3);
	CHECK(dec[0] == 0xaa && dec[1] == 0xbb && dec[2] == 0xcc);

	CHECK(fzn_hex_decode_var("abc", dec, sizeof(dec), &dec_len) != 0); /* odd length */
	CHECK(fzn_hex_decode_var("", dec, sizeof(dec), &dec_len) != 0);    /* empty */
}

/* ONE BYTE, TWO DIGITS, AND NOTHING PAST THEM: a field with no room for a
 * terminator keeps the byte after it. */
static void test_hex_byte(void) {
	char out[3] = { 'x', 'x', '!' };
	fzn_hex_byte(0x00, out);
	CHECK(out[0] == '0' && out[1] == '0' && out[2] == '!');
	fzn_hex_byte(0xa9, out);
	CHECK(out[0] == 'a' && out[1] == '9' && out[2] == '!');
	fzn_hex_byte(0xff, out);
	CHECK(out[0] == 'f' && out[1] == 'f' && out[2] == '!');
}

/* EACH DIGIT'S VALUE, and the two readers' one difference: case. NUL, a
 * letter past f and a high byte are no digit to either. */
static void test_hex_digit(void) {
	CHECK(fzn_hex_digit_lower('0') == 0 && fzn_hex_digit_lower('9') == 9);
	CHECK(fzn_hex_digit_lower('a') == 10 && fzn_hex_digit_lower('f') == 15);
	CHECK(fzn_hex_digit_lower('A') == -1 && fzn_hex_digit_lower('F') == -1);
	CHECK(fzn_hex_digit('A') == 10 && fzn_hex_digit('F') == 15 && fzn_hex_digit('c') == 12);
	CHECK(fzn_hex_digit('0') == 0 && fzn_hex_digit('9') == 9);
	CHECK(fzn_hex_digit('\0') == -1 && fzn_hex_digit_lower('\0') == -1);
	CHECK(fzn_hex_digit('g') == -1 && fzn_hex_digit('G') == -1 && fzn_hex_digit('/') == -1);
	CHECK(fzn_hex_digit(':') == -1 && fzn_hex_digit('@') == -1 && fzn_hex_digit('`') == -1);
	CHECK(fzn_hex_digit((char)0xe1) == -1 && fzn_hex_digit_lower((char)0xe1) == -1);
}

int main(void) {
	test_hex_byte();
	test_hex_digit();
	test_hex_roundtrip();
	test_hex_decode_rejects_wrong_length();
	test_hex_decode_rejects_invalid_char();
	test_hex_decode_var();
	if (failures) return 1;
	printf("hex_test: all passed\n");
	return 0;
}
