/*
 * THE SMALLEST HOST ON A CORTEX-M3, project.md sec 1481: `device/device.h`
 * as `device/test/device_sim.c` runs it, built for Arm's MPS2 AN385 board as
 * qemu emulates it (`qemu-system-arm -machine mps2-an385`) -- the device core
 * on a 32-bit target with no operating system, its bearer SLIP on UART0 to a
 * `fuzznet-bridge`, what it was answered said on UART1.
 *
 * WHAT THE BOARD IS GIVEN, one line on UART0 before the bearer starts:
 *
 *     SEED UNIT NAME ARGS IMAGE
 *
 * SEED 64 hex digits of entropy, from which a ChaCha20 stream is the random
 * source -- a board's own generator in its place on real hardware, the
 * emulated one having none; UNIT the bearer's unit; NAME the procedure
 * asked, ARGS its argument (`-` for none) and IMAGE the device's image
 * (`--device-image`). It asks once and says on UART1
 *
 *     device: status S, N byte(s): ANSWER
 *
 * or `device: ` and why it failed, and then idles.
 *
 * NO LIBRARY: the few string functions the core needs are here, written so
 * the compiler cannot turn their loops back into calls to themselves.
 */

#include <stddef.h>
#include <stdint.h>

#include "../device.h"
#include "../../net/bearer.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "monocypher.h"

/* ---- the board: CMSDK UARTs and the Cortex-M SysTick ------------------------ */

#define UART0 0x40004000u
#define UART1 0x40005000u
#define UART_DATA 0x00u
#define UART_STATE 0x04u /* bit 0 TX full, bit 1 RX full */
#define UART_CTRL 0x08u  /* bit 0 TX enable, bit 1 RX enable */
#define UART_BAUDDIV 0x10u

#define SYST_CSR (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR (*(volatile uint32_t *)0xE000E018u)
/* The AN385's core clock, 25 MHz: a tick a millisecond. */
#define CORE_HZ 25000000u

static volatile uint32_t *reg(uint32_t base, uint32_t off)
{
	return (volatile uint32_t *)(uintptr_t)(base + off);
}

static void uart_init(uint32_t base)
{
	*reg(base, UART_BAUDDIV) = 16u;
	*reg(base, UART_CTRL) = 3u;
}

static void uart_put(uint32_t base, uint8_t c)
{
	while (*reg(base, UART_STATE) & 1u)
		;
	*reg(base, UART_DATA) = c;
}

static int uart_get(uint32_t base, uint8_t *c)
{
	if (!(*reg(base, UART_STATE) & 2u))
		return 0;
	*c = (uint8_t)*reg(base, UART_DATA);
	return 1;
}

static volatile uint64_t ticks_ms;

void systick_handler(void);
void systick_handler(void)
{
	ticks_ms++;
}

static uint64_t uptime_ms(void *ctx)
{
	uint64_t a, b;

	(void)ctx;
	do { /* read twice: a 64-bit count is two loads on this core */
		a = ticks_ms;
		b = ticks_ms;
	} while (a != b);
	return a;
}

/* ---- the few string functions, none of them a call to itself ---------------- */

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);

void *memcpy(void *dst, const void *src, size_t n)
{
	volatile uint8_t *d = dst;
	const uint8_t *s = src;

	while (n--)
		*d++ = *s++;
	return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
	volatile uint8_t *d = dst;
	const uint8_t *s = src;

	if (d < s) {
		while (n--)
			*d++ = *s++;
	} else {
		while (n--)
			d[n] = s[n];
	}
	return dst;
}

void *memset(void *dst, int c, size_t n)
{
	volatile uint8_t *d = dst;

	while (n--)
		*d++ = (uint8_t)c;
	return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
	const volatile uint8_t *x = a, *y = b;

	for (; n; n--, x++, y++)
		if (*x != *y)
			return *x < *y ? -1 : 1;
	return 0;
}

size_t strlen(const char *s)
{
	const volatile char *p = s;

	while (*p)
		p++;
	return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
	const volatile unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;

	while (*x && *x == *y) {
		x++;
		y++;
	}
	return *x - *y;
}

int strncmp(const char *a, const char *b, size_t n)
{
	const volatile unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;

	for (; n; n--, x++, y++)
		if (*x != *y || !*x)
			return *x - *y;
	return 0;
}

/* ---- what the device is told, and says --------------------------------------- */

static void say(const char *s)
{
	while (*s)
		uart_put(UART1, (uint8_t)*s++);
}

static void say_n(const uint8_t *s, size_t n)
{
	while (n--)
		uart_put(UART1, *s++);
}

static void say_number(uint32_t v)
{
	char digits[11];
	int n = 0;

	do {
		digits[n++] = (char)('0' + v % 10u);
		v /= 10u;
	} while (v);
	while (n)
		uart_put(UART1, (uint8_t)digits[--n]);
}

/* THE RANDOM SOURCE: ChaCha20 over the seed the line gave, its block counter
 * never reused. */
static uint8_t seed[32];
static uint64_t seed_block;

static int fill(void *ctx, uint8_t *out, size_t len)
{
	static const uint8_t nonce[8];

	(void)ctx;
	seed_block = crypto_chacha20_djb(out, NULL, len, seed, nonce, seed_block);
	return 1;
}

static int hex_digit(uint8_t c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* ---- the bearer over UART0 ---------------------------------------------------- */

static int stream_send(void *ctx, const uint8_t *bytes, size_t len)
{
	static uint8_t coded[2u * FZN_BEARER_UNIT_MAX + 2u];
	size_t n = fzn_slip_encode(bytes, len, coded, sizeof(coded)), at;

	(void)ctx;
	for (at = 0; at < n; at++)
		uart_put(UART0, coded[at]);
	return n != 0;
}

static size_t stream_recv(void *ctx, uint8_t *out, size_t cap, unsigned wait_ms)
{
	static fzn_slip_reader_t reader;
	static uint8_t held[FZN_BEARER_UNIT_MAX];
	const uint64_t until = uptime_ms(NULL) + wait_ms;

	(void)ctx;
	reader.buffer = held;
	reader.cap = sizeof(held);
	while (uptime_ms(NULL) < until) {
		uint8_t byte;
		size_t done;

		if (!uart_get(UART0, &byte))
			continue;
		done = fzn_slip_feed(&reader, byte);
		if (done && done <= cap) {
			memcpy(out, held, done);
			return done;
		}
	}
	return 0;
}

/* ---- the line, then the call ------------------------------------------------- */

static char line[8192];

/* The next word of `*at`, NUL-ended in place, or NULL. */
static char *word(char **at)
{
	char *w = *at;

	while (*w == ' ')
		w++;
	if (!*w)
		return NULL;
	*at = w;
	while (**at && **at != ' ')
		(*at)++;
	if (**at)
		*(*at)++ = '\0';
	return w;
}

int main(void);
int main(void)
{
	static fzn_device_t d;
	static fzn_bearer_slot_t slot;
	static uint8_t answer[1024];
	static fzn_hash_ops_t hash;
	static fzn_aead_ops_t aead;
	static fzn_random_ops_t rng;
	static fzn_bearer_t bearer;
	static fzn_bearer_join_t join;
	char *at = line, *w_seed, *w_unit, *name, *args, *image;
	size_t n = 0, len = 0, i;
	unsigned status = 0, unit = 0;
	fzn_device_err_t err;

	uart_init(UART0);
	uart_init(UART1);
	SYST_RVR = CORE_HZ / 1000u - 1u;
	SYST_CVR = 0u;
	SYST_CSR = 7u; /* the core's clock, the interrupt, on */
	say("device: ready\n");
	for (;;) {
		uint8_t c;

		if (!uart_get(UART0, &c))
			continue;
		if (c == '\n' || n + 1u >= sizeof(line))
			break;
		line[n++] = (char)c;
	}
	line[n] = '\0';
	if (!(w_seed = word(&at)) || strlen(w_seed) != 64u || !(w_unit = word(&at)) || !(name = word(&at))
	    || !(args = word(&at)) || !(image = word(&at))) {
		say("device: a line SEED UNIT NAME ARGS IMAGE was wanted\n");
		for (;;)
			;
	}
	for (i = 0; i < 64u; i++) {
		const int v = hex_digit((uint8_t)w_seed[i]);

		if (v < 0) {
			say("device: the seed is no hex\n");
			for (;;)
				;
		}
		seed[i / 2u] = (uint8_t)(i & 1u ? seed[i / 2u] | v : v << 4);
	}
	for (i = 0; w_unit[i]; i++)
		unit = unit * 10u + (unsigned)(w_unit[i] - '0');
	if (args[0] == '-' && !args[1])
		args[0] = '\0';
	if (!fzn_device_image_from_text(image, strlen(image), &d.image)) {
		say("device: the image did not read\n");
		for (;;)
			;
	}
	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);
	rng.fill = fill;
	bearer.unit = unit;
	bearer.send = stream_send;
	bearer.recv = stream_recv;
	join.held = &slot;
	join.n_held = 1u;
	join.unit = unit;
	d.hash = &hash;
	d.aead = &aead;
	d.rng = &rng;
	d.bearer = &bearer;
	d.join = &join;
	d.uptime_ms = uptime_ms;
	d.wait_ms = 400u;
	d.tries = 30u;
	d.life_s = 60u;
	err = fzn_device_call(&d, name, (const uint8_t *)args, strlen(args), answer, sizeof(answer), &len, &status);
	if (err != FZN_DEVICE_OK) {
		say("device: ");
		say(fzn_device_err_str(err));
		say("\n");
	} else {
		say("device: status ");
		say_number(status);
		say(", ");
		say_number((uint32_t)len);
		say(" byte(s): ");
		say_n(answer, len);
		say("\n");
	}
	for (;;)
		;
}

/* ---- the start: a stack, zeroed memory, the vectors --------------------------- */

extern uint32_t __stack_top, __bss_start, __bss_end;
void reset_handler(void);
void default_handler(void);

void reset_handler(void)
{
	volatile uint32_t *p;

	for (p = &__bss_start; p < &__bss_end; p++)
		*p = 0u;
	(void)main();
	for (;;)
		;
}

void default_handler(void)
{
	for (;;)
		;
}

__attribute__((section(".vectors"), used)) static void (*const vectors[16])(void) = {
	(void (*)(void))(uintptr_t)&__stack_top,
	reset_handler,
	default_handler, /* NMI */
	default_handler, /* HardFault */
	default_handler, default_handler, default_handler, 0, 0, 0, 0,
	default_handler, /* SVCall */
	default_handler, 0,
	default_handler, /* PendSV */
	systick_handler,
};
