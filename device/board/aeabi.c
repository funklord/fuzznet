/*
 * WHAT THE ARM EABI ASKS OF A RUNTIME, for `device/board/mps2.c` (project.md
 * sec 1481): a board built with no compiler-rt still divides 64-bit numbers
 * and clears memory. 64-bit division returns its quotient in r0:r1 and its
 * remainder in r2:r3, which no C function's return can say, so the two
 * entry points are a few naked instructions around a shift-and-subtract
 * division in C that never itself divides a 64-bit number.
 */

#include <stddef.h>
#include <stdint.h>

void *memset(void *dst, int c, size_t n);
uint64_t fzn_board_udivmod(uint64_t num, uint64_t den, uint64_t *rem);
int64_t fzn_board_divmod(int64_t num, int64_t den, int64_t *rem);
void __aeabi_memclr(void *dst, size_t n);
void __aeabi_memclr4(void *dst, size_t n);
void __aeabi_memclr8(void *dst, size_t n);
void __aeabi_uldivmod(void);
void __aeabi_ldivmod(void);

/* NUM over DEN, the remainder in `*rem`; a zero DEN gives all ones, and
 * NUM back as the remainder, rather than a trap. */
uint64_t fzn_board_udivmod(uint64_t num, uint64_t den, uint64_t *rem)
{
	uint64_t q = 0, r = 0;
	int i;

	if (!den) {
		*rem = num;
		return ~(uint64_t)0;
	}
	for (i = 63; i >= 0; i--) {
		r = (r << 1) | ((num >> i) & 1u);
		if (r >= den) {
			r -= den;
			q |= (uint64_t)1 << i;
		}
	}
	*rem = r;
	return q;
}

/* C's division: the quotient toward zero, the remainder the sign of NUM. */
int64_t fzn_board_divmod(int64_t num, int64_t den, int64_t *rem)
{
	const int neg_q = (num < 0) != (den < 0), neg_r = num < 0;
	const uint64_t un = num < 0 ? 0u - (uint64_t)num : (uint64_t)num;
	const uint64_t ud = den < 0 ? 0u - (uint64_t)den : (uint64_t)den;
	uint64_t r, q = fzn_board_udivmod(un, ud, &r);

	*rem = neg_r ? (int64_t)(0u - r) : (int64_t)r;
	return neg_q ? (int64_t)(0u - q) : (int64_t)q;
}

void __aeabi_memclr(void *dst, size_t n)
{
	memset(dst, 0, n);
}

void __aeabi_memclr4(void *dst, size_t n)
{
	memset(dst, 0, n);
}

void __aeabi_memclr8(void *dst, size_t n)
{
	memset(dst, 0, n);
}

/* r0:r1 / r2:r3: the remainder through a slot on the stack, kept 8-aligned
 * at the call. */
__attribute__((naked)) void __aeabi_uldivmod(void)
{
	__asm__ volatile("push {r4, lr}\n\t"
	                 "sub sp, sp, #16\n\t"
	                 "add r4, sp, #8\n\t"
	                 "str r4, [sp]\n\t"
	                 "bl fzn_board_udivmod\n\t"
	                 "ldrd r2, r3, [sp, #8]\n\t"
	                 "add sp, sp, #16\n\t"
	                 "pop {r4, pc}\n\t");
}

__attribute__((naked)) void __aeabi_ldivmod(void)
{
	__asm__ volatile("push {r4, lr}\n\t"
	                 "sub sp, sp, #16\n\t"
	                 "add r4, sp, #8\n\t"
	                 "str r4, [sp]\n\t"
	                 "bl fzn_board_divmod\n\t"
	                 "ldrd r2, r3, [sp, #8]\n\t"
	                 "add sp, sp, #16\n\t"
	                 "pop {r4, pc}\n\t");
}
