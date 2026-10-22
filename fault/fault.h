/*
 * FAULTS ON PURPOSE, IN A TEST BUILD ONLY, sec 689 step 0b: the network
 * losing, repeating and reordering datagrams, the process dying at a named
 * point of a write, and a disk that fills -- inside fuzznetd, where a live
 * test can reach them, rather than at library level alone
 * (`sim/test/network_test.c`).
 *
 * COMPILED OUT OF EVERY OTHER BUILD. Without FZN_TEST_FAULTS each macro
 * below is a constant and `fault.c` defines nothing, so a production
 * binary carries no switch a stranger could find. `make fuzznetd-faults`
 * builds the one copy that has them, in a build directory of its own.
 *
 * CONFIGURED BY THE ENVIRONMENT, read once at the first use:
 *
 *   FZN_FAULT_SEED=N          the generator's seed; the pid when unset
 *   FZN_FAULT_LOSS=P          drop P per cent of datagrams sent
 *   FZN_FAULT_DUP=P           send P per cent twice
 *   FZN_FAULT_REORDER=P       hold P per cent back until the next is sent
 *   FZN_FAULT_CRASH=NAME[:N]  die by SIGKILL at the Nth reach (1st when
 *                             unset) of the point NAME -- as a power cut
 *                             does: no cleanup, no core
 *   FZN_FAULT_WRITE_BUDGET=B  after B bytes written, every write fails as
 *                             a full disk does, ENOSPC
 *
 * Each fault taken is said once on stderr, `fault: ...`, so a test can
 * tell a fault from a failure.
 */
#ifndef FZN_FAULT_H
#define FZN_FAULT_H

#include <stddef.h>

typedef enum fzn_fault_datagram {
	FZN_FAULT_SEND = 0, /* send it as usual */
	FZN_FAULT_DROP,     /* report it sent, and send nothing */
	FZN_FAULT_TWICE,    /* send it, and once more */
	FZN_FAULT_HOLD      /* send it after the next one */
} fzn_fault_datagram_t;

#ifdef FZN_TEST_FAULTS

/* What to do with the datagram about to be sent. */
fzn_fault_datagram_t fzn_fault_datagram(void);

/* The point NAME is reached: dies there when it is the one named. */
void fzn_fault_point(const char *name);

/* `n` bytes are about to be written: 1 to go on, or 0 with errno ENOSPC
 * once the budget is spent. */
int fzn_fault_write(size_t n);

#define FZN_FAULT_DATAGRAM() fzn_fault_datagram()
#define FZN_FAULT_POINT(name) fzn_fault_point(name)
#define FZN_FAULT_WRITE(n) fzn_fault_write(n)

#else

#define FZN_FAULT_DATAGRAM() FZN_FAULT_SEND
#define FZN_FAULT_POINT(name) ((void)0)
#define FZN_FAULT_WRITE(n) 1

#endif

#endif /* FZN_FAULT_H */
