/* The ports a host listens on, sec 1289. */
#include "ports.h"

uint16_t fzn_ports_nth(int root, unsigned i)
{
	if (i >= FZN_PORTS_SPAN)
		return 0;
	return (uint16_t)((root ? FZN_PORTS_ROOT_FIRST : FZN_PORTS_USER_FIRST) + i);
}

int fzn_ports_in_span(uint16_t port)
{
	return (port >= FZN_PORTS_ROOT_FIRST && port < FZN_PORTS_ROOT_FIRST + FZN_PORTS_SPAN)
	       || (port >= FZN_PORTS_USER_FIRST && port < FZN_PORTS_USER_FIRST + FZN_PORTS_SPAN);
}

size_t fzn_ports_scan(uint16_t out[FZN_PORTS_ALL])
{
	unsigned i;

	for (i = 0; i < FZN_PORTS_SPAN; i++) {
		out[i] = fzn_ports_nth(0, i);
		out[FZN_PORTS_SPAN + i] = fzn_ports_nth(1, i);
	}
	return FZN_PORTS_ALL;
}
