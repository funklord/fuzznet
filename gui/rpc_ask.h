/*
 * THE TYPED CLIENT ON A VIEW'S ASK CALLBACK, sec 1102: every view here takes
 * `fzn_notebook_view_ask_t` from its host -- the socket's, or a test's node --
 * and the views that read the node through `fzn_rpc_` put the client on that
 * callback by the client's `answer` hook. Each request becomes the line the
 * callback sends; the reply line comes back without its newline. One place,
 * so no view reads a reply's grammar itself.
 */
#ifndef FZN_GUI_RPC_ASK_H
#define FZN_GUI_RPC_ASK_H

#include "notebook_view.h"

extern "C" {
#include "../local/rpc.h"
#include "../local/rpc_err.h"
}

#include <stdio.h>

struct fzn_gui_rpc {
	fzn_rpc_t c;
	fzn_notebook_view_ask_t ask;
	void *ask_ctx;
};

static inline int fzn_gui_rpc_answer(void *ctx, const char *verb, const char *arg, size_t arg_len,
                                     uint8_t *reply, size_t reply_cap, size_t *reply_len)
{
	auto *r = static_cast<fzn_gui_rpc *>(ctx);
	char line[FZN_RPC_REPLY_MAX];
	int n = arg_len ? snprintf(line, sizeof line, "%s %.*s", verb, (int)arg_len, arg)
	                : snprintf(line, sizeof line, "%s", verb);

	if (n < 0 || (size_t)n >= sizeof line)
		return FZN_RPC_ERR_MALFORMED;
	size_t got = r->ask(r->ask_ctx, line, (char *)reply, reply_cap);
	if (!got)
		return FZN_RPC_ERR_SEND_FAILED;
	while (got && (reply[got - 1] == '\n' || reply[got - 1] == '\r'))
		got--;
	*reply_len = got;
	return FZN_RPC_OK;
}

/* WHY A CALL FAILED, in words for a person: the node's own, or the client's
 * where it refused before asking -- a name already held, a host's own
 * setting -- and "the node did not answer" only when nothing could be asked
 * of it. `answered` alone cannot tell those apart, since a refusal made
 * before asking leaves it 0 as silence does (sec 1107). */
static inline const char *fzn_gui_rpc_silent(const fzn_gui_rpc *r)
{
	return !r->c.answered && (r->c.error_code == FZN_RPC_ERR_SEND_FAILED
	                          || r->c.error_code == FZN_RPC_ERR_NO_PEER_TRANSPORT)
	               ? "The node did not answer."
	               : r->c.error;
}

/* WEAK HERE, sec 1181: a program that links no `notebook_view.o` -- a
 * view's own test, a host with an ask of its own -- has no socket ask, and
 * the comparison below then never holds. */
extern size_t fzn_notebook_view_socket_ask(void *ctx, const char *line, char *reply,
                                           size_t reply_cap) __attribute__((weak));

/* Ready to call: the client initialised and asking through `ask`.
 *
 * A HOST THAT GIVES THE SOCKET ASK, sec 1181, gives the node's socket path
 * as its context -- fuzzypickles' every page does -- so the client is put on
 * that socket itself rather than on the line callback: there it speaks the
 * binary messages of secs 1152-1180 where the node reads them, and the
 * verbs where it does not. Through the line callback every call was text,
 * since a callback that carries lines cannot carry a binary request. Any
 * other ask -- a test's scripted node, a host's own -- is used as before. */
static inline void fzn_gui_rpc_init(fzn_gui_rpc *r, fzn_notebook_view_ask_t ask, void *ask_ctx)
{
	fzn_rpc_init(&r->c);
	r->ask = ask;
	r->ask_ctx = ask_ctx;
	if (fzn_notebook_view_socket_ask && ask == fzn_notebook_view_socket_ask && ask_ctx
	    && fzn_rpc_set_node_socket(&r->c, (const char *)ask_ctx) == 0 && r->c.node_socket[0])
		return;
	r->c.answer = fzn_gui_rpc_answer;
	r->c.answer_ctx = r;
}

#endif /* FZN_GUI_RPC_ASK_H */
