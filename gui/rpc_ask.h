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

/* Ready to call: the client initialised and asking through `ask`. */
static inline void fzn_gui_rpc_init(fzn_gui_rpc *r, fzn_notebook_view_ask_t ask, void *ask_ctx)
{
	fzn_rpc_init(&r->c);
	r->ask = ask;
	r->ask_ctx = ask_ctx;
	r->c.answer = fzn_gui_rpc_answer;
	r->c.answer_ctx = r;
}

#endif /* FZN_GUI_RPC_ASK_H */
