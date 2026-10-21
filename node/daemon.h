/*
 * FUZZNETD'S NODE AS A CALL, sec 666 stage 3 (sec 670): everything fuzznetd
 * does -- its options, its store, the claim and the face or follower it
 * makes this process, the local and remote hops and the rounds -- behind
 * one function, so another daemon of the same identity's work (fzpd, sec
 * 666) runs this node rather than a copy of it. fuzznetd's own main is a
 * call to it with no extension.
 *
 * ONCE PER PROCESS, and it does not return while it serves: it reads its
 * options from `argv` as fuzznetd's command line, keeps `argv` to start
 * again in place (sec 638), installs signal handlers and an atexit, and
 * answers the process's exit status.
 */
#ifndef FZN_NODE_DAEMON_H
#define FZN_NODE_DAEMON_H

/* WHAT A DAEMON ADDS TO THE NODE: its own local verbs, remote request types
 * and journal kinds -- sec 666 stage 4, not yet defined, so NULL is the
 * only extension there is. */
typedef struct fzn_daemon_ext fzn_daemon_ext_t;

/* RUN THE NODE as fuzznetd with `argc` and `argv`, `ext` NULL: the exit
 * status, as fuzznetd's main would return it. */
int fzn_daemon_main(int argc, char **argv, const fzn_daemon_ext_t *ext);

#endif /* FZN_NODE_DAEMON_H */
