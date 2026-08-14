# fuzznet

The authenticated datagram protocol shared by `fuzzypickles`, `netcfgd` and
the planned `raidcfgd`, so that three projects do not write the same envelope,
signing, session and chunking three times.

A C library, using Monocypher, linked by **unprivileged** processes. It carries
messages; it does not know what they mean. Each consuming project keeps its own
command vocabulary, its own semantics and its own local socket.

**Status: the pieces that do not need `situ` are built.** `project.md` is
the design and the source of truth; §8 says which modules exist and §10 has
the order of work.

Built and tested: capability chains with minting, delegation and revocation
(`chain/`); command expiry and the replay window it bounds (`frame/`);
splitting, reassembly and the memory bound (`chunk/`); constant-time
comparison (`constant_time/`). `make test` runs five suites and five fuzz
harnesses; `make test SANITIZE=1` runs the lot under ASan and UBSan.

Not built, and each waiting on something named: the frame itself, which is a
`situ` schema that does not yet generate code (§6); the rung this library
stands on, which is the blocking decision (§10 step 4); and `local/`, which
waits for a real `raidcfgd` (§2).

Three things to know before reading further, because each contradicts what a
shared protocol library usually looks like:

- **The local socket is not part of this.** Two consumers already have one,
  they disagree about its encoding, and both disagreements are load-bearing.
  §2 argues that rather than asserting it.
- **The privileged daemon never links this.** Whatever speaks UDP is a
  separate unprivileged process, so a defect here is not a root defect. §3.
- **Grants do not expire; commands do.** The two consumers' rules look like
  they conflict and do not. §4.3.
