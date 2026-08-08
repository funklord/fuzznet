# fuzznet

The authenticated datagram protocol shared by `fuzzypickles`, `netcfgd` and
the planned `raidcfgd`, so that three projects do not write the same envelope,
signing, session and chunking three times.

A C library, using Monocypher, linked by **unprivileged** processes. It carries
messages; it does not know what they mean. Each consuming project keeps its own
command vocabulary, its own semantics and its own local socket.

**Status: design, no code.** `project.md` is the design and the source of
truth. `project.md` §9 has the order of work, and the first item is an
evaluation rather than an implementation.

Three things to know before reading further, because each contradicts what a
shared protocol library usually looks like:

- **The local socket is not part of this.** Two consumers already have one,
  they disagree about its encoding, and both disagreements are load-bearing.
  §2 argues that rather than asserting it.
- **The privileged daemon never links this.** Whatever speaks UDP is a
  separate unprivileged process, so a defect here is not a root defect. §3.
- **Grants do not expire; commands do.** The two consumers' rules look like
  they conflict and do not. §4.3.
