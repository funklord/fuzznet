# fuzznet's journal: what was true once

Moved out of `project.md` under the holder's rule of 2026-11-20: dated
state-of-play sweeps, session narrative and closed findings, so that
`project.md` stays readable enough to be authoritative. Oldest first,
appended to and never rewritten. **A section here keeps its number**, so
a `sec N` citing it resolves here -- `make cites` reads both files'
headings (project.md sec 1403).

## 878. Where this stands, folded 2026-11-04

A session's fold, so the next one starts from the record rather than
from memory. Everything below is committed and pushed, the tree is level
with origin, and the inbox is empty.

**Built across secs 852 to 877, in the order the holder set** (sec 851,
and the holder's word of 2026-11-04 for 871 to 875):
- Local permissions, 852.
- `call` by name, here, across hosts and through a follower: 853, with
  the bound on its answer in 863.
- Lists and records under a prefix: 854, 855 and 861.
- The consumer services as build flags, with unreachable code dropped at
  link: 856 and 860.
- Huge pages refused before main, 862.
- Events since a cursor, 866.
- Group-scoped settings and `get setting here`, 868.
- The relay route, 871.
- Command propagation, 872.
- The staged commit, 873.
- Sealed group values and later members: 874 and 875.
- The in-process reader, 877.

**Open, none asked for:**
- **A staged clear** (`remove staged`). The machinery of sec 873 would
  carry it.
- ~~A sealed value reaching a later member once its sealer is gone.~~
  Built in sec 880.
- **A contact's key as a `message` event's NAME.** fuzzypickles says it
  does not need this.

**Notes for the next session:**
- `fzn_node_settings_here` and `fzn_daemon_setting_here` answer -1 for a
  value sealed to a key this host lacks. Test for `> 0`, not for nonzero.
- An older build refuses a group cell (sec 868) or a stage object (sec
  873) it is carried, and goes on with the rest of the stream.
- `live_ext` now runs about seven minutes. Its Makefile bound is 560 s.

**Waiting on the holder:** nothing.

## 892. Where this stands, folded 2026-11-05

Everything is committed and pushed, the tree is level with origin, and the
inbox is empty. Since sec 878: secs 879 to 891.

**Verified on the final code:** `make test`, `make style`, `make livecheck`
(235 phase lines, no failure, the new scripts among them) and `make
livecheck-faults`, which is where `live_estate` runs.

**`make livecheck-san`, its first run as a target: 0 reports, 18 scripts
passed, and `live_siblings` failed once**, at phase a: "after 6 rounds each, a
pairing taken at B False, at C False". Unexplained. Repeated at once, it passed
4 of 4 sanitized and 2 of 2 plain, which is what an intermittent fault does and
clears nothing. Neither host paired in any of twelve daemons, so it is no late
log line. **The candidate, not proved:** its ports were 28000 to 32000, across
fuzzypickles' fixed 29800 to 31000, and a suite of theirs was running. The run's
logs went with its scratch. Its ports are moved past theirs; if it fails again
there, this was not the cause.

**Leaks:** nothing reports through `live_ext`'s clean stops. A daemon stopped
by SIGTERM dies without LeakSanitizer running, since nothing here handles that
signal, so a live script over `fuzznetd` says nothing about leaks. Memory
reachable from a static is not a leak to it either.

**Two trailers are wrong and stand, the commits being pushed.** `4312c3a`'s
names no commit (sec 890). `aaf69c2`'s reads `09b200d0aa52`, its first seven
right, for `09b200d3379d`.

**Open, none asked for:**
- A staged clear (sec 873), for want of a consumer.
- `sec 880`'s limits: a holder away at a reseal may hand on the old value, and
  a sealed value is replaced, never withdrawn.

**Waiting on others:** fuzzypickles' pin and its step 3, told of every fix; fzpd
on `fzn_daemon_main` is its tree's work. netcfgd told of `any=x`, the follower's
read, and sec 879.

**Waiting on the holder:** nothing.

## 901. Where this stands, folded 2026-11-05

**Built since sec 892, all on the holder's word or a consumer's asking:** two
people may share a name (893), a host keeping and relaying nothing carries no
group's lines (894), what is decided apart is tracked (895), a device joins by one
code (896), SIGTERM stops cleanly and leaks are looked for (897), a contact's root
is asked first (898), a held event stream (899), a kept reply goes only where it
was asked from (900). `FZN_PRODUCT_NETCFGD` is 3.

**Gates at `03a3337`, nothing beside them:** `make test`, `installcheck`, `style`,
`livecheck` (252 lines), `livecheck-faults` pass. `livecheck-san`: 19 scripts
passed, 0 reports, leaks on, and two failed.

**`live_siblings`' failure is explained, and sec 892's candidate was wrong.** It came
back with its ports moved and no other suite up, so ports were not it. C takes its
pairing once, says so 15 ms past the reconcile line, and the script read the log
at that line and stopped the daemon: read after the stop now, 5 of 5 and more.

**`live_contacts` f0, explained 2026-11-06.** Bounds of 90 and 150 s at e2 and f2 are
180 and 300 now, a sanitized round being 66 s. f0 went on failing now and then, in
the plain suite too, so "under the sanitizer" was wrong, and so was reading a tail
of S's log as S offering nothing. With every log kept: S delivered the line, and
**R3 filed and settled it.** R3 has no address of its own, but says hello to R, and R
advertises where a host was seen (sec 697), so S may reach it, by timing. That is
right. The script looked only at R and R2, believing R3 unreachable. It now takes R3
as a filer, and such a run leaves sec 802 unasked.

**`make livecheck-san` at `4677d9d`, nothing beside it:** 21 scripts, no report,
leaks on: its first clean run.

**Open, unexplained, said as that:**
- **`live_names` b failed once** in `make livecheck`: after 180 s neither host had
  the other's name. It then passed 18 of 18 alone, and in every gate since. Logs
  went with the run. Orphaned daemons of this session's were up on those ports for
  part of the day, from runs killed by an outer `timeout`, which may or may not
  bear on it. Not concluded.
- **Why sec 897's stop raised `live_contacts`' f2 failures** (sec 898).
- **`live_faults` j** failed once at its 60 s bound, with other runs beside it, and
  passed alone.

**A lesson of this run:** `timeout` around a live script kills the script and not
its daemons, whose process groups are their own. Stop one with `-s INT`, or let it
reach its own deadline.

**Waiting on the holder:**
- A right to hold the application's events for `any` (netcfgd's asking): sec 883
  refused `any=r`. The 4 held slots this line once feared for are gone (sec 903), and
  the word with them (sec 899), so what is left to weigh is any local user hearing
  what the application publishes through `local/events`.

**Waiting on others:** fuzzypickles' `contacts-same-name` expectation, its pin and
step 3, and fzpd on `fzn_daemon_main`. A real second user for sec 899, on either
side. Open from before: a staged clear (sec 873), sec 880's limits.

