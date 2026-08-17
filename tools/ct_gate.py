#!/usr/bin/env python3
"""Check that fzn_ct_memeq compiled to something without a data-dependent branch.

WHY THIS EXISTS. project.md said of `constant_time/`: "Verified rather than
asserted: ... the -Os object has exactly one conditional branch -- the loop's
length test -- with the accumulator spilled through memory each iteration." All
true, and verified exactly once, by hand, on one compiler, on one day. Nothing
re-checked it. The compiler, its version, or the flags can move and that
sentence becomes false without anything saying so -- and it is a security
property, which makes it the weakest evidence in the tree for one of its
strongest claims.

WHAT THIS IS, HONESTLY. A tripwire, not a proof. Deciding from a disassembly
which branch depends on which value is not something a hundred lines of Python
settles, and pretending otherwise would be worse than not checking. What it
does instead is pin the shape the function is known to compile to, so that a
change in that shape stops the build and a person looks. That is a much weaker
claim than "constant time" and a much stronger one than a comment.

WHAT IT REFUSES. Four properties, each one a thing that would have to change
for the function to acquire a data-dependent branch:

  1. Exactly one conditional branch. The loop's length test, and nothing else.
     An early exit on a mismatch is a second one; so is the compiler deciding
     to branch on `diff == 0` at the end.
  2. The boolean is produced without branching -- a conditional SET, not a
     jump. This is the instruction the early exit would replace.
  3. Exactly one return.
  4. The accumulator is stored to memory inside the loop, which is what the
     `volatile` is for. If that store disappears, the accumulator has been
     kept in a register and the compiler is free to reason about its value.

x86-64 ONLY, AND IT SAYS SO. The mnemonics are architecture-specific and
generalising them without a machine to test on would be guesswork. On anything
else it reports SKIPPED and exits 0, because a check that cannot run must not
look like one that passed -- but it exits non-zero if it cannot find the
function at all, since that is indistinguishable from a check of nothing.
"""

import re
import shutil
import subprocess
import sys

FUNCTION = "fzn_ct_memeq"

# Conditional jumps on x86-64: j<cc>, but not the unconditional `jmp`. `jrcxz`
# is conditional and does not start with a condition code, so it is named.
COND_JUMP = re.compile(r"^(j(?!mp\b)[a-z]+|jrcxz)\b")
# A conditional set -- sete/setne/... -- which is how a boolean is produced
# without a branch. cmov would serve the same purpose and is accepted.
COND_SET = re.compile(r"^(set[a-z]+|cmov[a-z]+)\b")
RETURN = re.compile(r"^ret\b")
# A store whose destination is a stack slot: `mov %cl,-0x1(%rsp)`. The
# destination is the last comma-separated operand in AT&T syntax.
STACK_STORE = re.compile(r"^mov[a-z]*\s+[^,]+,\s*-?(0x[0-9a-f]+)?\(%rsp\)")


def fail(message):
	print(f"ct-gate: {message}", file=sys.stderr)
	sys.exit(1)


def disassemble(obj):
	if not shutil.which("objdump"):
		print("ct-gate: SKIPPED -- no objdump on PATH, so nothing was checked")
		sys.exit(0)

	arch = subprocess.run(
		["objdump", "-f", obj], capture_output=True, text=True, check=False
	)
	if arch.returncode != 0:
		fail(f"objdump could not read {obj}: {arch.stderr.strip()}")
	if "i386:x86-64" not in arch.stdout:
		first = next(
			(ln for ln in arch.stdout.splitlines() if "architecture" in ln), "unknown"
		)
		print(f"ct-gate: SKIPPED -- not x86-64 ({first.strip()}), so nothing was checked")
		sys.exit(0)

	out = subprocess.run(
		["objdump", "-d", "--no-show-raw-insn", obj],
		capture_output=True,
		text=True,
		check=False,
	)
	if out.returncode != 0:
		fail(f"objdump failed on {obj}: {out.stderr.strip()}")
	return out.stdout


def body(listing, obj):
	"""The instructions of FUNCTION, in order, as bare mnemonic+operand text."""
	lines = listing.splitlines()
	start = None
	for i, line in enumerate(lines):
		if line.rstrip().endswith(f"<{FUNCTION}>:"):
			start = i + 1
			break
	if start is None:
		# The vacuous-pass guard, and the failure this gate is most likely to
		# have: a renamed function, a stale object, an inlined-away symbol.
		# Reporting "no branches found" here would be a pass.
		fail(f"{FUNCTION} is not in {obj} -- nothing was checked, which is not a pass")

	insns = []
	for line in lines[start:]:
		if not line.strip():
			break
		# `   1a:\tor     %r8d,%ecx`
		parts = line.split("\t", 1)
		if len(parts) != 2:
			continue
		insns.append(" ".join(parts[1].split()))
	if not insns:
		fail(f"{FUNCTION} in {obj} disassembled to no instructions")
	return insns


def main():
	obj = sys.argv[1] if len(sys.argv) > 1 else "constant_time/constant_time.o"
	insns = body(disassemble(obj), obj)

	cond_jumps = [i for i in insns if COND_JUMP.match(i)]
	cond_sets = [i for i in insns if COND_SET.match(i)]
	returns = [i for i in insns if RETURN.match(i)]
	stores = [i for i in insns if STACK_STORE.match(i)]

	problems = []
	if len(cond_jumps) != 1:
		problems.append(
			f"expected exactly 1 conditional branch (the loop's length test), "
			f"found {len(cond_jumps)}: {', '.join(cond_jumps) or 'none'}"
		)
	if not cond_sets:
		problems.append(
			"the result is not produced by a conditional set or move, so the "
			"final comparison may have become a branch"
		)
	if len(returns) != 1:
		problems.append(f"expected exactly 1 return, found {len(returns)}")
	if not stores:
		problems.append(
			"the accumulator is never stored to the stack, so `volatile` is not "
			"forcing it through memory and the compiler may reason about its value"
		)

	print(
		f"ct-gate: {FUNCTION} in {obj}: {len(insns)} instructions, "
		f"{len(cond_jumps)} conditional branch, {len(cond_sets)} conditional set, "
		f"{len(returns)} return, {len(stores)} accumulator store"
	)
	if problems:
		for p in problems:
			print(f"  ct-gate: {p}", file=sys.stderr)
		fail(
			"the shape changed. This is a tripwire rather than a proof, so the "
			"answer is to read the disassembly and decide, not to relax the gate"
		)
	print("ct-gate: shape unchanged -- no data-dependent branch introduced")


if __name__ == "__main__":
	main()
