#!/usr/bin/env python3
"""Check that two security-critical functions still compile to the shape they must.

WHY THIS EXISTS. Both properties below were measured once, by hand, on one
compiler, on one day, and then written into a comment as though they were
standing facts. Both are security properties. The compiler, its version or the
flags can move and make either sentence false with nothing saying so, and one
of the two comments ends with "re-measure if the wipe is ever rewritten" --
an instruction to a person who will not be there.

WHAT THIS IS, HONESTLY. A tripwire, not a proof. Deciding from a disassembly
which branch depends on which value, or whether a secret is truly unrecoverable,
is not something a couple of hundred lines of Python settles, and pretending
otherwise would be worse than not checking. What it does is pin the shape each
function is known to compile to, so that a change stops the build and a person
reads the disassembly. That is a much weaker claim than the ones the comments
make and a much stronger one than a comment.

THE TWO CHECKS.

fzn_ct_memeq -- no data-dependent branch. Four properties, each one something
that would have to change for one to appear:

  1. Exactly one conditional branch: the loop's length test, and nothing else.
     An early exit on a mismatch is a second one; so is the compiler deciding
     to branch on `diff == 0` at the end.
  2. The boolean is produced without branching -- a conditional SET, not a
     jump. This is the instruction an early exit would replace.
  3. Exactly one return.
  4. The accumulator is stored to memory inside the loop, which is what the
     `volatile` is for. If that store disappears, the accumulator has been kept
     in a register and the compiler is free to reason about its value.

Property 4 carries more than its share, and that is measured rather than
guessed: the same function with `volatile` removed compiles, at -Os today, to
one conditional branch, one conditional set and one return -- identical to the
correct function on the other three. Only the missing store separates them.

fzn_commitment_derive -- the key-material wipe survives. The two loops at the
end zero `derived` and `input`, and `volatile` is what stops dead-store
elimination removing writes to something never read again. Measured: 411 bytes
of text with the qualifier and 337 without, and inside the function two
zero-immediate stores with it against none at all. So the property is that
those stores exist -- one per wipe.

x86-64 ONLY, AND IT SAYS SO. The mnemonics are architecture-specific and
generalising them without a machine to test on would be guesswork. On anything
else it reports SKIPPED and exits 0, because a check that cannot run must not
look like one that passed -- but it exits non-zero if it cannot find the
function, since that is indistinguishable from a check of nothing.
"""

import re
import shutil
import subprocess
import sys

# Conditional jumps on x86-64: j<cc>, but not the unconditional `jmp`. `jrcxz`
# is conditional and does not start with a condition code, so it is named.
COND_JUMP = re.compile(r"^(j(?!mp\b)[a-z]+|jrcxz)\b")
# A conditional set -- sete/setne/... -- which is how a boolean is produced
# without a branch. cmov serves the same purpose and is accepted.
COND_SET = re.compile(r"^(set[a-z]+|cmov[a-z]+)\b")
RETURN = re.compile(r"^ret\b")
# A store whose destination is a stack slot: `mov %cl,-0x1(%rsp)`.
STACK_STORE = re.compile(r"^mov[a-z]*\s+[^,]+,\s*-?(0x[0-9a-f]+)?\(%rsp\)")
# A store of an immediate zero anywhere: `movb $0x0,-0x21(%rbp)`. This is what
# a wipe compiles to and what dead-store elimination removes.
ZERO_STORE = re.compile(r"^mov[a-z]*\s+\$0x0,")


def fail(message):
	print(f"codegen-gate: {message}", file=sys.stderr)
	sys.exit(1)


def instrumented(obj):
	"""Was this object built with a sanitizer?

	It matters because the whole gate is about the shape -Os produces, and a
	sanitizer produces a different one on purpose: ASan brackets every access
	with a shadow-memory check, so fzn_ct_memeq goes from 16 instructions and
	one conditional branch to 118 and sixteen, and moves the accumulator off
	the stack frame the store pattern looks for.

	None of that is the property failing. The constant-time claim is about the
	build people ship, and nobody ships a sanitizer build -- so the honest
	answer here is that the check does not apply, not that it failed.

	Found by the gate refusing `make test SANITIZE=1` outright, which is a
	target the Makefile documents and this file had made impossible.
	"""
	if not shutil.which("nm"):
		return False
	out = subprocess.run(["nm", obj], capture_output=True, text=True, check=False)
	if out.returncode != 0:
		return False
	return "__asan_" in out.stdout or "__ubsan_" in out.stdout or "__sanitizer" in out.stdout


def disassemble(obj):
	if not shutil.which("objdump"):
		print("codegen-gate: SKIPPED -- no objdump on PATH, so nothing was checked")
		sys.exit(0)

	if instrumented(obj):
		print(
			f"codegen-gate: SKIPPED -- {obj} is a sanitizer build, whose codegen is "
			"deliberately a different shape, so nothing was checked"
		)
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
		print(
			f"codegen-gate: SKIPPED -- not x86-64 ({first.strip()}), so nothing "
			"was checked"
		)
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


def body(listing, obj, function):
	"""The instructions of `function`, in order, as bare mnemonic+operand text."""
	lines = listing.splitlines()
	start = None
	for i, line in enumerate(lines):
		if line.rstrip().endswith(f"<{function}>:"):
			start = i + 1
			break
	if start is None:
		# The vacuous-pass guard, and the failure this gate is most likely to
		# have: a renamed function, a stale object, a symbol inlined away.
		# Reporting "no branches found" here would be a pass.
		fail(f"{function} is not in {obj} -- nothing was checked, which is not a pass")

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
		fail(f"{function} in {obj} disassembled to no instructions")
	return insns


def check_ct_memeq(insns):
	"""No data-dependent branch. Returns (counts, problems)."""
	cond_jumps = [i for i in insns if COND_JUMP.match(i)]
	cond_sets = [i for i in insns if COND_SET.match(i)]
	returns = [i for i in insns if RETURN.match(i)]
	stores = [i for i in insns if STACK_STORE.match(i)]

	problems = []
	# ONE OR TWO, AND THE RANGE IS MEASURED RATHER THAN GENEROUS.
	#
	# This was "exactly 1", which encoded gcc's loop shape rather than the
	# property. A loop over the caller's length may be top-tested -- gcc, one
	# conditional plus an unconditional back edge -- or rotated -- clang, a
	# zero-length guard plus a conditional back edge. Both branch on the
	# LENGTH and neither touches the data, so both are correct and the gate
	# refused one of them.
	#
	# Measured 2026-08-20 across gcc 14.2 and clang 19.1, real against the two
	# sabotages, which is what makes 2 a bound rather than a shrug:
	#
	#   real:       gcc 1/1/1, clang 2/1/1   (branches/sets/returns)
	#   early exit: gcc 2/0/2, clang 4/1/2
	#   no volatile:gcc 1/1/1, clang 2/1/2
	#
	# gcc's early exit is the case that fits inside the relaxed bound, and it
	# is still caught -- by the missing conditional set and the second return.
	# Every sabotage remains caught at both compilers; none survives on the
	# branch count alone, which is why widening it costs nothing.
	if not 1 <= len(cond_jumps) <= 2:
		problems.append(
			"expected 1 or 2 conditional branches, both on the length -- a "
			"top-tested loop or a rotated one -- and "
			f"found {len(cond_jumps)}: {', '.join(cond_jumps) or 'none'}"
		)
	if not cond_sets:
		problems.append(
			"the result is not produced by a conditional set or move, so the final "
			"comparison may have become a branch"
		)
	if len(returns) != 1:
		problems.append(f"expected exactly 1 return, found {len(returns)}")
	if not stores:
		problems.append(
			"the accumulator is never stored to the stack, so `volatile` is not "
			"forcing it through memory and the compiler may reason about its value"
		)

	counts = (
		f"{len(cond_jumps)} conditional branch, {len(cond_sets)} conditional set, "
		f"{len(returns)} return, {len(stores)} accumulator store"
	)
	return counts, problems


def check_wipe(insns):
	"""The key-material wipe was not deleted. Returns (counts, problems)."""
	zeros = [i for i in insns if ZERO_STORE.match(i)]

	problems = []
	if len(zeros) < 2:
		problems.append(
			f"expected at least 2 zero stores, one per wipe loop, found {len(zeros)}. "
			"Without `volatile` there are none at all, so a count of zero means the "
			"wipe was deleted and key material is left on the stack"
		)

	return f"{len(zeros)} zero store", problems


CHECKS = {
	"ct": ("fzn_ct_memeq", check_ct_memeq),
	"wipe": ("fzn_commitment_derive", check_wipe),
}


def main():
	if len(sys.argv) != 3 or sys.argv[1] not in CHECKS:
		fail(f"usage: codegen_gate.py {{{'|'.join(CHECKS)}}} <object>")
	function, checker = CHECKS[sys.argv[1]]
	obj = sys.argv[2]

	insns = body(disassemble(obj), obj, function)
	counts, problems = checker(insns)

	print(f"codegen-gate: {function} in {obj}: {len(insns)} instructions, {counts}")
	if problems:
		for p in problems:
			print(f"  codegen-gate: {p}", file=sys.stderr)
		fail(
			"the shape changed. This is a tripwire rather than a proof, so the answer "
			"is to read the disassembly and decide, not to relax the gate"
		)
	print(f"codegen-gate: {function} -- shape unchanged")


if __name__ == "__main__":
	main()
