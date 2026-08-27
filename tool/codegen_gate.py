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

fzn_commitment_derive_root -- the key-material wipe survives. The two loops at the
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
# A store whose destination is a stack slot: `mov %cl,-0x1(%rsp)`, or the same
# through a frame pointer, `mov %cl,-0x19(%rbp)`. Both spellings, because which
# one appears is the compiler's choice -- gcc at -Os and clang both use %rsp,
# gcc with a frame pointer uses %rbp, and the property is that the accumulator
# goes through memory rather than which register addresses it.
STACK_STORE = re.compile(r"^mov[a-z]*\s+[^,]+,\s*-?(0x[0-9a-f]+)?\(%r[sb]p\)")
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


def unoptimised(obj):
	"""Was this built without optimisation? Returns the flag, or None.

	IT MUST SKIP RATHER THAN PASS, and that is measured rather than assumed.
	At -O0 every local is spilled, so the non-volatile variant of
	fzn_ct_memeq has seven stack stores against the real one's eight -- the
	check that carries the whole `volatile` claim cannot tell them apart. At
	-Os it is two against zero.

	So a floor that reported success here would be reporting it for the one
	property this file exists to defend, in the build where that property is
	invisible. A check that cannot run must not look like one that passed.

	Read from DWARF's producer string, which is the compiler's own record of
	the flags it was given, rather than inferred from the shape -- inferring
	"this looks like -O0" from a frame pointer would be guessing at exactly
	the thing being checked.
	"""
	if not shutil.which("readelf"):
		return None
	out = subprocess.run(
		["readelf", "--debug-dump=info", obj], capture_output=True, text=True, check=False
	)
	if out.returncode != 0:
		return None
	for line in out.stdout.splitlines():
		if "DW_AT_producer" not in line:
			continue
		flags = line.split(":", 2)[-1]
		if " -O0" in flags:
			return "with -O0"
		# ABSENCE OF A FLAG IS NOT EVIDENCE OF -O0, and treating it as such
		# was worse than the problem it fixed. clang records only its version
		# in DW_AT_producer -- "Debian clang version 19.1.7" -- with no flags
		# at all, so a rule that skipped when no -O appeared silently stopped
		# checking every clang build, optimised ones included. It turned a
		# working check into a skipped one for a whole compiler, which is the
		# failure this file is otherwise written to avoid.
		return None
	return None


def disassemble(obj):
	if not shutil.which("objdump"):
		print("codegen-gate: SKIPPED -- no objdump on PATH, so nothing was checked")
		sys.exit(0)

	unopt = unoptimised(obj)
	if unopt is not None:
		print(
			f"codegen-gate: SKIPPED -- {obj} was built {unopt}, where every local "
			"is spilled and the accumulator store cannot discriminate, so nothing "
			"was checked"
		)
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


def check_ct_memeq(insns, obj):
	_ = obj
	"""No data-dependent branch. Returns (counts, problems)."""
	cond_jumps = [i for i in insns if COND_JUMP.match(i)]
	cond_sets = [i for i in insns if COND_SET.match(i)]
	returns = [i for i in insns if RETURN.match(i)]
	stores = [i for i in insns if STACK_STORE.match(i)]

	problems = []
	# THE BRANCH COUNT IS REPORTED AND NOT FAILED ON, which is measured
	# rather than conceded.
	#
	# It began as "exactly 1", which was gcc -Os's loop shape. clang rotates
	# the loop and gives 2; gcc -O2 gives 2; clang -O2 unrolls and gives 4.
	# Widening it once was already a patch over the wrong idea, so the whole
	# matrix was measured -- real against both sabotages, two compilers, two
	# levels:
	#
	#           branches  sets  rets  stores
	#   gcc -Os   real 1     1     1       2
	#           early 2     0     2       0
	#           novol 1     1     1       0
	#   gcc -O2   real 2     1     1       2
	#           early 3     0     2       0
	#           novol 2     1     2       0
	#   clang-Os  real 2     1     1       1
	#           early 4     1     2       0
	#           novol 2     1     2       0
	#   clang-O2  real 4     1     1       1
	#           early 4     1     2       0
	#           novol 9     1     2       0
	#
	# A correct build ranges 1 to 4, a sabotaged one 2 to 9, and the ranges
	# OVERLAP: clang -O2's real function has four branches and clang -Os's
	# early exit has four. So the count cannot separate them, and every
	# widening of it was buying nothing while rejecting correct builds.
	#
	# The store check separates real from both sabotages in every one of the
	# twelve cells. The return check does in all but one. The conditional set
	# catches gcc's early exit. Those three are what fail the gate now; the
	# count is printed because a human reading a changed number may still want
	# to look, which is what a tripwire is for.
	if not cond_jumps:
		problems.append(
			"no conditional branch at all, so there is no loop -- the function "
			"was replaced or optimised away rather than compiled"
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


def wipe_calls(obj, function):
	"""Lines of `function`'s disassembly, with relocations, naming a callee.

	Its own objdump run rather than `disassemble`'s, because `-r` interleaves
	relocation lines that `body` would count as instructions and the two
	existing checks count instructions for a living.
	"""
	out = subprocess.run(
		["objdump", "-dr", "--no-show-raw-insn", obj],
		capture_output=True,
		text=True,
		check=False,
	)
	if out.returncode != 0:
		fail(f"objdump -dr failed on {obj}: {out.stderr.strip()}")

	lines = out.stdout.splitlines()
	start = None
	for i, line in enumerate(lines):
		if line.rstrip().endswith(f"<{function}>:"):
			start = i + 1
			break
	if start is None:
		fail(f"{function} is not in {obj} -- nothing was checked, which is not a pass")

	block = []
	for line in lines[start:]:
		if not line.strip():
			break
		block.append(line.strip())
	return block


def check_wipe(insns, obj):
	"""The key material is still handed to fzn_wipe. Returns (counts, problems).

	WHAT THIS USED TO CHECK, and why it moved. It counted zero-immediate
	stores in fzn_commitment_derive_root, because the wipe was two inline loops
	there and a compiler allowed to delete them left key material on the
	stack. The wipe is now fzn_wipe in constant_time.c, exported because a
	consumer holding a derived key needs it too.

	COUNTING ZERO STORES IN fzn_wipe WOULD NOT DISCRIMINATE, and moving the
	check there would have been the mistake this project has already paid
	for once. Measured: across a translation unit the compiler cannot see
	that the caller's buffer is dead, so fzn_wipe compiled WITHOUT the
	volatile qualifier still writes -- 10 instructions against 11. The check
	would pass either way and would be quoted afterwards as though it had
	discriminated.

	So the property worth gating moved with the code: the derivation must
	still HAND its buffers to the wipe. Deleting a call fails here, which is
	the failure that now loses the erasure.

	Under link-time optimisation the call may vanish into an inline copy and
	this would report a false absence. Nothing here builds that way, and a
	false ALARM is the right direction for a security check to fail in.
	"""
	root = [ln for ln in wipe_calls(obj, "fzn_commitment_derive_root") if "fzn_wipe" in ln]
	frame = [ln for ln in wipe_calls(obj, "fzn_commitment_for_nonce") if "fzn_wipe" in ln]

	problems = []
	if len(root) < 2:
		problems.append(
			f"expected 2 calls to fzn_wipe in fzn_commitment_derive_root, one per "
			f"key-material buffer, found {len(root)}. The derivation is leaving key "
			f"material behind"
		)
	# ONE, NOT TWO, and the asymmetry is deliberate. The per-frame hash wipes
	# its input, which holds the commitment key; it does NOT wipe its output,
	# because the commitment is about to be written into a cleartext header.
	# Erasing a value that is about to be published is not a security measure,
	# and a gate demanding it here would be demanding the wrong thing.
	if len(frame) < 1:
		problems.append(
			f"expected 1 call to fzn_wipe in fzn_commitment_for_nonce, for the input "
			f"holding the commitment key, found {len(frame)}"
		)

	return f"{len(root)} + {len(frame)} wipe calls", problems


CHECKS = {
	"ct": ("fzn_ct_memeq", check_ct_memeq),
	"wipe": ("fzn_commitment_derive_root", check_wipe),
}


def main():
	if len(sys.argv) != 3 or sys.argv[1] not in CHECKS:
		fail(f"usage: codegen_gate.py {{{'|'.join(CHECKS)}}} <object>")
	function, checker = CHECKS[sys.argv[1]]
	obj = sys.argv[2]

	insns = body(disassemble(obj), obj, function)
	counts, problems = checker(insns, obj)

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
