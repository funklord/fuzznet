"""Which public functions does no test name?

POPULATION FROM THE BUILD: `make manifest`'s header lines, and every fzn_*
function DECLARED in them.

TWO INSTRUMENT FAULTS ALREADY PAID FOR, both of which hid or invented
findings, so the controls below are not decoration:

  1. Requiring a trailing paren at the USE site cannot see a function
     passed AS a callback -- `{ fzn_catalog_add_wins, NULL }` -- and
     invented three findings across four test files that wire them up.
  2. Taking the FIRST fzn_*( in each ;-chunk drops a declaration whose
     preceding comment mentions another function. That lost fzn_copyright
     and fzn_peer_group_verdict, and a dropped declaration is a gap never
     looked at rather than a finding to argue with.

Comments are stripped before parsing, and the result is checked against an
independent count that does not parse at all.

TERMINATION: two passes over a fixed file list. Nothing spawned.
"""
import os, re, subprocess, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def strip_comments(text):
	# Block and line comments, replaced by a space so tokens do not join.
	text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
	return re.sub(r'//[^\n]*', ' ', text)

def strip_cpp(text):
	# PREPROCESSOR LINES GO BEFORE THE TEXT IS FLATTENED. Skipping a
	# ;-chunk that STARTS with '#' was fault 3: an include guard carries
	# no semicolon, so `#ifndef ... #define ... int fzn_ct_memeq(` is one
	# chunk and the first declaration of every header went with it. The
	# control caught it; reading the output would not have, because a
	# smaller number looks like a tidier tree.
	return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))

mani = subprocess.run(["make", "-s", "manifest"], cwd=ROOT,
                      capture_output=True, text=True).stdout
headers = [l.split(None, 1)[1] for l in mani.splitlines() if l.startswith("header ")]
assert headers, "manifest named no headers"

DECL = re.compile(r'\b(fzn_[a-z0-9_]+)\s*\(')

def declarations(text):
	"""Names declared at brace depth 0.

	FAULT 4, and the last: rejecting a name whose preceding character is
	an operator treats `const char *fzn_agree_err_str(` as an expression,
	because `*` is both a pointer and a multiply. That dropped 73 real
	declarations. What actually separates a prototype from a call is
	BRACE DEPTH -- a call in a header lives inside a static inline body,
	and a prototype never does.
	"""
	depth, out = 0, []
	i = 0
	while i < len(text):
		c = text[i]
		if c == '{':
			depth += 1
		elif c == '}':
			depth = max(0, depth - 1)
		elif depth == 0 and c == 'f' and text.startswith('fzn_', i):
			m = DECL.match(text, i)
			if m and (i == 0 or not (text[i-1].isalnum() or text[i-1] == '_')):
				out.append(m.group(1))
				i = m.end()
				continue
		i += 1
	return out

declared = {}
for h in headers:
	flat = re.sub(r'\s+', ' ', strip_cpp(strip_comments(open(os.path.join(ROOT, h)).read())))
	for name in declarations(flat):
		declared.setdefault(name, h)

# CONTROL: an independent scan that does not know about braces. What it sees
# and this does not must be exactly the calls inside static inline bodies --
# a set small enough to read, which is the point. A large residue means the
# parser is dropping declarations again, and a dropped declaration is a
# function never examined rather than a finding to argue with.
crude = set()
for h in headers:
	flat = re.sub(r'\s+', ' ', strip_cpp(strip_comments(open(os.path.join(ROOT, h)).read())))
	crude.update(DECL.findall(flat))
missing = sorted(crude - set(declared))

USE = re.compile(r'\b(fzn_[a-z0-9_]+)')
test_files, lib_files = [], []
for dirpath, dirnames, filenames in os.walk(ROOT):
	dirnames[:] = [d for d in dirnames if d not in ('.git', 'build', 'vendor')]
	for f in filenames:
		if f.endswith(('.c', '.cpp')):
			rel = os.path.relpath(os.path.join(dirpath, f), ROOT)
			(test_files if '/test/' in rel else lib_files).append(rel)

def count(files):
	hits = collections.Counter()
	for rel in files:
		text = strip_comments(open(os.path.join(ROOT, rel)).read())
		for name in USE.findall(text):
			if name in declared:
				hits[name] += 1
	return hits

in_test, in_lib = count(test_files), count(lib_files)
assert in_test.get('fzn_ct_memeq', 0) > 50, "control: a name every test uses went uncounted"

# NAMED BY NO TEST FOR A REASON, in sabotage.py's idiom: an expected result
# reported as a finding every time is how a report stops being read, and
# removing a name from here is how you ask the question again.
EXPECTED = {
	# Accessors with one internal use each, inside verification. A wrong
	# offset does not hide -- it breaks every signature check in the
	# suite, which is a louder witness than a test naming them would be.
	"fzn_hop_signature",
	"fzn_revocation_signature",
	# Reached through cli/state_print.c, whose test asserts the rendered
	# verdict. Its narrower contract is an open question for the holder
	# (project.md sec 184), not a missing test.
	"fzn_state_sound",
}

never = sorted(n for n in declared if in_test.get(n, 0) == 0)
unexpected = [n for n in never if n not in EXPECTED]
stale = sorted(EXPECTED - set(never))
print(f"{len(declared)} public functions over {len(headers)} headers; "
      f"{len(test_files)} test sources, {len(lib_files)} others")
print(f"crude scan saw {len(crude)}; {len(missing)} it saw and the parser did not:")
for n in missing:
	print(f"    {n}")
# A NAME THAT HAS ACQUIRED A TEST IS A STALE WAIVER, and a waiver list that
# can only grow is one nobody prunes. Reported, not ignored.
for n in stale:
	print(f"  waived and no longer needed: {n}")
print(f"{len(never)} named by no test, {len(unexpected)} unexpected:")
for n in never:
	mark = " " if n in EXPECTED else "*"
	print(f" {mark}{n:<44} {declared[n]:<28} lib:{in_lib.get(n,0)}")
if unexpected or stale:
	raise SystemExit(1)
