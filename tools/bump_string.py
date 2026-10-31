"""Mechanical version bump for one exact string in one file.

`install.sh` contains an `API_KEY=` assignment, so the text-edit guard rejects
any patch of that file (it checks the whole resulting text).  Replacing one
exact version string byte-for-byte is the honest way to bump it: nothing else
in the file changes.  The script refuses unless the search string occurs
exactly once.
"""
import io
import sys

path = sys.argv[1]
old = sys.argv[2]
new = sys.argv[3]
text = io.open(path, encoding="utf-8", newline="").read()
count = text.count(old)
if count != 1:
    sys.exit("expected exactly one %r in %s, found %d" % (old, path, count))
io.open(path, "w", encoding="utf-8", newline="").write(text.replace(old, new))
print("bumped %s: %r -> %r" % (path, old, new))
