# Conformance vectors

Copied verbatim from `contextpassport/conformance-tests`, which publishes them
CC0 precisely so that any implementation can run them:

> Implementations in other languages should ship their own runners that load
> each vector JSON and report pass/fail against `expected`. The vectors are
> CC0 — copy them freely.

DarkMatter is JavaScript and the reference harness is Python, so this is that
runner. It reads the same files, in the same format, and applies the same
`expected` values as every other implementation.

**Do not edit these files.** They are not ours. If one fails, DarkMatter is
wrong, or the vector has changed upstream and should be re-copied wholesale.
Editing a vector so our implementation passes it would make the whole exercise
worthless, and would be exactly the privileged path this is meant to rule out:
the vendor that publishes the standard grading its own homework.

Re-copy with:

    node test/sync-conformance-vectors.js

Run with:

    node test/conformance-suite.test.js
