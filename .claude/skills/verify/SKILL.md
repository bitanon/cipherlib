---
name: verify
description: The cipherlib verification gate — run after completing any change and before declaring it done. Ordered, fail-fast, CI-parity checks with a pass/fail report. Also covers when to add node-platform and integration runs.
---

# Verify a cipherlib change

Run the steps in this order (cheap and common failures first). Stop at the
first failure, fix, and restart from that step. Report the full matrix at the
end. All commands from the repo root.

## The gate

```sh
# 1. Formatting (CI job: lint)
dart format --output=none --set-exit-if-changed .

# 2. Analyzer at CI strictness — plain `dart analyze` is NOT enough
dart analyze --fatal-infos

# 3. Full VM test suite — never just the touched file; cross-cutting tests
#    (cipher_test, compare_test, correctness_test, nonce_test, padding_test)
#    exercise shared code paths
dart test -p vm

# 4. Integration parity suite (separate pub package)
cd test_integration && dart pub get && dart run main.dart && cd ..

# 5. Smoke-run the main example
dart run example/cipherlib_example.dart
```

## Conditional additions

- **Web-relevant change** (anything touching typed-data views, `>>>`/bit
  tricks, `dart:io`, or a reported JS bug): also run `dart test -p node`.
  JS ints are not VM ints; shifts and masks near 32/53 bits behave
  differently — this is exactly where node catches what vm cannot.
- **Perf-sensitive change**: additionally follow the `benchmark` skill
  (measurement-only unless on the reference M3 Pro).
- **New/changed public API**: `dart pub global run pana --exit-code-threshold 0`
  to catch scoring regressions before they surface at release time.

## Verification is not just tests

If the change alters runtime behavior, exercise it directly: write a
5-line scratch program in the session scratchpad (not in the repo) that drives
the changed path and print-compare against a spec vector or a prior-version
output. For crypto code, a green round-trip is NOT verification —
only a known-answer vector proves the keystream (AGENTS.md §0).

## Report format

End with an explicit matrix, e.g.:

```text
format          PASS
analyze         PASS (--fatal-infos)
test -p vm      PASS (N tests)
integration     PASS
example         PASS
node            SKIPPED (change not web-relevant)
KAT coverage    RFC-8439 §2.3.2 vectors cover the changed path
```

Never report "done" with a failing or skipped-without-reason row. If a
failure is pre-existing on `main` (verify by `git stash` + rerun), say so
explicitly and leave it unfixed (AGENTS.md §6, Flag-2).
