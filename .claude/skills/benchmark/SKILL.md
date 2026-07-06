---
name: benchmark
description: Run cipherlib benchmarks and regenerate BENCHMARK.md plus its README embed safely, with the reference-machine guard. Use when measuring a performance change or when benchmark tables need refreshing.
---

# Benchmark cipherlib

`BENCHMARK.md` is generated output, and its numbers are only meaningful from
the reference machine (36GB Apple M3 Pro, compiled exe). The README embeds
BENCHMARK.md verbatim. This skill keeps all three honest.

## Step 0 — Machine guard (always first)

```sh
sysctl -n machdep.cpu.brand_string
```

- Output contains `Apple M3 Pro` → full run allowed, results may be committed.
- Anything else → **measurement-only mode**: you may run benchmarks to compare
  before/after ratios for a local change, but you must NOT commit changes to
  `BENCHMARK.md` or the README benchmark section, and you must say so in your
  summary. Committed numbers from other machines mislead package users.

## Step 1 — Choose the scope

**A. Single algorithm (fast, for perf-change feedback):**

```sh
sh scripts/compiled.sh benchmark/<algo>.dart
```

This runs the algorithm's matching test file first (KAT safety), compiles the
benchmark to `build/`, and runs it over 1MB/1KB/32B inputs. To measure a
change: run on the pre-change commit (`git stash` the work), record, restore,
run again, report the ratio per input size. Anything beyond ±5% on 1MB inputs
is signal; 32B numbers are noisy — say so when reporting them.

**B. Full regeneration (only on the reference machine):**

```sh
sh scripts/benchmark.sh
```

This runs the full VM test suite, compiles `benchmark/benchmark.dart`,
rewrites `BENCHMARK.md`, and appends the machine/SDK footer. It takes several
minutes (each benchmark warms up 100ms and exercises 2s, per size, per
library). Close other heavy processes first; a loaded machine skews results.

## Step 2 — Sanity-check the new numbers

Diff `BENCHMARK.md` against git:

- Any cell that moved more than ~2x without a code change touching that
  algorithm is suspect — rerun that algorithm once
  (`sh scripts/compiled.sh benchmark/<algo>.dart`) before accepting it.
- The `**bold**` winner marking and `` `N.NNx slow` `` annotations are
  generated — never hand-edit them.
- The footer must state the M3 Pro machine and current `dart --version`.

## Step 3 — Re-embed into README

`README.md` contains BENCHMARK.md verbatim between a **pair** of identical
markers:

```text
<!-- file: BENCHMARK.md -->
...embedded copy...
<!-- file: BENCHMARK.md -->
```

Replace everything between the two markers with the new `BENCHMARK.md`
content (keep the markers). The same mechanism embeds
`example/cipherlib_example.dart` between its own marker pair — leave that one
alone unless the example changed.

## Step 4 — Verify and hand off

- `git diff` should show only `BENCHMARK.md` + the README benchmark section
  (plus whatever perf change prompted this).
- If this was part of a performance change: confirm all KATs still pass
  (`dart test -p vm`) and state the measured delta per input size in your
  summary. AGENTS.md §5 "Performance change" is the bar.
- Commit only when asked; message style: `Update benchmarks` or
  `Update BENCHMARK.md after <change>`.
