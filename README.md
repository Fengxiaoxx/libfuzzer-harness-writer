# libfuzzer-harness-writer

A [Claude Code](https://claude.ai/claude-code) skill that writes production-quality
[LibFuzzer](https://llvm.org/docs/LibFuzzer.html) harnesses for C and C++ libraries —
covering the full public API surface, avoiding duplication of existing harnesses, and
passing a compile + smoke-test gate before declaring success.

---

## Why this exists

Writing a fuzzer harness that actually finds bugs is harder than it looks. A naive
harness often:

- Covers only the "happy path", missing the error-handling code where bugs hide
- Leaks memory or double-frees, producing false positives that drown real findings
- Uses NUL-delimited string scanning, wasting mutation entropy and confusing libFuzzer's
  corpus evolution
- Misses API pairs (case-sensitive vs. case-insensitive, valid vs. OOB index) that are
  exactly where off-by-one errors live
- Has no semantic oracle, so logical bugs that don't crash the process go undetected

This skill gives Claude a systematic, seven-step process and a library of proven code
patterns to avoid all of the above.

---

## Installation

Copy the skill into Claude Code's skill directory, then restart Claude Code:

```bash
git clone git@github.com:Fengxiaoxx/libfuzzer-harness-writer.git \
    ~/.claude/skills/libfuzzer-harness-writer
```

Claude Code will automatically detect and load the skill. It triggers whenever you
mention fuzzing, harnesses, LibFuzzer, AFL, OSS-Fuzz, or ask about security / robustness
testing for a C/C++ library.

---

## How to invoke it

Just describe your task in plain language:

```
Write LibFuzzer harnesses for libpng. The library is at build/libpng.a and
headers are in include/. There's already a harness for png_read_png in
fuzzing/read_fuzzer.c — don't touch that one.
```

Claude will run the full seven-step workflow automatically.

---

## The seven-step workflow

```
1. Inventory     Export symbols, read headers, list existing harnesses
      │
2. Gap analysis  Subtract covered APIs → group remainder by functional area
      │
3. Design        Choose input format per group (raw / multi-region / op-records)
      │
4. Write         Implement using the patterns in references/patterns.md
      │
5. Review        Codex MCP review if available; otherwise references/checklist.md
      │
6. Compile       clang -fsanitize=fuzzer,address -Wall -Wextra -Werror (zero warnings)
      │
7. Smoke-test    Run 5 s, verify no crashes, throughput > 1000 exec/s
```

Steps 6 and 7 use the bundled scripts (see below). Claude reruns from step 4 until
the harness passes both gates.

---

## Bundled scripts

### `scripts/export_symbols.sh` — Step 1

List every exported function from a shared library:

```bash
bash scripts/export_symbols.sh path/to/library.so
```

### `scripts/compile_fuzz.sh` — Step 6

Compile a harness with LibFuzzer + AddressSanitizer:

```bash
bash scripts/compile_fuzz.sh harness.c library.a include/ /tmp/harness_bin
```

Flags used: `-fsanitize=fuzzer,address -O1 -g -Wall -Wextra -Werror`

### `scripts/smoke_test.sh` — Step 7

Run the binary for a configurable duration and check health:

```bash
bash scripts/smoke_test.sh /tmp/harness_bin [corpus_dir] [seconds]
```

Default: 5 seconds. Exit 0 = pass (no crash, throughput ≥ 1000 exec/s).

---

## Key patterns the skill uses

The full templates live in [`references/patterns.md`](references/patterns.md).
Here is what sets the generated harnesses apart from naive ones:

**Length-prefixed strings** instead of NUL scanning
> Reads a 1-byte length prefix then exactly that many bytes. This keeps
> libFuzzer's mutation budget predictable and corpus evolution stable.

**Multi-region input splitting**
> A short byte header splits the payload into N independent regions, one per
> functional group. Mutations to region A do not shift the byte offsets of
> region B.

**Fixed-size op records** (for mutation/query harnesses)
> Each operation is exactly K bytes. The first byte is `n_ops`; the rest are
> `n_ops × K` bytes of records. Frame-shift mutations never corrupt unrelated
> operations.

**Semantic oracles**
> Assertions that catch logical bugs, not just crashes. Two examples:
> - *Deep-copy oracle*: a deep duplicate of a parsed object must compare equal
>   to the original.
> - *Round-trip text oracle*: `print(parse(print(X))) == print(X)` — fires
>   with `__builtin_trap()` so ASan reports it as a crash.

---

## Reference examples

The [`references/examples/`](references/examples/) directory contains three
production-quality harnesses written for [cJSON](https://github.com/DaveGamble/cJSON),
demonstrating every pattern in the skill:

| File | Patterns demonstrated |
|---|---|
| `cjson_ops_fuzzer.c` | Raw input, tree walker, type predicates, PrintPreallocated boundary test, deep-copy oracle |
| `cjson_builder_fuzzer.c` | Multi-region splitting, Consumer struct, typed array constructors, reference lifecycle |
| `cjson_mutate_fuzzer.c` | Fixed-size op records, TreeIndex, stash-and-reinsert, round-trip oracle |

---

## Reference documents

| File | Purpose |
|---|---|
| [`SKILL.md`](SKILL.md) | Full step-by-step instructions loaded by Claude Code |
| [`references/patterns.md`](references/patterns.md) | Nine copy-paste C templates |
| [`references/checklist.md`](references/checklist.md) | Pre-submission quality checklist (memory, input, coverage, oracles, style) |

---

## Requirements

- **clang ≥ 6** with LibFuzzer support
- **nm** (binutils) — for symbol export
- A compiled library (`*.a` or `*.so`) and its public headers

---

## Output

Harnesses are placed in the project's `fuzzing/` directory alongside existing
harnesses. Each file starts with a header comment documenting:

- Which API functions it covers
- The input byte layout (raw / multi-region / op-records)
- The memory safety contract specific to that functional group
