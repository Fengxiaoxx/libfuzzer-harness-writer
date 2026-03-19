---
name: libfuzzer-harness-writer
description: >
  Use this skill whenever a user wants to write, improve, or generate LibFuzzer
  fuzz drivers (harnesses) for a C or C++ library. Triggers when you see words
  like "fuzz", "fuzzing", "harness", "fuzz driver", "libfuzzer", "afl", "oss-fuzz",
  "coverage", or when the user has a compiled library (.so / .a) and wants to find
  bugs in it via fuzzing. Also use this skill if the user asks to "improve fuzzing
  coverage", "add more fuzz targets", or "write libfuzzer tests". Use this skill
  proactively — if the user is working with a C/C++ library and mentions security
  or robustness testing, this skill is almost certainly relevant.
---

# LibFuzzer Harness Writer

A systematic process for producing high-quality, non-redundant LibFuzzer harnesses
that maximise code coverage and find real bugs.

## Overview of the process

1. **Inventory** — export symbols, read headers, list existing harnesses
2. **Gap analysis** — identify API groups NOT yet covered
3. **Design** — choose harness architecture (one harness per functional group)
4. **Write** — implement following the quality patterns in `references/patterns.md`
5. **Review** — use the codex MCP tool if available; otherwise self-review against `references/checklist.md`
6. **Compile & smoke-test** — must compile with `-fsanitize=fuzzer,address` and run for 5 s without crashes
7. **Iterate** — fix all findings, re-test

---

## Step 1 — Inventory

### 1a. Export symbols from the shared library

If a `build_harness/` directory exists at the project root, the shared library
is already built there — use it directly:

```bash
nm -D build_harness/lib<name>.so | grep ' T ' | awk '{print $3}' | sort
```

If `build_harness/` does not exist, build the library first (without sanitizer
flags — this is just for inspection) and export symbols from the result.
The pipeline skill (Stage 0) creates `build_harness/` when running the full
workflow; when using this skill standalone, create it yourself:

```bash
mkdir -p build_harness && cd build_harness
cmake <source_dir> -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
nm -D lib<name>.so | grep ' T ' | awk '{print $3}' | sort
```

This lists every exported function. Use it to understand the full public API surface.

### 1b. Read all public header files

Read every `.h` file that belongs to the library. Note:
- Function signatures and their parameter types
- Which functions allocate / return owned memory (caller must free)
- Which functions take ownership of passed pointers
- Struct/type layout

### 1c. List existing harnesses

Scan for any `*fuzzer*.c`, `*fuzz*.c`, or `LLVMFuzzerTestOneInput` in the repo.
For each existing harness, list the API functions it exercises. This becomes your
**covered set**.

---

## Step 2 — Gap analysis

Subtract the covered set from the full API list. Group the remaining functions by
functional area (e.g., "parse", "build/create", "mutation", "query", "utils").
Each functional group becomes one harness.

**Key rule**: do NOT rewrite an existing harness. If a function is already covered,
skip it. Only add new harness files for uncovered groups.

---

## Step 3 — Design each harness

Before writing any code, decide for each harness:

| Design question | Why it matters |
|---|---|
| What is the natural input? | Determines whether to split input regions or parse it directly |
| How many API functions? | More functions → need multi-region input splitting |
| Does the harness do mutations? | If yes, use fixed-size op records (see patterns) |
| Are there semantic oracles? | Identify invariants that should always hold |

Read `references/patterns.md` for the concrete implementation templates.

---

## Step 4 — Write the harnesses

Follow the patterns in `references/patterns.md`. The most important rules:

### Memory safety contract (non-negotiable)
- Every allocated node must eventually be freed
- Reference nodes (`IsReference` flag) must NOT be freed after their referent
- After `AddItemToArray/Object` succeeds → item is owned by the container, caller does NOT free
- After `AddItemToArray/Object` fails → caller MUST free the item

### Input consumption quality
- Use **length-prefixed strings** (`consume_lstr`) instead of NUL-delimited scanning — NUL scanning eats unpredictable amounts of entropy and makes corpus evolution unstable
- Use **fixed-size op records** for harnesses that execute a sequence of operations — this prevents frame-shift mutations that confuse libFuzzer
- For harnesses with multiple independent test paths, **split the input into regions** using a byte-header — each region drives one test function independently

### Coverage quality
- Always test both success and failure paths of each API function
- For index-based functions (`GetArrayItem`, `ReplaceItemInArray`), test valid index, index -1, and index == size
- For case-sensitive/insensitive API pairs, flip the ASCII case of a real key to stably cover both branches
- For string setters (`SetValuestring`), test on correct type, wrong type, and NULL argument

### Semantic oracles
Where possible, add an assertion that catches logical bugs, not just crashes:
- **Deep copy oracle**: `Compare(original, Duplicate(original, 1))` must be true
- **Round-trip oracle**: `PrintUnformatted(Parse(PrintUnformatted(X))) == PrintUnformatted(X)` (text equality, not cJSON_Compare — avoids float precision false positives)

Use `__builtin_trap()` to fire the oracle so ASan/libFuzzer reports it as a crash.

---

## Step 5 — Review

### If the codex MCP tool is available

Ask codex to review each harness. Provide the full file content and ask it to evaluate:
1. Memory management correctness (leaks, double-free, use-after-free)
2. Coverage gaps (which branches / API paths are not reached)
3. Input consumption efficiency (does the consumer pattern waste entropy?)
4. Oracle correctness (can the oracle produce false positives?)

Consider the feedback carefully. Apply changes that address real defects.
Discard suggestions that are overly conservative or would reduce coverage.

### Self-review checklist (if no codex MCP)

See `references/checklist.md` for the complete list. Key items:
- [ ] All malloc'd memory is freed (including on error paths)
- [ ] Reference nodes deleted before their referents
- [ ] Fixed-size op records used where applicable
- [ ] Length-prefix strings used (no NUL scanning)
- [ ] At least one invalid-input path per API function
- [ ] Oracle does not produce false positives on valid inputs

---

## Step 6 — Compile and smoke-test

Use `build_harness/lib<name>.a` as the library archive for compilation — it is
the baseline (non-sanitized) build created in Stage 0 of the pipeline, or built
manually in Step 1a above. Do not rebuild the library here; link against the
existing artifact.

Use the scripts provided in `scripts/`:

```bash
# Compile one harness (link against build_harness/lib<name>.a)
bash scripts/compile_fuzz.sh <harness.c> build_harness/lib<name>.a <include_dir> /tmp/<harness_binary>

# Smoke-test for 5 seconds
bash scripts/smoke_test.sh /tmp/<harness_binary> [corpus_dir]
```

A harness is acceptable only when:
- It compiles with `-Wall -Wextra -Werror` (zero warnings)
- It runs 5 s without `CRASH`, `ERROR`, or `abort`
- Throughput is > 1000 exec/s (if much lower, investigate and fix)

---

## Step 7 — Iterate

For each issue found by codex or the smoke test:
1. Understand the root cause (do not just suppress the symptom)
2. Fix the harness
3. Recompile and re-smoke-test

Repeat until all three harnesses are clean.

---

## Output

The final deliverables are `.c` files placed in the project's `fuzzing/` directory,
alongside existing harnesses. Each file has a header comment listing:
- What API functions it covers
- Key design decisions (input format, oracle logic)
- Memory safety contract
