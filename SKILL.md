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
6. **Compile & smoke-test** — must compile against the **ASan** build and run for 60 s without crashes; MSan compile is optional (skip if no local MSan environment)
7. **Iterate** — fix all findings, re-test

---

## Step 1 — Inventory

### 1a. Export symbols from the shared library

**Always use the `.so` file with `nm -D`** (dynamic symbol table). Static archives
(`.a`) may include internal symbols and do not reflect the true public API surface.
The helper script `scripts/export_symbols.sh` wraps this command.

If `build_harness/` exists (created by `libfuzzer-lib-builder`), use the ASan
`.so` — it carries the same public API as the MSan build:

```bash
# Preferred: use the helper script
bash scripts/export_symbols.sh build_harness/asan/lib<name>.so

# Or run directly
nm -D build_harness/asan/lib<name>.so | grep ' T ' | awk '{print $3}' | sort
```

If `build_harness/` does not exist, build the library first for inspection only
(no sanitizer flags needed at this stage), then use the `.so`:

```bash
mkdir -p build_harness/inspect && cd build_harness/inspect
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

## Step 5 — Review (mandatory gate — do NOT proceed until this passes)

This step is a hard gate. A harness may not advance to Step 6 until both you
and codex independently agree it is ready. The goal is to catch logical bugs
and coverage gaps that compile-time checks and smoke tests cannot see.

### If the codex MCP tool is available (preferred path)

Call `mcp__codex__codex` with the full harness source and ask it to evaluate:

1. **Memory management** — every allocation freed; no double-free; no use-after-free;
   ownership semantics correct after `AddItemToArray/Object` success vs. failure
2. **Coverage gaps** — which API branches / error paths are unreachable from the
   current input consumer? Which opcodes or flag combinations are missing?
3. **Input consumption efficiency** — does the consumer waste entropy (e.g., NUL
   scanning, unbounded modulo)? Would a different consumer pattern reach more code?
4. **Oracle correctness** — can the semantic oracle produce false positives on
   valid inputs? Is `__builtin_trap()` used correctly?

**Iteration protocol with codex:**

- For each issue codex raises, decide whether it is a real defect or an
  overly conservative suggestion. Apply fixes for real defects; document
  (in a comment) why you rejected suggestions that would reduce coverage.
- After fixing, call codex again with the updated source.
- **Repeat until codex raises no new defects AND you agree with its
  assessment.** Only then is the review gate considered passed.

If codex and you disagree on a point, err on the side of correctness over
coverage — a harness that leaks memory or fires false-positive oracles is
worse than one with slightly lower coverage.

### Self-review checklist (fallback — only if codex MCP is unavailable)

Work through `references/checklist.md` in full. At minimum verify:
- [ ] All malloc'd memory is freed (including on every error path)
- [ ] Reference nodes deleted before their referents
- [ ] Fixed-size op records used where applicable (no frame-shift mutations)
- [ ] Length-prefix strings used (no NUL scanning)
- [ ] At least one invalid-input path per API function
- [ ] Oracle does not produce false positives on valid inputs

Even without codex, do not self-certify until you have walked through every
checklist item for every harness and found no remaining issues.

---

## Step 6 — Compile and smoke-test

Compile the harness against the **ASan** build and smoke-test it. The MSan
build is compiled for portability validation but **not** smoke-tested locally
— a clean ASan run is sufficient to confirm harness correctness.

Do not rebuild the library here; link against the pre-built archives from
`libfuzzer-lib-builder`.

Use the scripts provided in `scripts/`:

```bash
# ── ASan build + smoke test (required) ───────────────────────────────────────
bash scripts/compile_fuzz.sh asan \
    <harness.c> \
    build_harness/asan/lib<name>.a \
    build_harness/asan/include \
    /tmp/<harness>_asan

bash scripts/smoke_test.sh /tmp/<harness>_asan [corpus_dir]

# ── MSan build only — compile to catch portability issues (no smoke test) ────
bash scripts/compile_fuzz.sh msan \
    <harness.c> \
    build_harness/msan/lib<name>.a \
    build_harness/msan/include \
    /tmp/<harness>_msan
# Do NOT run smoke_test.sh for MSan — no local MSan environment.
```

A harness is acceptable when the **ASan** build satisfies:
- Compiles with `-Wall -Wextra -Werror` (zero warnings)
- Runs 60 s without `CRASH`, `ERROR`, or `abort` (aligned with OSS-Fuzz)
- Throughput > 1000 exec/s

The **MSan** build must compile cleanly (zero warnings/errors). Do **not** run
the smoke test for MSan — there is no local MSan environment.

---

## Step 7 — Iterate

For each issue found by codex or the smoke test:
1. Understand the root cause — do not just suppress the symptom
2. Fix the harness
3. Return to Step 5: call codex again with the updated source and get its sign-off
4. Only after codex confirms no new defects, recompile and re-smoke-test (Step 6)

A harness is finished only when **both** conditions hold simultaneously:
- Step 5 gate passed: codex raises no defects and you agree with its assessment
- Step 6 gate passed: ASan build compiles clean and runs 60 s without errors;
  MSan build compiles clean (no smoke test — MSan environment not available)

---

## Output

The final deliverables are `.c` files placed in the project's `fuzzing/` directory,
alongside existing harnesses. Each file has a header comment listing:
- What API functions it covers
- Key design decisions (input format, oracle logic)
- Memory safety contract
