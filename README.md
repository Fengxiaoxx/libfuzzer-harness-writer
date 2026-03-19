# libfuzzer-harness-writer

A GitHub Copilot skill (agent instruction set) that guides an AI coding assistant through writing high-quality, non-redundant [LibFuzzer](https://llvm.org/docs/LibFuzzer.html) harnesses for C and C++ libraries.

---

## What this skill does

When activated, the skill walks the assistant through a systematic, seven-step process:

1. **Inventory** — export symbols, read headers, find existing harnesses
2. **Gap analysis** — identify API groups not yet covered by existing harnesses
3. **Design** — pick the right harness architecture for each uncovered group
4. **Write** — implement harnesses using the proven patterns in `references/patterns.md`
5. **Review** — use the Codex MCP tool (if available) or the self-review checklist
6. **Compile & smoke-test** — must compile with `-fsanitize=fuzzer,address` and survive 5 s without crashes
7. **Iterate** — fix every finding, recompile, retest

The skill is designed to produce harnesses that:
- Maximise code coverage across the full public API surface
- Never rewrite or duplicate existing harnesses
- Follow strict memory-safety contracts (no leaks, no double-frees, no use-after-free)
- Use stable input-consumption patterns (length-prefixed strings, fixed-size op records) so libFuzzer's corpus evolution stays productive
- Include semantic oracles that catch logical bugs, not just crashes

---

## When to use this skill

Trigger this skill whenever:
- A user wants to **write**, **improve**, or **generate** LibFuzzer fuzz drivers / harnesses
- Keywords like `fuzz`, `fuzzing`, `harness`, `fuzz driver`, `libfuzzer`, `afl`, `oss-fuzz`, `coverage` appear
- A user has a compiled library (`.so` / `.a`) and wants to find bugs via fuzzing
- A user asks to "improve fuzzing coverage", "add more fuzz targets", or "write libfuzzer tests"
- A user working with a C/C++ library mentions **security** or **robustness testing**

---

## Repository structure

```
libfuzzer-harness-writer/
├── SKILL.md                     # Skill definition read by the AI assistant
├── references/
│   ├── patterns.md              # Copy-paste-ready C code templates
│   ├── checklist.md             # Pre-submission quality checklist
│   └── examples/                # Real harnesses for cJSON (reference implementations)
│       ├── cjson_builder_fuzzer.c
│       ├── cjson_mutate_fuzzer.c
│       └── cjson_ops_fuzzer.c
└── scripts/
    ├── compile_fuzz.sh          # Compile one harness with ASan + libFuzzer
    ├── smoke_test.sh            # Run the binary for 5 s and check health
    └── export_symbols.sh        # List exported functions from a .so
```

---

## Quick start

### 1. Export the public API of your library

```bash
bash scripts/export_symbols.sh path/to/library.so
```

This prints every exported function, sorted alphabetically.

### 2. Write a harness

Follow the seven-step process in `SKILL.md`. Use `references/patterns.md` for the concrete C templates (consumer, length-prefixed strings, multi-region splitting, fixed-size op records, semantic oracles, etc.).

### 3. Compile

```bash
bash scripts/compile_fuzz.sh my_harness.c path/to/library.a path/to/include /tmp/my_harness
```

The script uses:
```
clang -fsanitize=fuzzer,address -O1 -g -Wall -Wextra -Werror
```

A zero-warning build is required.

### 4. Smoke-test

```bash
bash scripts/smoke_test.sh /tmp/my_harness [corpus_dir] [seconds]
```

Default runtime is 5 seconds. The script checks for crashes/sanitizer errors and reports throughput. A healthy harness runs at **> 1 000 exec/s**.

---

## Key design rules

### Memory safety (non-negotiable)

| Situation | Rule |
|---|---|
| `malloc` / `Create*` | Must have a matching `free` / `Delete` on every exit path |
| `AddItemToArray/Object` succeeds | Item is **owned by the container** — do NOT free it |
| `AddItemToArray/Object` fails | Caller **must** free the item |
| Reference containers | Delete containers **before** their referents |

### Input consumption

- Use **length-prefixed strings** (`consume_lstr`) — never NUL-delimited scanning
- Use **fixed-size op records** for mutation harnesses — prevents frame-shift
- Use **multi-region splitting** when one harness covers several independent code paths

### Coverage quality

- Test both success **and** failure paths for every API function
- For index-based functions: valid index, `-1`, `size` (OOB), `INT32_MAX`
- For case-sensitive/insensitive pairs: test both cases
- For string setters: correct type, wrong type, NULL argument

### Semantic oracles

```c
/* Deep-copy oracle (parse-only harnesses) */
cJSON *dup = cJSON_Duplicate(json, 1);
if (dup && (!cJSON_Compare(json, dup, 1) || !cJSON_Compare(json, dup, 0)))
    __builtin_trap();
cJSON_Delete(dup);

/* Round-trip text oracle (mutation harnesses) */
char *p1 = cJSON_PrintUnformatted(root);
if (p1) {
    cJSON *re = cJSON_Parse(p1);
    if (!re) __builtin_trap();
    char *p2 = cJSON_PrintUnformatted(re);
    if (p2 && strcmp(p1, p2) != 0) __builtin_trap();
    cJSON_free(p2); cJSON_Delete(re); cJSON_free(p1);
}
```

---

## Reference documents

| File | Contents |
|---|---|
| [`SKILL.md`](SKILL.md) | Full step-by-step skill instructions for the AI assistant |
| [`references/patterns.md`](references/patterns.md) | Nine copy-paste C templates (consumer, strings, splitting, op records, oracles, skeleton, …) |
| [`references/checklist.md`](references/checklist.md) | Pre-submission checklist covering memory, input, coverage, oracles, compilation, and style |
| [`references/examples/`](references/examples/) | Three production-quality cJSON harnesses demonstrating all patterns |

---

## Requirements

- **clang** with libFuzzer support (clang 6 or later)
- **nm** (binutils) for symbol export
- A compiled library (`*.a` or `*.so`) and its public headers

---

## Output

Harnesses are placed in the project's `fuzzing/` directory alongside any existing harnesses. Each file starts with a header comment that documents:

- Which API functions it covers
- Input byte-layout (single blob / multi-region / op records)
- Memory safety contract specific to that group
