# Harness Quality Checklist

Use this before submitting any harness for review or compilation.

---

## Memory management

- [ ] Every `malloc` / `Create*` call has a matching `Delete` / `free` on ALL paths
      (including early-return paths, NULL-check exits, and failure branches)
- [ ] After `AddItemToArray/Object` succeeds → do NOT free the item (owned by container)
- [ ] After `AddItemToArray/Object` fails → DO free the item
- [ ] Reference containers are deleted BEFORE their referents
- [ ] `Duplicate(item, 0)` (shallow) is safe to delete — it doesn't touch children,
      so deleting it won't double-free the original's children
- [ ] `cJSON_free()` used (not `free()`) for strings returned by library print functions
      — respects custom allocator hooks

## Input consumption

- [ ] Length-prefixed strings (`consume_lstr`) used instead of NUL-delimited scanning
- [ ] For mutation harnesses: fixed-size op records used (not variable-length encoding)
- [ ] For multi-path harnesses: input split into regions with byte-header proportions
- [ ] Consumer never reads past `remaining` (check: `if (c->remaining == 0) return 0;`)

## Coverage completeness

For each API function covered:
- [ ] At least one success path (valid inputs that produce a result)
- [ ] At least one failure path (invalid/NULL/OOB inputs — must not crash)
- [ ] For case-sensitive/insensitive pairs: tested both with matching and non-matching case
- [ ] For index-based functions: valid idx, idx = -1, idx = size (OOB), idx = INT32_MAX
- [ ] For string setters: correct-type node, wrong-type node, NULL string argument
- [ ] For number setters: correct-type node, wrong-type node

## Oracles

- [ ] Deep-copy oracle used where applicable (parse-only harnesses without NaN mutation)
- [ ] Round-trip text oracle used in mutation harnesses (NOT cJSON_Compare, to avoid float false positives)
- [ ] Oracle `__builtin_trap()` cannot be triggered by valid, expected library behaviour
- [ ] NaN/Inf special values accounted for: if a mutation can write NaN into a node,
      the text oracle is used rather than the structural oracle

## Compilation and runtime

- [ ] Compiles with `clang -fsanitize=fuzzer,address -Wall -Wextra -Werror`
- [ ] Zero warnings at `-Wall -Wextra -Werror`
- [ ] Runs 5 s without CRASH / ERROR / abort (smoke test)
- [ ] Throughput > 1000 exec/s (if lower, investigate: likely a deep recursion or large malloc in the hot path)

## Style

- [ ] File header comment lists: covered APIs, input format, memory safety contract
- [ ] `#define` constants used for magic numbers (MAX_OPS, MAX_NODES, OP_RECORD_SIZE)
- [ ] No `printf` / `fprintf` inside the fuzzer loop (slows throughput dramatically)
- [ ] Recursive helpers cap depth at `CJSON_NESTING_LIMIT` (or library equivalent)
      to stay consistent with the library's own recursion guard
