# LibFuzzer Harness Patterns

Concrete, copy-paste-ready code templates derived from battle-tested harnesses.

---

## Table of Contents

1. [Consumer — basic byte-stream reader](#1-consumer--basic-byte-stream-reader)
2. [Length-prefixed string](#2-length-prefixed-string)
3. [Multi-region input splitting](#3-multi-region-input-splitting)
4. [Fixed-size op records](#4-fixed-size-op-records)
5. [Tree/object index pattern](#5-treeobject-index-pattern)
6. [Semantic oracles](#6-semantic-oracles)
7. [PrintPreallocated exact-boundary test](#7-printpreallocated-exact-boundary-test)
8. [Reference node lifecycle](#8-reference-node-lifecycle)
9. [Harness skeleton](#9-harness-skeleton)

---

## 1. Consumer — basic byte-stream reader

```c
typedef struct { const uint8_t *ptr; size_t remaining; } Consumer;

static void consumer_init(Consumer *c, const uint8_t *data, size_t size)
{ c->ptr = data; c->remaining = size; }

static int consumer_empty(const Consumer *c) { return c->remaining == 0; }

static uint8_t consume_u8(Consumer *c) {
    uint8_t v;
    if (c->remaining == 0) return 0;
    v = *c->ptr++; c->remaining--; return v;
}

static uint16_t consume_u16(Consumer *c) {
    uint16_t lo = consume_u8(c), hi = consume_u8(c);
    return (uint16_t)(lo | (hi << 8));
}

static double consume_double(Consumer *c) {
    uint8_t buf[8] = {0}; size_t n = c->remaining < 8 ? c->remaining : 8;
    memcpy(buf, c->ptr, n); c->ptr += n; c->remaining -= n;
    double v; memcpy(&v, buf, 8); return v;
}
```

---

## 2. Length-prefixed string

**Always prefer this over NUL-delimited scanning.**

NUL scanning is unstable: a single byte change can shift all subsequent field
offsets, making corpus evolution chaotic. A length prefix (1 byte → 0–63 chars)
keeps fields aligned regardless of content.

```c
/* Consume: 1-byte length (masked to 0..63) + that many body bytes. */
static const char *consume_lstr(Consumer *c, char *buf, size_t bufsize)
{
    uint8_t len = consume_u8(c) & 0x3F;     /* 0..63 */
    size_t  n   = len < bufsize - 1 ? len : bufsize - 2;
    n           = n < c->remaining ? n : c->remaining;
    memcpy(buf, c->ptr, n); buf[n] = '\0';
    c->ptr += n; c->remaining -= n;
    return buf;
}
```

---

## 3. Multi-region input splitting

When a single harness exercises several independent test functions (e.g.,
"build API" + "typed arrays" + "reference semantics"), split the input so
libFuzzer can evolve each region independently.

```c
/*
 * Input layout: [4-byte header] [payload]
 *   header[0] = fraction of payload given to region A (out of 256)
 *   header[1] = fraction of remaining given to region B
 *   header[2] = fraction of remaining given to region C
 *   header[3] = (unused / region D gets the rest)
 */
static void split_input(const uint8_t *data, size_t size,
                        Consumer *cA, Consumer *cB,
                        Consumer *cC, Consumer *cD)
{
    if (size < 4) {
        consumer_init(cA, data, 0); consumer_init(cB, data, 0);
        consumer_init(cC, data, 0); consumer_init(cD, data, 0); return;
    }
    const uint8_t *p = data + 4; size_t n = size - 4;
    size_t a = ((size_t)data[0] * n) / 256;
    size_t b = ((size_t)data[1] * (n - a)) / 256;
    size_t c = ((size_t)data[2] * (n - a - b)) / 256;
    size_t d = n - a - b - c;
    consumer_init(cA, p,             a);
    consumer_init(cB, p + a,         b);
    consumer_init(cC, p + a + b,     c);
    consumer_init(cD, p + a + b + c, d);
}
```

---

## 4. Fixed-size op records

For harnesses that execute a sequence of mutation operations, encode each
operation as a fixed-size record. This prevents frame-shift when libFuzzer
mutates the middle of the input.

```c
/* OP_RECORD_SIZE must be constant; never vary it. */
#define OP_RECORD_SIZE 12
#define MAX_OPS        32

typedef struct {
    uint8_t  opcode;    /* rec[0]   — which operation */
    uint8_t  selector;  /* rec[1]   — multi-purpose: case/hops/bool */
    uint16_t index;     /* rec[2-3] — array/object index selection */
    uint8_t  payload[8];/* rec[4-11]— 8-byte double OR 7-char string+NUL */
} OpRecord;

static OpRecord parse_op(const uint8_t *rec) {
    OpRecord o; o.opcode = rec[0]; o.selector = rec[1];
    o.index = (uint16_t)(rec[2] | (rec[3] << 8));
    memcpy(o.payload, rec + 4, 8); return o;
}

/*
 * Input layout:
 *   [u8 n_ops] [n_ops × OP_RECORD_SIZE bytes] [JSON payload]
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    int    n_ops     = (int)(data[0] % (MAX_OPS + 1));
    size_t ops_bytes = (size_t)n_ops * OP_RECORD_SIZE;
    if (1 + ops_bytes > size) { ops_bytes = 0; n_ops = 0; }
    size_t json_off  = 1 + ops_bytes;

    /* parse JSON tail */
    /* ... */

    for (int i = 0; i < n_ops; i++) {
        OpRecord op = parse_op(data + 1 + (size_t)i * OP_RECORD_SIZE);
        execute_op(root, &op /*, ... */);
    }
    /* ... */
    return 0;
}
```

---

## 5. Tree/object index pattern

For mutation harnesses that need to target specific node types (strings, numbers,
nested containers) without guessing their location, walk the tree once before
each op and collect everything into flat arrays.

```c
#define MAX_NODES 512

typedef struct {
    void  *containers[MAX_NODES]; int n_containers;
    void  *via_parent[MAX_NODES];
    void  *via_child[MAX_NODES];  int n_via;
    void  *strings[MAX_NODES];   int n_strings;
    void  *numbers[MAX_NODES];   int n_numbers;
} TreeIndex;

/* Rebuild before each op to stay consistent after mutations. */
static void index_tree(cJSON *root, TreeIndex *idx, int depth) {
    cJSON *child;
    if (!root || depth > CJSON_NESTING_LIMIT) return;
    if (cJSON_IsArray(root) || cJSON_IsObject(root)) {
        if (idx->n_containers < MAX_NODES)
            idx->containers[idx->n_containers++] = root;
        cJSON_ArrayForEach(child, root) {
            if (idx->n_via < MAX_NODES) {
                idx->via_parent[idx->n_via] = root;
                idx->via_child[idx->n_via++] = child;
            }
            index_tree(child, idx, depth + 1);
        }
    }
    if (cJSON_IsString(root) && idx->n_strings < MAX_NODES)
        idx->strings[idx->n_strings++] = root;
    if (cJSON_IsNumber(root) && idx->n_numbers < MAX_NODES)
        idx->numbers[idx->n_numbers++] = root;
}
```

---

## 6. Semantic oracles

### Deep-copy equality oracle

```c
cJSON *dup = cJSON_Duplicate(json, 1);
if (dup != NULL) {
    /* A recursive duplicate must always compare equal to the original.
       If not, Duplicate or Compare has a bug. */
    if (!cJSON_Compare(json, dup, 1) || !cJSON_Compare(json, dup, 0))
        __builtin_trap();
    cJSON_Delete(dup);
}
```

**Why not trap for float NaN?** — `cJSON_Parse` never produces NaN in number
nodes (it only parses valid JSON). So this oracle is safe for parse-only harnesses.
For mutation harnesses where `SetNumberHelper` may write NaN, use the text oracle.

### Round-trip text oracle

```c
/* Do NOT use cJSON_Compare(root, reparsed) — SetNumberHelper can write NaN
   into a number node, which serializes as "null", making the tree no longer
   structurally round-trippable via cJSON_Compare. */
char *p1 = cJSON_PrintUnformatted(root);
if (p1) {
    cJSON *re = cJSON_Parse(p1);
    if (!re) __builtin_trap();      /* valid output must reparse */
    char *p2 = cJSON_PrintUnformatted(re);
    if (p2) {
        if (strcmp(p1, p2) != 0)
            __builtin_trap();       /* print(parse(print(X))) == print(X) */
        cJSON_free(p2);
    }
    cJSON_Delete(re);
    cJSON_free(p1);
}
```

---

## 7. PrintPreallocated exact-boundary test

```c
static void test_print_preallocated(cJSON *item)
{
    /* Compute reference output length first */
    char *ref_unf = cJSON_PrintUnformatted(item);
    char *ref_fmt = cJSON_Print(item);
    int   nu = ref_unf ? (int)strlen(ref_unf) + 1 : 1;
    int   nf = ref_fmt ? (int)strlen(ref_fmt)  + 1 : 1;
    free(ref_unf); free(ref_fmt);

#define TPA(len, fmt) do { \
    char *b = (char*)malloc((size_t)(len) + 1); \
    if (b) { cJSON_PrintPreallocated(item, b, (len), (fmt)); free(b); } \
} while(0)

    /* Unformatted: 0, 1, need-1, need, +4, +5, +64 */
    TPA(0, 0); TPA(1, 0); TPA(nu-1, 0); TPA(nu, 0);
    TPA(nu+4, 0); TPA(nu+5, 0); TPA(nu+64, 0);
    /* Formatted: same range */
    TPA(0, 1); TPA(1, 1); TPA(nf-1, 1); TPA(nf, 1);
    TPA(nf+4, 1); TPA(nf+5, 1); TPA(nf+64, 1);
#undef TPA
}
```

The `+5` boundary matters because the cJSON header documents: "NOTE: cJSON is
not always 100% accurate in estimating how much memory it will use, so to be
safe allocate 5 bytes more than you actually need."

---

## 8. Reference node lifecycle

Reference nodes (created by `CreateStringReference`, `CreateObjectReference`,
`CreateArrayReference`) carry a `cJSON_IsReference` flag. When deleted, they do
**NOT** free the underlying data they point to.

`AddItemReferenceToArray/Object` creates an internal reference-wrapper node;
the original node is still owned by the caller.

**Always delete containers before the referent:**

```c
cJSON *original = /* ... */;
cJSON *arr      = cJSON_CreateArray();

cJSON_AddItemReferenceToArray(arr, original); /* wrapper inside arr */

/* USE arr before freeing anything */
char *out = cJSON_PrintUnformatted(arr); free(out);

/* Delete order: holder first, referent last */
cJSON_Delete(arr);      /* frees wrapper; does NOT free original's data */
cJSON_Delete(original); /* now safe */
```

---

## 9. Harness skeleton

```c
/*
 * <library>_<group>_fuzzer.c — LibFuzzer harness for <group> APIs.
 *
 * Coverage:
 *   - List every API function covered here
 *
 * Input format:
 *   Describe the byte layout (single JSON blob / multi-region / op records)
 *
 * Memory safety contract:
 *   Summarise ownership rules specific to this group
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "library.h"

/* --- consumer / split helpers --- */
/* (paste from patterns above) */

/* --- test functions --- */
static void test_group_a(Consumer *c) { /* ... */ }
static void test_group_b(Consumer *c) { /* ... */ }

/* --- entry point --- */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Consumer cA, cB;
    if (size < 4) return 0;
    split_input(data, size, &cA, &cB, /* ... */);
    test_group_a(&cA);
    test_group_b(&cB);
    return 0;
}
```
