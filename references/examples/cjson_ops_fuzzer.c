/*
 * cjson_ops_fuzzer.c — LibFuzzer harness for cJSON query/compare/print operations.
 *
 * Coverage targets (NOT in existing cjson_read_fuzzer.c):
 *   - cJSON_ParseWithLength          (no null-terminator required)
 *   - cJSON_ParseWithLengthOpts      (require_null_terminated = 0 AND 1)
 *   - cJSON_GetErrorPtr              (failure path)
 *   - cJSON_GetArraySize
 *   - cJSON_GetArrayItem             (valid, negative, out-of-bounds indices)
 *   - cJSON_GetObjectItem            (case-insensitive)
 *   - cJSON_GetObjectItemCaseSensitive
 *   - cJSON_HasObjectItem
 *   - cJSON_GetStringValue
 *   - cJSON_GetNumberValue
 *   - cJSON_IsInvalid / IsFalse / IsTrue / IsBool / IsNull /
 *     IsNumber / IsString / IsArray / IsObject / IsRaw
 *   - cJSON_Duplicate                (recurse=0 and recurse=1)
 *   - cJSON_Compare                  (semantic oracle: deep-copy must equal original)
 *   - cJSON_PrintPreallocated        (zero, under, exact, +4, +5 byte buffers)
 *   - cJSON_Version
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../cJSON.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Recursively walk every node and exercise all query / type-check APIs.
 * Depth is capped at CJSON_NESTING_LIMIT to stay consistent with the
 * library's own recursion guard.
 */
static void traverse_and_query(const cJSON *item, int depth)
{
    const cJSON *child = NULL;
    int          size  = 0;

    if (item == NULL || depth > CJSON_NESTING_LIMIT)
        return;

    /* --- type predicates --- */
    cJSON_IsInvalid(item);
    cJSON_IsFalse(item);
    cJSON_IsTrue(item);
    cJSON_IsBool(item);
    cJSON_IsNull(item);
    cJSON_IsNumber(item);
    cJSON_IsString(item);
    cJSON_IsArray(item);
    cJSON_IsObject(item);
    cJSON_IsRaw(item);

    /* --- value accessors --- */
    cJSON_GetStringValue(item);
    cJSON_GetNumberValue(item);

    /* --- array queries --- */
    if (cJSON_IsArray(item))
    {
        size = cJSON_GetArraySize(item);

        /* valid indices */
        if (size > 0)
        {
            cJSON_GetArrayItem(item, 0);
            cJSON_GetArrayItem(item, size - 1);
            if (size > 1)
                cJSON_GetArrayItem(item, size / 2);
        }
        /* boundary / invalid indices — must not crash */
        cJSON_GetArrayItem(item, -1);
        cJSON_GetArrayItem(item, size);
        cJSON_GetArrayItem(item, INT32_MAX);

        cJSON_ArrayForEach(child, item)
            traverse_and_query(child, depth + 1);
    }

    /* --- object queries --- */
    if (cJSON_IsObject(item))
    {
        /* Probe with a synthetic key to exercise the not-found path */
        cJSON_GetObjectItem(item, "key");
        cJSON_GetObjectItemCaseSensitive(item, "key");
        cJSON_HasObjectItem(item, "key");

        /* Probe with the first child's real key (if any) to hit found paths */
        if (item->child != NULL && item->child->string != NULL)
        {
            const char *real_key = item->child->string;
            cJSON_GetObjectItem(item, real_key);
            cJSON_GetObjectItemCaseSensitive(item, real_key);
            cJSON_HasObjectItem(item, real_key);

            /* Case-sensitivity divergence: flip ASCII case of first char.
               This stably exercises the case-sensitive vs. insensitive branches. */
            {
                char flipped_key[256];
                size_t klen = strlen(real_key);
                if (klen >= sizeof(flipped_key))
                    klen = sizeof(flipped_key) - 1;
                memcpy(flipped_key, real_key, klen);
                flipped_key[klen] = '\0';
                if (klen > 0)
                    flipped_key[0] = (char)(islower((unsigned char)flipped_key[0])
                                           ? toupper((unsigned char)flipped_key[0])
                                           : tolower((unsigned char)flipped_key[0]));
                cJSON_GetObjectItem(item, flipped_key);             /* may match */
                cJSON_GetObjectItemCaseSensitive(item, flipped_key); /* won't match */
            }
        }

        cJSON_ArrayForEach(child, item)
            traverse_and_query(child, depth + 1);
    }
}

/*
 * Exercise cJSON_PrintPreallocated with buffers sized relative to the
 * actual output length, covering the +5 bytes boundary documented in cJSON.h.
 *
 * The function is called with both fmt=0 and fmt=1.
 */
static void test_print_preallocated(cJSON *item)
{
    /* Get the reference output so we can compute exact ± N sizes */
    char *ref_unformatted = cJSON_PrintUnformatted(item);
    char *ref_formatted   = cJSON_Print(item);

    int  need_unf = ref_unformatted ? (int)strlen(ref_unformatted) + 1 : 1;
    int  need_fmt = ref_formatted   ? (int)strlen(ref_formatted)   + 1 : 1;

    free(ref_unformatted);
    free(ref_formatted);

#define TEST_PA(len, fmt) \
    do { \
        char *_buf = (char *)malloc((size_t)(len) + 1); \
        if (_buf) { \
            cJSON_PrintPreallocated(item, _buf, (len), (fmt)); \
            free(_buf); \
        } \
    } while (0)

    /* Unformatted (fmt=0) */
    TEST_PA(0,             0);
    TEST_PA(1,             0);
    TEST_PA(need_unf - 1,  0);  /* one byte too small */
    TEST_PA(need_unf,      0);  /* exact */
    TEST_PA(need_unf + 4,  0);  /* +4 (just under the +5 safety margin) */
    TEST_PA(need_unf + 5,  0);  /* +5 (meets documented safety margin) */
    TEST_PA(need_unf + 64, 0);  /* comfortably large */

    /* Formatted (fmt=1) */
    TEST_PA(0,             1);
    TEST_PA(1,             1);
    TEST_PA(need_fmt - 1,  1);
    TEST_PA(need_fmt,      1);
    TEST_PA(need_fmt + 4,  1);
    TEST_PA(need_fmt + 5,  1);
    TEST_PA(need_fmt + 64, 1);

#undef TEST_PA
}

/* ------------------------------------------------------------------ */
/* Fuzzer entry point                                                  */
/* ------------------------------------------------------------------ */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    cJSON      *json1         = NULL;
    cJSON      *json2         = NULL;
    cJSON      *json3         = NULL;
    cJSON      *dup_deep      = NULL;
    cJSON      *dup_shallow   = NULL;
    const char *parse_end     = NULL;
    char       *null_term_buf = NULL;

    if (size == 0)
        return 0;

    /* Touch version symbol (ensures it is linked) */
    cJSON_Version();

    /* --- Parse path 1: ParseWithLength — raw bytes, no NUL required --- */
    json1 = cJSON_ParseWithLength((const char *)data, size);

    /* --- Parse path 2: ParseWithLengthOpts — require_null_terminated = 0 --- */
    parse_end = NULL;
    json2 = cJSON_ParseWithLengthOpts((const char *)data, size, &parse_end, 0);

    /* --- Parse path 3: ParseWithLengthOpts — require_null_terminated = 1
           Requires a NUL-terminated copy to expose that validation branch.  --- */
    null_term_buf = (char *)malloc(size + 1);
    if (null_term_buf != NULL)
    {
        memcpy(null_term_buf, data, size);
        null_term_buf[size] = '\0';
        parse_end = NULL;
        json3 = cJSON_ParseWithLengthOpts(null_term_buf, size, &parse_end, 1);
    }

    /* --- Failure path: GetErrorPtr must be callable after failed parse --- */
    if (json1 == NULL)
        cJSON_GetErrorPtr();

    /* --- Exercise all query APIs on json1 --- */
    if (json1 != NULL)
    {
        traverse_and_query(json1, 0);

        /* Duplicate: deep */
        dup_deep = cJSON_Duplicate(json1, 1 /* recurse */);

        /* Duplicate: shallow — also exercise query APIs on it */
        dup_shallow = cJSON_Duplicate(json1, 0 /* no recurse */);
        if (dup_shallow != NULL)
        {
            traverse_and_query(dup_shallow, 0);
            test_print_preallocated(dup_shallow);
        }

        /* Semantic oracle: deep copy must compare equal to the original.
           If the library disagrees, it is a correctness bug — abort loudly. */
        if (dup_deep != NULL)
        {
            int eq_cs  = cJSON_Compare(json1, dup_deep, 1);
            int eq_ci  = cJSON_Compare(json1, dup_deep, 0);
            /* Both case-sensitive and case-insensitive should agree here
               because the deep copy is bit-exact. */
            if (!eq_cs || !eq_ci)
            {
                /* Trigger ASan / sanitizer crash to surface the bug */
                __builtin_trap();
            }
        }

        /* Compare json1 vs json2 — parsed from the same bytes, usually equal */
        if (json2 != NULL)
        {
            cJSON_Compare(json1, json2, 1);
            cJSON_Compare(json1, json2, 0);
        }

        /* Compare degenerate / NULL cases */
        cJSON_Compare(json1, NULL,  1);
        cJSON_Compare(NULL,  json1, 0);
        cJSON_Compare(NULL,  NULL,  1);

        /* Compare against an "invalid" node (type == 0) */
        {
            cJSON invalid;
            memset(&invalid, 0, sizeof(invalid));
            cJSON_Compare(json1, &invalid, 1);
            cJSON_Compare(&invalid, json1, 0);
        }

        /* PrintPreallocated with exact-boundary buffers */
        test_print_preallocated(json1);
        if (dup_deep != NULL)
            test_print_preallocated(dup_deep);

        cJSON_Delete(dup_deep);
        cJSON_Delete(dup_shallow);
    }

    cJSON_Delete(json1);
    cJSON_Delete(json2);
    cJSON_Delete(json3);
    free(null_term_buf);

    return 0;
}
