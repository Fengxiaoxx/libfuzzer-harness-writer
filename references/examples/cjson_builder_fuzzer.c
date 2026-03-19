/*
 * cjson_builder_fuzzer.c — LibFuzzer harness for cJSON programmatic build API.
 *
 * Coverage targets (NOT in existing harnesses):
 *   - cJSON_CreateNull / True / False / Bool / Number / String / Raw
 *   - cJSON_CreateArray / Object
 *   - cJSON_CreateStringReference / ObjectReference / ArrayReference
 *   - cJSON_CreateIntArray / FloatArray / DoubleArray / StringArray
 *   - cJSON_AddItemToArray / Object / ObjectCS
 *   - cJSON_AddItemReferenceToArray / Object
 *   - cJSON_AddNullToObject / TrueToObject / FalseToObject / BoolToObject
 *   - cJSON_AddNumberToObject / StringToObject / RawToObject
 *   - cJSON_AddObjectToObject / ArrayToObject
 *   - cJSON_InsertItemInArray        (begin / middle / end / OOB)
 *   - cJSON_SetNumberHelper
 *   - cJSON_SetValuestring
 *
 * Design rationale:
 *   The input is split into four fixed-length regions using a 4-byte header
 *   (one byte per region length, stored as fractions of the remaining input).
 *   Each region drives an independent Consumer so that mutations to one region
 *   do not shift the byte-offsets of the others — making libFuzzer's corpus
 *   evolution stable.
 *
 *   Region layout:
 *     [0]  tree_len_frac   (u8 — fraction of data[4:] given to tree builder)
 *     [1]  typed_len_frac  (u8 — fraction of remainder given to typed arrays)
 *     [2]  helper_len_frac (u8 — fraction of remainder given to Add helpers)
 *     [3]  misc_len_frac   (u8 — remaining bytes go to insert/set/references)
 *
 * Memory safety contract:
 *   - Reference nodes (IsReference flag set) do NOT free their pointed-to
 *     data when deleted. The referent must outlive all containers that hold
 *     references to it. We enforce this by deleting holders first.
 *   - AddItemReferenceToArray/Object wraps the referent in a shallow copy
 *     node; the original referent must still be freed by the caller.
 *   - AddItemToArray/Object transfers ownership on success; caller must NOT
 *     free the item afterwards. On failure, caller must free it.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../cJSON.h"

/* ------------------------------------------------------------------ */
/* Byte-stream consumer                                                */
/* ------------------------------------------------------------------ */

typedef struct
{
    const uint8_t *ptr;
    size_t         remaining;
} Consumer;

static void consumer_init(Consumer *c, const uint8_t *data, size_t size)
{
    c->ptr       = data;
    c->remaining = size;
}

static int consumer_empty(const Consumer *c)
{
    return c->remaining == 0;
}

static uint8_t consume_u8(Consumer *c)
{
    uint8_t v;
    if (c->remaining == 0) return 0;
    v = *c->ptr++;
    c->remaining--;
    return v;
}

static uint16_t consume_u16(Consumer *c)
{
    uint16_t lo = consume_u8(c);
    uint16_t hi = consume_u8(c);
    return (uint16_t)(lo | (hi << 8));
}

static double consume_double(Consumer *c)
{
    uint8_t buf[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    size_t  n      = c->remaining < 8 ? c->remaining : 8;
    memcpy(buf, c->ptr, n);
    c->ptr += n; c->remaining -= n;
    double v; memcpy(&v, buf, 8);
    return v;
}

/*
 * Length-prefixed string: consume one byte for length (0-63), then that
 * many bytes as the string body (NUL-terminated in buf).
 * Using length prefix avoids the NUL-separator instability of cstr scanning.
 */
static const char *consume_lstr(Consumer *c, char *buf, size_t bufsize)
{
    uint8_t len = consume_u8(c) & 0x3F;  /* 0..63 */
    size_t  n   = len < bufsize - 1 ? len : bufsize - 2;
    n           = n < c->remaining ? n : c->remaining;
    memcpy(buf, c->ptr, n);
    buf[n] = '\0';
    c->ptr += n; c->remaining -= n;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Input region splitting                                              */
/* ------------------------------------------------------------------ */

static void split_input(const uint8_t *data, size_t size,
                        Consumer *c_tree, Consumer *c_typed,
                        Consumer *c_helper, Consumer *c_misc)
{
    /* Need at least the 4-byte header */
    if (size < 4)
    {
        consumer_init(c_tree,   data, 0);
        consumer_init(c_typed,  data, 0);
        consumer_init(c_helper, data, 0);
        consumer_init(c_misc,   data, 0);
        return;
    }

    /* Fractions: split the payload (data[4:]) proportionally */
    const uint8_t *payload = data + 4;
    size_t         plen    = size - 4;

    /* Use the header bytes as numerators over 256 */
    size_t t = ((size_t)data[0] * plen) / 256;
    size_t y = ((size_t)data[1] * (plen - t)) / 256;
    size_t h = ((size_t)data[2] * (plen - t - y)) / 256;
    size_t m = plen - t - y - h;

    consumer_init(c_tree,   payload,             t);
    consumer_init(c_typed,  payload + t,         y);
    consumer_init(c_helper, payload + t + y,     h);
    consumer_init(c_misc,   payload + t + y + h, m);
}

/* ------------------------------------------------------------------ */
/* Tree builder                                                        */
/* ------------------------------------------------------------------ */

#define MAX_BUILD_DEPTH 12

static cJSON *build_tree(Consumer *c, int depth);

static cJSON *build_scalar(Consumer *c)
{
    char    buf[128];
    uint8_t sel;
    if (consumer_empty(c)) return cJSON_CreateNull();
    sel = consume_u8(c) % 7;
    switch (sel)
    {
        case 0: return cJSON_CreateNull();
        case 1: return cJSON_CreateTrue();
        case 2: return cJSON_CreateFalse();
        case 3: return cJSON_CreateBool(consume_u8(c) & 1);
        case 4: return cJSON_CreateNumber(consume_double(c));
        case 5: return cJSON_CreateString(consume_lstr(c, buf, sizeof(buf)));
        case 6: return cJSON_CreateRaw(consume_lstr(c, buf, sizeof(buf)));
        default: return cJSON_CreateNull();
    }
}

static cJSON *build_array_node(Consumer *c, int depth)
{
    cJSON  *arr   = cJSON_CreateArray();
    uint8_t count = consume_u8(c) % 8;
    uint8_t i;
    if (arr == NULL) return NULL;
    for (i = 0; i < count; i++)
    {
        cJSON *child = build_tree(c, depth + 1);
        if (child == NULL) break;
        if (!cJSON_AddItemToArray(arr, child))
            cJSON_Delete(child);
    }
    return arr;
}

static cJSON *build_object_node(Consumer *c, int depth)
{
    cJSON  *obj   = cJSON_CreateObject();
    uint8_t count = consume_u8(c) % 8;
    uint8_t i;
    char    key[64];
    if (obj == NULL) return NULL;
    for (i = 0; i < count; i++)
    {
        consume_lstr(c, key, sizeof(key));
        cJSON *val = build_tree(c, depth + 1);
        if (val == NULL) break;
        if (!cJSON_AddItemToObject(obj, key, val))
            cJSON_Delete(val);
    }
    return obj;
}

static cJSON *build_tree(Consumer *c, int depth)
{
    if (consumer_empty(c) || depth >= MAX_BUILD_DEPTH)
        return cJSON_CreateNull();
    switch (consume_u8(c) % 4)
    {
        case 0: return build_scalar(c);
        case 1: return build_array_node(c, depth);
        case 2: return build_object_node(c, depth);
        default: return build_scalar(c);
    }
}

/* ------------------------------------------------------------------ */
/* Typed array constructors                                            */
/* ------------------------------------------------------------------ */

#define MAX_TYPED 32

static void test_typed_arrays(Consumer *c)
{
    int    i_arr[MAX_TYPED];
    float  f_arr[MAX_TYPED];
    double d_arr[MAX_TYPED];
    const char *s_arr[8] = {"a", "bb", "ccc", "", "hello", "world", "42", "x"};
    int  count;
    int  i;
    cJSON *node;

    count = (int)(consume_u8(c) % MAX_TYPED) + 1;

    for (i = 0; i < count; i++)
    {
        i_arr[i] = (int)(int16_t)consume_u16(c);
        f_arr[i] = (float)consume_double(c);
        d_arr[i] = consume_double(c);
    }

    /* count == 0 boundary */
    node = cJSON_CreateIntArray(i_arr, 0);     cJSON_Delete(node);
    node = cJSON_CreateFloatArray(f_arr, 0);   cJSON_Delete(node);
    node = cJSON_CreateDoubleArray(d_arr, 0);  cJSON_Delete(node);
    node = cJSON_CreateStringArray(s_arr, 0);  cJSON_Delete(node);

    /* Normal cases */
    node = cJSON_CreateIntArray(i_arr, count);    cJSON_Delete(node);
    node = cJSON_CreateFloatArray(f_arr, count);  cJSON_Delete(node);
    node = cJSON_CreateDoubleArray(d_arr, count); cJSON_Delete(node);

    /* String array — cap at 8 entries to stay in bounds */
    {
        int sc = count < 8 ? count : 8;
        node = cJSON_CreateStringArray(s_arr, sc); cJSON_Delete(node);
    }
}

/* ------------------------------------------------------------------ */
/* AddXxxToObject helper functions                                     */
/* ------------------------------------------------------------------ */

static void test_add_helpers(Consumer *c)
{
    cJSON *obj = cJSON_CreateObject();
    char   str[128];
    if (obj == NULL) return;

    /* Each helper creates-and-inserts; return is owned by obj. Never free it. */
    cJSON_AddNullToObject(obj,    "n");
    cJSON_AddTrueToObject(obj,    "t");
    cJSON_AddFalseToObject(obj,   "f");
    cJSON_AddBoolToObject(obj,    "b",   (int)(consume_u8(c) & 1));
    cJSON_AddNumberToObject(obj,  "num", consume_double(c));
    cJSON_AddStringToObject(obj,  "s",   consume_lstr(c, str, sizeof(str)));
    cJSON_AddRawToObject(obj,     "r",   consume_lstr(c, str, sizeof(str)));
    cJSON_AddObjectToObject(obj,  "o");
    cJSON_AddArrayToObject(obj,   "a");

    /* AddItemToObjectCS (constant-string key) */
    {
        cJSON *num = cJSON_CreateNumber(consume_double(c));
        if (num != NULL)
            if (!cJSON_AddItemToObjectCS(obj, "cs", num))
                cJSON_Delete(num);
    }

    /* Serialise the whole object to exercise the print path */
    {
        char *out = cJSON_PrintUnformatted(obj);
        free(out);
    }

    cJSON_Delete(obj);
}

/* ------------------------------------------------------------------ */
/* Reference semantics                                                 */
/* ------------------------------------------------------------------ */

/*
 * Correct reference lifecycle:
 *   1. Allocate the referent (original).
 *   2. Create containers that hold reference-wrapper nodes pointing to it.
 *   3. Use (print/traverse) the containers BEFORE freeing the referent.
 *   4. Delete the containers FIRST, then the referent.
 *
 * AddItemReferenceToArray/Object allocates a shallow-copy wrapper with
 * cJSON_IsReference set; the wrapper does NOT free the underlying data.
 * We must still free `original` ourselves.
 */
static void test_references(Consumer *c)
{
    cJSON *original = NULL;
    cJSON *arr      = NULL;
    cJSON *obj      = NULL;
    char   str[64];
    char   key[32];

    original = build_tree(c, 0);
    if (original == NULL) return;

    arr = cJSON_CreateArray();
    obj = cJSON_CreateObject();
    if (arr == NULL || obj == NULL)
    {
        cJSON_Delete(arr);
        cJSON_Delete(obj);
        cJSON_Delete(original);
        return;
    }

    /* --- CreateObjectReference / CreateArrayReference wrapping the original --- */
    {
        /* Use original->child if it is an array/object, otherwise use original */
        cJSON *ref_target = (original->child != NULL) ? original->child : original;

        cJSON *obj_ref = cJSON_CreateObjectReference(ref_target);
        if (obj_ref != NULL)
            if (!cJSON_AddItemToArray(arr, obj_ref))
                cJSON_Delete(obj_ref);

        cJSON *arr_ref = cJSON_CreateArrayReference(ref_target);
        if (arr_ref != NULL)
        {
            consume_lstr(c, key, sizeof(key));
            if (!cJSON_AddItemToObject(obj, key[0] ? key : "arr_ref", arr_ref))
                cJSON_Delete(arr_ref);
        }
    }

    /* --- CreateStringReference for string nodes --- */
    {
        const char *s = cJSON_IsString(original) ? original->valuestring : "literal";
        cJSON *str_ref = cJSON_CreateStringReference(s);
        if (str_ref != NULL)
            if (!cJSON_AddItemToArray(arr, str_ref))
                cJSON_Delete(str_ref);
    }

    /* --- AddItemReferenceToArray / AddItemReferenceToObject ---
         These create a wrapper node internally; `original` must outlive arr/obj. */
    cJSON_AddItemReferenceToArray(arr, original);   /* wrapper owned by arr */
    consume_lstr(c, key, sizeof(key));
    cJSON_AddItemReferenceToObject(obj, key[0] ? key : "ref", original);

    /* --- Use the containers BEFORE releasing anything --- */
    {
        char *out;
        out = cJSON_PrintUnformatted(arr); free(out);
        out = cJSON_PrintUnformatted(obj); free(out);
    }

    /* --- Delete order: containers first, referent last --- */
    cJSON_Delete(arr);      /* wrappers inside are freed; original->data is NOT */
    cJSON_Delete(obj);
    cJSON_Delete(original); /* now safe to free the actual data */

    (void)str;
}

/* ------------------------------------------------------------------ */
/* InsertItemInArray + SetValuestring + SetNumberHelper                */
/* ------------------------------------------------------------------ */

static void test_insert_and_set(Consumer *c)
{
    cJSON *arr  = NULL;
    cJSON *item = NULL;
    int    size;
    char   str[128];

    arr = cJSON_CreateArray();
    if (arr == NULL) return;

    /* Populate with 4 number elements */
    {
        int i;
        for (i = 0; i < 4; i++)
        {
            item = cJSON_CreateNumber((double)i);
            if (item != NULL)
                if (!cJSON_AddItemToArray(arr, item))
                    cJSON_Delete(item);
        }
    }

    size = cJSON_GetArraySize(arr);

    /* InsertItemInArray: beginning (idx=0) */
    item = cJSON_CreateString("begin");
    if (item != NULL)
        if (!cJSON_InsertItemInArray(arr, 0, item))
            cJSON_Delete(item);

    /* InsertItemInArray: middle */
    size = cJSON_GetArraySize(arr);
    if (size > 1)
    {
        item = cJSON_CreateString(consume_lstr(c, str, sizeof(str)));
        if (item != NULL)
        {
            int mid = size / 2;
            if (!cJSON_InsertItemInArray(arr, mid, item))
                cJSON_Delete(item);
        }
    }

    /* InsertItemInArray: append (idx == size, valid end-of-array) */
    size = cJSON_GetArraySize(arr);
    item = cJSON_CreateString("end");
    if (item != NULL)
        if (!cJSON_InsertItemInArray(arr, size, item))
            cJSON_Delete(item);

    /* InsertItemInArray: negative index (invalid — must not crash) */
    item = cJSON_CreateNull();
    if (item != NULL)
        if (!cJSON_InsertItemInArray(arr, -1, item))
            cJSON_Delete(item);

    /* SetNumberHelper on a standalone number node */
    {
        cJSON *num = cJSON_CreateNumber(1.0);
        if (num != NULL)
        {
            cJSON_SetNumberHelper(num, consume_double(c));
            /* Also test on a non-number node — should be safe */
            cJSON *str_node = cJSON_CreateString("s");
            if (str_node != NULL)
            {
                cJSON_SetNumberHelper(str_node, 42.0);
                cJSON_Delete(str_node);
            }
            cJSON_Delete(num);
        }
    }

    /* SetValuestring on a string node */
    {
        cJSON *str_node = cJSON_CreateString("original");
        if (str_node != NULL)
        {
            cJSON_SetValuestring(str_node, consume_lstr(c, str, sizeof(str)));
            /* Also test on a non-string node (returns NULL, must not crash) */
            cJSON *null_node = cJSON_CreateNull();
            if (null_node != NULL)
            {
                cJSON_SetValuestring(null_node, "wont_take");
                cJSON_Delete(null_node);
            }
            cJSON_Delete(str_node);
        }
    }

    /* Serialize final array */
    {
        char *out = cJSON_PrintUnformatted(arr);
        free(out);
    }

    cJSON_Delete(arr);
}

/* ------------------------------------------------------------------ */
/* Fuzzer entry point                                                  */
/* ------------------------------------------------------------------ */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Consumer c_tree, c_typed, c_helper, c_misc;
    cJSON   *tree = NULL;
    char    *out  = NULL;

    if (size < 4)
        return 0;

    split_input(data, size, &c_tree, &c_typed, &c_helper, &c_misc);

    /* 1. Build a complex tree and serialise it (also tests Print path) */
    tree = build_tree(&c_tree, 0);
    if (tree != NULL)
    {
        out = cJSON_Print(tree);          free(out);
        out = cJSON_PrintUnformatted(tree); free(out);
        cJSON_Delete(tree);
    }

    /* 2. Typed array constructors */
    test_typed_arrays(&c_typed);

    /* 3. AddXxxToObject helper functions */
    test_add_helpers(&c_helper);

    /* 4. Reference semantics (fixed lifecycle order) */
    test_references(&c_misc);

    /* 5. InsertItemInArray + SetValuestring + SetNumberHelper */
    test_insert_and_set(&c_misc);

    /* 6. CreateArrayReference / CreateObjectReference standalone edge cases */
    {
        cJSON *inner = cJSON_CreateObject();
        if (inner != NULL)
        {
            cJSON *a_ref = cJSON_CreateArrayReference(inner);
            cJSON *o_ref = cJSON_CreateObjectReference(inner);
            /* Delete wrappers BEFORE inner */
            cJSON_Delete(a_ref);
            cJSON_Delete(o_ref);
            cJSON_Delete(inner);
        }
    }

    return 0;
}
