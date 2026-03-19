/*
 * cjson_mutate_fuzzer.c — LibFuzzer harness for cJSON mutation / detach / delete API.
 *
 * Coverage targets (NOT in existing harnesses):
 *   - cJSON_DetachItemViaPointer
 *   - cJSON_DetachItemFromArray       (valid, negative, OOB)
 *   - cJSON_DetachItemFromObject      (case-insensitive)
 *   - cJSON_DetachItemFromObjectCaseSensitive
 *   - cJSON_DeleteItemFromArray
 *   - cJSON_DeleteItemFromObject
 *   - cJSON_DeleteItemFromObjectCaseSensitive
 *   - cJSON_ReplaceItemViaPointer
 *   - cJSON_ReplaceItemInArray        (valid, OOB, negative)
 *   - cJSON_ReplaceItemInObject       (found / missing key)
 *   - cJSON_ReplaceItemInObjectCaseSensitive
 *   - cJSON_SetValuestring            (on String nodes, non-String nodes, NULL arg)
 *   - cJSON_SetNumberHelper           (on Number nodes, non-Number nodes, NULL)
 *
 * Input format:
 *   [u8 n_ops]  — number of op records that follow (0..32)
 *   [n_ops × OP_RECORD_SIZE bytes] — fixed-size op records
 *   [remaining bytes] — JSON text for cJSON_ParseWithLength
 *
 *   Fixed-size op records eliminate the frame-shift instability that
 *   variable-length encodings cause in corpus evolution.
 *
 *   OP_RECORD_SIZE = 12 bytes:
 *     [0]    opcode (u8, selects the operation)
 *     [1]    selector (u8, multi-purpose: hops / case / recurse / bool)
 *     [2-3]  index (u16, little-endian, used for array index selection)
 *     [4-11] payload (8 bytes: double or up to 7-char string + NUL)
 *
 * Target selection strategy:
 *   We walk the tree once before each operation to collect all containers
 *   (arrays and objects), all string nodes, and all number nodes into flat
 *   arrays. Operations then select targets by index, ensuring stable coverage
 *   of deeply-nested structures regardless of tree shape.
 *
 * Stash for detach-then-reinsert:
 *   A single "stash" slot saves the most recently detached node so that
 *   subsequent operations can reinsert it, exercising cross-container
 *   ownership transfer.
 *
 * Memory safety contract:
 *   - Detached nodes are either re-inserted (ownership transferred to new
 *     parent) or freed before the stash is overwritten / at end of input.
 *   - Replace* transfers ownership of the replacement on success; on failure
 *     the caller frees it.
 *   - SetValuestring result is owned by the node; never freed separately.
 *   - cJSON_free() is used instead of free() for library-allocated strings.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../cJSON.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define OP_RECORD_SIZE  12
#define MAX_OPS         32
#define MAX_NODES       512   /* max nodes we collect per walk */

/* ------------------------------------------------------------------ */
/* Op-record accessors                                                 */
/* ------------------------------------------------------------------ */

typedef struct
{
    uint8_t  opcode;
    uint8_t  selector;
    uint16_t index;
    uint8_t  payload[8];
} OpRecord;

static OpRecord parse_op(const uint8_t *rec)
{
    OpRecord o;
    o.opcode   = rec[0];
    o.selector = rec[1];
    o.index    = (uint16_t)(rec[2] | (rec[3] << 8));
    memcpy(o.payload, rec + 4, 8);
    return o;
}

static double op_double(const OpRecord *o)
{
    double v; memcpy(&v, o->payload, 8); return v;
}

/* payload bytes 0-6 as a NUL-terminated string (7 usable chars) */
static const char *op_str(const OpRecord *o, char *buf)
{
    memcpy(buf, o->payload, 7);
    buf[7] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/* Tree walker: collect containers / typed nodes                       */
/* ------------------------------------------------------------------ */

typedef struct
{
    cJSON *containers[MAX_NODES]; /* arrays and objects */
    int    n_containers;

    /* (parent, child) pairs — for DetachItemViaPointer / ReplaceItemViaPointer */
    cJSON *via_parent[MAX_NODES];
    cJSON *via_child[MAX_NODES];
    int    n_via;

    cJSON *strings[MAX_NODES];   /* cJSON_String nodes */
    int    n_strings;

    cJSON *numbers[MAX_NODES];   /* cJSON_Number nodes */
    int    n_numbers;
} TreeIndex;

static void index_tree(cJSON *root, TreeIndex *idx, int depth)
{
    cJSON *child;

    if (root == NULL || depth > CJSON_NESTING_LIMIT)
        return;

    if (cJSON_IsArray(root) || cJSON_IsObject(root))
    {
        if (idx->n_containers < MAX_NODES)
            idx->containers[idx->n_containers++] = root;

        cJSON_ArrayForEach(child, root)
        {
            if (idx->n_via < MAX_NODES)
            {
                idx->via_parent[idx->n_via] = root;
                idx->via_child[idx->n_via]  = child;
                idx->n_via++;
            }
            index_tree(child, idx, depth + 1);
        }
    }

    if (cJSON_IsString(root) && idx->n_strings < MAX_NODES)
        idx->strings[idx->n_strings++] = root;

    if (cJSON_IsNumber(root) && idx->n_numbers < MAX_NODES)
        idx->numbers[idx->n_numbers++] = root;
}

/* ------------------------------------------------------------------ */
/* Operation execution                                                 */
/* ------------------------------------------------------------------ */

static void execute_op(cJSON *root, const OpRecord *op,
                       cJSON **stash, TreeIndex *idx)
{
    char    key[8];    /* from op->payload */
    char    val[8];    /* same payload as string */
    cJSON  *container  = NULL;
    cJSON  *detached   = NULL;
    cJSON  *replacement = NULL;
    int     size       = 0;
    int     arr_idx    = 0;

    op_str(op, key);

    /* Rebuild index on each op to stay consistent after mutations */
    memset(idx, 0, sizeof(*idx));
    index_tree(root, idx, 0);

    /* Pick a container using op->selector % n_containers */
    if (idx->n_containers > 0)
        container = idx->containers[op->selector % (uint8_t)idx->n_containers];

    size = (container != NULL) ? cJSON_GetArraySize(container) : 0;
    arr_idx = (size > 0) ? (int)(op->index % (uint16_t)size) : 0;

    switch (op->opcode % 20)
    {

    /* ----------------------------------------------------------------
     * 0: DetachItemFromArray — valid index — stash result
     * -------------------------------------------------------------- */
    case 0:
        if (cJSON_IsArray(container) && size > 0)
        {
            cJSON_Delete(*stash);  /* free previous stash */
            *stash = cJSON_DetachItemFromArray(container, arr_idx);
        }
        break;

    /* ----------------------------------------------------------------
     * 1: DetachItemFromArray — invalid indices (must return NULL)
     * -------------------------------------------------------------- */
    case 1:
        if (cJSON_IsArray(container))
        {
            detached = cJSON_DetachItemFromArray(container, -1);
            cJSON_Delete(detached);
            detached = cJSON_DetachItemFromArray(container, size + 100);
            cJSON_Delete(detached);
        }
        break;

    /* ----------------------------------------------------------------
     * 2: DetachItemFromObject (case-insensitive) — stash result
     * -------------------------------------------------------------- */
    case 2:
        if (cJSON_IsObject(container))
        {
            cJSON_Delete(*stash);
            *stash = cJSON_DetachItemFromObject(container, key);
            /* Also try with the real first key if exists */
            if (container->child != NULL && container->child->string != NULL
                && *stash == NULL)
            {
                *stash = cJSON_DetachItemFromObject(
                    container, container->child->string);
            }
        }
        break;

    /* ----------------------------------------------------------------
     * 3: DetachItemFromObjectCaseSensitive — stash result
     * -------------------------------------------------------------- */
    case 3:
        if (cJSON_IsObject(container))
        {
            cJSON_Delete(*stash);
            *stash = cJSON_DetachItemFromObjectCaseSensitive(container, key);
            if (container->child != NULL && container->child->string != NULL
                && *stash == NULL)
            {
                *stash = cJSON_DetachItemFromObjectCaseSensitive(
                    container, container->child->string);
            }
        }
        break;

    /* ----------------------------------------------------------------
     * 4: DetachItemViaPointer — select a (parent,child) pair from index
     * -------------------------------------------------------------- */
    case 4:
        if (idx->n_via > 0)
        {
            int vi = op->index % (uint16_t)idx->n_via;
            cJSON_Delete(*stash);
            *stash = cJSON_DetachItemViaPointer(idx->via_parent[vi],
                                                idx->via_child[vi]);
        }
        break;

    /* ----------------------------------------------------------------
     * 5: Reinsert stash into a container array (transfer ownership)
     * -------------------------------------------------------------- */
    case 5:
        if (*stash != NULL && cJSON_IsArray(container))
        {
            if (!cJSON_AddItemToArray(container, *stash))
                cJSON_Delete(*stash);
            *stash = NULL;  /* ownership transferred or freed */
        }
        break;

    /* ----------------------------------------------------------------
     * 6: Reinsert stash into a container object
     * -------------------------------------------------------------- */
    case 6:
        if (*stash != NULL && cJSON_IsObject(container))
        {
            if (!cJSON_AddItemToObject(container, key[0] ? key : "s", *stash))
                cJSON_Delete(*stash);
            *stash = NULL;
        }
        break;

    /* ----------------------------------------------------------------
     * 7: DeleteItemFromArray
     * -------------------------------------------------------------- */
    case 7:
        if (cJSON_IsArray(container) && size > 0)
            cJSON_DeleteItemFromArray(container, arr_idx);
        /* OOB must not crash */
        if (cJSON_IsArray(container))
            cJSON_DeleteItemFromArray(container, -1);
        break;

    /* ----------------------------------------------------------------
     * 8: DeleteItemFromObject (case-insensitive)
     * -------------------------------------------------------------- */
    case 8:
        if (cJSON_IsObject(container))
        {
            cJSON_DeleteItemFromObject(container, key);
            if (container->child != NULL && container->child->string != NULL)
                cJSON_DeleteItemFromObject(container,
                                           container->child->string);
        }
        break;

    /* ----------------------------------------------------------------
     * 9: DeleteItemFromObjectCaseSensitive
     * -------------------------------------------------------------- */
    case 9:
        if (cJSON_IsObject(container))
        {
            cJSON_DeleteItemFromObjectCaseSensitive(container, key);
            if (container->child != NULL && container->child->string != NULL)
                cJSON_DeleteItemFromObjectCaseSensitive(container,
                    container->child->string);
        }
        break;

    /* ----------------------------------------------------------------
     * 10: ReplaceItemInArray — valid, OOB, negative
     * -------------------------------------------------------------- */
    case 10:
        if (cJSON_IsArray(container) && size > 0)
        {
            replacement = cJSON_CreateNumber(op_double(op));
            if (replacement != NULL)
                if (!cJSON_ReplaceItemInArray(container, arr_idx, replacement))
                    cJSON_Delete(replacement);
        }
        /* OOB and negative index — should return false, not crash */
        if (cJSON_IsArray(container))
        {
            replacement = cJSON_CreateNull();
            if (replacement != NULL)
                if (!cJSON_ReplaceItemInArray(container, -1, replacement))
                    cJSON_Delete(replacement);

            replacement = cJSON_CreateNull();
            if (replacement != NULL)
                if (!cJSON_ReplaceItemInArray(container, size + 100, replacement))
                    cJSON_Delete(replacement);
        }
        break;

    /* ----------------------------------------------------------------
     * 11: ReplaceItemInObject (case-insensitive) — found and missing key
     * -------------------------------------------------------------- */
    case 11:
        if (cJSON_IsObject(container))
        {
            /* Missing key — must fail gracefully */
            replacement = cJSON_CreateBool(op->selector & 1);
            if (replacement != NULL)
                if (!cJSON_ReplaceItemInObject(container,
                                               "missing_key_xyzzy", replacement))
                    cJSON_Delete(replacement);

            /* Real key if present */
            if (container->child != NULL && container->child->string != NULL)
            {
                replacement = cJSON_CreateString(key[0] ? key : "v");
                if (replacement != NULL)
                    if (!cJSON_ReplaceItemInObject(container,
                                                   container->child->string,
                                                   replacement))
                        cJSON_Delete(replacement);
            }
        }
        break;

    /* ----------------------------------------------------------------
     * 12: ReplaceItemInObjectCaseSensitive — found and missing key
     * -------------------------------------------------------------- */
    case 12:
        if (cJSON_IsObject(container))
        {
            replacement = cJSON_CreateNumber(op_double(op));
            if (replacement != NULL)
                if (!cJSON_ReplaceItemInObjectCaseSensitive(container,
                                                             "no_such", replacement))
                    cJSON_Delete(replacement);

            if (container->child != NULL && container->child->string != NULL)
            {
                replacement = cJSON_CreateNull();
                if (replacement != NULL)
                    if (!cJSON_ReplaceItemInObjectCaseSensitive(container,
                                                                container->child->string,
                                                                replacement))
                        cJSON_Delete(replacement);
            }
        }
        break;

    /* ----------------------------------------------------------------
     * 13: ReplaceItemViaPointer — valid pair, then NULL child (failure)
     * -------------------------------------------------------------- */
    case 13:
        if (idx->n_via > 0)
        {
            int vi = op->index % (uint16_t)idx->n_via;
            replacement = cJSON_CreateNumber(op_double(op));
            if (replacement != NULL)
                if (!cJSON_ReplaceItemViaPointer(idx->via_parent[vi],
                                                 idx->via_child[vi],
                                                 replacement))
                    cJSON_Delete(replacement);
        }
        /* NULL child — must return false without crash */
        if (container != NULL)
        {
            replacement = cJSON_CreateNull();
            if (replacement != NULL)
                if (!cJSON_ReplaceItemViaPointer(container, NULL, replacement))
                    cJSON_Delete(replacement);
        }
        break;

    /* ----------------------------------------------------------------
     * 14: SetValuestring
     *   a) on an actual cJSON_String node (from index)
     *   b) on a non-String node (must return NULL, not crash)
     *   c) with the node's own valuestring (overlap test — safe to alias?)
     * -------------------------------------------------------------- */
    case 14:
    {
        op_str(op, val);
        /* On indexed string node */
        if (idx->n_strings > 0)
        {
            cJSON *sn = idx->strings[op->selector % (uint8_t)idx->n_strings];
            cJSON_SetValuestring(sn, val[0] ? val : "empty");
            /* Overlap: set to the current valuestring */
            if (sn->valuestring != NULL)
                cJSON_SetValuestring(sn, sn->valuestring);
        }
        /* On a non-String node */
        if (idx->n_numbers > 0)
        {
            cJSON *nn = idx->numbers[op->selector % (uint8_t)idx->n_numbers];
            cJSON_SetValuestring(nn, val);  /* should return NULL */
        }
        /* SetValuestring(node, NULL) — must not crash */
        if (idx->n_strings > 0)
        {
            cJSON *sn = idx->strings[0];
            cJSON_SetValuestring(sn, NULL);
        }
        break;
    }

    /* ----------------------------------------------------------------
     * 15: SetNumberHelper
     *   a) on an actual cJSON_Number node
     *   b) on a non-Number node (bluntly writes valueint/valuedouble)
     *   c) on NULL (must not crash)
     * -------------------------------------------------------------- */
    case 15:
    {
        double num = op_double(op);
        if (idx->n_numbers > 0)
        {
            cJSON *nn = idx->numbers[op->selector % (uint8_t)idx->n_numbers];
            cJSON_SetNumberHelper(nn, num);
        }
        /* Non-Number node */
        if (idx->n_strings > 0)
        {
            cJSON *sn = idx->strings[0];
            cJSON_SetNumberHelper(sn, num);  /* writes valueint/valuedouble blindly */
        }
        break;
    }

    /* ----------------------------------------------------------------
     * 16-19: Round-trip oracle
     *   Print root  →  parse  →  print again.
     *   The two printed strings must be identical (text consistency).
     *   We do NOT use cJSON_Compare(root, reparsed) because mutation ops
     *   like SetNumberHelper can write NaN/Inf into non-number nodes,
     *   which serialize as "null", making the tree no longer structurally
     *   round-trippable through cJSON_Compare.
     * -------------------------------------------------------------- */
    case 16:
    case 17:
    case 18:
    case 19:
    {
        char *printed1 = cJSON_PrintUnformatted(root);
        if (printed1 != NULL)
        {
            cJSON *reparsed = cJSON_Parse(printed1);
            /* Oracle 1: valid JSON output must be parseable */
            if (reparsed == NULL)
                __builtin_trap();

            char *printed2 = cJSON_PrintUnformatted(reparsed);
            /* Oracle 2: print(parse(print(X))) == print(X) */
            if (printed2 != NULL)
            {
                if (strcmp(printed1, printed2) != 0)
                    __builtin_trap();
                cJSON_free(printed2);
            }
            cJSON_Delete(reparsed);
            cJSON_free(printed1);
        }
        break;
    }

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Fuzzer entry point                                                  */
/* ------------------------------------------------------------------ */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    cJSON     *root   = NULL;
    cJSON     *stash  = NULL;  /* detached node waiting for reinsertion */
    TreeIndex  idx;
    int        n_ops;
    size_t     ops_bytes;
    size_t     json_off;
    int        i;

    /* Need at least 1 byte for n_ops */
    if (size < 1)
        return 0;

    n_ops     = (int)(data[0] % (MAX_OPS + 1));
    ops_bytes = (size_t)n_ops * OP_RECORD_SIZE;

    /* Ensure op records fit in the input */
    if (1 + ops_bytes > size)
        ops_bytes = 0, n_ops = 0;

    json_off = 1 + ops_bytes;

    /* Parse the JSON payload (may be empty) */
    root = cJSON_ParseWithLength(
        (const char *)data + json_off,
        size - json_off);

    if (root == NULL)
    {
        cJSON_GetErrorPtr();
        return 0;
    }

    /* Execute fixed-size op records */
    for (i = 0; i < n_ops; i++)
    {
        OpRecord op = parse_op(data + 1 + (size_t)i * OP_RECORD_SIZE);
        execute_op(root, &op, &stash, &idx);
    }

    /* Free any leftover stash */
    cJSON_Delete(stash);

    /* Final round-trip print */
    {
        char *out = cJSON_PrintUnformatted(root);
        cJSON_free(out);
    }

    cJSON_Delete(root);
    return 0;
}
