/* VENDORED from lucianpopovici/objectdb @ fece251 (ADR-008 pilot).
 * Do not edit here — fix upstream, re-run its test suite, then re-copy
 * object_graph.{c,h} together and update this pin. Local divergence is the
 * bug class the libdnswire extraction exists to prevent.
 */
/* object_graph.c — v2: OODB with dynamic fields, lists, transactions, WAL */
#define _POSIX_C_SOURCE 200809L
#include "object_graph.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pthread.h>

/* ============================================================
 * Constants and formats
 * ============================================================ */

#define INITIAL_OBJ_CAP    64
#define INITIAL_ROOT_CAP   16
#define INITIAL_FIELD_CAP   4
#define INITIAL_LIST_CAP    4
#define INITIAL_LOG_CAP    32

#define POGE_MAGIC   0x45474F50u   /* "POGE" */
#define POGE_VERSION 4u            /* v4: adds OBJ_BYTES value type */

#define POGW_MAGIC   0x57474F50u   /* "POGW" */
#define POGW_VERSION 1u

#define POGV_MAGIC   0x56474F50u   /* "POGV" */
#define POGV_VERSION 1u

enum {
    WOP_TXN_BEGIN   = 1,
    WOP_TXN_COMMIT  = 2,

    WOP_NEW_OBJECT  = 10,
    WOP_NEW_INT     = 11,
    WOP_NEW_STRING  = 12,
    WOP_NEW_LIST    = 13,
    WOP_NEW_VLIST   = 14,
    WOP_NEW_BYTES   = 15,

    WOP_SET_INT     = 20,
    WOP_SET_STR     = 21,
    WOP_SET_FIELD   = 22,
    WOP_SET_BYTES   = 23,

    WOP_LIST_APPEND = 30,
    WOP_LIST_SET    = 31,
    WOP_LIST_INSERT = 32,
    WOP_LIST_REMOVE = 33,

    WOP_BIND_ROOT   = 40,
    WOP_UNBIND_ROOT = 41,

    WOP_SET_CLASS   = 50,   /* class_name == "" means untag */
};

/* ============================================================
 * Transaction record (unified forward + undo)
 * ============================================================ */

typedef struct {
    uint8_t  op;
    Object  *target;
    uint32_t target_id;
    char     key[POG_MAX_KEY_LEN];   /* field key / root name */
    size_t   index;

    Object  *new_ref;
    int64_t  new_int;
    char    *new_str;                /* owned */
    uint8_t *new_bytes;               /* owned */
    size_t   new_bytes_len;

    Object  *old_ref;
    int64_t  old_int;
    char    *old_str;                /* owned */
    uint8_t *old_bytes;               /* owned */
    size_t   old_bytes_len;
    bool     had_prev;
    bool     is_create;
} TxnRec;

struct Txn {
    uint32_t  id;
    TxnRec   *log;
    size_t    count;
    size_t    cap;

    /* snapshots captured at begin, for bulk-rewind on abort */
    size_t    begin_obj_count;
    uint32_t  begin_next_id;
    size_t    begin_root_count;
};

static void txnrec_free_owned(TxnRec *r)
{
    free(r->new_str); r->new_str = NULL;
    free(r->old_str); r->old_str = NULL;
    free(r->new_bytes); r->new_bytes = NULL;
    free(r->old_bytes); r->old_bytes = NULL;
}

/* ============================================================
 * Overflow-checked growth helpers
 *
 * Every dynamic array in this file grows by capacity doubling. On 64-bit
 * these overflow checks are not reachable with realistic in-memory counts,
 * but they're cheap and make every growth site uniformly safe against a
 * future caller (or a 32-bit build) driving a count near SIZE_MAX.
 * ============================================================ */

static bool next_cap(size_t cap, size_t initial, size_t *out)
{
    if (cap == 0) { *out = initial; return true; }
    return !__builtin_mul_overflow(cap, (size_t)2, out);
}

static bool mul_bytes(size_t count, size_t elem_size, size_t *out)
{
    return !__builtin_mul_overflow(count, elem_size, out);
}

static bool log_push(Store *s, TxnRec rec)
{
    if (!s || !s->active_txn) { txnrec_free_owned(&rec); return true; }
    Txn *t = s->active_txn;
    if (t->count >= t->cap) {
        size_t nc, bytes;
        if (!next_cap(t->cap, INITIAL_LOG_CAP, &nc) ||
            !mul_bytes(nc, sizeof(*t->log), &bytes)) {
            txnrec_free_owned(&rec); return false;
        }
        TxnRec *a = realloc(t->log, bytes);
        if (!a) { txnrec_free_owned(&rec); return false; }
        t->log = a; t->cap = nc;
    }
    t->log[t->count++] = rec;
    return true;
}

/* ============================================================
 * Virtual list registry + transient items
 * ============================================================ */

#define POG_MAX_VLIST_TYPES 32
static const VListOps *g_vlist_types[POG_MAX_VLIST_TYPES];
static size_t          g_vlist_type_count = 0;
static bool            g_builtins_registered = false;

bool pog_register_vlist_type(const VListOps *ops)
{
    if (!ops || !ops->type_name || !ops->len || !ops->at) return false;
    /* replace existing registration with same name (idempotent) */
    for (size_t i = 0; i < g_vlist_type_count; i++) {
        if (strcmp(g_vlist_types[i]->type_name, ops->type_name) == 0) {
            g_vlist_types[i] = ops;
            return true;
        }
    }
    if (g_vlist_type_count >= POG_MAX_VLIST_TYPES) return false;
    g_vlist_types[g_vlist_type_count++] = ops;
    return true;
}

static const VListOps *find_vlist_ops(const char *name)
{
    if (!name) return NULL;
    for (size_t i = 0; i < g_vlist_type_count; i++)
        if (strcmp(g_vlist_types[i]->type_name, name) == 0)
            return g_vlist_types[i];
    return NULL;
}

/* Transient (off-store) item allocation for generators. */
static Object *make_transient(ObjectKind k)
{
    Object *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->id = 0; o->store = NULL; o->kind = k;
    return o;
}

static void free_transient(Object *o)
{
    if (!o) return;
    if (o->kind == OBJ_STRING)         free(o->str_value);
    else if (o->kind == OBJ_BYTES)     free(o->bytes.data);
    else if (o->kind == OBJ_COMPOSITE) free(o->composite.items);
    else if (o->kind == OBJ_LIST)      free(o->list.items);
    free(o);
}

static bool scratch_push(Object *view, Object *item)
{
    if (view->vlist.scratch_count >= view->vlist.scratch_cap) {
        size_t nc, bytes;
        if (!next_cap(view->vlist.scratch_cap, 8, &nc) ||
            !mul_bytes(nc, sizeof(*view->vlist.scratch), &bytes))
            return false;
        Object **a = realloc(view->vlist.scratch, bytes);
        if (!a) return false;
        view->vlist.scratch = a;
        view->vlist.scratch_cap = nc;
    }
    view->vlist.scratch[view->vlist.scratch_count++] = item;
    return true;
}

Object *pog_vlist_emit_int(Object *view, int64_t v)
{
    if (!view || view->kind != OBJ_VLIST) return NULL;
    Object *o = make_transient(OBJ_INT);
    if (!o) return NULL;
    o->int_value = v;
    if (!scratch_push(view, o)) { free(o); return NULL; }
    return o;
}

Object *pog_vlist_emit_string(Object *view, const char *v)
{
    if (!view || view->kind != OBJ_VLIST) return NULL;
    Object *o = make_transient(OBJ_STRING);
    if (!o) return NULL;
    o->str_value = strdup(v ? v : "");
    if (!o->str_value) { free(o); return NULL; }
    if (!scratch_push(view, o)) { free(o->str_value); free(o); return NULL; }
    return o;
}

/* ============================================================
 * Class index: per-class instance lists
 *
 * Classes are identified by name. Internally we keep parallel arrays:
 *   class_names[i]  — owned class name
 *   class_instances[i] — Object** array of members
 *   class_counts[i] / class_caps[i] — size / capacity of that array
 *
 * The index is fully derivable from object state (each composite has a
 * class_name) so we do NOT persist it — we rebuild after load/replay.
 * Mutations of the index ARE NOT separately WAL-logged — the WOP_SET_CLASS
 * op is the logged thing; the index just follows.
 * ============================================================ */

static bool class_ensure_cap(Store *s)
{
    if (s->class_count < s->class_capacity) return true;
    size_t nc, b_nn, b_ni, b_nco, b_nca;
    if (!next_cap(s->class_capacity, 8, &nc) ||
        !mul_bytes(nc, sizeof(*s->class_names),     &b_nn)  ||
        !mul_bytes(nc, sizeof(*s->class_instances),  &b_ni)  ||
        !mul_bytes(nc, sizeof(*s->class_counts),     &b_nco) ||
        !mul_bytes(nc, sizeof(*s->class_caps),       &b_nca))
        return false;
    char    **nn = realloc(s->class_names,     b_nn);
    Object ***ni = realloc(s->class_instances, b_ni);
    size_t   *nco = realloc(s->class_counts,   b_nco);
    size_t   *nca = realloc(s->class_caps,     b_nca);
    if (!nn || !ni || !nco || !nca) {
        /* realloc may succeed for some but not others; those that did are
         * still valid under their pointers; leak the partial grow for now
         * rather than trying to unwind. */
        free(nn); free(ni); free(nco); free(nca);
        return false;
    }
    s->class_names     = nn;
    s->class_instances = ni;
    s->class_counts    = nco;
    s->class_caps      = nca;
    for (size_t i = s->class_capacity; i < nc; i++) {
        s->class_names[i] = NULL;
        s->class_instances[i] = NULL;
        s->class_counts[i] = 0;
        s->class_caps[i] = 0;
    }
    s->class_capacity = nc;
    return true;
}

/* Return index of class in s->class_names, or SIZE_MAX if not present. */
static size_t class_find_idx(Store *s, const char *name)
{
    if (!s || !name) return SIZE_MAX;
    for (size_t i = 0; i < s->class_count; i++)
        if (s->class_names[i] && strcmp(s->class_names[i], name) == 0)
            return i;
    return SIZE_MAX;
}

/* Return index of class in s, creating the class slot if necessary. */
static size_t class_get_or_create(Store *s, const char *name)
{
    size_t idx = class_find_idx(s, name);
    if (idx != SIZE_MAX) return idx;
    if (!class_ensure_cap(s)) return SIZE_MAX;
    char *dup = strdup(name);
    if (!dup) return SIZE_MAX;
    idx = s->class_count++;
    s->class_names[idx] = dup;
    s->class_instances[idx] = NULL;
    s->class_counts[idx] = 0;
    s->class_caps[idx] = 0;
    return idx;
}

static bool class_list_append(Store *s, size_t idx, Object *o)
{
    if (s->class_counts[idx] >= s->class_caps[idx]) {
        size_t nc, bytes;
        if (!next_cap(s->class_caps[idx], 8, &nc) ||
            !mul_bytes(nc, sizeof(*s->class_instances[idx]), &bytes))
            return false;
        Object **a = realloc(s->class_instances[idx], bytes);
        if (!a) return false;
        s->class_instances[idx] = a;
        s->class_caps[idx] = nc;
    }
    s->class_instances[idx][s->class_counts[idx]++] = o;
    return true;
}

static void class_list_remove(Store *s, size_t idx, Object *o)
{
    size_t n = s->class_counts[idx];
    for (size_t i = 0; i < n; i++) {
        if (s->class_instances[idx][i] == o) {
            /* swap-and-pop; order within a class is not meaningful */
            s->class_instances[idx][i] = s->class_instances[idx][n - 1];
            s->class_counts[idx]--;
            return;
        }
    }
}

/* Rebuild the entire class index from object state. Called after
 * load / WAL replay. */
static void class_index_rebuild(Store *s)
{
    /* clear existing */
    for (size_t i = 0; i < s->class_count; i++) {
        free(s->class_names[i]);
        free(s->class_instances[i]);
    }
    s->class_count = 0;
    /* re-scan */
    for (size_t i = 0; i < s->count; i++) {
        Object *o = s->objects[i];
        if (!o->class_name) continue;
        size_t idx = class_get_or_create(s, o->class_name);
        if (idx == SIZE_MAX) continue;
        class_list_append(s, idx, o);
    }
}

/* Returns false (o not stored) on allocation failure — caller owns o and
 * must free it. An embeddable library must let the host handle OOM rather
 * than abort() the whole process out from under it. */
static bool store_push_obj(Store *s, Object *o)
{
    if (s->count >= s->capacity) {
        size_t nc, bytes;
        if (!next_cap(s->capacity, INITIAL_OBJ_CAP, &nc) ||
            !mul_bytes(nc, sizeof(*s->objects), &bytes))
            return false;
        Object **a = realloc(s->objects, bytes);
        if (!a) return false;
        s->objects = a; s->capacity = nc;
    }
    s->objects[s->count++] = o;
    return true;
}

static Object *alloc_with_id(Store *s, ObjectKind kind, uint32_t id)
{
    Object *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->id = id; o->kind = kind; o->store = s;
    if (!store_push_obj(s, o)) { free(o); return NULL; }
    if (id >= s->next_id) s->next_id = id + 1;
    return o;
}

static Object *alloc_object(Store *s, ObjectKind kind)
{
    if (!s) return NULL;
    return alloc_with_id(s, kind, s->next_id);
}

static void free_object(Object *o)
{
    if (!o) return;
    free(o->class_name);
    if (o->kind == OBJ_STRING)         free(o->str_value);
    else if (o->kind == OBJ_BYTES)     free(o->bytes.data);
    else if (o->kind == OBJ_COMPOSITE) free(o->composite.items);
    else if (o->kind == OBJ_LIST)      free(o->list.items);
    else if (o->kind == OBJ_VLIST) {
        free(o->vlist.type_name);
        for (size_t i = 0; i < o->vlist.scratch_count; i++)
            free_transient(o->vlist.scratch[i]);
        free(o->vlist.scratch);
    }
    free(o);
}

static Field *find_field(Object *o, const char *key)
{
    if (!o || o->kind != OBJ_COMPOSITE || !key) return NULL;
    for (size_t i = 0; i < o->composite.count; i++)
        if (strncmp(o->composite.items[i].key, key, POG_MAX_KEY_LEN) == 0)
            return &o->composite.items[i];
    return NULL;
}

/* grow a composite's field array */
static bool composite_grow(Object *o)
{
    if (o->composite.count < o->composite.cap) return true;
    size_t nc, bytes;
    if (!next_cap(o->composite.cap, INITIAL_FIELD_CAP, &nc) ||
        !mul_bytes(nc, sizeof(*o->composite.items), &bytes))
        return false;
    Field *a = realloc(o->composite.items, bytes);
    if (!a) return false;
    o->composite.items = a; o->composite.cap = nc;
    return true;
}

static bool list_grow(Object *l)
{
    if (l->list.count < l->list.cap) return true;
    size_t nc, bytes;
    if (!next_cap(l->list.cap, INITIAL_LIST_CAP, &nc) ||
        !mul_bytes(nc, sizeof(*l->list.items), &bytes))
        return false;
    Object **a = realloc(l->list.items, bytes);
    if (!a) return false;
    l->list.items = a; l->list.cap = nc;
    return true;
}

static Root *find_root(Store *s, const char *name)
{
    if (!s || !name) return NULL;
    for (size_t i = 0; i < s->root_count; i++) {
        if (s->roots[i].used &&
            strncmp(s->roots[i].name, name, POG_MAX_ROOT_NAME) == 0)
            return &s->roots[i];
    }
    return NULL;
}

/* ============================================================
 * Secondary hash index: declared (class, field) -> value -> [Object*]
 *
 * Derived state, modeled directly on the class index above: never
 * WAL-logged, rebuilt wholesale after abort/GC (index_rebuild_all, called
 * right after every class_index_rebuild call site) and maintained
 * incrementally inline by set_field_unlocked/set_class_unlocked_impl.
 * Index *declarations* (which (class, field) pairs exist) are NOT
 * persisted — the application re-declares via index_create() after
 * store_open()/load(); that call does its own initial full build.
 *
 * Each PogIndex is a chaining hash table keyed by field value: buckets[]
 * is sized bucket_count (always a power of two), each bucket holds a
 * growable array of PogIndexEntry (one per distinct value hashing there),
 * each entry holds a growable array of the objects currently at that
 * value. No linked lists anywhere — everything grows via the existing
 * next_cap/mul_bytes overflow-checked doubling helpers.
 * ============================================================ */

static uint64_t pog_fnv1a(const char *s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= (uint64_t)*p;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static bool index_ensure_cap(Store *s)
{
    if (s->index_count < s->index_capacity) return true;
    size_t nc, bytes;
    if (!next_cap(s->index_capacity, 4, &nc) ||
        !mul_bytes(nc, sizeof(*s->indexes), &bytes))
        return false;
    PogIndex *a = realloc(s->indexes, bytes);
    if (!a) return false;
    s->indexes = a;
    for (size_t i = s->index_capacity; i < nc; i++)
        s->indexes[i] = (PogIndex){0};
    s->index_capacity = nc;
    return true;
}

static size_t index_find_idx_unlocked(Store *s, const char *cls, const char *field)
{
    if (!s || !cls || !field) return SIZE_MAX;
    for (size_t i = 0; i < s->index_count; i++)
        if (strcmp(s->indexes[i].cls, cls) == 0 &&
            strcmp(s->indexes[i].field, field) == 0)
            return i;
    return SIZE_MAX;
}

static bool index_bucket_ensure_cap(PogIndexBucket *b)
{
    if (b->count < b->cap) return true;
    size_t nc, bytes;
    if (!next_cap(b->cap, 4, &nc) || !mul_bytes(nc, sizeof(*b->entries), &bytes))
        return false;
    PogIndexEntry *a = realloc(b->entries, bytes);
    if (!a) return false;
    b->entries = a; b->cap = nc;
    return true;
}

static bool index_entry_append_item(PogIndexEntry *e, Object *o)
{
    if (e->count >= e->cap) {
        size_t nc, bytes;
        if (!next_cap(e->cap, 8, &nc) || !mul_bytes(nc, sizeof(*e->items), &bytes))
            return false;
        Object **a = realloc(e->items, bytes);
        if (!a) return false;
        e->items = a; e->cap = nc;
    }
    e->items[e->count++] = o;
    return true;
}

static void index_entry_remove_item(PogIndexEntry *e, Object *o)
{
    for (size_t i = 0; i < e->count; i++) {
        if (e->items[i] == o) {
            e->items[i] = e->items[e->count - 1];   /* swap-and-pop */
            e->count--;
            return;
        }
    }
}

/* bucket_count is always a power of two (0 initially, then only ever set
 * by index_rehash below, starting at 8) — nothing else may assign it,
 * since index_find_entry_unlocked relies on that for `& (bucket_count-1)`
 * to be a valid substitute for `% bucket_count`. */
static PogIndexEntry *index_find_entry_unlocked(PogIndex *idx, const char *value)
{
    if (idx->bucket_count == 0) return NULL;
    uint64_t h = pog_fnv1a(value);
    size_t b = (size_t)(h & (uint64_t)(idx->bucket_count - 1));
    PogIndexBucket *bucket = &idx->buckets[b];
    for (size_t i = 0; i < bucket->count; i++)
        if (strcmp(bucket->entries[i].value, value) == 0)
            return &bucket->entries[i];
    return NULL;
}

/* Atomic rehash: idx is only mutated in the final phase, after every
 * allocation needed for the new layout has already succeeded — so an OOM
 * at any earlier phase leaves idx completely untouched. */
static bool index_rehash(PogIndex *idx, size_t new_bucket_count)
{
    if (idx->total_entries == 0) {
        size_t bytes;
        if (!mul_bytes(new_bucket_count, sizeof(PogIndexBucket), &bytes)) return false;
        PogIndexBucket *nb = calloc(1, bytes);
        if (!nb) return false;
        free(idx->buckets);
        idx->buckets = nb;
        idx->bucket_count = new_bucket_count;
        return true;
    }

    /* Phase 1: flatten every existing entry into a temp array. Old
     * buckets are only read here, not freed. */
    size_t total = idx->total_entries;
    size_t tmp_bytes;
    if (!mul_bytes(total, sizeof(PogIndexEntry), &tmp_bytes)) return false;
    PogIndexEntry *tmp = malloc(tmp_bytes);
    if (!tmp) return false;
    size_t w = 0;
    for (size_t b = 0; b < idx->bucket_count; b++)
        for (size_t e = 0; e < idx->buckets[b].count; e++)
            tmp[w++] = idx->buckets[b].entries[e];

    /* Phase 2: compute each entry's target bucket under the new size and
     * tally per-bucket counts (counting only, no final allocation yet). */
    size_t *target = malloc(total * sizeof(size_t));
    size_t *bucket_counts = calloc(new_bucket_count, sizeof(size_t));
    if (!target || !bucket_counts) {
        free(tmp); free(target); free(bucket_counts); return false;
    }
    for (size_t i = 0; i < total; i++) {
        uint64_t h = pog_fnv1a(tmp[i].value);
        size_t b = (size_t)(h & (uint64_t)(new_bucket_count - 1));
        target[i] = b;
        bucket_counts[b]++;
    }

    /* Phase 3: reserve — allocate each new bucket's entries array to its
     * exact final size. Allocation only, no writes; a failure here is
     * fully recoverable since idx/old buckets are still intact. */
    PogIndexBucket *nb = calloc(new_bucket_count, sizeof(PogIndexBucket));
    if (!nb) { free(tmp); free(target); free(bucket_counts); return false; }
    bool ok = true;
    for (size_t b = 0; b < new_bucket_count && ok; b++) {
        if (bucket_counts[b] == 0) continue;
        size_t bytes;
        if (!mul_bytes(bucket_counts[b], sizeof(PogIndexEntry), &bytes)) { ok = false; break; }
        nb[b].entries = malloc(bytes);
        if (!nb[b].entries) { ok = false; break; }
        nb[b].cap = bucket_counts[b];
    }
    if (!ok) {
        for (size_t b = 0; b < new_bucket_count; b++) free(nb[b].entries);
        free(nb); free(tmp); free(target); free(bucket_counts);
        return false;   /* idx completely untouched */
    }

    /* Phase 4: commit — copy each entry into its reserved slot. Cannot
     * fail: pure copy, capacity already reserved in phase 3. */
    for (size_t i = 0; i < total; i++) {
        size_t b = target[i];
        nb[b].entries[nb[b].count++] = tmp[i];
    }

    /* Phase 5: swap in the new table. Free only the OLD shell arrays —
     * entry internals (value/items) were relocated by value into nb, not
     * duplicated, so this cannot double-free. */
    for (size_t b = 0; b < idx->bucket_count; b++) free(idx->buckets[b].entries);
    free(idx->buckets);
    idx->buckets = nb;
    idx->bucket_count = new_bucket_count;

    free(tmp); free(target); free(bucket_counts);
    return true;
}

static bool index_maybe_grow(PogIndex *idx)
{
    if (idx->bucket_count != 0 && idx->total_entries < idx->bucket_count) return true;
    size_t nc;
    if (!next_cap(idx->bucket_count, 8, &nc)) return false;
    return index_rehash(idx, nc);
}

static bool index_insert_unlocked(PogIndex *idx, const char *value, Object *o)
{
    PogIndexEntry *e = index_find_entry_unlocked(idx, value);
    if (e) return index_entry_append_item(e, o);

    if (!index_maybe_grow(idx)) return false;

    uint64_t h = pog_fnv1a(value);
    size_t b = (size_t)(h & (uint64_t)(idx->bucket_count - 1));
    PogIndexBucket *bucket = &idx->buckets[b];

    /* Build the new entry fully in a local before touching the live
     * bucket — a failure here leaves the bucket completely unchanged. */
    PogIndexEntry ne = {0};
    ne.value = strdup(value);
    if (!ne.value) return false;
    if (!index_entry_append_item(&ne, o)) { free(ne.value); return false; }
    if (!index_bucket_ensure_cap(bucket)) { free(ne.value); free(ne.items); return false; }

    bucket->entries[bucket->count++] = ne;
    idx->total_entries++;
    return true;
}

static void index_remove_unlocked(PogIndex *idx, const char *value, Object *o)
{
    PogIndexEntry *e = index_find_entry_unlocked(idx, value);
    if (!e) return;
    index_entry_remove_item(e, o);
}

static void index_free_contents(PogIndex *idx)
{
    for (size_t b = 0; b < idx->bucket_count; b++) {
        for (size_t e = 0; e < idx->buckets[b].count; e++) {
            free(idx->buckets[b].entries[e].value);
            free(idx->buckets[b].entries[e].items);
        }
        free(idx->buckets[b].entries);
    }
    free(idx->buckets);
    idx->buckets = NULL; idx->bucket_count = 0; idx->total_entries = 0;
}

static void index_free_all(PogIndex *idx)
{
    index_free_contents(idx);
    free(idx->cls); free(idx->field);
    idx->cls = idx->field = NULL;
}

/* Rebuild one index's CONTENTS from current live state (keeps the
 * declaration — cls/field — intact). Scans through the already-rebuilt
 * class index rather than s->objects: O(class size), not O(store size).
 * Returns false on allocation failure mid-build; index_create checks this
 * (fallible, all-or-nothing), index_rebuild_all deliberately ignores it
 * (best-effort, matching class_index_rebuild's own precedent of ignoring
 * class_list_append's return value) — do not "fix" one call site to
 * match the other. */
static bool index_rebuild_one_unlocked(Store *s, PogIndex *idx)
{
    index_free_contents(idx);
    size_t ci = class_find_idx(s, idx->cls);
    if (ci == SIZE_MAX) return true;   /* class has no instances (yet) */
    size_t n = s->class_counts[ci];
    for (size_t i = 0; i < n; i++) {
        Object *o = s->class_instances[ci][i];
        Field *f = find_field(o, idx->field);
        if (f && f->value && f->value->kind == OBJ_STRING) {
            if (!index_insert_unlocked(idx, f->value->str_value, o))
                return false;
        }
    }
    return true;
}

/* Rebuild ALL declared indexes' contents from current live state. Call
 * immediately after every class_index_rebuild(s) call site — depends on
 * the class index already being fresh. */
static void index_rebuild_all(Store *s)
{
    for (size_t i = 0; i < s->index_count; i++)
        (void)index_rebuild_one_unlocked(s, &s->indexes[i]);
}

/* Remove o from every index declared on cls_name, among s->indexes[0..upto),
 * wherever o currently has a string value at that index's field. Used both
 * for a bounded partial-unwind (upto == the index where an insert loop
 * failed) and a full unwind/removal (upto == s->index_count) by
 * set_class_unlocked_impl. */
static void index_unwind_class_inserts(Store *s, size_t upto, const char *cls_name, Object *o)
{
    for (size_t i = 0; i < upto; i++) {
        PogIndex *idx = &s->indexes[i];
        if (strcmp(idx->cls, cls_name) != 0) continue;
        Field *f = find_field(o, idx->field);
        if (!f || !f->value || f->value->kind != OBJ_STRING) continue;
        index_remove_unlocked(idx, f->value->str_value, o);
    }
}

static bool index_create_unlocked(Store *s, const char *cls, const char *field)
{
    if (!s || !cls || !*cls || !field || !*field) return false;
    if (strlen(field) >= POG_MAX_KEY_LEN) return false;
    if (strlen(cls) >= POG_MAX_CLASS_NAME) return false;

    if (index_find_idx_unlocked(s, cls, field) != SIZE_MAX) return true;  /* idempotent */

    if (!index_ensure_cap(s)) return false;
    char *cls_dup = strdup(cls);
    char *field_dup = cls_dup ? strdup(field) : NULL;
    if (!cls_dup || !field_dup) { free(cls_dup); free(field_dup); return false; }

    size_t i = s->index_count++;
    s->indexes[i] = (PogIndex){ .cls = cls_dup, .field = field_dup };

    if (!index_rebuild_one_unlocked(s, &s->indexes[i])) {
        index_free_all(&s->indexes[i]);
        s->index_count--;
        return false;
    }
    return true;
}

static bool index_drop_unlocked(Store *s, const char *cls, const char *field)
{
    size_t i = index_find_idx_unlocked(s, cls, field);
    if (i == SIZE_MAX) return false;
    index_free_all(&s->indexes[i]);
    s->indexes[i] = s->indexes[--s->index_count];   /* swap-and-pop */
    return true;
}

/* ============================================================
 * Ordered index: canonical DNS-name order (Tier 3a)
 *
 * Declared (class, field) -> a single flat array of PogIndexEntry (the
 * same value+Object* shape the hash index's buckets use), kept sorted
 * ascending by pog_dns_name_cmp. Gives index_succ/index_pred (next/
 * previous existent name) and index_range (canonical-order range scan) —
 * the traversal primitives DNSSEC NSEC chains and zone signing need,
 * which the O(1) point-lookup hash index above cannot provide.
 *
 * Binary search gives O(log n) lookup; insert/remove are O(n) (a memmove
 * to keep the array sorted), trading a balanced tree's O(log n) both ways
 * for a much smaller, more auditable implementation — consistent with
 * this file's existing precedent of dynamic arrays over pointer-linked
 * structures everywhere (class index, hash index buckets). Authoritative
 * zones are edited occasionally and served constantly (see
 * CLAUDE-index.md's scope boundary), so O(n) insert is an acceptable
 * trade here.
 *
 * Same derived-state rules as the hash index: never WAL-logged, rebuilt
 * wholesale after abort/GC/load (ord_index_rebuild_all, called at every
 * index_rebuild_all call site), maintained incrementally inline by
 * set_field_unlocked/set_class_unlocked_impl, declarations not persisted.
 * ============================================================ */

#define POG_DNS_MAX_LABELS 128

/* Split `name` into label spans (pointer+len into the original string, no
 * allocation), left to right. Returns the label count; 0 for the root/
 * empty name. Silently stops after POG_DNS_MAX_LABELS labels — real DNS
 * names cannot exceed 127, so this never triggers on legitimate input. */
static size_t pog_dns_split_labels(const char *name, const char **starts, size_t *lens)
{
    size_t n = 0;
    if (!name || !*name) return 0;
    const char *p = name;
    while (*p && n < POG_DNS_MAX_LABELS) {
        const char *start = p;
        while (*p && *p != '.') p++;
        starts[n] = start; lens[n] = (size_t)(p - start);
        n++;
        if (*p == '.') p++;
        else break;
    }
    return n;
}

/* Canonical DNS name comparator (RFC 4034 section 6.1), minus its
 * case-folding step — this engine keeps case handling in the DNS layer
 * per CLAUDE-index.md tier 2b; the ordered index is byte-exact like the
 * hash index. Compares label sequences most-significant (rightmost) label
 * first; a name that is a proper suffix of another (fewer labels, all
 * matching from the right) sorts first. The root ("") sorts before
 * everything, since it has zero labels. */
static int pog_dns_name_cmp(const char *a, const char *b)
{
    const char *as[POG_DNS_MAX_LABELS], *bs[POG_DNS_MAX_LABELS];
    size_t alen[POG_DNS_MAX_LABELS], blen[POG_DNS_MAX_LABELS];
    size_t an = pog_dns_split_labels(a, as, alen);
    size_t bn = pog_dns_split_labels(b, bs, blen);

    size_t i = an, j = bn;
    while (i > 0 && j > 0) {
        i--; j--;
        size_t ml = alen[i] < blen[j] ? alen[i] : blen[j];
        int c = memcmp(as[i], bs[j], ml);
        if (c != 0) return c;
        if (alen[i] != blen[j]) return alen[i] < blen[j] ? -1 : 1;
    }
    if (an != bn) return an < bn ? -1 : 1;
    return 0;
}

static bool ord_index_ensure_cap(Store *s)
{
    if (s->ord_index_count < s->ord_index_capacity) return true;
    size_t nc, bytes;
    if (!next_cap(s->ord_index_capacity, 4, &nc) ||
        !mul_bytes(nc, sizeof(*s->ord_indexes), &bytes))
        return false;
    PogOrdIndex *a = realloc(s->ord_indexes, bytes);
    if (!a) return false;
    s->ord_indexes = a;
    for (size_t i = s->ord_index_capacity; i < nc; i++)
        s->ord_indexes[i] = (PogOrdIndex){0};
    s->ord_index_capacity = nc;
    return true;
}

static size_t ord_index_find_idx_unlocked(Store *s, const char *cls, const char *field)
{
    if (!s || !cls || !field) return SIZE_MAX;
    for (size_t i = 0; i < s->ord_index_count; i++)
        if (strcmp(s->ord_indexes[i].cls, cls) == 0 &&
            strcmp(s->ord_indexes[i].field, field) == 0)
            return i;
    return SIZE_MAX;
}

static bool ord_entries_ensure_cap(PogOrdIndex *idx)
{
    if (idx->count < idx->cap) return true;
    size_t nc, bytes;
    if (!next_cap(idx->cap, 8, &nc) || !mul_bytes(nc, sizeof(*idx->entries), &bytes))
        return false;
    PogIndexEntry *a = realloc(idx->entries, bytes);
    if (!a) return false;
    idx->entries = a; idx->cap = nc;
    return true;
}

/* Binary search idx->entries (sorted by pog_dns_name_cmp) for `value`. On
 * exact match, *pos is its index and this returns true. On miss, *pos is
 * the insertion point (index of the first entry > value, == idx->count if
 * value is greater than everything) and this returns false. */
static bool ord_index_bsearch(PogOrdIndex *idx, const char *value, size_t *pos)
{
    size_t lo = 0, hi = idx->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = pog_dns_name_cmp(idx->entries[mid].value, value);
        if (c == 0) { *pos = mid; return true; }
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    *pos = lo;
    return false;
}

static bool ord_index_insert_unlocked(PogOrdIndex *idx, const char *value, Object *o)
{
    size_t pos;
    if (ord_index_bsearch(idx, value, &pos))
        return index_entry_append_item(&idx->entries[pos], o);

    if (!ord_entries_ensure_cap(idx)) return false;

    /* Build the new entry fully in a local before touching the live array
     * — a failure here leaves idx completely unchanged. */
    PogIndexEntry ne = {0};
    ne.value = strdup(value);
    if (!ne.value) return false;
    if (!index_entry_append_item(&ne, o)) { free(ne.value); return false; }

    memmove(&idx->entries[pos + 1], &idx->entries[pos],
            (idx->count - pos) * sizeof(*idx->entries));
    idx->entries[pos] = ne;
    idx->count++;
    return true;
}

static void ord_index_remove_unlocked(PogOrdIndex *idx, const char *value, Object *o)
{
    size_t pos;
    if (!ord_index_bsearch(idx, value, &pos)) return;
    PogIndexEntry *e = &idx->entries[pos];
    index_entry_remove_item(e, o);
    if (e->count == 0) {
        free(e->value); free(e->items);
        memmove(&idx->entries[pos], &idx->entries[pos + 1],
                (idx->count - pos - 1) * sizeof(*idx->entries));
        idx->count--;
    }
}

static void ord_index_free_contents(PogOrdIndex *idx)
{
    for (size_t i = 0; i < idx->count; i++) {
        free(idx->entries[i].value);
        free(idx->entries[i].items);
    }
    free(idx->entries);
    idx->entries = NULL; idx->count = 0; idx->cap = 0;
}

static void ord_index_free_all(PogOrdIndex *idx)
{
    ord_index_free_contents(idx);
    free(idx->cls); free(idx->field);
    idx->cls = idx->field = NULL;
}

/* Rebuild one ordered index's CONTENTS from current live state (keeps the
 * declaration intact). Mirrors index_rebuild_one_unlocked exactly, just
 * inserting into the sorted array instead of a hash table. */
static bool ord_index_rebuild_one_unlocked(Store *s, PogOrdIndex *idx)
{
    ord_index_free_contents(idx);
    size_t ci = class_find_idx(s, idx->cls);
    if (ci == SIZE_MAX) return true;   /* class has no instances (yet) */
    size_t n = s->class_counts[ci];
    for (size_t i = 0; i < n; i++) {
        Object *o = s->class_instances[ci][i];
        Field *f = find_field(o, idx->field);
        if (f && f->value && f->value->kind == OBJ_STRING) {
            if (!ord_index_insert_unlocked(idx, f->value->str_value, o))
                return false;
        }
    }
    return true;
}

/* Rebuild ALL declared ordered indexes' contents from current live state.
 * Call alongside every index_rebuild_all(s) call site. */
static void ord_index_rebuild_all(Store *s)
{
    for (size_t i = 0; i < s->ord_index_count; i++)
        (void)ord_index_rebuild_one_unlocked(s, &s->ord_indexes[i]);
}

/* Remove o from every ordered index declared on cls_name, among
 * s->ord_indexes[0..upto). Mirrors index_unwind_class_inserts exactly. */
static void ord_index_unwind_class_inserts(Store *s, size_t upto, const char *cls_name, Object *o)
{
    for (size_t i = 0; i < upto; i++) {
        PogOrdIndex *idx = &s->ord_indexes[i];
        if (strcmp(idx->cls, cls_name) != 0) continue;
        Field *f = find_field(o, idx->field);
        if (!f || !f->value || f->value->kind != OBJ_STRING) continue;
        ord_index_remove_unlocked(idx, f->value->str_value, o);
    }
}

static bool ord_index_create_unlocked(Store *s, const char *cls, const char *field)
{
    if (!s || !cls || !*cls || !field || !*field) return false;
    if (strlen(field) >= POG_MAX_KEY_LEN) return false;
    if (strlen(cls) >= POG_MAX_CLASS_NAME) return false;

    if (ord_index_find_idx_unlocked(s, cls, field) != SIZE_MAX) return true;  /* idempotent */

    if (!ord_index_ensure_cap(s)) return false;
    char *cls_dup = strdup(cls);
    char *field_dup = cls_dup ? strdup(field) : NULL;
    if (!cls_dup || !field_dup) { free(cls_dup); free(field_dup); return false; }

    size_t i = s->ord_index_count++;
    s->ord_indexes[i] = (PogOrdIndex){ .cls = cls_dup, .field = field_dup };

    if (!ord_index_rebuild_one_unlocked(s, &s->ord_indexes[i])) {
        ord_index_free_all(&s->ord_indexes[i]);
        s->ord_index_count--;
        return false;
    }
    return true;
}

static bool ord_index_drop_unlocked(Store *s, const char *cls, const char *field)
{
    size_t i = ord_index_find_idx_unlocked(s, cls, field);
    if (i == SIZE_MAX) return false;
    ord_index_free_all(&s->ord_indexes[i]);
    s->ord_indexes[i] = s->ord_indexes[--s->ord_index_count];   /* swap-and-pop */
    return true;
}

/* ============================================================
 * Locking helpers
 *
 * Convention:
 *   - Public mutator functions (new_*, set_*, list_*, bind, unbind,
 *     set_class, txn_*, store_checkpoint) acquire wrlock on entry and
 *     release on exit.
 *   - Public readers (get, get_field, list_get, list_len, class_of,
 *     query_class, find_by_field) acquire rdlock.
 *   - Internal helpers do not touch the lock. Anything named *_unlocked
 *     assumes the caller holds the appropriate lock.
 *   - Transactions hold wrlock from begin until commit/abort.
 *     Autocommit is a special case: the calling public mutator already
 *     holds wrlock, so its implicit begin/commit simply skip lock ops.
 * ============================================================ */

static void s_wrlock(Store *s) {
    if (s) pthread_rwlock_wrlock(&s->lock);
}
static void s_rdlock(Store *s) {
    if (s) pthread_rwlock_rdlock(&s->lock);
}
static void s_unlock(Store *s) {
    if (s) pthread_rwlock_unlock(&s->lock);
}

/* Forward declarations for the unlocked core implementations. */
static bool txn_begin_unlocked_impl (Store *s);
static bool txn_commit_unlocked_impl(Store *s);
static bool txn_abort_unlocked_impl (Store *s);

/* Clean names used internally — they just call the impls. Introduced so
 * auto_begin/auto_end and internal mutators don't depend on the _impl
 * suffix, which exists only to dodge a name collision with the public
 * lock-taking wrappers defined lower in the file. */
static bool txn_begin_unlocked (Store *s) { return txn_begin_unlocked_impl(s); }
static bool txn_commit_unlocked(Store *s) { return txn_commit_unlocked_impl(s); }
static bool txn_abort_unlocked (Store *s) { return txn_abort_unlocked_impl(s); }

/* ============================================================
 * Autocommit wrappers — persistent stores auto-wrap bare
 * mutations in a single-op transaction.
 *
 * These run inside an already-locked public mutator, so they must
 * call the _unlocked txn variants.
 * ============================================================ */

static bool auto_begin(Store *s, bool *started)
{
    *started = false;
    if (!s || !s->path) return true;       /* ephemeral: nothing to do */
    if (s->active_txn) return true;        /* already in explicit txn  */
    if (!txn_begin_unlocked(s)) return false;
    *started = true;
    return true;
}

static bool auto_end(Store *s, bool started, bool ok)
{
    if (!started) return ok;
    if (ok)       return txn_commit_unlocked(s);
    txn_abort_unlocked(s);
    return false;
}

/* ============================================================
 * Store lifecycle (ephemeral)
 * ============================================================ */

Store *store_create(void)
{
    pog_register_builtins();
    Store *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->objects = calloc(INITIAL_OBJ_CAP, sizeof(*s->objects));
    if (!s->objects) { free(s); return NULL; }
    s->capacity = INITIAL_OBJ_CAP;
    s->next_id = 1;
    s->next_txn_id = 1;
    s->lock_fd = -1;

    s->roots = calloc(INITIAL_ROOT_CAP, sizeof(*s->roots));
    if (!s->roots) { free(s->objects); free(s); return NULL; }
    s->root_capacity = INITIAL_ROOT_CAP;

    if (pthread_rwlock_init(&s->lock, NULL) != 0) {
        free(s->roots); free(s->objects); free(s);
        return NULL;
    }
    return s;
}

void store_destroy(Store *s)
{
    if (!s) return;
    if (s->active_txn) {
        for (size_t i = 0; i < s->active_txn->count; i++)
            txnrec_free_owned(&s->active_txn->log[i]);
        free(s->active_txn->log);
        free(s->active_txn);
    }
    if (s->wal_fp) fclose(s->wal_fp);
    if (s->vlog_fp) fclose(s->vlog_fp);
    if (s->lock_fd >= 0) {
        /* closing the fd releases the flock automatically */
        close(s->lock_fd);
    }
    free(s->path);
    for (size_t i = 0; i < s->count; i++) free_object(s->objects[i]);
    free(s->objects);
    free(s->roots);

    /* class index */
    for (size_t i = 0; i < s->class_count; i++) {
        free(s->class_names[i]);
        free(s->class_instances[i]);
    }
    free(s->class_names);
    free(s->class_instances);
    free(s->class_counts);
    free(s->class_caps);

    /* secondary hash indexes */
    for (size_t i = 0; i < s->index_count; i++)
        index_free_all(&s->indexes[i]);
    free(s->indexes);

    /* ordered indexes (Tier 3a) */
    for (size_t i = 0; i < s->ord_index_count; i++)
        ord_index_free_all(&s->ord_indexes[i]);
    free(s->ord_indexes);

    pthread_rwlock_destroy(&s->lock);
    free(s);
}

void store_close(Store *s) { store_destroy(s); }

/* ============================================================
 * Object creation
 * ============================================================ */

static Object *new_object_unlocked(Store *s)
{
    if (!s) return NULL;
    bool started;
    if (!auto_begin(s, &started)) return NULL;
    Object *o = alloc_object(s, OBJ_COMPOSITE);
    if (!o) { auto_end(s, started, false); return NULL; }

    TxnRec r = {0};
    r.op = WOP_NEW_OBJECT; r.target = o; r.target_id = o->id; r.is_create = true;
    log_push(s, r);

    if (!auto_end(s, started, true)) return NULL;
    return o;
}

static Object *new_int_unlocked(Store *s, int64_t v)
{
    if (!s) return NULL;
    bool started;
    if (!auto_begin(s, &started)) return NULL;
    Object *o = alloc_object(s, OBJ_INT);
    if (!o) { auto_end(s, started, false); return NULL; }
    o->int_value = v;

    TxnRec r = {0};
    r.op = WOP_NEW_INT; r.target = o; r.target_id = o->id;
    r.new_int = v; r.is_create = true;
    log_push(s, r);

    if (!auto_end(s, started, true)) return NULL;
    return o;
}

static Object *new_string_unlocked(Store *s, const char *v)
{
    if (!s) return NULL;
    bool started;
    if (!auto_begin(s, &started)) return NULL;
    Object *o = alloc_object(s, OBJ_STRING);
    if (!o) { auto_end(s, started, false); return NULL; }
    o->str_value = strdup(v ? v : "");
    if (!o->str_value) { auto_end(s, started, false); return NULL; }

    TxnRec r = {0};
    r.op = WOP_NEW_STRING; r.target = o; r.target_id = o->id;
    r.new_str = strdup(v ? v : "");
    if (!r.new_str) { auto_end(s, started, false); return NULL; }
    r.is_create = true;
    log_push(s, r);

    if (!auto_end(s, started, true)) return NULL;
    return o;
}

/* malloc+memcpy duplicate of a byte buffer, analogous to strdup() for
 * OBJ_STRING. Never returns NULL for len==0 (allocates a 1-byte sentinel,
 * so bytes.data is never NULL for a live OBJ_BYTES object). NULL only on
 * allocation failure. */
static uint8_t *bytes_dup(const void *data, size_t len)
{
    uint8_t *b = malloc(len ? len : 1);
    if (!b) return NULL;
    if (len) memcpy(b, data, len);
    return b;
}

static Object *new_bytes_unlocked(Store *s, const void *data, size_t len)
{
    if (!s) return NULL;
    bool started;
    if (!auto_begin(s, &started)) return NULL;
    Object *o = alloc_object(s, OBJ_BYTES);
    if (!o) { auto_end(s, started, false); return NULL; }
    o->bytes.data = bytes_dup(data, len);
    if (!o->bytes.data) { auto_end(s, started, false); return NULL; }
    o->bytes.len = len;

    TxnRec r = {0};
    r.op = WOP_NEW_BYTES; r.target = o; r.target_id = o->id;
    r.new_bytes = bytes_dup(data, len);
    if (!r.new_bytes) { auto_end(s, started, false); return NULL; }
    r.new_bytes_len = len;
    r.is_create = true;
    log_push(s, r);

    if (!auto_end(s, started, true)) return NULL;
    return o;
}

static Object *new_list_unlocked(Store *s)
{
    if (!s) return NULL;
    bool started;
    if (!auto_begin(s, &started)) return NULL;
    Object *o = alloc_object(s, OBJ_LIST);
    if (!o) { auto_end(s, started, false); return NULL; }

    TxnRec r = {0};
    r.op = WOP_NEW_LIST; r.target = o; r.target_id = o->id; r.is_create = true;
    log_push(s, r);

    if (!auto_end(s, started, true)) return NULL;
    return o;
}

static Object *new_vlist_unlocked(Store *s, const char *type_name, Object *params)
{
    if (!s || !type_name) return NULL;
    const VListOps *ops = find_vlist_ops(type_name);
    if (!ops) return NULL;

    bool started;
    if (!auto_begin(s, &started)) return NULL;
    Object *o = alloc_object(s, OBJ_VLIST);
    if (!o) { auto_end(s, started, false); return NULL; }
    o->vlist.type_name = strdup(type_name);
    if (!o->vlist.type_name) { auto_end(s, started, false); return NULL; }
    o->vlist.ops = ops;
    o->vlist.params = params;

    TxnRec r = {0};
    r.op = WOP_NEW_VLIST; r.target = o; r.target_id = o->id; r.is_create = true;
    r.new_str = strdup(type_name);
    r.new_ref = params;
    log_push(s, r);

    if (!auto_end(s, started, true)) return NULL;
    return o;
}

/* ============================================================
 * Primitive setters
 * ============================================================ */

static bool set_int_unlocked(Object *o, int64_t v)
{
    if (!o || o->kind != OBJ_INT) return false;
    Store *s = o->store;
    bool started;
    if (!auto_begin(s, &started)) return false;

    int64_t prev = o->int_value;
    o->int_value = v;

    TxnRec r = {0};
    r.op = WOP_SET_INT; r.target = o; r.target_id = o->id;
    r.new_int = v; r.old_int = prev; r.had_prev = true;
    log_push(s, r);

    return auto_end(s, started, true);
}

static bool set_str_unlocked(Object *o, const char *v)
{
    if (!o || o->kind != OBJ_STRING) return false;
    Store *s = o->store;
    bool started;
    if (!auto_begin(s, &started)) return false;

    char *old = o->str_value;
    o->str_value = strdup(v ? v : "");
    if (!o->str_value) { o->str_value = old; auto_end(s, started, false); return false; }

    TxnRec r = {0};
    r.op = WOP_SET_STR; r.target = o; r.target_id = o->id;
    r.new_str = strdup(v ? v : "");
    r.old_str = old; r.had_prev = true;        /* take ownership of old */
    log_push(s, r);

    return auto_end(s, started, true);
}

static bool set_bytes_unlocked(Object *o, const void *data, size_t len)
{
    if (!o || o->kind != OBJ_BYTES) return false;
    Store *s = o->store;
    bool started;
    if (!auto_begin(s, &started)) return false;

    uint8_t *new_data = bytes_dup(data, len);
    if (!new_data) { auto_end(s, started, false); return false; }

    /* Capture old pointer/len BEFORE reassigning; ownership transfers to
     * r.old_bytes, never dereferenced again through these locals — avoids
     * the borrowed-pointer-after-free shape found in set_class_unlocked_impl. */
    uint8_t *old_data = o->bytes.data;
    size_t   old_len  = o->bytes.len;
    o->bytes.data = new_data;
    o->bytes.len  = len;

    TxnRec r = {0};
    r.op = WOP_SET_BYTES; r.target = o; r.target_id = o->id;
    r.new_bytes = bytes_dup(data, len);
    if (!r.new_bytes) {
        o->bytes.data = old_data; o->bytes.len = old_len;   /* roll back */
        free(new_data);
        auto_end(s, started, false);
        return false;
    }
    r.new_bytes_len = len;
    r.old_bytes = old_data; r.old_bytes_len = old_len; r.had_prev = true;
    log_push(s, r);

    return auto_end(s, started, true);
}

/* ============================================================
 * Composite fields
 * ============================================================ */

static bool set_field_unlocked(Object *o, const char *key, Object *value)
{
    if (!o || !key || o->kind != OBJ_COMPOSITE) return false;
    Store *s = o->store;
    bool started;
    if (!auto_begin(s, &started)) return false;

    Field *ex = find_field(o, key);

    /* Secondary-index maintenance: only touches an index declared on this
     * object's class + this field, if any. Insert-new-before-mutate
     * (failure needs no unwind of the field itself), remove-old-after-
     * mutate (cannot fail). same_value guards against re-setting a field
     * to its current string content, which would otherwise insert a
     * duplicate Object* into an entry it's already a member of. */
    PogIndex *idx = NULL;
    PogOrdIndex *oidx = NULL;
    if (o->class_name) {
        size_t ii = index_find_idx_unlocked(s, o->class_name, key);
        if (ii != SIZE_MAX) idx = &s->indexes[ii];
        size_t oi = ord_index_find_idx_unlocked(s, o->class_name, key);
        if (oi != SIZE_MAX) oidx = &s->ord_indexes[oi];
    }
    const char *old_str = (ex && ex->value && ex->value->kind == OBJ_STRING)
                           ? ex->value->str_value : NULL;
    const char *new_str = (value && value->kind == OBJ_STRING)
                           ? value->str_value : NULL;
    bool same_value = old_str && new_str && strcmp(old_str, new_str) == 0;

    if (idx && new_str && !same_value) {
        if (!index_insert_unlocked(idx, new_str, o)) {
            auto_end(s, started, false);
            return false;
        }
    }
    if (oidx && new_str && !same_value) {
        if (!ord_index_insert_unlocked(oidx, new_str, o)) {
            if (idx) index_remove_unlocked(idx, new_str, o);   /* unwind the hash-index insert above */
            auto_end(s, started, false);
            return false;
        }
    }

    TxnRec r = {0};
    r.op = WOP_SET_FIELD; r.target = o; r.target_id = o->id;
    strncpy(r.key, key, POG_MAX_KEY_LEN - 1);
    r.new_ref = value;

    if (ex) {
        r.had_prev = true; r.old_ref = ex->value;
        ex->value = value;
    } else {
        if (!composite_grow(o)) {
            if (idx && new_str && !same_value) index_remove_unlocked(idx, new_str, o);
            if (oidx && new_str && !same_value) ord_index_remove_unlocked(oidx, new_str, o);
            auto_end(s, started, false);
            return false;
        }
        Field *f = &o->composite.items[o->composite.count++];
        memset(f, 0, sizeof(*f));
        strncpy(f->key, key, POG_MAX_KEY_LEN - 1);
        f->value = value;
    }

    if (idx && old_str && !same_value)
        index_remove_unlocked(idx, old_str, o);
    if (oidx && old_str && !same_value)
        ord_index_remove_unlocked(oidx, old_str, o);

    log_push(s, r);
    return auto_end(s, started, true);
}

static Object *get_field_unlocked(Object *o, const char *key)
{
    Field *f = find_field(o, key);
    return f ? f->value : NULL;
}

static size_t field_count_unlocked(Object *o)
{
    return (o && o->kind == OBJ_COMPOSITE) ? o->composite.count : 0;
}

/* ============================================================
 * Lists
 * ============================================================ */

static bool list_append_unlocked(Object *l, Object *v)
{
    if (!l || l->kind != OBJ_LIST) return false;
    Store *s = l->store;
    bool started;
    if (!auto_begin(s, &started)) return false;
    if (!list_grow(l)) { auto_end(s, started, false); return false; }

    l->list.items[l->list.count++] = v;

    TxnRec r = {0};
    r.op = WOP_LIST_APPEND; r.target = l; r.target_id = l->id;
    r.new_ref = v;
    log_push(s, r);
    return auto_end(s, started, true);
}

static bool list_set_unlocked(Object *l, size_t index, Object *v)
{
    if (!l || l->kind != OBJ_LIST || index >= l->list.count) return false;
    Store *s = l->store;
    bool started;
    if (!auto_begin(s, &started)) return false;

    Object *prev = l->list.items[index];
    l->list.items[index] = v;

    TxnRec r = {0};
    r.op = WOP_LIST_SET; r.target = l; r.target_id = l->id;
    r.index = index; r.new_ref = v; r.old_ref = prev; r.had_prev = true;
    log_push(s, r);
    return auto_end(s, started, true);
}

static bool list_insert_unlocked(Object *l, size_t index, Object *v)
{
    if (!l || l->kind != OBJ_LIST || index > l->list.count) return false;
    Store *s = l->store;
    bool started;
    if (!auto_begin(s, &started)) return false;
    if (!list_grow(l)) { auto_end(s, started, false); return false; }

    memmove(&l->list.items[index + 1], &l->list.items[index],
            (l->list.count - index) * sizeof(Object *));
    l->list.items[index] = v;
    l->list.count++;

    TxnRec r = {0};
    r.op = WOP_LIST_INSERT; r.target = l; r.target_id = l->id;
    r.index = index; r.new_ref = v;
    log_push(s, r);
    return auto_end(s, started, true);
}

static bool list_remove_unlocked(Object *l, size_t index)
{
    if (!l || l->kind != OBJ_LIST || index >= l->list.count) return false;
    Store *s = l->store;
    bool started;
    if (!auto_begin(s, &started)) return false;

    Object *prev = l->list.items[index];
    memmove(&l->list.items[index], &l->list.items[index + 1],
            (l->list.count - index - 1) * sizeof(Object *));
    l->list.count--;

    TxnRec r = {0};
    r.op = WOP_LIST_REMOVE; r.target = l; r.target_id = l->id;
    r.index = index; r.old_ref = prev; r.had_prev = true;
    log_push(s, r);
    return auto_end(s, started, true);
}

static Object *list_get_unlocked(Object *l, size_t index)
{
    if (!l) return NULL;
    if (l->kind == OBJ_LIST) {
        if (index >= l->list.count) return NULL;
        return l->list.items[index];
    }
    if (l->kind == OBJ_VLIST) {
        if (!l->vlist.ops || !l->vlist.ops->at) return NULL;
        return l->vlist.ops->at(l, index);
    }
    return NULL;
}

static size_t list_len_unlocked(Object *l)
{
    if (!l) return 0;
    if (l->kind == OBJ_LIST) return l->list.count;
    if (l->kind == OBJ_VLIST) {
        if (!l->vlist.ops || !l->vlist.ops->len) return 0;
        return l->vlist.ops->len(l);
    }
    return 0;
}

/* ============================================================
 * Roots
 * ============================================================ */

static bool ensure_root_cap(Store *s)
{
    if (s->root_count < s->root_capacity) return true;
    size_t nc = s->root_capacity * 2;
    Root *a = realloc(s->roots, nc * sizeof(*a));
    if (!a) return false;
    memset(a + s->root_capacity, 0, (nc - s->root_capacity) * sizeof(*a));
    s->roots = a; s->root_capacity = nc;
    return true;
}

static bool bind_unlocked(Store *s, const char *name, Object *o)
{
    if (!s || !name) return false;
    bool started;
    if (!auto_begin(s, &started)) return false;

    Root *ex = find_root(s, name);
    TxnRec r = {0};
    r.op = WOP_BIND_ROOT;
    strncpy(r.key, name, POG_MAX_ROOT_NAME - 1);
    r.new_ref = o;

    if (ex) {
        r.had_prev = true; r.old_ref = ex->obj;
        ex->obj = o;
    } else {
        if (!ensure_root_cap(s)) { auto_end(s, started, false); return false; }
        Root *nr = &s->roots[s->root_count++];
        memset(nr, 0, sizeof(*nr));
        strncpy(nr->name, name, POG_MAX_ROOT_NAME - 1);
        nr->obj = o; nr->used = true;
    }

    log_push(s, r);
    return auto_end(s, started, true);
}

static Object *get_unlocked(Store *s, const char *name)
{
    Root *r = find_root(s, name);
    return r ? r->obj : NULL;
}

static bool unbind_unlocked(Store *s, const char *name)
{
    if (!s || !name) return false;
    Root *ex = find_root(s, name);
    if (!ex) return false;
    bool started;
    if (!auto_begin(s, &started)) return false;

    TxnRec r = {0};
    r.op = WOP_UNBIND_ROOT;
    strncpy(r.key, name, POG_MAX_ROOT_NAME - 1);
    r.had_prev = true; r.old_ref = ex->obj;
    ex->used = false; ex->obj = NULL;
    log_push(s, r);
    return auto_end(s, started, true);
}

/* ============================================================
 * Dump
 * ============================================================ */

typedef struct { Object **items; size_t count, cap; } PtrSet;

static bool pset_has(PtrSet *p, Object *o)
{
    for (size_t i = 0; i < p->count; i++) if (p->items[i] == o) return true;
    return false;
}
static void pset_add(PtrSet *p, Object *o)
{
    if (p->count >= p->cap) {
        size_t nc, bytes;
        if (!next_cap(p->cap, 16, &nc) || !mul_bytes(nc, sizeof(*p->items), &bytes))
            return;
        Object **a = realloc(p->items, bytes);
        if (!a) return;
        p->items = a; p->cap = nc;
    }
    p->items[p->count++] = o;
}

/* Debug-only, but still driven by graph shape (possibly loaded from a
 * crafted/deep snapshot), so recursion depth must be bounded the same way
 * mark_from() bounds it via an explicit worklist. */
#define DUMP_MAX_DEPTH 1000
#define POG_DUMP_BYTES_HEX_CAP 8   /* max bytes rendered as hex before "..." */

static void dump_rec(Object *o, PtrSet *v, int depth)
{
    if (!o)                  { printf("<null>");              return; }
    if (depth >= DUMP_MAX_DEPTH) { printf("<max depth>");      return; }
    if (pset_has(v, o))      { printf("<cycle to #%u>", o->id); return; }
    pset_add(v, o);

    switch (o->kind) {
    case OBJ_INT:    printf("%lld", (long long)o->int_value);         break;
    case OBJ_STRING: printf("\"%s\"", o->str_value ? o->str_value : ""); break;
    case OBJ_BYTES: {
        size_t cap = o->bytes.len < POG_DUMP_BYTES_HEX_CAP
                     ? o->bytes.len : POG_DUMP_BYTES_HEX_CAP;
        printf("<%zu bytes: ", o->bytes.len);
        for (size_t i = 0; i < cap; i++)
            printf("%02x", (unsigned)o->bytes.data[i]);
        if (o->bytes.len > cap) printf("...");
        printf(">");
        break;
    }
    case OBJ_LIST:
        printf("#%u[", o->id);
        for (size_t i = 0; i < o->list.count; i++) {
            if (i) printf(", ");
            dump_rec(o->list.items[i], v, depth + 1);
        }
        printf("]");
        break;
    case OBJ_VLIST: {
        size_t n = (o->vlist.ops && o->vlist.ops->len) ? o->vlist.ops->len(o) : 0;
        printf("#%u<%s>[", o->id,
               o->vlist.type_name ? o->vlist.type_name : "?");
        size_t limit = n > 10 ? 10 : n;
        for (size_t i = 0; i < limit; i++) {
            if (i) printf(", ");
            Object *it = o->vlist.ops->at(o, i);
            dump_rec(it, v, depth + 1);
        }
        if (n > 10) printf(", ... (%zu more)", n - 10);
        printf("]");
        break;
    }
    case OBJ_COMPOSITE: {
        printf("#%u{", o->id);
        for (size_t i = 0; i < o->composite.count; i++) {
            if (i) printf(", ");
            printf("%s: ", o->composite.items[i].key);
            dump_rec(o->composite.items[i].value, v, depth + 1);
        }
        printf("}");
        break;
    }}
}

void dump(Object *o)
{
    Store *s = o ? o->store : NULL;
    bool took_lock = false;
    if (s && !(s->active_txn && pthread_equal(s->txn_owner, pthread_self()))) {
        pthread_rwlock_rdlock(&s->lock);
        took_lock = true;
    }
    PtrSet v = {0};
    dump_rec(o, &v, 0);
    printf("\n");
    free(v.items);
    if (took_lock) pthread_rwlock_unlock(&s->lock);
}

void dump_store(Store *s)
{
    if (!s) { printf("<null store>\n"); return; }
    bool took_lock = false;
    if (!(s->active_txn && pthread_equal(s->txn_owner, pthread_self()))) {
        pthread_rwlock_rdlock(&s->lock);
        took_lock = true;
    }
    printf("Store: %zu objects, %zu roots, seq=%u%s\n",
           s->count, s->root_count, s->seq, s->path ? " (persistent)" : "");
    for (size_t i = 0; i < s->root_count; i++) {
        if (!s->roots[i].used) continue;
        printf("  %s -> ", s->roots[i].name);
        PtrSet v = {0};
        dump_rec(s->roots[i].obj, &v, 0);
        printf("\n");
        free(v.items);
    }
    if (took_lock) pthread_rwlock_unlock(&s->lock);
}

/* ============================================================
 * GC
 * ============================================================ */

/* Explicit heap worklist, not the call stack — a deep chain of composites
 * or lists (e.g. loaded from a crafted or merely large snapshot) must not
 * blow the C stack via per-edge recursion. */
typedef struct { Object **items; size_t count, cap; } MarkStack;

static bool mark_stack_push(MarkStack *ms, Object *o)
{
    if (ms->count >= ms->cap) {
        size_t nc, bytes;
        if (!next_cap(ms->cap, 256, &nc) || !mul_bytes(nc, sizeof(*ms->items), &bytes))
            return false;
        Object **a = realloc(ms->items, bytes);
        if (!a) return false;
        ms->items = a; ms->cap = nc;
    }
    ms->items[ms->count++] = o;
    return true;
}

/* Mark everything reachable from root. Returns false on OOM mid-traversal —
 * the caller must not sweep in that case, since incomplete marking would
 * free still-reachable objects. */
static bool mark_from(MarkStack *ms, Object *root)
{
    if (!root || root->marked) return true;
    if (!mark_stack_push(ms, root)) return false;
    while (ms->count > 0) {
        Object *o = ms->items[--ms->count];
        if (o->marked) continue;
        o->marked = true;
        if (o->kind == OBJ_COMPOSITE) {
            for (size_t i = 0; i < o->composite.count; i++) {
                Object *c = o->composite.items[i].value;
                if (c && !c->marked && !mark_stack_push(ms, c)) return false;
            }
        } else if (o->kind == OBJ_LIST) {
            for (size_t i = 0; i < o->list.count; i++) {
                Object *c = o->list.items[i];
                if (c && !c->marked && !mark_stack_push(ms, c)) return false;
            }
        } else if (o->kind == OBJ_VLIST) {
            if (o->vlist.params && !o->vlist.params->marked &&
                !mark_stack_push(ms, o->vlist.params)) return false;
        }
    }
    return true;
}

static void gc_unlocked(Store *s)
{
    if (!s) return;
    if (s->active_txn) {
        fprintf(stderr, "pog: gc() forbidden during transaction\n");
        return;
    }
    for (size_t i = 0; i < s->count; i++) s->objects[i]->marked = false;

    MarkStack ms = {0};
    bool ok = true;
    for (size_t i = 0; i < s->root_count && ok; i++)
        if (s->roots[i].used) ok = mark_from(&ms, s->roots[i].obj);
    free(ms.items);

    if (!ok) {
        fprintf(stderr, "pog: gc() aborted — out of memory during mark\n");
        return;
    }

    size_t w = 0;
    for (size_t r = 0; r < s->count; r++) {
        Object *o = s->objects[r];
        if (o->marked) s->objects[w++] = o;
        else           free_object(o);
    }
    s->count = w;
    /* GC may have freed tagged objects; rebuild the class index. */
    class_index_rebuild(s);
    index_rebuild_all(s);
    ord_index_rebuild_all(s);
}

void gc(Store *s)
{
    if (!s) return;
    /* GC takes wrlock; forbidden during txn (checked inside) */
    s_wrlock(s);
    gc_unlocked(s);
    s_unlock(s);
}

/* ============================================================
 * Binary I/O primitives
 * ============================================================ */

static bool w_u8 (FILE *f, uint8_t  v) { return fwrite(&v,1,1,f)==1; }
static bool w_u32(FILE *f, uint32_t v) { return fwrite(&v,4,1,f)==1; }
static bool w_i64(FILE *f, int64_t  v) { return fwrite(&v,8,1,f)==1; }
static bool r_u8 (FILE *f, uint8_t  *v){ return fread(v,1,1,f)==1; }
static bool r_u32(FILE *f, uint32_t *v){ return fread(v,4,1,f)==1; }
static bool r_i64(FILE *f, int64_t  *v){ return fread(v,8,1,f)==1; }

static bool w_str(FILE *f, const char *s)
{
    uint32_t len = s ? (uint32_t)strlen(s) : 0;
    if (!w_u32(f, len)) return false;
    return len == 0 || fwrite(s, 1, len, f) == len;
}

static char *r_str(FILE *f)
{
    uint32_t len;
    if (!r_u32(f, &len) || len > (1u << 24)) return NULL;
    char *s = malloc(len + 1);
    if (!s) return NULL;
    if (len && fread(s, 1, len, f) != len) { free(s); return NULL; }
    s[len] = '\0';
    return s;
}

/* Length-prefixed raw-byte I/O, analogous to w_str/r_str but taking an
 * explicit length instead of deriving it from strlen() — required because
 * OBJ_BYTES payloads may contain embedded zero bytes. Unlike w_str (which
 * derives its length from strlen() and would silently truncate at the
 * first embedded zero), w_bytes fails outright on a length that doesn't
 * fit in a u32 rather than writing a corrupt/wrapped-length record. */
static bool w_bytes(FILE *f, const uint8_t *data, size_t len)
{
    if (len > UINT32_MAX) return false;
    uint32_t n = (uint32_t)len;
    if (!w_u32(f, n)) return false;
    return n == 0 || fwrite(data, 1, n, f) == n;
}

static uint8_t *r_bytes(FILE *f, size_t *out_len)
{
    uint32_t len;
    if (!r_u32(f, &len) || len > (1u << 24)) return NULL;
    uint8_t *b = malloc(len ? len : 1);
    if (!b) return NULL;
    if (len && fread(b, 1, len, f) != len) { free(b); return NULL; }
    *out_len = len;
    return b;
}

/* ============================================================
 * Snapshot I/O (save/load)
 * ============================================================ */

bool save(Store *s, const char *path)
{
    if (!s || !path) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;

    bool ok = true;
    ok &= w_u32(f, POGE_MAGIC);
    ok &= w_u32(f, POGE_VERSION);
    ok &= w_u32(f, s->seq);
    ok &= w_u32(f, s->next_id);
    ok &= w_u32(f, (uint32_t)s->count);

    for (size_t i = 0; i < s->count && ok; i++) {
        Object *o = s->objects[i];
        ok &= w_u32(f, o->id);
        ok &= w_u8 (f, (uint8_t)o->kind);
        switch (o->kind) {
        case OBJ_INT:
            ok &= w_i64(f, o->int_value);
            break;
        case OBJ_STRING:
            ok &= w_str(f, o->str_value);
            break;
        case OBJ_BYTES:
            ok &= w_bytes(f, o->bytes.data, o->bytes.len);
            break;
        case OBJ_COMPOSITE:
            ok &= w_str(f, o->class_name ? o->class_name : "");
            ok &= w_u32(f, (uint32_t)o->composite.count);
            for (size_t j = 0; j < o->composite.count && ok; j++) {
                ok &= w_str(f, o->composite.items[j].key);
                ok &= w_u32(f, o->composite.items[j].value
                            ? o->composite.items[j].value->id : 0);
            }
            break;
        case OBJ_LIST:
            ok &= w_u32(f, (uint32_t)o->list.count);
            for (size_t j = 0; j < o->list.count && ok; j++)
                ok &= w_u32(f, o->list.items[j] ? o->list.items[j]->id : 0);
            break;
        case OBJ_VLIST:
            ok &= w_str(f, o->vlist.type_name);
            ok &= w_u32(f, o->vlist.params ? o->vlist.params->id : 0);
            break;
        }
    }

    uint32_t nroots = 0;
    for (size_t i = 0; i < s->root_count; i++)
        if (s->roots[i].used) nroots++;
    ok &= w_u32(f, nroots);
    for (size_t i = 0; i < s->root_count && ok; i++) {
        if (!s->roots[i].used) continue;
        ok &= w_str(f, s->roots[i].name);
        ok &= w_u32(f, s->roots[i].obj ? s->roots[i].obj->id : 0);
    }

    if (fflush(f) != 0) ok = false;
    int fd = fileno(f);
    if (fd >= 0 && fsync(fd) != 0) { /* best effort */ }
    fclose(f);
    return ok;
}

/* id-map for load/replay */
typedef struct { Object **items; uint32_t cap; } IdMap;
/* Returns false on allocation failure instead of aborting the process. */
static bool idmap_put(IdMap *m, uint32_t id, Object *o)
{
    if (id >= m->cap) {
        /* widen to 64-bit for the doubling loop: id can be up to UINT32_MAX,
         * and doubling a uint32_t past it would wrap and spin forever. */
        uint64_t nc = m->cap ? m->cap : 64;
        while (nc <= id) nc *= 2;
        if (nc > UINT32_MAX) return false;
        size_t bytes;
        if (!mul_bytes((size_t)nc, sizeof(*m->items), &bytes)) return false;
        Object **a = realloc(m->items, bytes);
        if (!a) return false;
        memset(a + m->cap, 0, (size_t)(nc - m->cap) * sizeof(*a));
        m->items = a; m->cap = (uint32_t)nc;
    }
    m->items[id] = o;
    return true;
}
static Object *idmap_get(IdMap *m, uint32_t id)
{
    if (id == 0 || id >= m->cap) return NULL;
    return m->items[id];
}

typedef struct {
    Object *owner; char *key; uint32_t target_id;
} PendField;
typedef struct {
    Object *list; uint32_t target_id;
} PendListItem;

/* Reject a claimed element count that can't possibly fit in the bytes left
 * in the file — guards calloc(count, ...) sites against a crafted/corrupt
 * file claiming millions of elements it doesn't actually contain. */
#define MIN_OBJ_BYTES   5   /* u32 id + u8 kind */
#define MIN_FIELD_BYTES 8   /* min r_str(key) + u32 tid */
#define MIN_LIST_BYTES  4   /* u32 tid */
#define MIN_ROOT_BYTES  8   /* min r_str(name) + u32 oid */

static bool count_fits_remaining(long fsize, long pos, uint32_t count,
                                  size_t min_elem_size)
{
    if (fsize < 0 || pos < 0 || pos > fsize) return false;
    unsigned long long remaining = (unsigned long long)(fsize - pos);
    return (unsigned long long)count * (unsigned long long)min_elem_size
           <= remaining;
}

Store *load(const char *path)
{
    if (!path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    long fsize = -1;
    if (fseek(f, 0, SEEK_END) == 0) fsize = ftell(f);
    if (fsize < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    uint32_t magic, ver, seq, next_id, nobj;
    if (!r_u32(f,&magic) || magic != POGE_MAGIC ||
        !r_u32(f,&ver)   || ver   != POGE_VERSION ||
        !r_u32(f,&seq)   || !r_u32(f,&next_id) || !r_u32(f,&nobj) ||
        !count_fits_remaining(fsize, ftell(f), nobj, MIN_OBJ_BYTES)) {
        fclose(f); return NULL;
    }

    Store *s = store_create();
    if (!s) { fclose(f); return NULL; }

    IdMap map = {0};
    PendField    *pf = NULL; size_t pfc = 0, pfcap = 0;
    PendListItem *pl = NULL; size_t plc = 0, plcap = 0;

    bool ok = true;

    for (uint32_t i = 0; i < nobj && ok; i++) {
        uint32_t id; uint8_t kind;
        if (!r_u32(f,&id) || !r_u8(f,&kind) || id == 0 || id >= next_id) {
            ok = false; break;
        }
        Object *o = calloc(1, sizeof(*o));
        if (!o) { ok = false; break; }
        o->id = id; o->kind = (ObjectKind)kind; o->store = s;

        switch (kind) {
        case OBJ_INT:
            if (!r_i64(f, &o->int_value)) { free_object(o); ok = false; }
            break;
        case OBJ_STRING:
            o->str_value = r_str(f);
            if (!o->str_value) { free_object(o); ok = false; }
            break;
        case OBJ_BYTES: {
            size_t blen;
            o->bytes.data = r_bytes(f, &blen);
            if (!o->bytes.data) { free_object(o); ok = false; break; }
            o->bytes.len = blen;
            break;
        }
        case OBJ_COMPOSITE: {
            char *cname = r_str(f);
            if (!cname) { free_object(o); ok = false; break; }
            if (*cname) o->class_name = cname;
            else        { free(cname); o->class_name = NULL; }
            uint32_t nf;
            if (!r_u32(f, &nf) ||
                !count_fits_remaining(fsize, ftell(f), nf, MIN_FIELD_BYTES)) {
                free_object(o); ok = false; break;
            }
            o->composite.items = calloc(nf > 0 ? nf : 1, sizeof(Field));
            if (!o->composite.items) { free_object(o); ok = false; break; }
            o->composite.cap   = nf > 0 ? nf : 1;
            o->composite.count = nf;
            for (uint32_t j = 0; j < nf && ok; j++) {
                char *key = r_str(f); uint32_t tid;
                if (!key || !r_u32(f,&tid)) { free(key); ok = false; break; }
                strncpy(o->composite.items[j].key, key, POG_MAX_KEY_LEN - 1);
                o->composite.items[j].key[POG_MAX_KEY_LEN - 1] = '\0';
                free(key);
                if (pfc >= pfcap) {
                    size_t nc, bytes;
                    if (!next_cap(pfcap, 16, &nc) || !mul_bytes(nc, sizeof(*pf), &bytes)) {
                        ok = false; break;
                    }
                    PendField *np = realloc(pf, bytes);
                    if (!np) { ok = false; break; }
                    pf = np; pfcap = nc;
                }
                pf[pfc].owner = o;
                pf[pfc].key = strdup(o->composite.items[j].key);
                pf[pfc].target_id = tid;
                pfc++;
            }
            if (!ok) free_object(o);   /* not yet store_push_obj'd */
            break;
        }
        case OBJ_LIST: {
            uint32_t nl;
            if (!r_u32(f, &nl) ||
                !count_fits_remaining(fsize, ftell(f), nl, MIN_LIST_BYTES)) {
                free_object(o); ok = false; break;
            }
            o->list.items = calloc(nl > 0 ? nl : 1, sizeof(Object *));
            if (!o->list.items) { free_object(o); ok = false; break; }
            o->list.cap   = nl > 0 ? nl : 1;
            o->list.count = nl;
            for (uint32_t j = 0; j < nl && ok; j++) {
                uint32_t tid;
                if (!r_u32(f, &tid)) { ok = false; break; }
                if (plc >= plcap) {
                    size_t nc, bytes;
                    if (!next_cap(plcap, 16, &nc) || !mul_bytes(nc, sizeof(*pl), &bytes)) {
                        ok = false; break;
                    }
                    PendListItem *np = realloc(pl, bytes);
                    if (!np) { ok = false; break; }
                    pl = np; plcap = nc;
                }
                /* store slot via current index j */
                pl[plc].list = o;
                pl[plc].target_id = tid;
                o->list.items[j] = (Object *)(uintptr_t)tid; /* temp, patch later */
                plc++;
            }
            if (!ok) free_object(o);   /* not yet store_push_obj'd */
            break;
        }
        case OBJ_VLIST: {
            char *type = r_str(f);
            uint32_t pid;
            if (!type || !r_u32(f, &pid)) {
                free(type); free_object(o); ok = false; break;
            }
            const VListOps *ops = find_vlist_ops(type);
            if (!ops) {
                fprintf(stderr, "pog: unknown vlist type '%s' during load\n", type);
                free(type); free_object(o); ok = false; break;
            }
            o->vlist.type_name = type;
            o->vlist.ops = ops;
            /* stash params id temporarily; resolved in a post-pass below */
            o->vlist.params = (Object *)(uintptr_t)pid;
            break;
        }
        default:
            free_object(o); ok = false; break;
        }

        if (!ok) break;
        if (!store_push_obj(s, o)) { free_object(o); ok = false; break; }
        if (!idmap_put(&map, id, o)) { ok = false; break; }
    }

    /* resolve field references by key */
    if (ok) {
        for (size_t i = 0; i < pfc; i++) {
            Object *tgt = idmap_get(&map, pf[i].target_id);
            Field *fld = find_field(pf[i].owner, pf[i].key);
            if (fld) fld->value = tgt;
        }
    }
    for (size_t i = 0; i < pfc; i++) free(pf[i].key);
    free(pf);

    /* resolve list references */
    if (ok) {
        for (size_t i = 0; i < s->count; i++) {
            Object *o = s->objects[i];
            if (o->kind != OBJ_LIST) continue;
            for (size_t j = 0; j < o->list.count; j++) {
                uintptr_t tid = (uintptr_t)o->list.items[j];
                o->list.items[j] = idmap_get(&map, (uint32_t)tid);
            }
        }
    }
    free(pl);

    /* resolve vlist params */
    if (ok) {
        for (size_t i = 0; i < s->count; i++) {
            Object *o = s->objects[i];
            if (o->kind != OBJ_VLIST) continue;
            uintptr_t pid = (uintptr_t)o->vlist.params;
            o->vlist.params = idmap_get(&map, (uint32_t)pid);
        }
    }

    /* roots */
    uint32_t nroots = 0;
    if (ok && r_u32(f, &nroots) &&
        count_fits_remaining(fsize, ftell(f), nroots, MIN_ROOT_BYTES)) {
        for (uint32_t i = 0; i < nroots && ok; i++) {
            char *name = r_str(f); uint32_t oid;
            if (!name || !r_u32(f, &oid)) { free(name); ok = false; break; }
            Object *o = idmap_get(&map, oid);
            if (!ensure_root_cap(s)) { free(name); ok = false; break; }
            Root *nr = &s->roots[s->root_count++];
            memset(nr, 0, sizeof(*nr));
            strncpy(nr->name, name, POG_MAX_ROOT_NAME - 1);
            nr->obj = o; nr->used = true;
            free(name);
        }
    } else if (ok) {
        ok = false;
    }

    free(map.items);
    fclose(f);

    if (!ok) { store_destroy(s); return NULL; }
    s->next_id = next_id;
    s->seq = seq;
    class_index_rebuild(s);
    index_rebuild_all(s);
    ord_index_rebuild_all(s);
    return s;
}

/* ============================================================
 * WAL writing (commit path)
 * ============================================================ */

static bool wal_write_rec(FILE *f, const TxnRec *r)
{
    if (!w_u8(f, r->op)) return false;
    switch (r->op) {
    case WOP_NEW_OBJECT:
    case WOP_NEW_LIST:
        return w_u32(f, r->target_id);
    case WOP_NEW_VLIST:
        return w_u32(f, r->target_id) && w_str(f, r->new_str) &&
               w_u32(f, r->new_ref ? r->new_ref->id : 0);
    case WOP_NEW_INT:
    case WOP_SET_INT:
        return w_u32(f, r->target_id) && w_i64(f, r->new_int);
    case WOP_NEW_STRING:
    case WOP_SET_STR:
        return w_u32(f, r->target_id) && w_str(f, r->new_str);
    case WOP_NEW_BYTES:
    case WOP_SET_BYTES:
        return w_u32(f, r->target_id) && w_bytes(f, r->new_bytes, r->new_bytes_len);
    case WOP_SET_FIELD:
        return w_u32(f, r->target_id) && w_str(f, r->key) &&
               w_u32(f, r->new_ref ? r->new_ref->id : 0);
    case WOP_LIST_APPEND:
        return w_u32(f, r->target_id) &&
               w_u32(f, r->new_ref ? r->new_ref->id : 0);
    case WOP_LIST_SET:
    case WOP_LIST_INSERT:
        return w_u32(f, r->target_id) && w_u32(f, (uint32_t)r->index) &&
               w_u32(f, r->new_ref ? r->new_ref->id : 0);
    case WOP_LIST_REMOVE:
        return w_u32(f, r->target_id) && w_u32(f, (uint32_t)r->index);
    case WOP_BIND_ROOT:
        return w_str(f, r->key) &&
               w_u32(f, r->new_ref ? r->new_ref->id : 0);
    case WOP_UNBIND_ROOT:
        return w_str(f, r->key);
    case WOP_SET_CLASS:
        return w_u32(f, r->target_id) &&
               w_str(f, r->new_str ? r->new_str : "");
    }
    return false;
}

static bool wal_write_txn(Store *s, Txn *t)
{
    if (!s->wal_fp) return true;
    FILE *f = s->wal_fp;

    if (!w_u8(f, WOP_TXN_BEGIN) || !w_u32(f, t->id)) return false;
    for (size_t i = 0; i < t->count; i++)
        if (!wal_write_rec(f, &t->log[i])) return false;
    if (!w_u8(f, WOP_TXN_COMMIT) || !w_u32(f, t->id)) return false;

    if (fflush(f) != 0) return false;
    int fd = fileno(f);
    if (fd >= 0 && fsync(fd) != 0) return false;
    return true;
}

/* ============================================================
 * WAL reading & replay (recovery)
 * ============================================================ */

static bool wal_apply_pending(Store *s, IdMap *map,
                              TxnRec *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        TxnRec *r = &buf[i];
        switch (r->op) {
        case WOP_NEW_OBJECT: {
            Object *o = alloc_with_id(s, OBJ_COMPOSITE, r->target_id);
            if (!o || !idmap_put(map, r->target_id, o)) return false;
            break;
        }
        case WOP_NEW_INT: {
            Object *o = alloc_with_id(s, OBJ_INT, r->target_id);
            if (!o) return false;
            o->int_value = r->new_int;
            if (!idmap_put(map, r->target_id, o)) return false;
            break;
        }
        case WOP_NEW_STRING: {
            Object *o = alloc_with_id(s, OBJ_STRING, r->target_id);
            if (!o) return false;
            o->str_value = r->new_str; r->new_str = NULL; /* move */
            if (!idmap_put(map, r->target_id, o)) return false;
            break;
        }
        case WOP_NEW_BYTES: {
            Object *o = alloc_with_id(s, OBJ_BYTES, r->target_id);
            if (!o) return false;
            o->bytes.data = r->new_bytes; r->new_bytes = NULL; /* move */
            o->bytes.len  = r->new_bytes_len;
            if (!idmap_put(map, r->target_id, o)) return false;
            break;
        }
        case WOP_NEW_LIST: {
            Object *o = alloc_with_id(s, OBJ_LIST, r->target_id);
            if (!o || !idmap_put(map, r->target_id, o)) return false;
            break;
        }
        case WOP_NEW_VLIST: {
            const VListOps *ops = find_vlist_ops(r->new_str);
            if (!ops) {
                fprintf(stderr, "pog: unknown vlist type '%s' in WAL\n",
                        r->new_str ? r->new_str : "?");
                return false;
            }
            Object *o = alloc_with_id(s, OBJ_VLIST, r->target_id);
            if (!o) return false;
            o->vlist.type_name = r->new_str; r->new_str = NULL;  /* move */
            o->vlist.ops = ops;
            o->vlist.params = idmap_get(map, (uint32_t)r->old_int);
            if (!idmap_put(map, r->target_id, o)) return false;
            break;
        }
        case WOP_SET_INT: {
            Object *o = idmap_get(map, r->target_id);
            if (o && o->kind == OBJ_INT) o->int_value = r->new_int;
            break;
        }
        case WOP_SET_STR: {
            Object *o = idmap_get(map, r->target_id);
            if (o && o->kind == OBJ_STRING) {
                free(o->str_value);
                o->str_value = r->new_str; r->new_str = NULL;
            }
            break;
        }
        case WOP_SET_BYTES: {
            Object *o = idmap_get(map, r->target_id);
            if (o && o->kind == OBJ_BYTES) {
                free(o->bytes.data);
                o->bytes.data = r->new_bytes; r->new_bytes = NULL;
                o->bytes.len  = r->new_bytes_len;
            }
            break;
        }
        case WOP_SET_FIELD: {
            Object *o = idmap_get(map, r->target_id);
            Object *v = idmap_get(map, r->new_ref ? r->new_ref->id : 0);
            /* new_ref was stashed as raw id in old_int for replay */
            (void)v;
            Object *vv = idmap_get(map, (uint32_t)r->old_int);
            if (o && o->kind == OBJ_COMPOSITE) {
                Field *ex = find_field(o, r->key);
                if (ex) ex->value = vv;
                else {
                    if (!composite_grow(o)) return false;
                    Field *fn = &o->composite.items[o->composite.count++];
                    memset(fn, 0, sizeof(*fn));
                    strncpy(fn->key, r->key, POG_MAX_KEY_LEN - 1);
                    fn->value = vv;
                }
            }
            break;
        }
        case WOP_LIST_APPEND: {
            Object *l = idmap_get(map, r->target_id);
            Object *v = idmap_get(map, (uint32_t)r->old_int);
            if (l && l->kind == OBJ_LIST) {
                if (!list_grow(l)) return false;
                l->list.items[l->list.count++] = v;
            }
            break;
        }
        case WOP_LIST_SET: {
            Object *l = idmap_get(map, r->target_id);
            Object *v = idmap_get(map, (uint32_t)r->old_int);
            if (l && l->kind == OBJ_LIST && r->index < l->list.count)
                l->list.items[r->index] = v;
            break;
        }
        case WOP_LIST_INSERT: {
            Object *l = idmap_get(map, r->target_id);
            Object *v = idmap_get(map, (uint32_t)r->old_int);
            if (l && l->kind == OBJ_LIST && r->index <= l->list.count) {
                if (!list_grow(l)) return false;
                memmove(&l->list.items[r->index+1], &l->list.items[r->index],
                        (l->list.count - r->index) * sizeof(Object*));
                l->list.items[r->index] = v;
                l->list.count++;
            }
            break;
        }
        case WOP_LIST_REMOVE: {
            Object *l = idmap_get(map, r->target_id);
            if (l && l->kind == OBJ_LIST && r->index < l->list.count) {
                memmove(&l->list.items[r->index], &l->list.items[r->index+1],
                        (l->list.count - r->index - 1) * sizeof(Object*));
                l->list.count--;
            }
            break;
        }
        case WOP_BIND_ROOT: {
            Object *o = idmap_get(map, (uint32_t)r->old_int);
            Root *ex = find_root(s, r->key);
            if (ex) ex->obj = o;
            else {
                if (!ensure_root_cap(s)) return false;
                Root *nr = &s->roots[s->root_count++];
                memset(nr, 0, sizeof(*nr));
                strncpy(nr->name, r->key, POG_MAX_ROOT_NAME - 1);
                nr->obj = o; nr->used = true;
            }
            break;
        }
        case WOP_UNBIND_ROOT: {
            Root *ex = find_root(s, r->key);
            if (ex) { ex->used = false; ex->obj = NULL; }
            break;
        }
        case WOP_SET_CLASS: {
            Object *o = idmap_get(map, r->target_id);
            if (o && o->kind == OBJ_COMPOSITE) {
                free(o->class_name);
                /* "" means untag */
                if (r->new_str && *r->new_str) {
                    o->class_name = r->new_str; r->new_str = NULL;
                } else {
                    o->class_name = NULL;
                }
                /* class index is rebuilt in bulk after replay */
            }
            break;
        }
        }
    }
    return true;
}

static bool wal_read_rec(FILE *f, TxnRec *r)
{
    memset(r, 0, sizeof(*r));
    uint8_t op;
    if (!r_u8(f, &op)) return false;
    r->op = op;
    uint32_t tid;
    switch (op) {
    case WOP_TXN_BEGIN:
    case WOP_TXN_COMMIT:
        if (!r_u32(f, &tid)) return false;
        r->target_id = tid;
        return true;
    case WOP_NEW_OBJECT:
    case WOP_NEW_LIST:
        return r_u32(f, &r->target_id);
    case WOP_NEW_VLIST: {
        uint32_t pid;
        if (!r_u32(f, &r->target_id)) return false;
        r->new_str = r_str(f);
        if (!r->new_str || !r_u32(f, &pid)) return false;
        r->old_int = pid;   /* stash params id */
        return true;
    }
    case WOP_NEW_INT:
    case WOP_SET_INT:
        return r_u32(f, &r->target_id) && r_i64(f, &r->new_int);
    case WOP_NEW_STRING:
    case WOP_SET_STR:
        if (!r_u32(f, &r->target_id)) return false;
        r->new_str = r_str(f);
        return r->new_str != NULL;
    case WOP_NEW_BYTES:
    case WOP_SET_BYTES:
        if (!r_u32(f, &r->target_id)) return false;
        r->new_bytes = r_bytes(f, &r->new_bytes_len);
        return r->new_bytes != NULL;
    case WOP_SET_FIELD: {
        if (!r_u32(f, &r->target_id)) return false;
        char *k = r_str(f); uint32_t vid;
        if (!k || !r_u32(f, &vid)) { free(k); return false; }
        strncpy(r->key, k, POG_MAX_KEY_LEN - 1); free(k);
        r->old_int = vid;   /* reuse old_int to stash referenced id */
        return true;
    }
    case WOP_LIST_APPEND: {
        uint32_t vid;
        if (!r_u32(f, &r->target_id) || !r_u32(f, &vid)) return false;
        r->old_int = vid;
        return true;
    }
    case WOP_LIST_SET:
    case WOP_LIST_INSERT: {
        uint32_t idx, vid;
        if (!r_u32(f, &r->target_id) || !r_u32(f, &idx) || !r_u32(f, &vid))
            return false;
        r->index = idx; r->old_int = vid;
        return true;
    }
    case WOP_LIST_REMOVE: {
        uint32_t idx;
        if (!r_u32(f, &r->target_id) || !r_u32(f, &idx)) return false;
        r->index = idx;
        return true;
    }
    case WOP_BIND_ROOT: {
        char *k = r_str(f); uint32_t vid;
        if (!k || !r_u32(f, &vid)) { free(k); return false; }
        strncpy(r->key, k, POG_MAX_ROOT_NAME - 1); free(k);
        r->old_int = vid;
        return true;
    }
    case WOP_UNBIND_ROOT: {
        char *k = r_str(f);
        if (!k) return false;
        strncpy(r->key, k, POG_MAX_ROOT_NAME - 1); free(k);
        return true;
    }
    case WOP_SET_CLASS: {
        if (!r_u32(f, &r->target_id)) return false;
        r->new_str = r_str(f);
        return r->new_str != NULL;
    }
    }
    return false;  /* unknown op */
}

/* Bound on records buffered for a single uncommitted txn during replay
 * (mirrors the 1<<24 string-length cap in r_str: generous for legitimate
 * use, finite against a crafted/corrupt WAL). */
#define POG_MAX_TXN_RECS_REPLAY (1u << 24)

/* Replay committed transactions from WAL; returns byte offset of end
 * of last complete COMMIT (so we can truncate any torn tail). */
static bool wal_replay(Store *s, const char *wal_path, IdMap *map, long *good_end)
{
    FILE *f = fopen(wal_path, "rb");
    if (!f) { *good_end = 0; return true; }   /* no WAL: nothing to do */

    uint32_t magic, ver, baseline;
    if (!r_u32(f, &magic) || magic != POGW_MAGIC ||
        !r_u32(f, &ver)   || ver   != POGW_VERSION ||
        !r_u32(f, &baseline)) {
        fclose(f); *good_end = 0; return false;
    }
    long header_end = ftell(f);
    *good_end = header_end;

    /* If WAL baseline doesn't match snapshot seq, WAL is stale, discard. */
    if (baseline != s->seq) { fclose(f); return true; }

    TxnRec *pending = NULL;
    size_t  pcount = 0, pcap = 0;
    uint32_t pending_txn = 0;
    bool in_txn = false;

    for (;;) {
        long pos = ftell(f);
        TxnRec rec;
        if (!wal_read_rec(f, &rec)) break;    /* clean EOF or torn tail */

        if (rec.op == WOP_TXN_BEGIN) {
            /* discard any previously-pending (incomplete) txn */
            for (size_t i = 0; i < pcount; i++) txnrec_free_owned(&pending[i]);
            pcount = 0;
            in_txn = true;
            pending_txn = rec.target_id;
        } else if (rec.op == WOP_TXN_COMMIT) {
            if (in_txn && rec.target_id == pending_txn) {
                if (!wal_apply_pending(s, map, pending, pcount)) {
                    for (size_t i = 0; i < pcount; i++) txnrec_free_owned(&pending[i]);
                    free(pending);
                    fclose(f);
                    return false;
                }
                for (size_t i = 0; i < pcount; i++) txnrec_free_owned(&pending[i]);
                pcount = 0;
                in_txn = false;
                *good_end = ftell(f);
                if (rec.target_id >= s->next_txn_id)
                    s->next_txn_id = rec.target_id + 1;
            } else {
                /* mismatched commit: stop */
                break;
            }
            (void)pos;
        } else {
            if (!in_txn) { txnrec_free_owned(&rec); break; }
            /* Cap a single in-flight (uncommitted) txn's buffered record
             * count — an adversarial or corrupt WAL claiming one giant open
             * txn that never commits would otherwise buffer unboundedly in
             * RAM. Treated the same as a torn tail: stop and discard. */
            if (pcount >= POG_MAX_TXN_RECS_REPLAY) {
                txnrec_free_owned(&rec); break;
            }
            if (pcount >= pcap) {
                size_t nc, bytes;
                if (!next_cap(pcap, 32, &nc) || !mul_bytes(nc, sizeof(*pending), &bytes)) {
                    txnrec_free_owned(&rec); break;
                }
                TxnRec *a = realloc(pending, bytes);
                if (!a) { txnrec_free_owned(&rec); break; }
                pending = a; pcap = nc;
            }
            pending[pcount++] = rec;
        }
    }

    /* any un-committed pending records are discarded */
    for (size_t i = 0; i < pcount; i++) txnrec_free_owned(&pending[i]);
    free(pending);
    fclose(f);
    return true;
}

/* ============================================================
 * Version change log (.vlog) -- durable per-transaction diff history
 *
 * Wire format:
 *   header:  [POGV_MAGIC u32][POGV_VERSION u32]
 *   record:  [version u32][entry_count u32]
 *            entry_count * { [object_id u32][is_create u8][class_name:w_str] }
 *
 * One record per committed transaction that touched >=1 object.
 * WOP_BIND_ROOT/WOP_UNBIND_ROOT-only transactions produce no record and
 * do not bump the version. Append-only, never truncated by
 * store_checkpoint_unlocked (unlike the WAL) -- that's the whole point:
 * this history survives checkpoints.
 * ============================================================ */

typedef struct {
    uint32_t    object_id;
    bool        is_create;
    const char *class_name;   /* borrowed; "" if none/non-composite */
} VlogPendingEntry;

/* Build the deduplicated entry list for committed transaction t. Excludes
 * WOP_BIND_ROOT/WOP_UNBIND_ROOT (no target object). O(n^2) linear-scan
 * dedup -- matches this file's existing style for small bounded per-txn
 * record counts. class_name is read live from r->target->class_name: by
 * commit time every mutator has already applied its in-memory change
 * before calling log_push, so this is always the final post-commit value
 * regardless of which record for that object we read it from. Runs under
 * the store's wrlock with GC structurally forbidden while a txn is
 * active, so every r->target pointer is guaranteed live for the duration.
 * Returns false only on allocation failure (entries/out_count untouched;
 * any partial internal buffer already freed) -- caller must skip the
 * vlog write, warn, and continue (the txn is already durably committed). */
static bool vlog_build_entries(Txn *t, VlogPendingEntry **out, size_t *out_count)
{
    VlogPendingEntry *entries = NULL;
    size_t count = 0, cap = 0;

    for (size_t i = 0; i < t->count; i++) {
        TxnRec *r = &t->log[i];
        if (r->op == WOP_BIND_ROOT || r->op == WOP_UNBIND_ROOT) continue;
        if (!r->target) continue;

        size_t found = SIZE_MAX;
        for (size_t j = 0; j < count; j++)
            if (entries[j].object_id == r->target_id) { found = j; break; }
        if (found != SIZE_MAX) {
            entries[found].is_create = entries[found].is_create || r->is_create;
            continue;
        }

        if (count >= cap) {
            size_t nc, bytes;
            if (!next_cap(cap, 8, &nc) || !mul_bytes(nc, sizeof(*entries), &bytes)) {
                free(entries); return false;
            }
            VlogPendingEntry *a = realloc(entries, bytes);
            if (!a) { free(entries); return false; }
            entries = a; cap = nc;
        }
        entries[count].object_id  = r->target_id;
        entries[count].is_create  = r->is_create;
        entries[count].class_name =
            (r->target->kind == OBJ_COMPOSITE && r->target->class_name)
                ? r->target->class_name : "";
        count++;
    }

    *out = entries; *out_count = count;
    return true;
}

/* Write one .vlog record. No locking -- runs from txn_commit_unlocked_impl,
 * already under the active txn's wrlock, exactly like wal_write_txn.
 * Mirrors wal_write_txn's durability discipline (fflush + fsync). */
static bool vlog_write_record(Store *s, uint32_t version,
                              const VlogPendingEntry *entries, size_t count)
{
    if (!s->vlog_fp) return true;
    FILE *f = s->vlog_fp;

    bool ok = w_u32(f, version) && w_u32(f, (uint32_t)count);
    for (size_t i = 0; i < count && ok; i++) {
        ok = w_u32(f, entries[i].object_id) &&
             w_u8 (f, entries[i].is_create ? 1 : 0) &&
             w_str(f, entries[i].class_name);
    }
    if (!ok) return false;

    if (fflush(f) != 0) return false;
    int fd = fileno(f);
    if (fd >= 0 && fsync(fd) != 0) return false;
    return true;
}

typedef struct {
    uint32_t object_id;
    bool     is_create;
    char    *class_name;   /* owned */
} VlogRecEntry;

/* Same early-stop convention as query_fn (false to stop). class_name
 * borrowed, valid only for the duration of this call. */
typedef bool (*vlog_emit_fn)(void *ud, uint32_t version, uint32_t object_id,
                             bool is_create, const char *class_name);

/* Shared scan/parse core for .vlog, used by BOTH store_open (to determine
 * s->version and truncate a torn tail) and store_changes_since (to answer
 * a query) -- the one place this record format is parsed.
 *
 * f must be freshly opened at offset 0. since_version: entries with
 * version > since_version are emitted (0 = everything); only affects
 * what's passed to emit_entry -- max_version/good_end always reflect the
 * WHOLE valid prefix regardless. stop_after_version: if nonzero, stop
 * (cleanly) once a record with version >= stop_after_version has been
 * fully processed (0 = scan to EOF/torn-tail). emit_entry may be NULL
 * (store_open's use: only wants max_version/good_end/header_ok).
 *
 * Torn-tail handling mirrors wal_replay: a record is speculatively
 * buffered; only once ALL its entries parse successfully is it
 * "committed" (max_version/good_end advanced, emit_entry called). Any
 * failure partway discards that record's buffer and stops, without
 * having advanced good_end/max_version -- so *good_end always ends up
 * exactly at the byte offset just past the last fully-valid record,
 * letting the caller distinguish clean EOF (good_end == file size) from
 * a torn tail (good_end < file size), same comparison store_open already
 * makes for the WAL.
 *
 * *header_ok is false iff the magic/version header itself didn't parse.
 * Never fails otherwise; an empty/header-only file yields max_version=0. */
static void vlog_scan(FILE *f, uint32_t since_version, uint32_t stop_after_version,
                      vlog_emit_fn emit_entry, void *ud,
                      uint32_t *max_version, long *good_end, bool *header_ok)
{
    *max_version = 0; *good_end = 0; *header_ok = false;

    uint32_t magic, ver;
    if (!r_u32(f, &magic) || magic != POGV_MAGIC ||
        !r_u32(f, &ver)   || ver   != POGV_VERSION) {
        return;
    }
    *header_ok = true;
    *good_end = ftell(f);

    bool stop_requested = false;
    for (;;) {
        uint32_t version, count;
        if (!r_u32(f, &version) || !r_u32(f, &count)) break;
        if (count > POG_MAX_TXN_RECS_REPLAY) break;

        VlogRecEntry *buf = NULL;
        size_t bcap = 0;
        bool ok = true;
        uint32_t i;
        for (i = 0; i < count && ok; i++) {
            uint32_t oid; uint8_t isc; char *cls;
            if (!r_u32(f, &oid) || !r_u8(f, &isc)) { ok = false; break; }
            cls = r_str(f);
            if (!cls) { ok = false; break; }
            if (i >= bcap) {
                size_t nc, bytes;
                if (!next_cap(bcap, 8, &nc) || !mul_bytes(nc, sizeof(*buf), &bytes)) {
                    free(cls); ok = false; break;
                }
                VlogRecEntry *a = realloc(buf, bytes);
                if (!a) { free(cls); ok = false; break; }
                buf = a; bcap = nc;
            }
            buf[i].object_id = oid; buf[i].is_create = (isc != 0); buf[i].class_name = cls;
        }

        if (!ok) {
            for (uint32_t j = 0; j < i; j++) free(buf[j].class_name);
            free(buf);
            break;
        }

        if (version > *max_version) *max_version = version;

        if (emit_entry && version > since_version) {
            for (uint32_t j = 0; j < count; j++) {
                if (!emit_entry(ud, version, buf[j].object_id, buf[j].is_create,
                                buf[j].class_name)) {
                    stop_requested = true;
                    break;
                }
            }
        }
        for (uint32_t j = 0; j < count; j++) free(buf[j].class_name);
        free(buf);

        *good_end = ftell(f);

        if (stop_requested) break;
        if (stop_after_version != 0 && version >= stop_after_version) break;
    }
}

/* ============================================================
 * Transactions
 * ============================================================ */

static bool txn_begin_unlocked_impl(Store *s)
{
    if (!s || s->active_txn) return false;
    Txn *t = calloc(1, sizeof(*t));
    if (!t) return false;
    t->id = s->next_txn_id++;
    t->begin_obj_count = s->count;
    t->begin_next_id = s->next_id;
    t->begin_root_count = s->root_count;
    s->active_txn = t;
    s->txn_owner = pthread_self();
    return true;
}

bool txn_active(Store *s) { return s && s->active_txn != NULL; }

static bool txn_commit_unlocked_impl(Store *s)
{
    if (!s || !s->active_txn) return false;
    Txn *t = s->active_txn;

    bool ok = true;
    if (s->wal_fp) ok = wal_write_txn(s, t);

    if (!ok) {
        /* WAL failed: auto-abort so memory matches disk. Must call the
         * _unlocked variant — this function runs inside an already-locked
         * public mutator/txn_commit and must never touch the store lock. */
        txn_abort_unlocked_impl(s);
        return false;
    }

    /* Version change log: one record per committed txn that touched >=1
     * object. Best-effort only -- the txn is already durably WAL-committed
     * above, so a vlog failure here must NOT fail/abort it; the version is
     * simply not advanced, and the next successful write retries the same
     * version number. */
    if (s->vlog_fp) {
        VlogPendingEntry *entries = NULL;
        size_t entry_count = 0;
        if (!vlog_build_entries(t, &entries, &entry_count)) {
            fprintf(stderr, "pog: version log entry build failed for txn %u "
                            "(out of memory) -- version not advanced\n", t->id);
        } else {
            if (entry_count > 0) {
                uint32_t candidate = s->version + 1;
                if (vlog_write_record(s, candidate, entries, entry_count)) {
                    s->version = candidate;
                } else {
                    fprintf(stderr, "pog: version log write failed for txn %u "
                                    "-- version not advanced\n", t->id);
                }
            }
            free(entries);
        }
    }

    for (size_t i = 0; i < t->count; i++) txnrec_free_owned(&t->log[i]);
    free(t->log);
    free(t);
    s->active_txn = NULL;
    return true;
}

/* Apply one undo record — only called during abort. */
static void apply_undo(Store *s, TxnRec *r)
{
    (void)s;
    switch (r->op) {
    case WOP_SET_INT:
        if (r->target && r->target->kind == OBJ_INT)
            r->target->int_value = r->old_int;
        break;
    case WOP_SET_STR:
        if (r->target && r->target->kind == OBJ_STRING) {
            free(r->target->str_value);
            r->target->str_value = r->old_str; r->old_str = NULL;
        }
        break;
    case WOP_SET_BYTES:
        if (r->target && r->target->kind == OBJ_BYTES) {
            free(r->target->bytes.data);
            r->target->bytes.data = r->old_bytes; r->old_bytes = NULL;
            r->target->bytes.len  = r->old_bytes_len;
        }
        break;
    case WOP_SET_FIELD: {
        if (!r->target || r->target->kind != OBJ_COMPOSITE) break;
        if (r->had_prev) {
            Field *fld = find_field(r->target, r->key);
            if (fld) fld->value = r->old_ref;
        } else {
            /* new field — find by key, remove (may not be last if other ops
             * inserted fields on the same object later, but we undo in
             * reverse order so it WILL be last by now) */
            size_t n = r->target->composite.count;
            for (size_t i = n; i > 0; i--) {
                if (strncmp(r->target->composite.items[i-1].key, r->key,
                            POG_MAX_KEY_LEN) == 0) {
                    memmove(&r->target->composite.items[i-1],
                            &r->target->composite.items[i],
                            (n - i) * sizeof(Field));
                    r->target->composite.count--;
                    break;
                }
            }
        }
        break;
    }
    case WOP_LIST_APPEND:
        if (r->target && r->target->kind == OBJ_LIST && r->target->list.count > 0)
            r->target->list.count--;
        break;
    case WOP_LIST_SET:
        if (r->target && r->target->kind == OBJ_LIST && r->index < r->target->list.count)
            r->target->list.items[r->index] = r->old_ref;
        break;
    case WOP_LIST_INSERT:
        if (r->target && r->target->kind == OBJ_LIST && r->index < r->target->list.count) {
            memmove(&r->target->list.items[r->index],
                    &r->target->list.items[r->index + 1],
                    (r->target->list.count - r->index - 1) * sizeof(Object*));
            r->target->list.count--;
        }
        break;
    case WOP_LIST_REMOVE:
        if (r->target && r->target->kind == OBJ_LIST) {
            if (!list_grow(r->target)) break;
            memmove(&r->target->list.items[r->index + 1],
                    &r->target->list.items[r->index],
                    (r->target->list.count - r->index) * sizeof(Object*));
            r->target->list.items[r->index] = r->old_ref;
            r->target->list.count++;
        }
        break;
    case WOP_BIND_ROOT: {
        Root *ex = find_root(s, r->key);
        if (r->had_prev) {
            if (ex) ex->obj = r->old_ref;
        } else {
            /* was new — mark unused */
            for (size_t i = 0; i < s->root_count; i++) {
                if (s->roots[i].used &&
                    strncmp(s->roots[i].name, r->key, POG_MAX_ROOT_NAME) == 0) {
                    s->roots[i].used = false;
                    s->roots[i].obj = NULL;
                    break;
                }
            }
        }
        break;
    }
    case WOP_UNBIND_ROOT: {
        /* previously used; restore */
        for (size_t i = 0; i < s->root_count; i++) {
            if (!s->roots[i].used &&
                strncmp(s->roots[i].name, r->key, POG_MAX_ROOT_NAME) == 0) {
                s->roots[i].used = true;
                s->roots[i].obj = r->old_ref;
                break;
            }
        }
        break;
    }
    case WOP_SET_CLASS: {
        /* Undo: revert class_name to old_str (NULL-safe), fix up index.
         * Current tag is r->new_str (may be NULL/empty meaning untag was
         * the new state). Old tag is r->old_str (NULL if previously
         * untagged). */
        if (!r->target || r->target->kind != OBJ_COMPOSITE) break;
        /* Remove from current class's list */
        if (r->target->class_name) {
            size_t ci = class_find_idx(s, r->target->class_name);
            if (ci != SIZE_MAX) class_list_remove(s, ci, r->target);
        }
        free(r->target->class_name);
        r->target->class_name = NULL;
        /* Restore old */
        if (r->had_prev && r->old_str && *r->old_str) {
            r->target->class_name = strdup(r->old_str);
            if (r->target->class_name) {
                size_t oi = class_get_or_create(s, r->old_str);
                if (oi != SIZE_MAX) class_list_append(s, oi, r->target);
            }
        }
        break;
    }
    /* Create ops handled by bulk rewind below; no per-record undo */
    }
}

static bool txn_abort_unlocked_impl(Store *s)
{
    if (!s || !s->active_txn) return false;
    Txn *t = s->active_txn;

    /* Apply undo in reverse order (skip creates) */
    for (ssize_t i = (ssize_t)t->count - 1; i >= 0; i--) {
        TxnRec *r = &t->log[i];
        if (!r->is_create) apply_undo(s, r);
    }

    /* Bulk-rewind: free any objects created after begin */
    for (size_t i = t->begin_obj_count; i < s->count; i++)
        free_object(s->objects[i]);
    s->count   = t->begin_obj_count;
    s->next_id = t->begin_next_id;

    /* Any class-index entries for the freed objects are now dangling.
     * Rebuild the index from surviving object state. */
    class_index_rebuild(s);
    index_rebuild_all(s);
    ord_index_rebuild_all(s);

    /* Roots added after begin should be dropped (unused marker) — but our
     * undo already marks them unused. Also shrink root_count to drop any
     * fresh appended roots. */
    while (s->root_count > t->begin_root_count) {
        Root *r = &s->roots[s->root_count - 1];
        if (!r->used) s->root_count--;
        else break;
    }

    for (size_t i = 0; i < t->count; i++) txnrec_free_owned(&t->log[i]);
    free(t->log);
    free(t);
    s->active_txn = NULL;
    return true;
}

/* ============================================================
 * Persistent store lifecycle
 * ============================================================ */

static char *path_append(const char *base, const char *suffix)
{
    size_t n = strlen(base) + strlen(suffix) + 1;
    char *p = malloc(n);
    if (!p) return NULL;
    snprintf(p, n, "%s%s", base, suffix);
    return p;
}

static bool wal_open_append(Store *s, uint32_t baseline)
{
    char *wp = path_append(s->path, ".wal");
    if (!wp) return false;

    /* Does file exist? */
    struct stat st;
    bool exists = (stat(wp, &st) == 0) && st.st_size > 0;

    FILE *f = fopen(wp, exists ? "r+b" : "wb");
    if (!f) { free(wp); return false; }

    if (exists) {
        fseek(f, 0, SEEK_END);
    } else {
        if (!w_u32(f, POGW_MAGIC) || !w_u32(f, POGW_VERSION) ||
            !w_u32(f, baseline)) {
            fclose(f); free(wp); return false;
        }
        fflush(f);
        int fd = fileno(f);
        if (fd >= 0) fsync(fd);
    }
    s->wal_fp = f;
    free(wp);
    return true;
}

Store *store_open(const char *path)
{
    return store_open_flags(path, 0);
}

Store *store_open_flags(const char *path, unsigned flags)
{
    if (!path) return NULL;
    pog_register_builtins();

    /* 0) Acquire exclusive process lock on a dedicated ".lock" file
     *    next to the snapshot. We use a separate file so the flock
     *    survives checkpoint's atomic rename of the snapshot. */
    char *lockpath = path_append(path, ".lock");
    if (!lockpath) return NULL;
    int lfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (lfd < 0) { free(lockpath); return NULL; }
    if (flock(lfd, LOCK_EX | LOCK_NB) != 0) {
        /* another process holds the lock */
        close(lfd); free(lockpath);
        errno = EWOULDBLOCK;
        return NULL;
    }
    free(lockpath);

    /* 1) Load snapshot if it exists; else start fresh. */
    Store *s = NULL;
    struct stat st;
    if (stat(path, &st) == 0) {
        s = load(path);
        if (!s) { close(lfd); return NULL; }
    } else {
        s = store_create();
        if (!s) { close(lfd); return NULL; }
        s->seq = 1;
    }
    s->lock_fd = lfd;
    s->path = strdup(path);
    if (!s->path) { store_destroy(s); return NULL; }

    /* 2) Replay WAL if present and baseline matches. */
    char *wp = path_append(path, ".wal");
    if (!wp) { store_destroy(s); return NULL; }

    IdMap map = {0};
    bool seed_ok = true;
    for (size_t i = 0; i < s->count && seed_ok; i++)
        seed_ok = idmap_put(&map, s->objects[i]->id, s->objects[i]);

    long good_end = 0;
    bool replay_ok = seed_ok && wal_replay(s, wp, &map, &good_end);
    free(map.items);

    if (!replay_ok) {
        free(wp); store_destroy(s); return NULL;
    }

    /* WAL replay may have created newly-tagged composites; rebuild index. */
    class_index_rebuild(s);
    index_rebuild_all(s);
    ord_index_rebuild_all(s);

    /* 3) Truncate any torn tail from WAL so new writes append cleanly. */
    if (stat(wp, &st) == 0 && good_end > 0 && good_end < st.st_size) {
        int fd = open(wp, O_RDWR);
        if (fd >= 0) {
            if (ftruncate(fd, good_end) != 0) { /* best effort */ }
            close(fd);
        }
    }

    /* 4) Open WAL for append (or create with snapshot's seq as baseline). */
    if (!wal_open_append(s, s->seq)) {
        free(wp); store_destroy(s); return NULL;
    }
    free(wp);

    /* 5) Open/bootstrap/scan/truncate .vlog -- separate, dedicated,
     * never-checkpoint-truncated durable artifact. Skipped entirely under
     * POG_OPEN_NO_VLOG: vlog_fp stays NULL, which every vlog writer/reader
     * already treats as "no change log" (version stays 0). */
    if (flags & POG_OPEN_NO_VLOG) {
        if (s->next_id == 0) s->next_id = 1;
        if (s->next_txn_id == 0) s->next_txn_id = 1;
        return s;
    }
    char *vp = path_append(path, ".vlog");
    if (!vp) { store_destroy(s); return NULL; }

    /* Mirrors wal_open_append's exact st.st_size > 0 condition, not just
     * "stat succeeds" -- correctly re-bootstraps a header if a prior
     * crash left a zero-length file. */
    bool vlog_exists = (stat(vp, &st) == 0) && st.st_size > 0;
    if (!vlog_exists) {
        FILE *hf = fopen(vp, "wb");
        if (!hf || !w_u32(hf, POGV_MAGIC) || !w_u32(hf, POGV_VERSION)) {
            if (hf) fclose(hf);
            free(vp); store_destroy(s); return NULL;
        }
        fflush(hf);
        { int hfd = fileno(hf); if (hfd >= 0) fsync(hfd); }
        fclose(hf);
    }

    FILE *vf = fopen(vp, "rb");
    if (!vf) { free(vp); store_destroy(s); return NULL; }
    uint32_t v_max_version; long v_good_end; bool v_header_ok;
    vlog_scan(vf, 0, 0, NULL, NULL, &v_max_version, &v_good_end, &v_header_ok);
    fclose(vf);
    if (!v_header_ok) { free(vp); store_destroy(s); return NULL; }
    s->version = v_max_version;

    /* Truncate any torn tail -- same pattern as the WAL truncation above. */
    if (stat(vp, &st) == 0 && v_good_end > 0 && v_good_end < st.st_size) {
        int fd = open(vp, O_RDWR);
        if (fd >= 0) {
            if (ftruncate(fd, v_good_end) != 0) { /* best effort */ }
            close(fd);
        }
    }

    FILE *vaf = fopen(vp, "r+b");
    if (!vaf) { free(vp); store_destroy(s); return NULL; }
    fseek(vaf, 0, SEEK_END);
    s->vlog_fp = vaf;
    free(vp);

    if (s->next_id == 0) s->next_id = 1;
    if (s->next_txn_id == 0) s->next_txn_id = 1;
    return s;
}

static bool store_checkpoint_unlocked(Store *s)
{
    if (!s || !s->path) return false;
    if (s->active_txn) return false;

    /* bump seq, write new snapshot atomically */
    s->seq += 1;
    char *tmp = path_append(s->path, ".tmp");
    if (!tmp) { s->seq -= 1; return false; }

    if (!save(s, tmp)) { free(tmp); s->seq -= 1; return false; }
    if (rename(tmp, s->path) != 0) { free(tmp); s->seq -= 1; return false; }
    free(tmp);

    /* close and recreate WAL with new baseline */
    if (s->wal_fp) { fclose(s->wal_fp); s->wal_fp = NULL; }

    char *wp = path_append(s->path, ".wal");
    if (!wp) return false;
    /* truncate + write fresh header */
    FILE *f = fopen(wp, "wb");
    if (!f) { free(wp); return false; }
    bool ok = w_u32(f, POGW_MAGIC) && w_u32(f, POGW_VERSION) &&
              w_u32(f, s->seq);
    fflush(f);
    int fd = fileno(f);
    if (fd >= 0) fsync(fd);
    fclose(f);
    if (!ok) { free(wp); return false; }

    /* reopen for append */
    bool r = wal_open_append(s, s->seq);
    free(wp);
    return r;
}

bool store_checkpoint(Store *s)
{
    if (!s) return false;
    pthread_rwlock_wrlock(&s->lock);
    bool ok = store_checkpoint_unlocked(s);
    pthread_rwlock_unlock(&s->lock);
    return ok;
}

/* ============================================================
 * Built-in CIDR generators (IPv4 + IPv6)
 * ============================================================
 *
 * Registered generators:
 *   cidr.all     — host addresses in a network
 *   cidr.free    — unassigned host addresses
 *   cidr.subnets — child subnets at a given prefix length
 *
 * Family is detected from the prefix string: dotted quad → IPv4,
 * colon notation → IPv6. Mixed notation (::ffff:1.2.3.4) is accepted
 * on input but output uses pure v6 form.
 *
 * Expected params fields:
 *   prefix       — OBJ_STRING, parent prefix
 *   bits         — OBJ_INT, parent prefix length (0..32 for v4, 0..128 for v6)
 *   assigned     — (cidr.free only) OBJ_LIST of OBJ_STRING addresses
 *   subnet_bits  — (cidr.subnets only) OBJ_INT, child prefix length;
 *                  must be >= bits and <= max for family
 *
 * Conventions:
 *   - For /N where N <= max-2, network and broadcast addresses are
 *     excluded from cidr.all/free host enumeration.
 *   - For /31, /32 (v4) and /127, /128 (v6), all addresses are usable.
 *   - Enumeration is capped at 2^24 items (POG_VLIST_MAX_ENUM). Requests
 *     exceeding the cap return length 0 — write a specialized generator
 *     for larger ranges.
 *   - Host bits in the prefix are masked away (e.g. 192.168.1.250/24 is
 *     normalized to 192.168.1.0/24).
 */

#define POG_VLIST_MAX_ENUM (1u << 24)

typedef __uint128_t pog_u128;

typedef struct {
    int       family;   /* 4 or 6 */
    pog_u128  v;        /* host-order value; v4 uses only low 32 bits */
} pog_ip;

/* ---------- IPv4 parse / format ---------- */

static bool pog_parse_ipv4(const char *s, uint32_t *out)
{
    if (!s) return false;
    uint32_t ip = 0;
    for (int i = 0; i < 4; i++) {
        if (!*s) return false;
        int octet = 0, digits = 0;
        while (*s >= '0' && *s <= '9') {
            octet = octet * 10 + (*s - '0');
            if (octet > 255) return false;
            s++; digits++;
            if (digits > 3) return false;
        }
        if (digits == 0) return false;
        ip = (ip << 8) | (uint32_t)octet;
        if (i < 3) {
            if (*s != '.') return false;
            s++;
        }
    }
    if (*s != '\0') return false;
    *out = ip;
    return true;
}

static void pog_format_ipv4(uint32_t ip, char *buf, size_t n)
{
    snprintf(buf, n, "%u.%u.%u.%u",
             (ip >> 24) & 0xff, (ip >> 16) & 0xff,
             (ip >>  8) & 0xff,  ip        & 0xff);
}

/* ---------- IPv6 parse ---------- */

static int pog_hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

/* Parse an IPv6 address. Accepts canonical form, `::` compression,
 * and a trailing v4 dotted quad for the low 32 bits. */
static bool pog_parse_ipv6(const char *s, pog_u128 *out)
{
    if (!s) return false;
    uint16_t head[8] = {0};
    uint16_t tail[8] = {0};
    int head_n = 0, tail_n = 0;
    bool have_dc = false;
    uint16_t *cur = head;
    int      *curN = &head_n;

    /* leading "::" */
    if (s[0] == ':') {
        if (s[1] != ':') return false;         /* ':x...' invalid */
        have_dc = true;
        cur = tail; curN = &tail_n;
        s += 2;
        if (*s == '\0') { *out = 0; return true; }
    }

    for (;;) {
        /* look ahead: if we hit a '.' before the next ':' or end, this
         * group is actually the start of an embedded v4 suffix. */
        bool v4_suffix = false;
        for (const char *q = s; *q; q++) {
            if (*q == '.') { v4_suffix = true; break; }
            if (*q == ':') break;
        }
        if (v4_suffix) {
            uint32_t v4;
            if (!pog_parse_ipv4(s, &v4)) return false;
            if (*curN > 6) return false;       /* need room for 2 groups */
            cur[(*curN)++] = (uint16_t)(v4 >> 16);
            cur[(*curN)++] = (uint16_t)(v4 & 0xffff);
            break;
        }

        /* parse one hex group (1..4 digits) */
        int digits = 0;
        uint32_t g = 0;
        while (*s && *s != ':') {
            int d = pog_hex_digit(*s);
            if (d < 0) return false;
            g = (g << 4) | (uint32_t)d;
            if (++digits > 4) return false;
            s++;
        }
        if (digits == 0) return false;
        if (*curN >= 8) return false;
        cur[(*curN)++] = (uint16_t)g;

        if (*s == '\0') break;
        /* *s == ':' */
        s++;
        if (*s == ':') {
            if (have_dc) return false;          /* second :: forbidden */
            have_dc = true;
            cur = tail; curN = &tail_n;
            s++;
            if (*s == '\0') break;              /* trailing :: */
        } else if (*s == '\0') {
            return false;                       /* trailing single : */
        }
    }

    int total = head_n + tail_n;
    if (have_dc) {
        if (total > 7) return false;            /* :: must skip >=1 */
    } else {
        if (total != 8) return false;
    }

    uint16_t full[8] = {0};
    for (int i = 0; i < head_n; i++)         full[i] = head[i];
    for (int i = 0; i < tail_n; i++)         full[8 - tail_n + i] = tail[i];

    pog_u128 r = 0;
    for (int i = 0; i < 8; i++)
        r = (r << 16) | (pog_u128)full[i];
    *out = r;
    return true;
}

/* ---------- IPv6 format (RFC 5952) ---------- */

static void pog_format_ipv6(pog_u128 ip, char *buf, size_t n)
{
    uint16_t g[8];
    for (int i = 0; i < 8; i++)
        g[i] = (uint16_t)(ip >> (16 * (7 - i)));

    /* Find longest run of zero groups (length >= 2), leftmost on ties. */
    int best_s = -1, best_l = 0;
    int cur_s  = -1, cur_l  = 0;
    for (int i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (cur_s < 0) cur_s = i;
            cur_l++;
            if (cur_l > best_l) { best_s = cur_s; best_l = cur_l; }
        } else {
            cur_s = -1; cur_l = 0;
        }
    }
    if (best_l < 2) { best_s = -1; best_l = 0; }

    if (n == 0) return;
    char *out = buf;
    char *end = buf + n - 1;        /* reserve 1 byte for NUL */
    bool need_sep = false;
    for (int i = 0; i < 8; ) {
        if (i == best_s) {
            /* Always two colons: first is the separator from previous
             * group (or leading colon for position 0), second marks the
             * start of the compressed zero-run. Trailing :: works because
             * after this the loop exits. */
            if (out < end) *out++ = ':';
            if (out < end) *out++ = ':';
            i += best_l;
            need_sep = false;
            continue;
        }
        if (need_sep && out < end) *out++ = ':';
        char tmp[8];
        int w = snprintf(tmp, sizeof(tmp), "%x", g[i]);
        for (int k = 0; k < w && out < end; k++) *out++ = tmp[k];
        need_sep = true;
        i++;
    }
    *out = '\0';
}

/* ---------- family dispatchers ---------- */

static bool pog_parse_ip(const char *s, pog_ip *out)
{
    if (!s) return false;
    /* If any colon, it's v6. Else if any dot, v4. Else invalid. */
    if (strchr(s, ':')) {
        pog_u128 v;
        if (!pog_parse_ipv6(s, &v)) return false;
        out->family = 6; out->v = v;
        return true;
    }
    if (strchr(s, '.')) {
        uint32_t v;
        if (!pog_parse_ipv4(s, &v)) return false;
        out->family = 4; out->v = (pog_u128)v;
        return true;
    }
    return false;
}

static void pog_format_ip(const pog_ip *a, char *buf, size_t n)
{
    if (!a || n == 0) { if (n) buf[0] = '\0'; return; }
    if (a->family == 4) pog_format_ipv4((uint32_t)a->v, buf, n);
    else                 pog_format_ipv6(a->v, buf, n);
}

/* ---------- CIDR primitives (family-agnostic) ---------- */

/* Apply the /bits netmask to base->v (in place). */
static void pog_apply_mask(pog_ip *base, int bits)
{
    int max_bits = (base->family == 4) ? 32 : 128;
    pog_u128 mask;
    if (bits == 0)              mask = 0;
    else if (bits >= max_bits)  mask = ~(pog_u128)0;
    else                        mask = (~(pog_u128)0) << (max_bits - bits);
    /* For v4, the top 96 bits of base->v are already 0, so the wide mask
     * still produces the right answer. */
    base->v &= mask;
}

static bool cidr_get_net(Object *params, pog_ip *base, int *bits_out)
{
    if (!params || params->kind != OBJ_COMPOSITE) return false;
    Object *pf = get_field_unlocked(params, "prefix");
    Object *bf = get_field_unlocked(params, "bits");
    if (!pf || pf->kind != OBJ_STRING) return false;
    if (!bf || bf->kind != OBJ_INT)    return false;
    int bits = (int)bf->int_value;
    pog_ip raw;
    if (!pog_parse_ip(pf->str_value, &raw)) return false;
    int max_bits = (raw.family == 4) ? 32 : 128;
    if (bits < 0 || bits > max_bits) return false;
    pog_apply_mask(&raw, bits);
    *base = raw;
    *bits_out = bits;
    return true;
}

static size_t cidr_host_count(int family, int bits)
{
    int max_bits = (family == 4) ? 32 : 128;
    if (bits < 0 || bits > max_bits) return 0;
    int host_bits = max_bits - bits;
    if (host_bits > 24) return 0;                 /* exceeds enum cap */
    uint64_t total = 1ULL << host_bits;
    if (bits >= max_bits - 1) return (size_t)total;
    return (size_t)(total - 2);
}

static bool cidr_nth_ip(Object *params, size_t i, pog_ip *out)
{
    pog_ip base; int bits;
    if (!cidr_get_net(params, &base, &bits)) return false;
    int max_bits = (base.family == 4) ? 32 : 128;
    if (i >= cidr_host_count(base.family, bits)) return false;
    pog_u128 offset = (bits >= max_bits - 1) ? (pog_u128)i : (pog_u128)(i + 1);
    out->family = base.family;
    out->v      = base.v + offset;
    return true;
}

static bool cidr_is_assigned(Object *assigned, const pog_ip *target)
{
    if (!assigned || assigned->kind != OBJ_LIST) return false;
    for (size_t j = 0; j < assigned->list.count; j++) {
        Object *a = assigned->list.items[j];
        if (!a || a->kind != OBJ_STRING || !a->str_value) continue;
        pog_ip ai;
        if (!pog_parse_ip(a->str_value, &ai)) continue;
        if (ai.family == target->family && ai.v == target->v) return true;
    }
    return false;
}

/* ---------- cidr.all ---------- */

static size_t cidr_all_len(Object *self)
{
    pog_ip base; int bits;
    if (!cidr_get_net(self->vlist.params, &base, &bits)) return 0;
    return cidr_host_count(base.family, bits);
}

static Object *cidr_all_at(Object *self, size_t i)
{
    pog_ip ip;
    if (!cidr_nth_ip(self->vlist.params, i, &ip)) return NULL;
    char buf[48];
    pog_format_ip(&ip, buf, sizeof(buf));
    return pog_vlist_emit_string(self, buf);
}

const VListOps pog_cidr_all = {
    .type_name = "cidr.all",
    .len       = cidr_all_len,
    .at        = cidr_all_at,
};

/* ---------- cidr.free ---------- */

static size_t cidr_free_len(Object *self)
{
    Object *params = self->vlist.params;
    pog_ip base; int bits;
    if (!cidr_get_net(params, &base, &bits)) return 0;
    Object *assigned = get_field_unlocked(params, "assigned");
    size_t total = cidr_host_count(base.family, bits);
    if (!assigned) return total;

    int max_bits = (base.family == 4) ? 32 : 128;
    size_t free_count = 0;
    for (size_t k = 0; k < total; k++) {
        pog_u128 offset = (bits >= max_bits - 1) ? (pog_u128)k : (pog_u128)(k + 1);
        pog_ip probe = { base.family, base.v + offset };
        if (!cidr_is_assigned(assigned, &probe)) free_count++;
    }
    return free_count;
}

static Object *cidr_free_at(Object *self, size_t i)
{
    Object *params = self->vlist.params;
    pog_ip base; int bits;
    if (!cidr_get_net(params, &base, &bits)) return NULL;
    Object *assigned = get_field_unlocked(params, "assigned");
    size_t total = cidr_host_count(base.family, bits);
    int max_bits = (base.family == 4) ? 32 : 128;

    size_t found = 0;
    for (size_t k = 0; k < total; k++) {
        pog_u128 offset = (bits >= max_bits - 1) ? (pog_u128)k : (pog_u128)(k + 1);
        pog_ip probe = { base.family, base.v + offset };
        if (!cidr_is_assigned(assigned, &probe)) {
            if (found == i) {
                char buf[48];
                pog_format_ip(&probe, buf, sizeof(buf));
                return pog_vlist_emit_string(self, buf);
            }
            found++;
        }
    }
    return NULL;
}

const VListOps pog_cidr_free = {
    .type_name = "cidr.free",
    .len       = cidr_free_len,
    .at        = cidr_free_at,
};

/* ---------- cidr.subnets ---------- */

static bool cidr_subnets_params(Object *params, pog_ip *base,
                                int *parent_bits, int *subnet_bits)
{
    if (!cidr_get_net(params, base, parent_bits)) return false;
    Object *sb = get_field_unlocked(params, "subnet_bits");
    if (!sb || sb->kind != OBJ_INT) return false;
    int max_bits = (base->family == 4) ? 32 : 128;
    int sbv = (int)sb->int_value;
    if (sbv < *parent_bits || sbv > max_bits) return false;
    *subnet_bits = sbv;
    return true;
}

static size_t cidr_subnets_len(Object *self)
{
    pog_ip base; int parent_bits, subnet_bits;
    if (!cidr_subnets_params(self->vlist.params, &base, &parent_bits, &subnet_bits))
        return 0;
    int step = subnet_bits - parent_bits;
    if (step > 24) return 0;
    return (size_t)(1ULL << step);
}

static Object *cidr_subnets_at(Object *self, size_t i)
{
    pog_ip base; int parent_bits, subnet_bits;
    if (!cidr_subnets_params(self->vlist.params, &base, &parent_bits, &subnet_bits))
        return NULL;
    int step = subnet_bits - parent_bits;
    if (step > 24) return NULL;
    pog_u128 count = (pog_u128)1 << step;
    if ((pog_u128)i >= count) return NULL;

    int max_bits = (base.family == 4) ? 32 : 128;
    pog_u128 offset = 0;
    if (step > 0 && max_bits - subnet_bits < 128) {
        offset = (pog_u128)i << (max_bits - subnet_bits);
    }
    pog_ip sub = { base.family, base.v + offset };

    char ip_buf[48];
    pog_format_ip(&sub, ip_buf, sizeof(ip_buf));
    char buf[64];
    snprintf(buf, sizeof(buf), "%s/%d", ip_buf, subnet_bits);
    return pog_vlist_emit_string(self, buf);
}

const VListOps pog_cidr_subnets = {
    .type_name = "cidr.subnets",
    .len       = cidr_subnets_len,
    .at        = cidr_subnets_at,
};

/* ---------- dns.ancestors / dns.wildcards ---------- */

static bool dns_get_name(Object *params, const char **out)
{
    if (!params || params->kind != OBJ_COMPOSITE) return false;
    Object *nf = get_field_unlocked(params, "name");
    if (!nf || nf->kind != OBJ_STRING) return false;
    *out = nf->str_value ? nf->str_value : "";
    return true;
}

static size_t dns_label_count(const char *name)
{
    if (!name || !*name) return 0;
    size_t n = 1;
    for (const char *p = name; *p; p++) if (*p == '.') n++;
    return n;
}

/* Suffix after skipping `skip` leading labels; skip == label_count lands
 * exactly on the trailing NUL (""), since the last label has no dot. */
static const char *dns_skip_labels(const char *name, size_t skip)
{
    const char *p = name;
    for (size_t i = 0; i < skip; i++) {
        const char *dot = strchr(p, '.');
        if (!dot) return p + strlen(p);
        p = dot + 1;
    }
    return p;
}

static size_t dns_ancestors_len(Object *self)
{
    const char *name;
    if (!dns_get_name(self->vlist.params, &name)) return 0;
    return dns_label_count(name) + 1;
}

static Object *dns_ancestors_at(Object *self, size_t i)
{
    const char *name;
    if (!dns_get_name(self->vlist.params, &name)) return NULL;
    if (i > dns_label_count(name)) return NULL;
    return pog_vlist_emit_string(self, dns_skip_labels(name, i));
}

const VListOps pog_dns_ancestors = {
    .type_name = "dns.ancestors",
    .len       = dns_ancestors_len,
    .at        = dns_ancestors_at,
};

static size_t dns_wildcards_len(Object *self)
{
    const char *name;
    if (!dns_get_name(self->vlist.params, &name)) return 0;
    size_t lc = dns_label_count(name);
    return (lc >= 1) ? lc - 1 : 0;   /* guarded — size_t underflow otherwise */
}

static Object *dns_wildcards_at(Object *self, size_t i)
{
    const char *name;
    if (!dns_get_name(self->vlist.params, &name)) return NULL;
    size_t lc = dns_label_count(name);
    size_t wlen = (lc >= 1) ? lc - 1 : 0;
    if (i >= wlen) return NULL;
    const char *suffix = dns_skip_labels(name, i + 1);
    size_t n = 2 + strlen(suffix) + 1;
    char *buf = malloc(n);
    if (!buf) return NULL;
    snprintf(buf, n, "*.%s", suffix);
    Object *r = pog_vlist_emit_string(self, buf);
    free(buf);
    return r;
}

const VListOps pog_dns_wildcards = {
    .type_name = "dns.wildcards",
    .len       = dns_wildcards_len,
    .at        = dns_wildcards_at,
};

/* ---------- registration ---------- */

void pog_register_builtins(void)
{
    if (g_builtins_registered) return;
    g_builtins_registered = true;
    pog_register_vlist_type(&pog_cidr_all);
    pog_register_vlist_type(&pog_cidr_free);
    pog_register_vlist_type(&pog_cidr_subnets);
    pog_register_vlist_type(&pog_dns_ancestors);
    pog_register_vlist_type(&pog_dns_wildcards);
}

/* ============================================================
 * Class tag mutators (unlocked core)
 *
 * set_class(o, name):
 *   - removes o from its current class's instance list (if any)
 *   - sets o->class_name to name
 *   - inserts o into the new class's instance list
 *   - logs a WOP_SET_CLASS record for txn replay/undo
 *
 * unset_class(o): equivalent to set_class(o, NULL).
 * ============================================================ */

static bool set_class_unlocked_impl(Object *o, const char *new_name)
{
    if (!o || o->kind != OBJ_COMPOSITE) return false;
    Store *s = o->store;
    if (!s) return false;

    /* Normalize: NULL and "" both mean "untag" */
    bool want_tag = (new_name && *new_name);
    const char *old_name = o->class_name;   /* borrowed */

    /* No-op if the class is unchanged */
    if (!want_tag && !old_name) return true;
    if (want_tag && old_name && strcmp(old_name, new_name) == 0) return true;

    bool started;
    if (!auto_begin(s, &started)) return false;

    /* Secondary-index maintenance, phase 1: speculatively insert o into
     * every index declared on the NEW class, before touching class_name
     * or the class-membership lists at all. A mid-loop failure then only
     * needs a bounded partial-unwind of this same loop — no interaction
     * with the class-list unwind cascade below. */
    if (want_tag) {
        size_t failed_at = SIZE_MAX;
        for (size_t i = 0; i < s->index_count; i++) {
            PogIndex *idx = &s->indexes[i];
            if (strcmp(idx->cls, new_name) != 0) continue;
            Field *f = find_field(o, idx->field);
            if (!f || !f->value || f->value->kind != OBJ_STRING) continue;
            if (!index_insert_unlocked(idx, f->value->str_value, o)) { failed_at = i; break; }
        }
        if (failed_at != SIZE_MAX) {
            index_unwind_class_inserts(s, failed_at, new_name, o);
            auto_end(s, started, false);
            return false;
        }

        /* Same speculative-insert pass for the ordered index, run only
         * after the hash-index loop above fully succeeded. A mid-loop
         * failure here must unwind its own bounded partial insert AND the
         * hash-index loop's full set of inserts (which already succeeded). */
        size_t ord_failed_at = SIZE_MAX;
        for (size_t i = 0; i < s->ord_index_count; i++) {
            PogOrdIndex *oidx = &s->ord_indexes[i];
            if (strcmp(oidx->cls, new_name) != 0) continue;
            Field *f = find_field(o, oidx->field);
            if (!f || !f->value || f->value->kind != OBJ_STRING) continue;
            if (!ord_index_insert_unlocked(oidx, f->value->str_value, o)) { ord_failed_at = i; break; }
        }
        if (ord_failed_at != SIZE_MAX) {
            ord_index_unwind_class_inserts(s, ord_failed_at, new_name, o);
            index_unwind_class_inserts(s, s->index_count, new_name, o);
            auto_end(s, started, false);
            return false;
        }
    }

    /* Save old value for undo. */
    char *saved_old = old_name ? strdup(old_name) : NULL;
    if (old_name && !saved_old) {
        if (want_tag) {
            index_unwind_class_inserts(s, s->index_count, new_name, o);
            ord_index_unwind_class_inserts(s, s->ord_index_count, new_name, o);
        }
        auto_end(s, started, false);
        return false;
    }

    /* Remove from old class's list */
    if (old_name) {
        size_t oi = class_find_idx(s, old_name);
        if (oi != SIZE_MAX) class_list_remove(s, oi, o);
    }

    /* Install new class_name on the object */
    char *new_dup = NULL;
    if (want_tag) {
        new_dup = strdup(new_name);
        if (!new_dup) {
            /* put the object back in old class's list to keep the index
             * consistent with its state before we attempted the change */
            if (old_name) {
                size_t oi = class_get_or_create(s, old_name);
                if (oi != SIZE_MAX) class_list_append(s, oi, o);
            }
            index_unwind_class_inserts(s, s->index_count, new_name, o);
            ord_index_unwind_class_inserts(s, s->ord_index_count, new_name, o);
            free(saved_old);
            auto_end(s, started, false);
            return false;
        }
    }
    free(o->class_name);
    o->class_name = new_dup;

    /* Add to new class's list */
    if (want_tag) {
        size_t ni = class_get_or_create(s, new_name);
        if (ni == SIZE_MAX || !class_list_append(s, ni, o)) {
            /* undo on failure */
            free(o->class_name);
            o->class_name = saved_old; saved_old = NULL;
            if (old_name) {
                size_t oi = class_get_or_create(s, o->class_name);
                if (oi != SIZE_MAX) class_list_append(s, oi, o);
            }
            index_unwind_class_inserts(s, s->index_count, new_name, o);
            ord_index_unwind_class_inserts(s, s->ord_index_count, new_name, o);
            auto_end(s, started, false);
            return false;
        }
    }

    /* Secondary-index maintenance, phase 2: now that everything else has
     * succeeded, remove o from every index declared on the OLD class.
     * Reuses the same helper for its literal job (not as an unwind);
     * cannot fail (swap-and-pop only). Uses saved_old, not old_name: the
     * latter was a borrowed pointer into o->class_name, which was just
     * free()'d and reassigned above — old_name is dangling here. */
    if (saved_old) {
        index_unwind_class_inserts(s, s->index_count, saved_old, o);
        ord_index_unwind_class_inserts(s, s->ord_index_count, saved_old, o);
    }

    /* WAL record */
    TxnRec r = {0};
    r.op = WOP_SET_CLASS; r.target = o; r.target_id = o->id;
    if (want_tag) {
        r.new_str = strdup(new_name);
        if (!r.new_str) { free(saved_old); auto_end(s, started, false); return false; }
    }
    r.old_str = saved_old;              /* take ownership */
    r.had_prev = (old_name != NULL);
    log_push(s, r);

    return auto_end(s, started, true);
}

static const uint8_t *bytes_data_unlocked(Object *o)
{ return (o && o->kind == OBJ_BYTES) ? o->bytes.data : NULL; }
static size_t bytes_len_unlocked(Object *o)
{ return (o && o->kind == OBJ_BYTES) ? o->bytes.len : 0; }

static const char *class_of_unlocked(Object *o)
{
    return (o && o->kind == OBJ_COMPOSITE) ? o->class_name : NULL;
}

/* ============================================================
 * Public lock-taking wrappers
 *
 * Rules:
 *  - Mutators take wrlock unless the store already has an active_txn
 *    owned by the current thread (the txn already holds wrlock).
 *  - Readers take rdlock, same exception for the txn-owner thread
 *    (which holds wrlock and can read safely).
 *  - Transactions: txn_begin takes wrlock and retains it; commit/abort
 *    release it.
 * ============================================================ */

static bool holds_txn_writelock(Store *s)
{
    /* pthread_t compares via pthread_equal; only meaningful when
     * active_txn != NULL (txn_owner is stale otherwise). */
    return s && s->active_txn && pthread_equal(s->txn_owner, pthread_self());
}

/* ---- mutator wrappers ---- */

#define LOCK_W(s)   do { if (!holds_txn_writelock(s)) s_wrlock(s); } while (0)
#define UNLOCK_W(s) do { if (!holds_txn_writelock(s)) s_unlock(s); } while (0)
#define LOCK_R(s)   do { if (!holds_txn_writelock(s)) s_rdlock(s); } while (0)
#define UNLOCK_R(s) do { if (!holds_txn_writelock(s)) s_unlock(s); } while (0)

Object *new_object(Store *s) {
    LOCK_W(s); Object *r = new_object_unlocked(s); UNLOCK_W(s); return r;
}
Object *new_int(Store *s, int64_t v) {
    LOCK_W(s); Object *r = new_int_unlocked(s, v); UNLOCK_W(s); return r;
}
Object *new_string(Store *s, const char *v) {
    LOCK_W(s); Object *r = new_string_unlocked(s, v); UNLOCK_W(s); return r;
}
Object *new_bytes(Store *s, const void *data, size_t len) {
    LOCK_W(s); Object *r = new_bytes_unlocked(s, data, len); UNLOCK_W(s); return r;
}
Object *new_list(Store *s) {
    LOCK_W(s); Object *r = new_list_unlocked(s); UNLOCK_W(s); return r;
}
Object *new_vlist(Store *s, const char *t, Object *p) {
    LOCK_W(s); Object *r = new_vlist_unlocked(s, t, p); UNLOCK_W(s); return r;
}

bool set_int(Object *o, int64_t v) {
    Store *s = o ? o->store : NULL;
    LOCK_W(s); bool r = set_int_unlocked(o, v); UNLOCK_W(s); return r;
}
bool set_str(Object *o, const char *v) {
    Store *s = o ? o->store : NULL;
    LOCK_W(s); bool r = set_str_unlocked(o, v); UNLOCK_W(s); return r;
}
bool set_bytes(Object *o, const void *data, size_t len) {
    Store *s = o ? o->store : NULL;
    LOCK_W(s); bool r = set_bytes_unlocked(o, data, len); UNLOCK_W(s); return r;
}
bool set_field(Object *o, const char *k, Object *v) {
    Store *s = o ? o->store : NULL;
    LOCK_W(s); bool r = set_field_unlocked(o, k, v); UNLOCK_W(s); return r;
}
bool list_append(Object *l, Object *v) {
    Store *s = l ? l->store : NULL;
    LOCK_W(s); bool r = list_append_unlocked(l, v); UNLOCK_W(s); return r;
}
bool list_set(Object *l, size_t i, Object *v) {
    Store *s = l ? l->store : NULL;
    LOCK_W(s); bool r = list_set_unlocked(l, i, v); UNLOCK_W(s); return r;
}
bool list_insert(Object *l, size_t i, Object *v) {
    Store *s = l ? l->store : NULL;
    LOCK_W(s); bool r = list_insert_unlocked(l, i, v); UNLOCK_W(s); return r;
}
bool list_remove(Object *l, size_t i) {
    Store *s = l ? l->store : NULL;
    LOCK_W(s); bool r = list_remove_unlocked(l, i); UNLOCK_W(s); return r;
}

bool pog_bind(Store *s, const char *n, Object *o) {
    LOCK_W(s); bool r = bind_unlocked(s, n, o); UNLOCK_W(s); return r;
}
bool pog_unbind(Store *s, const char *n) {
    LOCK_W(s); bool r = unbind_unlocked(s, n); UNLOCK_W(s); return r;
}

bool set_class(Object *o, const char *name) {
    Store *s = o ? o->store : NULL;
    LOCK_W(s); bool r = set_class_unlocked_impl(o, name); UNLOCK_W(s); return r;
}
bool unset_class(Object *o) {
    return set_class(o, NULL);
}

/* ---- reader wrappers ---- */

Object *get_field(Object *o, const char *k) {
    /* read-only; vlist .at() may mutate scratch but not the graph */
    Store *s = o ? o->store : NULL;
    LOCK_R(s); Object *r = get_field_unlocked(o, k); UNLOCK_R(s); return r;
}
size_t field_count(Object *o) {
    Store *s = o ? o->store : NULL;
    LOCK_R(s); size_t r = field_count_unlocked(o); UNLOCK_R(s); return r;
}
Object *list_get(Object *l, size_t i) {
    Store *s = l ? l->store : NULL;
    /* vlist.at() calls pog_vlist_emit_* which mutate the view's scratch
     * buffer. That's private state on the view object, but the view is in
     * the store's object table — so concurrent readers could race.
     * We take wrlock for vlists specifically. */
    if (l && l->kind == OBJ_VLIST) { LOCK_W(s); } else { LOCK_R(s); }
    Object *r = list_get_unlocked(l, i);
    if (l && l->kind == OBJ_VLIST) { UNLOCK_W(s); } else { UNLOCK_R(s); }
    return r;
}
size_t list_len(Object *l) {
    Store *s = l ? l->store : NULL;
    LOCK_R(s); size_t r = list_len_unlocked(l); UNLOCK_R(s); return r;
}
Object *pog_get(Store *s, const char *n) {
    LOCK_R(s); Object *r = get_unlocked(s, n); UNLOCK_R(s); return r;
}

const char *class_of(Object *o) {
    Store *s = o ? o->store : NULL;
    LOCK_R(s);
    const char *r = class_of_unlocked(o);
    UNLOCK_R(s);
    return r;
}

const uint8_t *bytes_data(Object *o) {
    Store *s = o ? o->store : NULL;
    LOCK_R(s); const uint8_t *r = bytes_data_unlocked(o); UNLOCK_R(s); return r;
}
size_t bytes_len(Object *o) {
    Store *s = o ? o->store : NULL;
    LOCK_R(s); size_t r = bytes_len_unlocked(o); UNLOCK_R(s); return r;
}

/* ============================================================
 * Queries (readers)
 * ============================================================ */

size_t class_size(Store *s, const char *class_name)
{
    if (!s || !class_name) return 0;
    LOCK_R(s);
    size_t idx = class_find_idx(s, class_name);
    size_t n = (idx == SIZE_MAX) ? 0 : s->class_counts[idx];
    UNLOCK_R(s);
    return n;
}

size_t query_class(Store *s, const char *class_name,
                   query_fn fn, void *userdata)
{
    if (!s || !class_name || !fn) return 0;
    LOCK_R(s);
    size_t idx = class_find_idx(s, class_name);
    if (idx == SIZE_MAX) { UNLOCK_R(s); return 0; }

    /* Snapshot the member list so the callback can outlive the lock
     * without holding it. We hold rdlock during snapshotting; callback
     * runs lock-free. This prevents callback code from deadlocking on
     * re-entrant reader calls and lets it mutate the store safely
     * after we release, at the cost of seeing a slightly-stale view
     * if another thread mutates during iteration — which is the usual
     * snapshot-iteration semantic. */
    size_t n = s->class_counts[idx];
    Object **snap = NULL;
    if (n > 0) {
        snap = malloc(n * sizeof(*snap));
        if (!snap) { UNLOCK_R(s); return 0; }
        memcpy(snap, s->class_instances[idx], n * sizeof(*snap));
    }
    UNLOCK_R(s);

    size_t visited = 0;
    for (size_t i = 0; i < n; i++) {
        visited++;
        if (!fn(snap[i], userdata)) break;
    }
    free(snap);
    return visited;
}

/* Helper state for find_by_field */
typedef struct {
    const char *key;
    const char *value;
    Object     *found;
} fbf_state;

static bool fbf_cb(Object *o, void *ud)
{
    fbf_state *st = ud;
    /* Read field. Store is not locked during callback, but the field
     * pointer itself is stable — it's only rewritten by the writer, and
     * we're not the writer. A concurrent mutation could change the value
     * between our read here and the caller acting on it; that's the
     * standard racing semantic for read-committed queries. */
    Object *f = get_field_unlocked(o, st->key);
    if (f && f->kind == OBJ_STRING && f->str_value &&
        strcmp(f->str_value, st->value) == 0) {
        st->found = o;
        return false;   /* stop */
    }
    return true;
}

Object *find_by_field(Store *s, const char *class_name,
                      const char *key, const char *value)
{
    if (!s || !class_name || !key || !value) return NULL;

    /* Fast path: an index declared on (class_name, key) makes this O(1).
     * Check and release the lock before falling back to query_class,
     * which takes LOCK_R itself — holding LOCK_R across that call would
     * be a nested rdlock on one non-recursive pthread_rwlock_t from this
     * thread, a real deadlock hazard under writer contention. */
    LOCK_R(s);
    size_t ii = index_find_idx_unlocked(s, class_name, key);
    if (ii != SIZE_MAX) {
        PogIndexEntry *e = index_find_entry_unlocked(&s->indexes[ii], value);
        Object *found = (e && e->count > 0) ? e->items[0] : NULL;
        UNLOCK_R(s);
        return found;
    }
    UNLOCK_R(s);

    fbf_state st = { key, value, NULL };
    query_class(s, class_name, fbf_cb, &st);
    return st.found;
}

/* ---- secondary hash index: public wrappers ---- */

size_t index_lookup(Store *s, const char *cls, const char *field,
                    const char *value, query_fn cb, void *ud)
{
    if (!s || !cls || !field || !value || !cb) return 0;
    LOCK_R(s);
    size_t ii = index_find_idx_unlocked(s, cls, field);
    if (ii == SIZE_MAX) { UNLOCK_R(s); return 0; }
    PogIndexEntry *e = index_find_entry_unlocked(&s->indexes[ii], value);
    size_t n = e ? e->count : 0;
    Object **snap = NULL;
    if (n > 0) {
        snap = malloc(n * sizeof(*snap));
        if (!snap) { UNLOCK_R(s); return 0; }
        memcpy(snap, e->items, n * sizeof(*snap));
    }
    UNLOCK_R(s);

    size_t visited = 0;
    for (size_t i = 0; i < n; i++) {
        visited++;
        if (!cb(snap[i], ud)) break;
    }
    free(snap);
    return visited;
}

Object *index_lookup_one(Store *s, const char *cls, const char *field,
                         const char *value)
{
    if (!s || !cls || !field || !value) return NULL;
    LOCK_R(s);
    size_t ii = index_find_idx_unlocked(s, cls, field);
    if (ii == SIZE_MAX) { UNLOCK_R(s); return NULL; }
    PogIndexEntry *e = index_find_entry_unlocked(&s->indexes[ii], value);
    Object *r = (e && e->count > 0) ? e->items[0] : NULL;
    UNLOCK_R(s);
    return r;
}

bool index_create(Store *s, const char *cls, const char *field) {
    LOCK_W(s); bool r = index_create_unlocked(s, cls, field); UNLOCK_W(s); return r;
}
bool index_drop(Store *s, const char *cls, const char *field) {
    LOCK_W(s); bool r = index_drop_unlocked(s, cls, field); UNLOCK_W(s); return r;
}

/* ---- ordered index (Tier 3a): public wrappers ---- */

bool ord_index_create(Store *s, const char *cls, const char *field) {
    LOCK_W(s); bool r = ord_index_create_unlocked(s, cls, field); UNLOCK_W(s); return r;
}
bool ord_index_drop(Store *s, const char *cls, const char *field) {
    LOCK_W(s); bool r = ord_index_drop_unlocked(s, cls, field); UNLOCK_W(s); return r;
}

Object *index_succ(Store *s, const char *cls, const char *field, const char *value)
{
    if (!s || !cls || !field || !value) return NULL;
    LOCK_R(s);
    size_t ii = ord_index_find_idx_unlocked(s, cls, field);
    if (ii == SIZE_MAX) { UNLOCK_R(s); return NULL; }
    PogOrdIndex *idx = &s->ord_indexes[ii];
    size_t pos;
    bool exact = ord_index_bsearch(idx, value, &pos);
    size_t next = exact ? pos + 1 : pos;
    Object *r = (next < idx->count && idx->entries[next].count > 0)
                ? idx->entries[next].items[0] : NULL;
    UNLOCK_R(s);
    return r;
}

Object *index_pred(Store *s, const char *cls, const char *field, const char *value)
{
    if (!s || !cls || !field || !value) return NULL;
    LOCK_R(s);
    size_t ii = ord_index_find_idx_unlocked(s, cls, field);
    if (ii == SIZE_MAX) { UNLOCK_R(s); return NULL; }
    PogOrdIndex *idx = &s->ord_indexes[ii];
    size_t pos;
    /* Whether or not `value` exists exactly, the insertion-point/match
     * index `pos` is the first entry >= value, so pos-1 is always the
     * predecessor. */
    ord_index_bsearch(idx, value, &pos);
    Object *r = (pos > 0 && idx->entries[pos - 1].count > 0)
                ? idx->entries[pos - 1].items[0] : NULL;
    UNLOCK_R(s);
    return r;
}

size_t index_range(Store *s, const char *cls, const char *field,
                   const char *lo, const char *hi, query_fn cb, void *ud)
{
    if (!s || !cls || !field || !lo || !hi || !cb) return 0;
    LOCK_R(s);
    size_t ii = ord_index_find_idx_unlocked(s, cls, field);
    if (ii == SIZE_MAX) { UNLOCK_R(s); return 0; }
    PogOrdIndex *idx = &s->ord_indexes[ii];

    size_t start;
    ord_index_bsearch(idx, lo, &start);      /* first entry >= lo, exact or not */
    size_t end;
    if (ord_index_bsearch(idx, hi, &end)) end++;   /* include an exact match on hi */

    if (start >= end) { UNLOCK_R(s); return 0; }

    /* Snapshot every object pointer in [start, end) before releasing the
     * lock -- same discipline as index_lookup/query_class: callbacks run
     * lock-free and may safely re-enter the store. */
    size_t total = 0;
    for (size_t i = start; i < end; i++) total += idx->entries[i].count;
    Object **snap = NULL;
    if (total > 0) {
        snap = malloc(total * sizeof(*snap));
        if (!snap) { UNLOCK_R(s); return 0; }
        size_t w = 0;
        for (size_t i = start; i < end; i++) {
            PogIndexEntry *e = &idx->entries[i];
            memcpy(&snap[w], e->items, e->count * sizeof(*snap));
            w += e->count;
        }
    }
    UNLOCK_R(s);

    size_t visited = 0;
    for (size_t i = 0; i < total; i++) {
        visited++;
        if (!cb(snap[i], ud)) break;
    }
    free(snap);
    return visited;
}

uint32_t store_version(Store *s)
{
    if (!s) return 0;
    LOCK_R(s);
    uint32_t v = s->version;
    UNLOCK_R(s);
    return v;
}

typedef struct {
    change_fn cb;
    void     *userdata;
    size_t    visited;
} scs_state;

static bool scs_emit(void *ud, uint32_t version, uint32_t object_id,
                     bool is_create, const char *class_name)
{
    scs_state *st = ud;
    PogChange ch = { version, object_id, is_create, class_name };
    st->visited++;
    return st->cb(&ch, st->userdata);
}

size_t store_changes_since(Store *s, uint32_t since_version,
                           change_fn cb, void *userdata)
{
    if (!s || !cb) return 0;
    if (!s->path) return 0;   /* ephemeral: nothing tracked */

    /* Snapshot-then-release, matching query_class/index_lookup/
     * find_by_field's convention: never invoke a caller-supplied callback
     * while holding the store lock. Brief LOCK_R only to capture the
     * current version as an upper bound; safe lock-free afterward because
     * vlog_write_record's fflush+fsync (and s->version's bump) happen
     * under the writer's wrlock, which the rwlock's mutual exclusion
     * guarantees happened-before our rdlock observes s->version here. */
    LOCK_R(s);
    uint32_t upper = s->version;
    UNLOCK_R(s);

    if (since_version >= upper) return 0;

    char *vp = path_append(s->path, ".vlog");
    if (!vp) return 0;
    FILE *f = fopen(vp, "rb");
    free(vp);
    if (!f) return 0;

    scs_state st = { cb, userdata, 0 };
    uint32_t max_version; long good_end; bool header_ok;
    vlog_scan(f, since_version, upper, scs_emit, &st,
              &max_version, &good_end, &header_ok);
    fclose(f);
    if (!header_ok)
        fprintf(stderr, "pog: version log header unreadable in store_changes_since\n");
    return st.visited;
}

/* ============================================================
 * Transaction lock discipline
 *
 * txn_begin takes the write lock and leaves it held until commit or abort.
 * This gives us single-writer semantics naturally: a second thread calling
 * txn_begin blocks at the lock until the current txn commits/aborts.
 * It also means every mutation inside the txn can skip re-locking (the
 * LOCK_W macro checks holds_txn_writelock).
 * ============================================================ */

bool txn_begin(Store *s)
{
    if (!s) return false;
    s_wrlock(s);
    bool ok = txn_begin_unlocked_impl(s);
    if (!ok) s_unlock(s);
    return ok;
}

bool txn_commit(Store *s)
{
    if (!s) return false;
    /* Caller's txn holds the lock already. */
    if (!s->active_txn || !pthread_equal(s->txn_owner, pthread_self()))
        return false;
    bool ok = txn_commit_unlocked_impl(s);
    /* txn_commit_unlocked_impl clears s->active_txn on success.
     * On failure (WAL write failed) it calls txn_abort_unlocked_impl
     * internally which also clears it. Either way, lock should be
     * released. */
    s_unlock(s);
    return ok;
}

bool txn_abort(Store *s)
{
    if (!s) return false;
    if (!s->active_txn || !pthread_equal(s->txn_owner, pthread_self()))
        return false;
    bool ok = txn_abort_unlocked_impl(s);
    s_unlock(s);
    return ok;
}
