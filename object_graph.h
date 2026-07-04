/* VENDORED from lucianpopovici/objectdb @ 2ad8607 (ADR-008 pilot).
 * Do not edit here — fix upstream, re-run its test suite, then re-copy
 * object_graph.{c,h} together and update this pin. Local divergence is the
 * bug class the libdnswire extraction exists to prevent. These two files
 * keep UPSTREAM's formatting (CI's clang-format job excludes them) so the
 * pin stays byte-verifiable: upstream file + this header == this file.
 */
/* object_graph.h — Persistent Object Graph Engine (v2: OODB)
 *
 * v2 adds:
 *   - dynamic field vectors (no 16-field cap)
 *   - OBJ_LIST (first-class ordered collection of Object*)
 *   - WAL-backed transactions: txn_begin / txn_commit / txn_abort
 *   - crash recovery on store_open()
 *   - snapshot generation counter for safe checkpoints
 *
 * Persistent stores auto-wrap bare mutations in a single-op transaction
 * (autocommit) so every durable write hits the WAL. Ephemeral stores
 * (store_create) still work with no logging.
 */
#ifndef OBJECT_GRAPH_H
#define OBJECT_GRAPH_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <pthread.h>

#define POG_MAX_KEY_LEN    64
#define POG_MAX_ROOT_NAME  64
#define POG_MAX_CLASS_NAME 64

/* Root names are strncpy'd into TxnRec.key (object_graph.c), which is sized
 * POG_MAX_KEY_LEN — these two constants are independent by name but must
 * stay ordered or that strncpy overflows its destination. */
_Static_assert(POG_MAX_ROOT_NAME <= POG_MAX_KEY_LEN,
               "POG_MAX_ROOT_NAME must not exceed POG_MAX_KEY_LEN "
               "(TxnRec.key is sized POG_MAX_KEY_LEN)");

typedef enum {
    OBJ_COMPOSITE = 0,
    OBJ_INT       = 1,
    OBJ_STRING    = 2,
    OBJ_LIST      = 3,
    OBJ_VLIST     = 4,       /* virtual (computed) list, read-only */
    OBJ_BYTES     = 5,       /* binary blob; may contain embedded zero bytes */
} ObjectKind;

typedef struct Object Object;
typedef struct Store  Store;
typedef struct Txn    Txn;

/* VListOps: callback table for a virtual list generator. Register once at
 * startup with pog_register_vlist_type(). On load/replay, the type_name is
 * resolved back to ops via the registry. */
typedef struct VListOps {
    const char *type_name;                       /* unique, e.g. "cidr.all" */
    size_t  (*len)(Object *self);
    Object *(*at) (Object *self, size_t i);
} VListOps;

typedef struct {
    char    key[POG_MAX_KEY_LEN];
    Object *value;
} Field;

struct Object {
    uint32_t   id;
    bool       marked;
    ObjectKind kind;
    Store     *store;           /* back-pointer, required for WAL tracking */
    char      *class_name;      /* owned, NULL if untagged. Composite only. */

    union {
        int64_t int_value;
        char   *str_value;      /* owned */
        struct {
            uint8_t *data;      /* owned; may contain embedded zero bytes */
            size_t   len;
        } bytes;
        struct {
            Field  *items;
            size_t  count;
            size_t  cap;
        } composite;
        struct {
            Object **items;
            size_t   count;
            size_t   cap;
        } list;
        struct {
            char           *type_name;   /* owned; for persistence */
            const VListOps *ops;         /* resolved from registry */
            Object         *params;      /* input config (any Object) */
            /* scratch: transient items handed out by at(); freed on
             * object destruction. Not in the store, not WAL-tracked. */
            Object        **scratch;
            size_t          scratch_count;
            size_t          scratch_cap;
        } vlist;
    };
};

typedef struct {
    char    name[POG_MAX_ROOT_NAME];
    Object *obj;
    bool    used;
} Root;

/* Secondary hash index internals — exposed like the rest of Store's
 * internals (this engine has no opaque types). Use index_create,
 * index_lookup, index_lookup_one, index_drop — not these fields directly.
 *
 * PogIndexBucket is a chaining hash bucket implemented as a growable
 * array of entries — not a linked list (this file has none; everything
 * is a dynamic array grown via next_cap/mul_bytes). */
typedef struct {
    char    *value;    /* owned; the distinct field value this entry represents */
    Object **items;    /* owned array; objects whose field == value */
    size_t   count, cap;
} PogIndexEntry;

typedef struct {
    PogIndexEntry *entries;   /* owned array, growable */
    size_t         count, cap;
} PogIndexBucket;

typedef struct {
    char           *cls;            /* owned; declared class name */
    char           *field;          /* owned; declared field key */
    PogIndexBucket *buckets;        /* owned array, size == bucket_count */
    size_t          bucket_count;   /* ALWAYS a power of two; 0 until first insert */
    size_t          total_entries;  /* distinct values across all buckets */
} PogIndex;

/* Ordered (canonical DNS-name order) index internals — Tier 3a. Use
 * ord_index_create, ord_index_drop, index_succ, index_pred, index_range —
 * not these fields directly. Reuses PogIndexEntry (value + owned Object*
 * array) from the hash index above, but keeps a single flat array sorted
 * by canonical DNS-name order instead of hash buckets, trading a hash
 * index's O(1) point lookup for the ordered traversal (successor,
 * predecessor, range) that DNSSEC NSEC chains and zone signing need. */
typedef struct {
    char          *cls;     /* owned; declared class name */
    char          *field;   /* owned; declared field key */
    PogIndexEntry *entries; /* owned array, ALWAYS sorted ascending by
                              * canonical DNS-name order of ->value */
    size_t         count, cap;
} PogOrdIndex;

struct Store {
    /* object table */
    Object   **objects;
    size_t     count;
    size_t     capacity;
    uint32_t   next_id;

    /* named roots */
    Root    *roots;
    size_t   root_count;
    size_t   root_capacity;

    /* persistence */
    char     *path;         /* NULL = ephemeral */
    FILE     *wal_fp;       /* open for append when persistent */
    FILE     *vlog_fp;      /* open for append when persistent; durable
                              * per-txn change log backing store_version()/
                              * store_changes_since(). Unlike wal_fp, NEVER
                              * truncated by store_checkpoint -- kept
                              * forever by design. NULL for ephemeral stores. */
    int       lock_fd;      /* fd used for fcntl advisory lock; -1 if none */
    uint32_t  seq;          /* snapshot generation */
    uint32_t  next_txn_id;
    uint32_t  version;      /* current change-log version. 0 if no committed
                              * txn has touched an object yet, or ephemeral.
                              * Independent of next_txn_id/seq -- see
                              * store_version()'s doc comment for why those
                              * can't be reused for this. */

    /* active transaction (NULL = autocommit / none) */
    Txn      *active_txn;
    pthread_t txn_owner;    /* thread holding active_txn, valid iff active_txn != NULL */

    /* class index: per-class instance lists. Parallel arrays. */
    char    **class_names;        /* owned strings */
    Object ***class_instances;    /* class_instances[i] = Object** array */
    size_t   *class_counts;
    size_t   *class_caps;
    size_t    class_count;
    size_t    class_capacity;

    /* secondary hash indexes: declared (class, field) -> value -> [Object*].
     * Derived state like the class index above — NOT persisted, NOT
     * WAL-logged. index_create()/index_drop() are process-lifetime
     * declarations only; re-declare on every store_open(). */
    PogIndex *indexes;
    size_t    index_count;
    size_t    index_capacity;

    /* ordered (canonical DNS-name order) indexes: declared (class, field)
     * -> a single array of value -> [Object*] entries kept sorted. Tier 3a.
     * Same derived-state rules as the hash indexes above: NOT persisted,
     * NOT WAL-logged, rebuilt after abort/GC/load, maintained incrementally. */
    PogOrdIndex *ord_indexes;
    size_t       ord_index_count;
    size_t       ord_index_capacity;

    /* store-wide rwlock.
     * Rules:
     *   - Public readers take rdlock.
     *   - Public writers and anything that mutates the store take wrlock.
     *   - Transactions hold wrlock for their duration (pessimistic, single
     *     writer at a time — not MVCC).
     *   - Internal helpers are lock-free; the public entry takes the lock
     *     then calls an _unlocked variant. */
    pthread_rwlock_t lock;
};

/* --- Lifecycle --- */

/* store_open_flags flags. */
#define POG_OPEN_NO_VLOG 0x1u
/* POG_OPEN_NO_VLOG: do not create, scan, or append the <path>.vlog change
 * log. For high-churn stores (e.g. caches) that never call store_version()/
 * store_changes_since(), the never-pruned .vlog is pure disk growth. With
 * this flag store_version() stays 0 and store_changes_since() visits
 * nothing (matching the ephemeral-store behavior of those APIs); everything
 * else (WAL durability, crash recovery, checkpoint) is unchanged. The flag
 * is per-open, not persisted: a later plain store_open() of the same path
 * bootstraps a fresh .vlog whose version history starts from that point. */

Store *store_create(void);                   /* ephemeral, in-memory only        */
Store *store_open  (const char *path);       /* persistent: load snap + WAL      */
Store *store_open_flags(const char *path, unsigned flags); /* see POG_OPEN_*  */
bool   store_checkpoint(Store *s);           /* fold WAL into snapshot, reset WAL*/
void   store_close (Store *s);               /* works for both modes             */
void   store_destroy(Store *s);              /* alias for store_close            */

/* --- Object creation (WAL-tracked if persistent) --- */
Object *new_object (Store *s);
Object *new_int    (Store *s, int64_t     value);
Object *new_string (Store *s, const char *value);
Object *new_list   (Store *s);
Object *new_bytes  (Store *s, const void *data, size_t len);

/* --- Primitive setters (WAL-tracked) ---
 * Prefer these over directly writing to o->int_value / o->str_value /
 * o->bytes.{data,len}; direct writes are not logged and break durability. */
bool set_int  (Object *o, int64_t     v);
bool set_str  (Object *o, const char *v);
bool set_bytes(Object *o, const void *data, size_t len);

/* --- Bytes accessors ---
 * o->bytes.data / o->bytes.len are directly readable per this file's
 * no-opaque-types convention; these wrap that access with the store's
 * rdlock, same as class_of()/field_count(). Return NULL/0 if o is NULL or
 * not OBJ_BYTES. */
const uint8_t *bytes_data(Object *o);
size_t         bytes_len (Object *o);

/* --- Composite fields --- */
bool    set_field (Object *o, const char *key, Object *value);
Object *get_field (Object *o, const char *key);
size_t  field_count(Object *o);

/* --- Lists --- */
bool    list_append(Object *l, Object *v);
bool    list_set   (Object *l, size_t index, Object *v);
bool    list_insert(Object *l, size_t index, Object *v);
bool    list_remove(Object *l, size_t index);
Object *list_get   (Object *l, size_t index);
size_t  list_len   (Object *l);

/* --- Virtual lists (computed on demand) ---
 * `list_get` and `list_len` transparently dispatch to an OBJ_VLIST's ops.
 * `list_append`/`set`/`insert`/`remove` refuse OBJ_VLIST (return false).
 * The generator reads config from `params` (any Object, typically a
 * composite). Item objects handed back by at() live until the view is
 * freed and must not be retained past that. */
bool    pog_register_vlist_type(const VListOps *ops);
Object *new_vlist(Store *s, const char *type_name, Object *params);

/* Helpers for generator implementations to emit items tied to the view's
 * lifetime (not tracked in the store, not WAL-logged). */
Object *pog_vlist_emit_int   (Object *view, int64_t     v);
Object *pog_vlist_emit_string(Object *view, const char *v);

/* Built-in generators; auto-registered by store_create/store_open. */
extern const VListOps pog_cidr_all;     /* type_name = "cidr.all"     */
extern const VListOps pog_cidr_free;    /* type_name = "cidr.free"    */
extern const VListOps pog_cidr_subnets; /* type_name = "cidr.subnets" */
/* params: composite with string field "name" — a dot-separated,
 * presentation-format DNS name (case as given; no case-folding here).
 * dns.ancestors yields the name and each shorter suffix up to and
 * including the empty root (""); len() == label_count(name) + 1.
 * dns.wildcards yields "*."+suffix for the same suffixes, skipping the
 * first label and stopping one short of root (no "*." variant of the
 * root); len() == max(label_count(name) - 1, 0). */
extern const VListOps pog_dns_ancestors; /* type_name = "dns.ancestors" */
extern const VListOps pog_dns_wildcards; /* type_name = "dns.wildcards" */
void pog_register_builtins(void);

/* --- Named roots ---
 * pog_-prefixed: the original bare `bind` collided with the POSIX socket
 * bind(2) declaration the moment a host program included both
 * <sys/socket.h> and this header (simple-dns resolverd did). No short-name
 * compatibility macros: a function-like `bind()` macro rewrites the host's
 * socket bind(2) calls too, which static analyzers explore even when the
 * guard is off. */
bool    pog_bind  (Store *s, const char *name, Object *o);
Object *pog_get   (Store *s, const char *name);
bool    pog_unbind(Store *s, const char *name);

/* --- Debug --- */
void dump(Object *o);
void dump_store(Store *s);

/* --- GC (forbidden while a transaction is active) --- */
void gc(Store *s);

/* --- Transactions --- */
bool txn_begin (Store *s);
bool txn_commit(Store *s);
bool txn_abort (Store *s);
bool txn_active(Store *s);

/* --- Raw snapshot I/O (building blocks for store_open / checkpoint) --- */
bool   save(Store *s, const char *path);
Store *load(const char *path);

/* ============================================================
 * Class tags and queries
 * ============================================================
 *
 * Any composite object may be tagged with a class name. Tagging inserts
 * the object into a per-class instance list, maintained transactionally
 * alongside all other state. Untagging or GC-collection removes it.
 *
 * Tags are persisted through save/load and replayed through the WAL.
 */

/* Assign o to a class. Object must be OBJ_COMPOSITE. Replaces any prior
 * class on o. Returns false on invalid input or too-many-classes. */
bool    set_class(Object *o, const char *class_name);

/* Remove o from its class (no-op if untagged). */
bool    unset_class(Object *o);

/* Read the class of o, or NULL if untagged. */
const char *class_of(Object *o);

/* Query: iterate over all instances of a class. The callback receives
 * each Object*. Return false from the callback to stop early. Returns
 * the number of objects visited (including the one that stopped).
 *
 * Callback may read the store freely. Mutating the store (set_field,
 * new_object, etc.) from the callback is forbidden and triggers
 * undefined behavior — copy pointers out first, then mutate. */
typedef bool (*query_fn)(Object *o, void *userdata);
size_t  query_class(Store *s, const char *class_name,
                    query_fn fn, void *userdata);

/* Convenience: find the first instance of `class_name` whose string-valued
 * field `key` equals `value`. O(1) if an index is declared on
 * (class_name, key) via index_create(), else O(n) linear scan over the
 * class's instances. Returns NULL if no match. */
Object *find_by_field(Store *s, const char *class_name,
                      const char *key, const char *value);

/* How many instances in a class (0 if class doesn't exist). */
size_t  class_size(Store *s, const char *class_name);

/* ============================================================
 * Secondary hash index: name -> [objects]
 *
 * Declare an index on a (class, field) pair to make find_by_field (and
 * index_lookup*) O(1) average case instead of O(n). Only OBJ_STRING field
 * values participate — non-string or missing fields are simply not
 * indexed, mirroring find_by_field's existing restriction.
 *
 * Fully derived from object state (like the class index) — NOT persisted,
 * NOT WAL-logged. index_create/index_drop are not part of the transaction
 * log: a txn_abort does not "undo" an index_create/index_drop as an
 * operation, it only restores object/field/class state, after which the
 * index is rebuilt from that restored state. After load()/store_open() a
 * fresh process must re-declare every index it needs — idempotent, cheap.
 * ============================================================ */

/* Declare an index on (class, field). Idempotent — a second call with the
 * same pair is a no-op returning true. Builds the index over all current
 * instances of `class` immediately (O(class size)). Maintained
 * incrementally by set_field/set_class thereafter, rebuilt wholesale
 * after abort/GC. Returns false on invalid input (NULL/empty, or a name
 * exceeding POG_MAX_KEY_LEN/POG_MAX_CLASS_NAME — rejected, not truncated)
 * or on allocation failure (nothing declared in that case). */
bool    index_create(Store *s, const char *cls, const char *field);

/* Drop a previously-declared index. Returns false if none was declared.
 * find_by_field falls back to its O(n) scan for this pair afterward. */
bool    index_drop(Store *s, const char *cls, const char *field);

/* O(1) average-case lookup: invoke cb for every instance of `cls` whose
 * `field` string value equals `value`. Requires a declared index for
 * (cls, field) — returns 0 without scanning if none exists (use
 * find_by_field for scan-with-fallback). Snapshot semantics identical to
 * query_class. Returns the number of objects visited. */
size_t  index_lookup(Store *s, const char *cls, const char *field,
                     const char *value, query_fn cb, void *ud);

/* Convenience: first match from index_lookup, or NULL. Requires a
 * declared index; does not fall back to scanning. */
Object *index_lookup_one(Store *s, const char *cls, const char *field,
                         const char *value);

/* ============================================================
 * Ordered index: canonical DNS-name order (Tier 3a)
 *
 * A second kind of index over a (class, field) pair, declared and
 * maintained independently of the hash index above. Where the hash index
 * gives O(1) point lookup, this gives ordered traversal: "next existent
 * name after X" (index_succ), "previous" (index_pred), and a canonical-
 * order range scan (index_range) — what DNSSEC NSEC chains and
 * canonical-order zone signing need. A (class, field) pair may have a
 * hash index, an ordered index, both, or neither declared independently.
 *
 * Only OBJ_STRING field values participate, interpreted as dot-separated,
 * presentation-format DNS names (case as given — no folding here, see
 * CLAUDE-index.md tier 2b for why case-folding belongs in the DNS layer,
 * not this engine). Ordering follows RFC 4034 section 6.1's canonical
 * name comparison (label sequences compared most-significant/rightmost
 * label first; a name that is a proper suffix of another sorts first;
 * the root/empty name "" sorts before everything) but WITHOUT its
 * case-folding step, for the same reason.
 *
 * Fully derived from object state (like the hash index) — NOT persisted,
 * NOT WAL-logged. Declarations do not survive store_open()/load(); a
 * fresh process must re-declare via ord_index_create() (idempotent,
 * rebuilds from current state).
 * ============================================================ */

/* Declare an ordered index on (class, field). Idempotent — a second call
 * with the same pair is a no-op returning true. Builds the index over all
 * current instances of `class` immediately. Maintained incrementally by
 * set_field/set_class thereafter, rebuilt wholesale after abort/GC.
 * Returns false on invalid input (same validation as index_create) or
 * allocation failure (nothing declared in that case). */
bool    ord_index_create(Store *s, const char *cls, const char *field);

/* Drop a previously-declared ordered index. Returns false if none was
 * declared for this pair. */
bool    ord_index_drop(Store *s, const char *cls, const char *field);

/* The next existent name strictly after `value` in canonical order, or
 * NULL if `value` is the greatest (no wraparound — this is a plain
 * ordered index, not a signed zone's closed NSEC ring). `value` itself
 * need not exist in the index. Requires a declared ordered index for
 * (cls, field); returns NULL if none exists. If several objects share the
 * successor's value, returns one of them (like index_lookup_one). */
Object *index_succ(Store *s, const char *cls, const char *field,
                   const char *value);

/* The previous existent name strictly before `value` in canonical order,
 * or NULL if `value` is the least (or the index is empty). Same
 * requirements and non-uniqueness handling as index_succ. */
Object *index_pred(Store *s, const char *cls, const char *field,
                   const char *value);

/* Invoke cb for every object whose indexed field value falls in [lo, hi]
 * inclusive, in ascending canonical order, grouping all objects at each
 * distinct value together (non-unique values all visited). Requires a
 * declared ordered index for (cls, field) — returns 0 without scanning if
 * none exists. Snapshot semantics identical to index_lookup: the bucket
 * range is copied under the read lock, then cb is invoked lock-free.
 * Returns the number of objects visited; false from cb stops early. */
size_t  index_range(Store *s, const char *cls, const char *field,
                    const char *lo, const char *hi,
                    query_fn cb, void *ud);

/* ============================================================
 * Version change log (IXFR-style diffing)
 *
 * Persistent stores only. Every committed transaction (both explicit
 * txn_begin()/txn_commit() and autocommit's implicit single-op
 * transactions) that touches at least one object bumps a monotonically
 * increasing version counter and durably appends one change-log record
 * (one deduplicated entry per distinct object touched) to a dedicated
 * <path>.vlog file. Ephemeral stores never track this: store_version()
 * always returns 0 and store_changes_since() always returns 0 for them.
 *
 * This is diff/audit history only -- there is no point-in-time openable
 * Store, and history is never pruned. It survives store_checkpoint(),
 * which only folds the WAL into the snapshot and resets the WAL --
 * .vlog is a wholly separate artifact, never touched by checkpoint.
 * ============================================================ */

/* Current version: incremented once per committed transaction that
 * touched at least one object, on a persistent store only. 0 for an
 * ephemeral store or a persistent store with no such commits yet.
 * Survives store_open()/store_checkpoint() -- unlike the class/hash
 * indexes, this is durable append-only history, not derived state
 * rebuilt from current object state, so it is NOT reset by checkpoint.
 *
 * (Why not reuse next_txn_id or seq? next_txn_id increments per
 * txn_begin but is not persisted in the snapshot header written by
 * save() -- after a checkpoint truncates the WAL it depends on for
 * recovery, a restart would silently reset it, causing version reuse.
 * seq is a snapshot generation counter bumped only at checkpoint,
 * unrelated to per-transaction granularity. Neither is safe for this
 * purpose, hence the dedicated `version` counter and `.vlog` file.) */
uint32_t store_version(Store *s);

/* One change-log entry: an object created or mutated by the transaction
 * that produced `version`. class_name reflects that object's class AT
 * COMMIT TIME (it may have since changed class or been reclaimed by GC
 * -- this is a diff/audit log, not a point-in-time store). class_name is
 * "" if the object was not a tagged composite at that time, and is
 * borrowed/valid only for the duration of the change_fn call it's
 * passed to. */
typedef struct {
    uint32_t    version;
    uint32_t    object_id;
    bool        is_create;
    const char *class_name;
} PogChange;

typedef bool (*change_fn)(const PogChange *change, void *userdata);

/* Invoke cb once per change-log entry with version > since_version,
 * oldest first. Persistent stores only -- always returns 0 for an
 * ephemeral store. Takes the store's read lock only briefly to capture
 * the current version as an upper bound; the file scan and every
 * change_fn call then run lock-free, so cb may safely read the store
 * (e.g. class_of() on object_id) without risking a nested-rdlock
 * deadlock. Returns entries visited; false from cb stops early, same
 * convention as query_class. */
size_t store_changes_since(Store *s, uint32_t since_version,
                           change_fn cb, void *userdata);

#endif /* OBJECT_GRAPH_H */
