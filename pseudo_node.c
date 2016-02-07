/*
 * PseudoNode
 * Copyright (c) 2015 the copyright holders
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <getopt.h>

#include "sha256.c"

#define MAX_MESSAGE_LEN             (1 << 25)   // 32MB

#define MSG_TX                      1
#define MSG_BLOCK                   2
#define MSG_FILTERED_BLOCK          3

#define TX                          1
#define BLOCK                       2
#define ADDRESS                     3
#define HEADERS                     4

#define MAX_REQUESTS                32          // Max requests
#define MAX_INVS                    8192        // Max invs

#ifdef MACOSX
#define LINUX
#endif

#ifdef LINUX
#include "linux.c"
#endif

#ifdef WINDOWS
#include "windows.c"
#endif

#include "pseudo_node.h"

#define atomic_add(addr, val)       __sync_fetch_and_add((addr), (val))
#define atomic_sub(addr, val)       __sync_fetch_and_sub((addr), (val))

/*****************************************************************************/

// 256-bit number.
union uint256_s
{
    uint8_t i8[32];
    uint16_t i16[16];
    uint32_t i32[8];
    uint64_t i64[4];
};
typedef union uint256_s uint256_t;

#define HASH_FORMAT         "%.16llx%.16llx%.16llx%.16llx"
#define HASH_FORMAT_SHORT   "%.16llx%.16llx..."
#define HASH(hsh)           \
    (hsh).i64[3], (hsh).i64[2], (hsh).i64[1], (hsh).i64[0]
#define HASH_SHORT(hsh)     \
    (hsh).i64[3], (hsh).i64[2]

// Protocol message header.
struct header
{
    uint32_t magic;             // Magic number.
    char command[12];           // Message command (e.g. "version").
    uint32_t length;            // Message length.
    uint32_t checksum;          // Message checksum.
} __attribute__((__packed__));

// Block header.
struct block
{
    uint32_t version;           // Block version.
    uint256_t prev_block;       // Previous block hash.
    uint256_t merkle_root;      // Block Merkle root.
    uint32_t timestamp;         // Block timestamp.
    uint32_t bits;              // Block difficulty.
    uint32_t nonce;             // Block nonce.
} __attribute__((__packed__));

// Data buffer.
struct buf
{
    char *data;                 // Buffer data.
    uint32_t ptr;               // Buffer current position.
    uint32_t len;               // Buffer length of data.
    int32_t ref_count;          // Buffer reference count.
    jmp_buf *env;               // jmp_buf for pop() errors.
};

// Fetch data info.
struct fetch
{
    uint256_t hash;             // Data hash.
    uint64_t nonce;             // Peer nonce.
    uint32_t type;              // Data type.
    bool sync;                  // Requires synced node.
    int8_t ttl;                 // TTL.
    time_t time;                // Time of last request.
    struct fetch *next;         // Next.
};

// Peer message queue.
struct msg
{
    struct buf *buf;            // Queued message.
    struct msg *next;           // Next message.
};

// Peer information.
struct peer
{
    sock sock;                  // Peer socket.
    mutex lock;                 // Peer lock (for messages).
    event event;                // Peer event (for messages).
    time_t timeout;             // Peer timeout.
    uint64_t nonce;             // Peer nonce.
    int32_t ref_count;          // Peer reference count.
    struct msg *msg_head;       // Message queue head.
    struct msg *msg_tail;       // Message queue tail.
    size_t msg_len;             // Total message queue length.
    time_t alive;               // Peer last message time (alive or not?)
    struct in6_addr to_addr;    // Peer remote address.
    in_port_t to_port;          // Peer remote port.
    struct in6_addr from_addr;  // Peer local address.
    in_port_t from_port;        // Peer local port.
    char *name;                 // Peer name (string version of to_addr).
    uint32_t index;             // Peer index.
    int16_t score;              // Peer DoS score.
    int16_t inv_score;          // Peer inv limit.
    bool ready;                 // Peer is ready? (have seen version message?)
    bool sync;                  // Peer is synced? (up-to-date height?)
    bool local_sync;            // This peer is synced?
    bool outbound;              // Peer is an outbound connection?
    bool error;                 // Has an error occurred?
};

// Delayed message.
struct delay
{
    size_t index;               // Peer index waiting for response.
    uint64_t nonce;             // Peer nonce.
    struct delay *next;         // Next delayed message.
};

// Table entry.
struct entry
{
    uint256_t hash;             // Entry hash.
    uint64_t vote;              // Entry vote mask (which peers have object?)
    time_t time;                // Entry time.
    uint8_t type;               // Entry type.
    uint8_t state;              // Entry state (observed, fetching, available).
    uint16_t ref_count;         // Entry reference count.
    uint32_t len;               // Entry data length.
    void *data;                 // Entry data.
    struct delay *delays;       // Entry delayed messages (waiting for data).
    struct entry *next;         // Next entry.
};

// The big data table.
struct table
{
    size_t len;                 // Table size.
    size_t count;               // Table entry count.
    mutex lock;                 // Table lock.
    struct entry **entries;     // Table entries.
};

// Peer initialization info.
struct info
{
    struct state *state;        // The state.
    size_t peer_idx;            // The peer's index.
    int sock;                   // The peer's socket.
    struct in6_addr addr;       // The peer's remote address.
    bool outbound;              // Is the peer outbound?
};

// Send worker initialization.
struct send_info
{
    struct state *state;        // The state.
    struct peer *peer;          // The peer.
};

// Inv vector element.
struct inv
{
    uint32_t type;              // The type.
    uint256_t hash;             // The hash.
};

// Entry states:
#define MISSING         0
#define OBSERVED        1
#define FETCHING        2
#define AVAILABLE       3

static void deref_peer(struct peer *peer);

/****************************************************************************/
// GLOBAL STATE:

#define PEER_RESERVE    ((struct peer *)1)
#define MAX_SEEDS       8

struct state
{
    // Global table:
    struct table *table;

    // Height logic:
    mutex height_lock;
    uint32_t init_height;
    uint32_t height;
    uint32_t height_0;
    uint32_t height_1;
    uint32_t height_inc;

    // Our address:
    mutex addr_lock;
    struct in6_addr myaddr;
    struct in6_addr myaddr_0;
    struct in6_addr myaddr_1;

    // Hash salts:
    uint64_t addr_salt;
    uint64_t headers_salt;

    // Random numbers:
    mutex rand_lock;
    uint64_t state[2];
    uint256_t rnum;
    size_t rnum_idx;

    // Stats:
    size_t recv_bytes;
    size_t send_bytes;
    size_t num_ins;
    size_t num_outs;

    // Peer storage:
    mutex peer_lock;
    size_t peers_len;
    struct peer **peers;
    size_t last_idx;

    // Address queue:
    mutex queue_lock;
    ssize_t queue_head;
    ssize_t queue_tail;
    size_t queue_len;
    struct in6_addr *queue;

    // Fetch queue:
    mutex pending_lock;
    struct fetch *pending;

    // Coin config:
    uint32_t protocol_version;
    uint32_t magic;
    uint16_t port;
    bool use_relay;
    const char *seeds[MAX_SEEDS + 1];

    // Callbacks:
    PN_callback cb_block;
    PN_callback cb_tx;
    PN_callback cb_inv;
    PN_callback cb_version;
    PN_callback cb_raw;
    PN_callback cb_warning;
    PN_callback cb_log;

    // Node config:
    const char *user_agent;
    uint64_t services;
    unsigned threshold;
    bool prefetch;
    unsigned num_peers;
};

// Create a new state
static struct state *alloc_state(void)
{
    struct state *S = (struct state *)malloc(sizeof(struct state));
    assert(S != NULL);
    memset(S, 0, sizeof(struct state));
    mutex_init(&S->queue_lock);
    mutex_init(&S->height_lock);
    mutex_init(&S->addr_lock);
    mutex_init(&S->peer_lock);
    mutex_init(&S->rand_lock);
    mutex_init(&S->pending_lock);
    return S;
}

/****************************************************************************/
// HEIGHT

// Set the current height.
static void set_height(struct state *S, uint32_t h)
{
    mutex_lock(&S->height_lock);
    if (h > S->height)
    {
        S->height_1 = S->height_0;
        S->height_0 = h;
        static const uint32_t MAX_DIFF = 6;
        uint32_t diff = (S->height_0 < S->height_1?
            S->height_1 - S->height_0:
            S->height_0 - S->height_1);
        if (diff <= MAX_DIFF)
        {
            S->height = (S->height_0 < S->height_1?
                S->height_0:
                S->height_1);
            S->height_inc = S->height;
        }
        else if (h <= S->height_inc && S->height_inc - h < MAX_DIFF)
        {
            S->height = h;
            S->height_inc = S->height;
        }
    }
    mutex_unlock(&S->height_lock);
}

// Set the current height.
static bool clobber_height(struct state *S, uint32_t h)
{
    bool is_new = false;
    mutex_lock(&S->height_lock);
    if (h > S->height)
    {
        is_new = true;
        S->height_1 = S->height_0 = S->height_inc = h;
    }
    mutex_unlock(&S->height_lock);
    return is_new;
}

// Increment the height for a new block.  This is tricky because of orphan
// blocks, so care must be taken not to overtake the real height.
static void height_inc(struct state *S)
{
    mutex_lock(&S->height_lock);
    if (S->height > S->init_height)
    {
        S->height_inc++;
        static const uint32_t MAX_DIFF = 6;
        if (S->height + MAX_DIFF < S->height_inc)
            S->height = S->height_inc - MAX_DIFF;
    }
    mutex_unlock(&S->height_lock);
}

// Get the current height.
static uint32_t get_height(struct state *S)
{
    mutex_lock(&S->height_lock);
    uint32_t h = S->height;
    mutex_unlock(&S->height_lock);
    return h;
}

/****************************************************************************/
// ADDRESS
//
// PseudoNode thinks its address is A if 2 or more outbound peers agree.

// Set address.
static bool set_my_addr(struct state *S, struct in6_addr addr)
{
    mutex_lock(&S->addr_lock);
    S->myaddr_1 = S->myaddr_0;
    S->myaddr_0 = addr;
    bool new = false;
    if (memcmp(&S->myaddr_0, &S->myaddr_1, sizeof(S->myaddr_0)) == 0)
    {
        new = (memcmp(&S->myaddr, &S->myaddr_1, sizeof(S->myaddr)) != 0);
        S->myaddr = S->myaddr_1;
    }
    mutex_unlock(&S->addr_lock);
    return new;
}

// Get address.
static struct in6_addr get_my_addr(struct state *S)
{
    mutex_lock(&S->addr_lock);
    struct in6_addr addr = S->myaddr;
    mutex_unlock(&S->addr_lock);
    return addr;
}

/****************************************************************************/
// LOGGING

#define MAX_LOG     4096

#define ACTION      0
#define LOG         1
#define WARNING     2
#define FATAL       3

// Print fancy log message.
static void print_log(struct state *S, unsigned type, PN_callback cb,
    struct in6_addr addr, const char *format, ...)
{
    if (cb == NULL)
        return;
    va_list ap;
    va_start(ap, format);
    char buf[MAX_LOG];
    int res = vsnprintf(buf, sizeof(buf)-1, format, ap);
    if (res <= 0 || res > sizeof(buf)-1)
    {
        va_end(ap);
        return;
    }
    char *message = strdup(buf);
    if (message == NULL)
    {
        va_end(ap);
        return;
    }
    unsigned len = res + 1;
    message = (char *)cb((struct PN *)S, type, addr, (unsigned char *)message,
        &len);
    free(message);
    va_end(ap);
}

#define action(S, addr, format, ...)                                \
    print_log(S, PN_CALLBACK_LOG, S->cb_log, addr, format, ##__VA_ARGS__)
#define log(S, format, ...)                                         \
    print_log(S, PN_CALLBACK_LOG, S->cb_log, addr, format, ##__VA_ARGS__)
#define warning(S, addr, format, ...)                               \
    print_log(S, PN_CALLBACK_WARNING, S->cb_warning, addr, format,  \
        ##__VA_ARGS__)
#define fatal(format, ...)                                          \
    do {                                                            \
        fprintf(stderr, "fatal: " format "\n", ##__VA_ARGS__);      \
        abort();                                                    \
    } while (false)

/****************************************************************************/
// MEMORY ALLOCATION

static inline void *mem_alloc(size_t size)
{
    void *mem = malloc(size);
    assert(mem != NULL);
    return mem;
}

#define mem_free        free

/****************************************************************************/
// HASH FUNCTIONS

static uint256_t sha256(const void *data, size_t len)
{
    uint256_t res;
    sha256_hash(data, len, (char *)&res);
    return res;
}

static uint256_t hash(const void *data, size_t len)
{
    uint256_t res = sha256(data, len);
    res = sha256(&res, sizeof(res));
    return res;
}

static uint256_t addr_hash(struct state *S, struct in6_addr addr)
{
    addr.s6_addr16[0] ^= (uint16_t)S->addr_salt;
    addr.s6_addr16[1] ^= (uint16_t)(S->addr_salt >> 16);
    addr.s6_addr16[2] ^= (uint16_t)(S->addr_salt >> 32);
    addr.s6_addr16[3] ^= (uint16_t)(S->addr_salt >> 48);
    return sha256(&addr, sizeof(addr));
}

static uint256_t headers_hash(struct state *S, uint256_t hsh)
{
    hsh.i64[0] ^= S->headers_salt;
    return sha256(&hsh, sizeof(hsh));
}

/****************************************************************************/
// RANDOM NUMBERS

// Initialize random numbers.
static void rand64_init(struct state *S)
{
    S->rnum_idx = SIZE_MAX;
    if (!rand_init(S->state))
        fatal("failed to initialize random numbers");
}

// Return a 64-bit random number.
static uint64_t rand64(struct state *S)
{
    mutex_lock(&S->rand_lock);
    if (S->rnum_idx >= sizeof(uint256_t) / sizeof(uint64_t))
    {
        S->state[0]++;
        if (S->state[0] == 0)
            S->state[1]++;
        S->rnum = sha256(S->state, sizeof(S->state));
        S->rnum_idx = 0;
    }
    uint64_t r = S->rnum.i64[S->rnum_idx++];
    mutex_unlock(&S->rand_lock);
    return r;
}

/****************************************************************************/
// SIMPLE DATA BUFFERS
//
// Data buffer are mainly used to store/construct/deconstruct messages.  They
// are analogous to C++'s vector<> type.

#define BUFFER_SIZE             256

// Allocate a new buffer.  Note env must be non-NULL if we intend to read from
// the buffer (e.g. use pop()).
static struct buf *alloc_buf(jmp_buf *env)
{
    struct buf *buf = (struct buf *)mem_alloc(sizeof(struct buf));
    char *data = (char *)mem_alloc(BUFFER_SIZE);
    buf->env       = env;
    buf->data      = data;
    buf->len       = BUFFER_SIZE;
    buf->ptr       = 0;
    buf->ref_count = 1;
    return buf;
}

// Reset an existing buffer.
static void reset_buf(struct buf *buf)
{
    if (buf->len > BUFFER_SIZE)
    {
        mem_free(buf->data);
        buf->data = (char *)mem_alloc(BUFFER_SIZE);
    }
    buf->len = BUFFER_SIZE;
    buf->ptr = 0;
}

static void ref_buf(struct buf *buf)
{
    if (buf == NULL)
        return;
    atomic_add(&buf->ref_count, 1);
}

static void deref_buf(struct buf *buf)
{
    if (buf == NULL)
        return;
    ssize_t ref_count = atomic_sub(&buf->ref_count, 1);
    if (ref_count > 1)
        return;
    mem_free(buf->data);
    mem_free(buf);
}

// Grow (i.e. reserve space) a buffer by length `len'. 
static void grow_buf(struct buf *buf, size_t len)
{
    if (buf->len - buf->ptr >= len)
        return;
    size_t old_len = buf->len;
    while (buf->len - buf->ptr < len)
        buf->len = 2 * buf->len;
    char *old_data = buf->data;
    buf->data = (char *)mem_alloc(buf->len);
    memcpy(buf->data, old_data, old_len);
    mem_free(old_data);
}

// Push data onto a buffer.
#define push(buf, v)                                                    \
    do {                                                                \
        grow_buf((buf), sizeof(v));                                     \
        memcpy((buf)->data + (buf)->ptr, &(v), sizeof(v));              \
        (buf)->ptr += sizeof(v);                                        \
    } while (false)

// Push a varint.
static void push_varint(struct buf *buf, uint64_t v)
{
    uint8_t v8; uint16_t v16; uint32_t v32;
    if (v < 0xFD)
    {
        v8 = (int8_t)v;
        push(buf, v8);
    }
    else if (v <= 0xFFFF)
    {
        v8 = 0xFD; push(buf, v8);
        v16 = (uint16_t)v; push(buf, v16);
    }
    else if (v <= 0xFFFFFFFF)
    {
        v8 = 0xFE; push(buf, v8);
        v32 = (uint32_t)v; push(buf, v32);
    }
    else
    {
        v8 = 0xFF; push(buf, v8);
        push(buf, v);
    }
}

// Push a varstr.
static void push_varstr(struct buf *buf, const char *str)
{
    size_t len = strlen(str);
    push_varint(buf, len);
    grow_buf(buf, len);
    memcpy(buf->data + buf->ptr, str, len);
    buf->ptr += len;
}

// Push the contents of another buffer.
static void push_buf(struct buf *buf, const struct buf *data)
{
    grow_buf(buf, data->ptr);
    memcpy(buf->data + buf->ptr, data->data, data->ptr);
    buf->ptr += data->ptr;
}

// Push arbitrary data.
static void push_data(struct buf *buf, size_t len, const void *data)
{
    grow_buf(buf, len);
    memcpy(buf->data + buf->ptr, data, len);
    buf->ptr += len;
}

// pop_error() will be called if a message is truncated.
static int pop_error(jmp_buf *env, size_t len)
{
    assert(env != NULL);
    longjmp(*env, 1);
}

// Pop data of `type' from the buffer.
#define pop(buf, type)                                                      \
    (((buf)->ptr + sizeof(type) <= (buf)->len? 0:                           \
        pop_error((buf)->env, sizeof(type))),                               \
     (buf)->ptr += sizeof(type),                                            \
     *(type *)((buf->data + (buf)->ptr - sizeof(type))))

// Pop a varint from the buffer.
static uint64_t pop_varint(struct buf *buf)
{
    uint8_t v8 = pop(buf, uint8_t);
    if (v8 < 0xFD)
        return (uint64_t)v8;
    else if (v8 == 0xFD)
        return (uint64_t)pop(buf, uint16_t);
    else if (v8 == 0xFE)
        return (uint64_t)pop(buf, uint32_t);
    else
        return pop(buf, uint64_t);
}

// Pop arbitrary "data" of length `len' from the buffer.
static char *pop_data(struct buf *buf, size_t len)
{
    if ((buf)->ptr + (len) > (buf)->len)
        pop_error(buf->env, len);
    char *data = mem_alloc(len);
    memcpy(data, buf->data + buf->ptr, len);
    buf->ptr += len;
    return data;
}

// Pop a varstr from the buffer.
static char *pop_varstr(struct buf *buf)
{
    size_t len = pop_varint(buf);
    if (buf->ptr + len > buf->len)
        pop_error(buf->env, len);
    char *s = (char *)mem_alloc(len+1);
    memcpy(s, buf->data + buf->ptr, len);
    s[len] = '\0';
    buf->ptr += len;
    return s;
}

// Returns `true' if the buffer has no more data.
static bool is_empty(struct buf *buf)
{
    return (buf->ptr == buf->len);
}

// Invoke a callback on a struct buf.
static bool callback_buf(struct state *S, unsigned type, struct in6_addr addr,
    struct buf *in, PN_callback f)
{
    unsigned len = in->ptr;
    unsigned char *new_data = f((struct PN *)S, type, addr,
        (unsigned char *)in->data, &len);
    if (new_data == NULL)
    {
        in->len = in->ptr = 0;
        in->data = NULL;
        return false;
    }
    in->len = in->ptr = len;
    in->data = (char *)new_data;
    return true;
}

/****************************************************************************/
// DATA TABLE
// 
// The monolithic data "table".  Stores blocks, tx, peers, addrs, etc., etc.
// Acts are PseudoNode's mempool, blockchain, address list, etc., etc.

// Create a new table.  Only ever called once.
static struct table *alloc_table(void)
{
    struct table *table = (struct table *)mem_alloc(sizeof(struct table));
    size_t len = 4096;
    struct entry **entries = (struct entry **)mem_alloc(
        len * sizeof(struct entry *));
    memset(entries, 0, len * sizeof(struct entry *));
    table->len = len;
    table->count = 0;
    table->entries = entries;
    mutex_init(&table->lock);
    return table;
}

// Population count (for tallying votes):
static size_t tally(uint64_t x)
{
    size_t count;
    for (count = 0; x; count++)
        x &= x - 1;
    return count;
}

// Get the table index from a hash.
#define get_index(table, hsh)       ((size_t)(hsh).i32[4] % (table)->len)

// Possibly grow the table if we are running out of space.  Assumes a locked
// table.
static void grow_table(struct table *table)
{
    const size_t FACTOR = 8;
    if (table->count < FACTOR * table->len)
        return;
    size_t len = table->len;
    table->len *= 2;
    struct entry **entries = table->entries;
    table->entries = (struct entry **)mem_alloc(
        table->len * sizeof(struct entry *));
    memset(table->entries, 0, table->len * sizeof(struct entry *));
    for (size_t i = 0; i < len; i++)
    {
        struct entry *entry = entries[i];
        while (entry != NULL)
        {
            struct entry *e = entry;
            entry = entry->next;
            size_t idx = get_index(table, e->hash);
            e->next = table->entries[idx];
            table->entries[idx] = e;
        }
    }
    mem_free(entries);
}

// Find the entry associated with `hsh'.  Assumes a locked table.
static struct entry *get_entry(struct table *table, uint256_t hsh)
{
    size_t idx = get_index(table, hsh);
    struct entry *entry = table->entries[idx];
    while (entry != NULL)
    {
        if (memcmp(&hsh, &entry->hash, sizeof(hsh)) == 0)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

// Vote some (potential) data into existence.  In effect, this creates and
// initializes a new entry (if one does not already exist), or records the
// vote for `vote_idx' of an existing entry.  Each index can only vote once.
// Inbound peers are not allowed to vote to prevent ballot stuffing.
static uint64_t vote(struct table *table, uint256_t hsh, unsigned type,
    size_t vote_idx, struct state *S)
{
    if (vote_idx >= S->num_peers)
        return 0;       // Inbound peers cannot vote.
    size_t vote = (1 << (vote_idx % 64));

    time_t curr_time = time(NULL);
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
    {
        entry->vote |= vote;
        size_t new_vote = entry->vote;
        mutex_unlock(&table->lock);
        return new_vote;
    }
    else
    {
        grow_table(table);
        size_t idx = get_index(table, hsh);
        entry = (struct entry *)mem_alloc(sizeof(struct entry));
        entry->hash = hsh;
        entry->type = type;
        entry->vote = vote;
        entry->time = curr_time;
        entry->state = OBSERVED;
        entry->ref_count = 1;
        entry->len = 0;
        entry->data = NULL;
        entry->delays = NULL;
        entry->next = table->entries[idx];
        table->entries[idx] = entry;
        table->count++;
        mutex_unlock(&table->lock);
        return vote;
    }
}

// Insert is similar to voting, except for data where the vote count is
// irrelevant.
#define insert(table, hsh, type, S)     vote((table), (hsh), (type), 0, (S))

// Free an entry.  Assumes a locked table.
static void free_entry(struct entry *entry)
{
    struct delay *delays = entry->delays;
    while (delays != NULL)
    {
        struct delay *d = delays;
        delays = delays->next;
        mem_free(d);
    }
    mem_free(entry->data);
    mem_free(entry);
}

// Associate data with `hsh'.  Returns false if data already exists.
static bool set_data(struct table *table, uint256_t hsh, void *data,
    size_t len)
{
    assert(len <= UINT32_MAX);
    bool ok = true;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
    {
        if (entry->data == NULL)
        {
            entry->len = len;
            entry->data = data;
            entry->state = AVAILABLE;
        }
        else
            ok = false;
    }
    else
        ok = false;
    mutex_unlock(&table->lock);
    return ok;
}

// Get the data associated with `hsh', otherwise return NULL.  If non-NULL
// data is returned, then the entry reference count is increased.
static void *get_data(struct table *table, uint256_t hsh, size_t *lenptr)
{
    void *data = NULL;
    if (lenptr != NULL)
        *lenptr = 0;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
    {
        data = entry->data;
        if (lenptr != NULL)
            *lenptr = (size_t)entry->len;
        if (data != NULL)
            entry->ref_count++;
    }
    mutex_unlock(&table->lock);
    return data;
}

// Deref the data associated with `hsh'.  Free the entry if the ref count is 0.
static bool deref_data(struct table *table, uint256_t hsh)
{
    mutex_lock(&table->lock);
    size_t idx = get_index(table, hsh);
    struct entry *entry = table->entries[idx], *prev = NULL;
    while (entry != NULL)
    {
        if (memcmp(&hsh, &entry->hash, sizeof(hsh)) == 0)
        {
            if (entry->ref_count > 1)
            {
                entry->ref_count--;
                mutex_unlock(&table->lock);
                return false;
            }
            if (prev == NULL)
                table->entries[idx] = entry->next;
            else
                prev->next = entry->next;
            table->count--;
            mutex_unlock(&table->lock);
            free_entry(entry);
            return true;
        }
        prev = entry;
        entry = entry->next;
    }
    mutex_unlock(&table->lock);
    return false;
}

// Set the state associated with `hsh'.  Return the old state.
static unsigned set_state(struct table *table, uint256_t hsh, unsigned state)
{
    time_t curr_time = time(NULL);
    unsigned old_state = MISSING;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL && entry->state < state)
    {
        old_state = entry->state;
        entry->state = state;
        entry->time = curr_time;
    }
    mutex_unlock(&table->lock);
    return old_state;
}

// Get the state associated with `hsh'.
static unsigned get_state(struct table *table, uint256_t hsh)
{
    unsigned state = MISSING;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
        state = entry->state;
    mutex_unlock(&table->lock);
    return state;
}

// Set the time associated with `hsh'.
static void set_time(struct table *table, uint256_t hsh, time_t time)
{
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
        entry->time = time;
    mutex_unlock(&table->lock);
}

// Get the time associated with `hsh'.
static time_t get_time(struct table *table, uint256_t hsh)
{
    time_t time = 0;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
        time = entry->time;
    mutex_unlock(&table->lock);
    return time;
}

// Get the vote associated with `hsh'.
static uint64_t get_vote(struct table *table, uint256_t hsh)
{
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    uint64_t vote = (entry != NULL? entry->vote: 0);
    mutex_unlock(&table->lock);
    return vote;
}

// Get the vote tally associated with `hsh'.
#define get_tally(table, hsh)    tally(get_vote((table), (hsh)))

// Delay peer with `index' on the arrival of data to `hsh' (via set_data()).
static void set_delay(struct table *table, uint256_t hsh, size_t idx,
    uint64_t nonce)
{
    struct delay *d = (struct delay *)mem_alloc(sizeof(struct delay));
    d->index = idx;
    d->nonce = nonce;
    bool ok = false;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
    {
        ok = true;
        d->next = entry->delays;
        entry->delays = d;
    }
    mutex_unlock(&table->lock);
    if (!ok)
        mem_free(d);
}

// Get the list of delayed peers associated with `hsh'.   Also resets this
// list to be empty.
static struct delay *get_delays(struct table *table, uint256_t hsh)
{
    struct delay *delays = NULL;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
    {
        delays = entry->delays;
        entry->delays = NULL;
    }
    mutex_unlock(&table->lock);
    return delays;
}

// Delete an entry.  Really the same as a deref.
static bool delete(struct table *table, uint256_t hsh)
{
    return deref_data(table, hsh);
}

// Stop-the-world and clean-up all "stale" objects.  This is done every time a
// new block is found.  There may be better ways to do this.
static void garbage_collect(struct table *table)
{
    time_t curr_time = time(NULL);
    size_t num_tx, num_blk, num_addr, num_bytes;
    num_tx = num_blk = num_addr = num_bytes = 0;
    mutex_lock(&table->lock);
    for (size_t i = 0; i < table->len; i++)
    {
        struct entry *entry = table->entries[i], *prev = NULL;
        while (entry != NULL)
        {
            long long int diff = llabs(curr_time - entry->time);
            bool del = false;
            switch (entry->type)
            {
                case TX:
                    del = (diff > 600);
                    num_tx += del;
                    break;
                case HEADERS:
                    del = (diff > 10);
                    break;
                case BLOCK:
                    del = (diff > 150);
                    num_blk += del;
                    break;
                case ADDRESS:
                    del = (diff > 10800);
                    num_addr += del;
                    break;
                default:
                    break;
            }
            if (del)
            {
                if (entry->ref_count > 1)
                    entry->ref_count--;
                else
                {
                    if (prev == NULL)
                        table->entries[i] = entry->next;
                    else
                        prev->next = entry->next;
                    table->count--;
                    struct entry *e = entry;
                    entry = entry->next;
                    num_bytes += e->len;
                    free_entry(e);
                    continue;
                }
            }
            prev = entry;
            entry = entry->next;
        }
    }
    mutex_unlock(&table->lock);
}

/****************************************************************************/
// PEER STORAGE
//
// Peers 0..maxpeers-1 are reserved for outbound connections.
// Peers maxpeers..oo are for inbound connections.

// Get the total number of peers (approx.)
static size_t get_num_peers(struct state *S)
{
    mutex_lock(&S->peer_lock);
    size_t num_peers = S->last_idx+1;
    mutex_unlock(&S->peer_lock);
    return num_peers;
}

// Allocate a slot for a new peer.
static ssize_t alloc_peer(struct state *S, bool outbound)
{
    mutex_lock(&S->peer_lock);
    ssize_t start = (outbound? 0: S->num_peers);
    ssize_t end   = (outbound? S->num_peers: S->peers_len);
    ssize_t idx = -1;
    for (size_t i = start; i < end; i++)
    {
        if (S->peers[i] == NULL)
        {
            S->peers[i] = PEER_RESERVE;
            idx = i;
            if (idx > S->last_idx)
                S->last_idx = idx;
            break;
        }
    }
    if (!outbound && idx == -1)
    {
        idx = S->peers_len;
        size_t len = (3 * S->peers_len) / 2 + 4;
        struct peer **new_peers = mem_alloc(len * sizeof(struct peer *));
        memset(new_peers, 0, len * sizeof(struct peer *));
        memcpy(new_peers, S->peers, S->peers_len * sizeof(struct peer *));
        S->peers_len = len;
        struct peer **old_peers = S->peers;
        S->peers = new_peers;
        mem_free(old_peers);
        S->peers[idx] = PEER_RESERVE;
        S->last_idx = idx;
    }
    if (idx != -1 && outbound)
        S->num_outs++;
    if (idx != -1 && !outbound)
        S->num_ins++;
    mutex_unlock(&S->peer_lock);
    return idx;
}

// Get the peer associated with a slot.  Also check the nonce if non-zero.
static struct peer *get_peer(struct state *S, size_t idx, uint64_t nonce)
{
    mutex_lock(&S->peer_lock);
    struct peer *peer = S->peers[idx];
    mutex_unlock(&S->peer_lock);
    if (peer == NULL)
        return NULL;
    if (peer == PEER_RESERVE)
        return NULL;
    if (nonce != 0 && peer->nonce != nonce)
        return NULL;
    atomic_add(&peer->ref_count, 1);
    return peer;
}

// Set the peer for a slot.
static void set_peer(struct state *S, size_t idx, struct peer *peer)
{
    mutex_lock(&S->peer_lock);
    S->peers[idx] = peer;
    mutex_unlock(&S->peer_lock);
}

// Delete a slot making it available again.
static void del_peer(struct state *S, size_t idx)
{
    mutex_lock(&S->peer_lock);
    S->peers[idx] = NULL;
    if (idx == S->last_idx)
    {
        for (ssize_t i = (ssize_t)idx-1; i >= 0; i--)
        {
            S->last_idx = i;
            if (S->peers[i] != NULL)
                break;
        }
    }
    if (idx < S->num_peers)
        S->num_outs--;
    else
        S->num_ins--;
    mutex_unlock(&S->peer_lock);
}

// Reset the state of all peers.
static void reset_peers(struct state *S)
{
    mutex_lock(&S->peer_lock);
    for (size_t i = 0; i < S->last_idx; i++)
    {
        if (S->peers[i] == NULL)
            continue;
        if (S->peers[i] == PEER_RESERVE)
            continue;
        S->peers[i]->score = 0;
        S->peers[i]->inv_score = 0;
    }
    mutex_unlock(&S->peer_lock);
}

// Add/sub peer DoS score.
static void score_peer(struct state *S, struct peer *peer, ssize_t score)
{
    static const ssize_t MAX_SCORE = 1000;
    ssize_t new_score = atomic_add(&peer->score, score);
    if (new_score >= MAX_SCORE)
    {
        peer->score = INT16_MAX;
        warning(S, peer->to_addr, "disconnecting misbehaving peer");
        peer->error = true;
    }
}

/****************************************************************************/
// ADDRESS QUEUE

// Queue a new address to be used later as a peer.
static void queue_push_address(struct state *S, struct in6_addr addr)
{
    mutex_lock(&S->queue_lock);
    if (S->queue_head - S->queue_tail < S->queue_len)
    {
        S->queue[S->queue_head % S->queue_len] = addr;
        S->queue_head++;
    }
    mutex_unlock(&S->queue_lock);
}

// Check if two IP addresses are "similar" or not.
static bool is_similar_address(struct in6_addr addr1, struct in6_addr addr2)
{
    if (memcmp(&addr1, &addr2, 12) != 0)
        return false;
    bool is_ipv4 =
        (addr1.s6_addr16[0] == 0 && addr1.s6_addr16[1] == 0 &&
         addr1.s6_addr16[2] == 0 && addr1.s6_addr16[3] == 0 &&
         addr1.s6_addr16[4] == 0 && addr1.s6_addr16[5] == 0xFFFF);
    if (is_ipv4)
        return (addr1.s6_addr16[6] == addr2.s6_addr16[6]);
    else
        return true;
}

// Get a queued address.
static struct in6_addr queue_pop_address(struct state *S, bool *ok)
{
    struct in6_addr addr;
    uint256_t addr_hsh;
    *ok = true;
    memset(&addr, 0, sizeof(addr));
    while (true)
    {
        bool found = false;
        mutex_lock(&S->queue_lock);
        if (S->queue_tail < S->queue_head)
        {
            found = true;
            addr = S->queue[S->queue_tail % S->queue_len];
            S->queue_tail++;
        }
        mutex_unlock(&S->queue_lock);
        if (!found)
        {
            *ok = false;
            return addr;
        }
        addr_hsh = addr_hash(S, addr);
        if (get_time(S->table, addr_hsh) == 0)
            continue;
        size_t num_peers = get_num_peers(S);
        bool addr_ok = true;
        for (size_t i = 0; addr_ok && i < num_peers; i++)
        {
            struct peer *p = get_peer(S, i, 0);
            if (p == NULL)
                continue;
            addr_ok = !is_similar_address(addr, p->to_addr);
            deref_peer(p);
        }
        if (addr_ok)
            break;
    }
    return addr;
}

// Get a collection of addresses to service a getaddr message.
static size_t queue_get_addresses(struct state *S, struct buf *buf,
    size_t maxlen)
{
    mutex_lock(&S->queue_lock);
    ssize_t start = S->queue_tail, end = S->queue_head;
    mutex_unlock(&S->queue_lock);

    time_t curr_time = time(NULL);
    size_t num_addr = 0;
    for (ssize_t i = start; i < end && num_addr < maxlen; i++)
    {
        mutex_lock(&S->queue_lock);
        struct in6_addr addr = S->queue[i % S->queue_len];
        mutex_unlock(&S->queue_lock);
        
        uint256_t addr_hsh = addr_hash(S, addr);
        time_t addr_time = get_time(S->table, addr_hsh);
        if (addr_time == 0 || llabs(addr_time - curr_time) > 10800)
            continue;

        uint32_t addr_time32 = (uint32_t)addr_time;
        push(buf, addr_time32);
        uint64_t services = S->services;
        push(buf, services);
        push(buf, addr);
        uint16_t port = S->port;
        push(buf, port);
        num_addr++;
    }
    return num_addr;
}

// Return `true' if we need more addresses.
static bool queue_need_addresses(struct state *S)
{
    mutex_lock(&S->queue_lock);
    bool ok = ((S->queue_head - S->queue_tail) < S->queue_len);
    mutex_unlock(&S->queue_lock);
    return ok;
}

// Shuffle the queue.
static void queue_shuffle(struct state *S)
{
    uint64_t r = rand64(S);
    mutex_lock(&S->queue_lock);
    ssize_t n = S->queue_head - S->queue_tail;
    for (size_t i = n-1; i >= 1; i--)
    {
        size_t j = r % i;
        struct in6_addr tmp = S->queue[(S->queue_tail+i) % S->queue_len];
        S->queue[(S->queue_tail+i) % S->queue_len] =
            S->queue[(S->queue_tail+j) % S->queue_len];
        S->queue[(S->queue_tail+j) % S->queue_len] = tmp;
        r = r * 333333333323 + 123456789;
    }
    mutex_unlock(&S->queue_lock);
}

/****************************************************************************/
// FETCH QUEUE
//
// Sometimes fetch data requests may fail.  Here we attempt to re-fetch data
// if necessary.

#define TTL_INIT        3

static bool fetch_data(struct state *S, struct peer *peer, uint32_t type,
    uint256_t hsh, bool sync, uint64_t mask, int8_t ttl);

// Re-fetch data if necessary.
static void refetch_data(struct state *S)
{
    mutex_lock(&S->pending_lock);
    struct fetch *reqs = S->pending;
    S->pending = NULL;
    mutex_unlock(&S->pending_lock);
    if (reqs == NULL)
        return;

    time_t curr_time = time(NULL);
    struct fetch *curr = reqs;
    reqs = NULL;
    while (curr != NULL)
    {
        struct fetch *next = curr->next;
        unsigned state = get_state(S->table, curr->hash);
        if (state != FETCHING)
        {
            // Clean-up old entry.
            mem_free(curr);
            curr = next;
            continue;
        }
        if (curr_time < curr->time)
        {
            curr->next = reqs;
            reqs = curr;
            curr = next;
            continue;
        }
        struct in6_addr addr;
        memset(&addr, 0, sizeof(addr));
        warning(S, addr, "refetching stalled data " HASH_FORMAT_SHORT,
            HASH_SHORT(curr->hash));
        
        // Punish offending peer:
        for (size_t i = 0; i < S->num_peers; i++)
        {
            struct peer *p = get_peer(S, i, curr->nonce);
            if (p == NULL)
                continue;
            score_peer(S, p, 100);
            deref_peer(p);
            break;
        }
        uint64_t mask = (curr->sync? get_vote(S->table, curr->hash):
            UINT64_MAX);
        fetch_data(S, NULL, curr->type, curr->hash, curr->sync, mask,
            curr->ttl-1);
        mem_free(curr);
        curr = next;
    }

    mutex_lock(&S->pending_lock);
    while (S->pending != NULL)
    {
        struct fetch *next = S->pending->next;
        S->pending->next = reqs;
        reqs = S->pending;
        S->pending = next;
    }
    S->pending = reqs;
    mutex_unlock(&S->pending_lock);
}

// Pend a fetch_data request.
static void pend_fetch(struct state *S, uint256_t hsh, uint32_t type,
    bool sync, uint64_t nonce, int8_t ttl)
{
    if (ttl <= 0)
        return;     // Give up...
    struct fetch *req = (struct fetch *)mem_alloc(sizeof(struct fetch));
    req->time = time(NULL) + (type == MSG_BLOCK? 30: 10);
    req->ttl   = ttl;
    req->nonce = nonce;
    req->sync  = sync;
    req->type  = type;
    req->hash  = hsh;
    mutex_lock(&S->pending_lock);
    req->next = S->pending;
    S->pending = req;
    mutex_unlock(&S->pending_lock);
}

/****************************************************************************/
// MAKE MESSAGES
//
// See the protocol specification for more information.

// Finalize a message (set length & calculate checksums).
static void finalize_message(struct buf *out)
{
    assert(out->ptr >= sizeof(struct header) && out->ptr <= UINT32_MAX);
    struct header *hdr = (struct header *)out->data;
    void *payload = (void *)(hdr + 1);
    uint32_t payload_len = out->ptr - sizeof(struct header);
    hdr->length = payload_len;
    uint256_t checksum = hash(payload, payload_len);
    hdr->checksum = checksum.i32[0];
}

static void make_version(struct state *S, struct buf *buf, struct peer *peer,
    uint64_t nonce, bool use_relay)
{
    struct header hdr = {S->magic, "version", 0, 0};
    push(buf, hdr);
    uint32_t version = S->protocol_version;
    push(buf, version);
    uint64_t services = S->services;
    push(buf, services);
    uint64_t curr_time = time(NULL);
    push(buf, curr_time);
    push(buf, services);
    push(buf, peer->to_addr);
    push(buf, peer->to_port);
    push(buf, services);
    push(buf, peer->from_addr);
    push(buf, peer->from_port);
    push(buf, nonce);
    push_varstr(buf, S->user_agent);
    uint32_t h = get_height(S);
    push(buf, h);
    if (use_relay && S->use_relay)
    {
        uint8_t relay = 1;
        push(buf, relay);
    }
    finalize_message(buf);
}

static void make_verack(struct state *S, struct buf *buf)
{
    struct header hdr = {S->magic, "verack", 0, 0};
    push(buf, hdr);
    finalize_message(buf);
}

static void make_addr(struct state *S, struct buf *buf, size_t num_addr,
    void *data, size_t len)
{
    struct header hdr = {S->magic, "addr", 0, 0};
    push(buf, hdr);
    push_varint(buf, num_addr);
    push_data(buf, len, data);
    finalize_message(buf);
}

static void make_addr_0(struct state *S, struct buf *buf, uint32_t time,
    struct in6_addr addr)
{
    struct header hdr = {S->magic, "addr", 0, 0};
    push(buf, hdr);
    push_varint(buf, 1);
    push(buf, time);
    uint64_t services = NODE_NETWORK;
    push(buf, services);
    push(buf, addr);
    uint16_t port = S->port;
    push(buf, port);
    finalize_message(buf);
}

static void make_tx(struct state *S, struct buf *buf, const void *data,
    size_t len)
{
    struct header hdr = {S->magic, "tx", 0, 0};
    push(buf, hdr);
    push_data(buf, len, data);
    finalize_message(buf);
}

static void make_block(struct state *S, struct buf *buf, const void *data,
    size_t len)
{
    struct header hdr = {S->magic, "block", 0, 0};
    push(buf, hdr);
    push_data(buf, len, data);
    finalize_message(buf);
}

static void make_getaddr(struct state *S, struct buf *buf)
{
    struct header hdr = {S->magic, "getaddr", 0, 0};
    push(buf, hdr);
    finalize_message(buf);
}

static void make_getdata(struct state *S, struct buf *buf, uint32_t type,
    uint256_t hsh)
{
    struct header hdr = {S->magic, "getdata", 0, 0};
    push(buf, hdr);
    push_varint(buf, 1);
    push(buf, type);
    push(buf, hsh);
    finalize_message(buf);
}

static void make_inv(struct state *S, struct buf *buf, uint32_t type,
    uint256_t hsh)
{
    struct header hdr = {S->magic, "inv", 0, 0};
    push(buf, hdr);
    push_varint(buf, 1);
    push(buf, type);
    push(buf, hsh);
    finalize_message(buf);
}

static void make_pong(struct state *S, struct buf *buf, uint64_t nonce)
{
    struct header hdr = {S->magic, "pong", 0, 0};
    push(buf, hdr);
    push(buf, nonce);
    finalize_message(buf);
}

static void make_notfound(struct state *S, struct buf *buf, uint32_t type,
    uint256_t hsh)
{
    struct header hdr = {S->magic, "notfound", 0, 0};
    push(buf, hdr);
    push_varint(buf, 1);
    push(buf, type);
    push(buf, hsh);
    finalize_message(buf);
}

/****************************************************************************/
// SENDING & RECEIVING MESSAGES:

// Send message handler.  Sending messages is handled by a single thread (this
// thread is allowed to block on a slow connection, whereas the other threads
// must not).  Other threads can pass messages via the send_message()
// function.
static void *send_message_worker(void *arg)
{
    struct send_info *info = (struct send_info *)arg;
    struct state *S = info->state;
    struct peer *peer = info->peer;
    mem_free(info);

    while (true)
    {
        // Wait for a message:
        if (!event_wait(&peer->event))
        {
            // Timeout:
            if (peer->error)
            {
                deref_peer(peer);
                return NULL;
            }
            continue;
        }
        while (true)
        {
            mutex_lock(&peer->lock);
            struct msg *msg = peer->msg_head;
            if (msg == NULL)
            {
                mutex_unlock(&peer->lock);
                break;
            }
            peer->msg_head = msg->next;
            if (peer->msg_head == NULL)
                peer->msg_tail = NULL;
            struct buf *buf = msg->buf;
            ssize_t len = buf->ptr;
            peer->msg_len -= len;
            mutex_unlock(&peer->lock);
            ssize_t r = socket_send(peer->sock, buf->data, len);
            deref_buf(buf);
            mem_free(msg);
            if (r != len)
            {
                warning(S, peer->to_addr, "failed to send message: %s",
                    get_error());
                peer->error = true;
                deref_peer(peer);
                return NULL;
            }
            atomic_add(&S->send_bytes, len);
        }
    }
}

// Send a message to the send_message_worker() thread.
static void send_message(struct peer *peer, struct buf *buf)
{
    static const size_t MAX_LEN = 2*(1 << 20);  // 2MB
    if (buf == NULL || buf->ptr == 0 || buf->ptr > MAX_MESSAGE_LEN)
        return;
    struct msg *msg = (struct msg *)mem_alloc(sizeof(struct msg));
    ref_buf(buf);
    msg->buf = buf;
    msg->next = NULL;
    mutex_lock(&peer->lock);
    if (peer->msg_len > MAX_LEN)
    {
        // Queue is full, drop the message.
        mutex_unlock(&peer->lock);
        deref_buf(buf);
        mem_free(msg);
        return;
    }
    peer->msg_len += buf->len;
    if (peer->msg_tail == NULL)
    {
        peer->msg_tail = msg;
        peer->msg_head = msg;
    }
    else
    {
        peer->msg_tail->next = msg;
        peer->msg_tail = msg;
    }
    mutex_unlock(&peer->lock);
    event_set(&peer->event);
}

// Read message data:
static bool read_message_data(struct state *S, struct peer *peer, char *buf,
    size_t len)
{
    static const time_t TIMEOUT = 300;  // 5mins
    sock s = peer->sock;
    ssize_t i = 0;
    while (true)
    {
        bool timeout = false;
        ssize_t r = socket_recv(s, buf+i, len-i, &timeout);
        if (peer->error)
            return false;
        if (r < 0)
        {
            warning(S, peer->to_addr, "failed to recv message: %s", 
                get_error());
            return false;
        }
        if (r == 0 && !timeout)
        {
            warning(S, peer->to_addr, "connection closed by peer");
            return false;
        }
        if (r == len-i)
            break;
        time_t curr_time = time(NULL);
        if (timeout && peer->alive + TIMEOUT < curr_time)
        {
            warning(S, peer->to_addr, "connection stalled");
            return false;
        }
        if (curr_time > peer->timeout)
        {
            action(S, peer->to_addr, "churn: disconnect from old peer");
            return false;
        }
        peer->alive = curr_time;
        i += r;
        atomic_add(&S->recv_bytes, r);
    }
    return true;
}

// Read a message:
static bool read_message(struct state *S, struct peer *peer, struct buf *in)
{
    reset_buf(in);
    char hdr0[sizeof(struct header)];
    if (!read_message_data(S, peer, hdr0, sizeof(hdr0)))
        return false;
    struct header hdr = *(struct header *)hdr0;
    if (hdr.magic != S->magic)
    {
        warning(S, peer->to_addr, "bad message (incorrect magic number)");
        return false;
    }
    if (hdr.length > MAX_MESSAGE_LEN)
    {
        warning(S, peer->to_addr, "bad message (too big)");
        return false;
    }
    bool found = false;
    for (size_t i = 0; !found && i < sizeof(hdr.command); i++)
        found = (hdr.command[i] == '\0');
    if (!found)
    {
        warning(S, peer->to_addr, "bad message (command not null-terminated)");
        return false;
    }
    push(in, hdr);
    if (hdr.length == 0)
    {
        uint256_t checksum = hash(NULL, 0);
        if (checksum.i32[0] != hdr.checksum)
        {
            warning(S, peer->to_addr, "bad message (checksum failed)");
            return false;
        }
        in->len = in->ptr;
        in->ptr = 0;
        return true;
    }

    size_t len = hdr.length;
    grow_buf(in, len);
    if (!read_message_data(S, peer, in->data + in->ptr, len))
        return false;

    uint256_t checksum = hash(in->data + in->ptr, len);
    if (checksum.i32[0] != hdr.checksum)
    {
        warning(S, peer->to_addr, "bad message (checksum failed)");
        return false;
    }

    in->len = in->ptr+len;
    in->ptr = 0;
    return true;
}

// Relay a message to all peers.
static void relay_message(struct state *S, struct peer *peer,
    uint64_t mask, struct buf *buf)
{
    size_t num_peers = get_num_peers(S);
    for (size_t i = 0; i < num_peers; i++)
    {
        uint64_t bit = (1 << i);
        if ((bit & mask) != 0)      // Skip if peer already has the data.  
            continue;
        struct peer *p = get_peer(S, i, 0);
        if (p != NULL && p != peer && p->ready)
            send_message(p, buf);
        deref_peer(p);
    }
}

// Relay a transaction.
static void relay_transaction(struct state *S, struct peer *peer,
    uint64_t mask, uint256_t tx_hsh)
{
    if (peer != NULL)
        action(S, peer->to_addr, "relay: " HASH_FORMAT " (tx)", HASH(tx_hsh));
    struct buf *out = alloc_buf(NULL);
    make_inv(S, out, MSG_TX, tx_hsh);
    relay_message(S, peer, mask, out);
    deref_buf(out);
}

// Relay a block.
static void relay_block(struct state *S, struct peer *peer,
    uint64_t mask, uint256_t blk_hsh)
{
    if (peer != NULL)
        action(S, peer->to_addr, "relay: " HASH_FORMAT " (blk)",
            HASH(blk_hsh));
    struct buf *out = alloc_buf(NULL);
    make_inv(S, out, MSG_BLOCK, blk_hsh);
    relay_message(S, peer, mask, out);
    deref_buf(out);
}

// Relay an address.
static void relay_address(struct state *S, struct peer *peer,
    time_t time, struct in6_addr addr)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    uint16_t port = S->port;
    action(S, peer->to_addr, "relay: %s:%u", name, ntohs(port));
    struct buf *out = alloc_buf(NULL);
    make_addr_0(S, out, (uint32_t)time, addr);
    relay_message(S, peer, 0, out);
    deref_buf(out);
}

// Find a suitable peer to forward "getdata" requests to.  The peer must be
// outbound, ready, synced (if sync=true) and must be different than `peer'.
// The peer must also match the given `mask'.  Return NULL if no suitable peer
// is found.
static struct peer *find_peer(struct state *S, struct peer *peer,
    bool sync, uint64_t mask, uint256_t hsh)
{
    mask &= (UINT64_MAX >> (64 - S->num_peers));
    size_t count = tally(mask);
    struct peer *p = NULL;
    while (count > 0)
    {
        size_t bitidx = (rand64(S) % count), i, j;
        for (i = 0, j = 0; i < 64; i++)
        {
            uint64_t bit = ((uint64_t)1 << i);
            if ((mask & bit) != 0)
            {
                if (j == bitidx)
                    break;
                j++;
            }
        }
        uint64_t bit = ((uint64_t)1 << i);
        size_t idx = i;
        mask &= ~bit;
        count--;
        p = get_peer(S, idx, 0);
        if (p != NULL && p != peer && p->ready && (!sync || p->sync))
            break;
        deref_peer(p);
        p = NULL;
    }
    return p;
}

// Fetch some data by sending a "getdata" request to a "suitable" peer.  See
// find_peer() for the definition of "suitable peer".
static bool fetch_data(struct state *S, struct peer *peer, uint32_t type,
    uint256_t hsh, bool sync, uint64_t mask, int8_t ttl)
{
    struct peer *p = find_peer(S, peer, sync, mask, hsh);
    if (p == NULL)
    {
        struct in6_addr addr;
        memset(&addr, 0, sizeof(addr));
        warning(S, addr, "failed to get data " HASH_FORMAT_SHORT "; no "
            "suitable peer", HASH_SHORT(hsh));
        return false;
    }
    struct buf *out = alloc_buf(NULL);
    make_getdata(S, out, type, hsh);
    send_message(p, out);
    deref_buf(out);
    deref_peer(p);
    pend_fetch(S, hsh, type, sync, p->nonce, ttl);
    return true;
}

// Wake all delayed peers (set by set_delay()) that are waiting on some
// message data,  Also clears all delays.  The message to send is stored in
// `out'.
static void wake_delays(struct state *S, uint256_t hsh, struct delay *delays,
    struct buf *out, const char *type)
{
    while (delays != NULL)
    {
        struct delay *d = delays;
        struct peer *p = get_peer(S, d->index, d->nonce);
        if (p != NULL)
        {
            action(S, p->to_addr, "send: " HASH_FORMAT_SHORT " (%s)",
                HASH_SHORT(hsh), type);
            send_message(p, out);
            score_peer(S, p, -10);
        }
        deref_peer(p);
        delays = delays->next;
        mem_free(d);
    }
}

// Test if an address is "good" or not, i.e. is public, routable, etc.
static bool is_good_address(struct in6_addr addr)
{
    uint16_t addrv6[8];
    for (size_t i = 0; i < 8; i++)
        addrv6[i] = ntohs(addr.s6_addr16[i]);
    bool is_ipv4 = (addrv6[0] == 0 && addrv6[1] == 0 && addrv6[2] == 0 &&
                    addrv6[3] == 0 && addrv6[4] == 0 && addrv6[5] == 0xFFFF);
    uint8_t addrv4[4] = {addrv6[6] >> 8, addrv6[6] & 0xFF,
                         addrv6[7] >> 8, addrv6[7] & 0xFF};
    if (is_ipv4)
    {
        switch (addrv4[0])
        {
            case 0:
                return false;                                   // 0-prefix
            case 127:
                return false;                                   // Local
            case 10:
                return false;                                   // RFC1918
            case 172:
                return (addrv4[1] < 16 || addrv4[1] > 31);      // RFC1918
            case 192:
                return (addrv4[1] != 168);                      // RFC1918
            case 169:
                return (addrv4[1] != 254);                      // RFC3927
            case 224: case 225: case 226: case 227: case 228: case 229:
            case 230: case 231: case 232: case 234: case 235: case 236:
            case 237: case 238: case 239:
                return false;                                   // Multicast
            default:
                return true;
        }
    }
    else
    {
        if (addrv6[0] == 0x2002)
            return false;                                       // RFC3964
        if (addrv6[0] == 0x0064 && addrv6[1] == 0xFF9B)
            return false;                                       // RFC6052
        if (addrv6[0] == 0x2001 && addrv6[1] == 0x0000)
            return false;                                       // RFC4380
        if (addrv6[0] == 0x2001 && addrv6[1] == 0x0DB8)
            return false;                                       // RFC3849
        if (addrv6[0] == 0x2001 && addrv6[1] == 0x0010)
            return false;                                       // RFC4843
        if (((addrv6[0] >> 8) & 0xFE) == 0xFC)
            return false;                                       // Local
        if ((addrv6[0] >> 8) == 0xFF)
            return false;                                       // Multicast
        static const uint16_t zerov6[] = {0, 0, 0, 0, 0, 0, 0, 0};
        if (memcmp(addrv6, zerov6, sizeof(zerov6) - 2*sizeof(uint16_t)) == 0)
            return false;                                       // 0-addr
        static const uint16_t localv6[] = {0, 0, 0, 0, 0, 0, 0, 1};
        if (memcmp(addrv6, localv6, sizeof(localv6)) == 0)
            return false;                                       // Local
        static const uint16_t rfc4862v6[] = {0xFE80, 0, 0, 0, 0, 0, 0, 0};
        if (memcmp(addrv6, rfc4862v6, sizeof(rfc4862v6)) == 0)
            return false;                                       // RFC4862
        return true;
    }
}

// Insert a newly found address into the table.  If the address is nee, then
// add it to the address queue.
static bool insert_address(struct state *S, struct in6_addr addr,
    time_t time)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    if (!is_good_address(addr))
    {
        warning(S, addr, "ignoring bad address");
        return false;
    }
    uint256_t addr_hsh = addr_hash(S, addr);
    if (get_vote(S->table, addr_hsh) != 0)
        return false;
    insert(S->table, addr_hsh, ADDRESS, S);
    set_time(S->table, addr_hsh, time);
    queue_push_address(S, addr);
//    action(S, addr, "add: new address");
    return true;
}

/*****************************************************************************/
// HANDLE MESSAGES

// Handle "addr".  Add the new addresses to the table & address queue.
static bool handle_addr(struct peer *peer, struct state *S, struct buf *in)
{
    size_t len = pop_varint(in);
    const size_t MAX_ADDRESSES = 1000;
    if (len > MAX_ADDRESSES)
    {
        warning(S, peer->to_addr, "too many addresses (got %u, max=%u)",
            len, MAX_ADDRESSES);
        return false;
    }
    time_t curr_time = time(NULL);
    for (size_t i = 0; i < len; i++)
    {
        time_t time = pop(in, uint32_t);
        uint64_t services = pop(in, uint64_t);
        struct in6_addr addr = pop(in, struct in6_addr);
        uint16_t port = pop(in, uint16_t);
        if ((services & NODE_NETWORK) == 0)
            continue;   // Ignore non-full nodes.
        if (port != S->port)
            continue;   // Simplification: ignore any non-standard port.
        if (time < curr_time && curr_time - time >= 10800)  // 3 hours
            continue;   // Too old.
        if (time > curr_time + 600)                         // 10 mins
            continue;   // Too far in the future.
        if (insert_address(S, addr, curr_time) && len == 1)
            relay_address(S, peer, curr_time, addr);
    }
    return true;
}

// Handle "inv".  Each inv message is treated as a vote as to the validity
// of the data.  Once the vote tally reaches THRESHOLD, then the data is
// considered valid.
static bool handle_inv(struct peer *peer, struct state *S, struct buf *in)
{
    size_t len = pop_varint(in);
    static const size_t MAX_LEN = 50000;
    if (len > MAX_LEN)
        return false;

    for (size_t i = 0; i < len; i++)
    {
        uint32_t type = pop(in, uint32_t);
        uint256_t hsh = pop(in, uint256_t);

        // Votes from inbound peers are not trusted.  Otherwise it would be
        // trivial for an attacker to fool PseudoNode into relaying invalid
        // data.  We parse the message anyway to check for errors.
        if (!peer->outbound) 
            continue;
   
        // Callback:
        if (S->cb_inv != NULL)
        {
            struct inv *vec = mem_alloc(sizeof(struct inv));
            vec->type = type;
            vec->hash = hsh;
            unsigned len = sizeof(struct inv);
            vec = (struct inv *)S->cb_inv((struct PN *)S, PN_CALLBACK_INV,
                peer->to_addr, (unsigned char *)vec, &len);
            if (vec == NULL || len != sizeof(struct inv))
            {
                mem_free(vec);
                continue;
            }
            type = vec->type;
            hsh  = vec->hash;
            mem_free(vec);
        }
 
        // For each type (tx or block), register the vote.  If we have reached
        // the THRESHOLD number of votes, then PseudoNode treats the data as
        // valid, and relay it to other peers.
        if (type != MSG_TX && type != MSG_BLOCK)
        {
            warning(S, peer->to_addr, "NYI inv type (%u)", type);
            continue;
        }
        uint64_t votes = vote(S->table, hsh, (type == MSG_TX? TX: BLOCK),
            peer->index, S);
        size_t count = tally(votes);
        if (count == 1)
        {
            int16_t invs = peer->inv_score++;
            if (invs > MAX_INVS)
            {
                // This peer is inv-flooding, disconnect.
                warning(S, peer->to_addr, "too many invs");
                return false;
            }
            if (type == MSG_BLOCK && !peer->local_sync)
            {
                // This peer thinks we have an out-of-date height, so do
                // not trust block invs.  Instead, silently disconnect.
                return false;
            }
        }
        if (count != S->threshold)
            continue;

        // Vote threshold reached; take some action.
        switch (type)
        {
            case MSG_TX:
                relay_transaction(S, peer, votes, hsh);
                break;
            case MSG_BLOCK:
                // PseudoNode assumes only new blocks are actively advertised.
                // This seems to work well in practice for THRESHOLD >= 2.
                relay_block(S, peer, votes, hsh);
                height_inc(S);
                garbage_collect(S->table);          // Clean-up stale data.
                reset_peers(S);
                queue_shuffle(S);
                break;
        }

        // If enabled, we prefetch data rather than waiting for a node to
        // explicitly request it.  Consumes more bandwidth but makes
        // PseudoNode faster.
        if (S->prefetch)
        {
            unsigned state = set_state(S->table, hsh, FETCHING);
            if (state != OBSERVED)
                continue;
            if (!fetch_data(S, NULL, type, hsh, false,
                    get_vote(S->table, hsh), TTL_INIT))
                delete(S->table, hsh);     // Fail-safe (unlikely)
        }
    }
    return true;
}

// Handle "notfound".  Such messages are forwarded to delayed peers if
// necessary.
static bool handle_notfound(struct peer *peer, struct state *S,
    struct buf *in)
{
    if (!peer->outbound)
        return true;
    size_t num_ent = pop_varint(in);
    for (size_t i = 0; i < num_ent; i++)
    {
        uint32_t type = pop(in, uint32_t);
        uint256_t hsh = pop(in, uint256_t);

        struct delay *delays = get_delays(S->table, hsh);
        delete(S->table, hsh);
        if (delays == NULL)
            continue;
        struct buf *out = alloc_buf(NULL);
        make_notfound(S, out, type, hsh);
        while (delays != NULL)
        {
            struct delay *d = delays;
            struct peer *p = get_peer(S, d->index, d->nonce);
            if (p != NULL && p != peer)
            {
                action(S, p->to_addr, "notfound: " HASH_FORMAT_SHORT " (%s)",
                    HASH_SHORT(hsh), (type == MSG_TX? "tx": "blk"));
                send_message(p, out);
            }
            deref_peer(p);
            delays = delays->next;
            mem_free(d);
        }
        deref_buf(out);
    }
    return true;
}

// Handle "tx".  If OK, cache the tx and forward it to any delayed peers.
static bool handle_tx(struct peer *peer, struct state *S, struct buf *in,
    unsigned len)
{
    char *tx = pop_data(in, len);
    uint256_t tx_hsh = hash(tx, len);

    // Check that we actually requested the tx, otherwise ignore.
    if (get_state(S->table, tx_hsh) < FETCHING)
    {
        mem_free(tx);
        warning(S, peer->to_addr, "ignoring unsolicited transaction "
            HASH_FORMAT_SHORT, HASH_SHORT(tx_hsh));
        return true;
    }

    // Run callback on tx.
    char *tx0 = tx;
    if (S->cb_tx != NULL)
        tx = (char *)S->cb_tx((struct PN *)S, PN_CALLBACK_TX, peer->to_addr,
            (unsigned char *)tx, &len);
    if (tx != tx0)
    {
        free(tx);
        delete(S->table, tx_hsh);
        return true;
    }

    // Forward the tx.
    struct delay *delays = get_delays(S->table, tx_hsh);
    if (delays != NULL)
    {
        struct buf *out = alloc_buf(NULL);
        make_tx(S, out, tx, len);
        wake_delays(S, tx_hsh, delays, out, "tx");
        deref_buf(out);
    }

    // Cache the tx.
    if (!set_data(S->table, tx_hsh, tx, len))
    {
        mem_free(tx);
        warning(S, peer->to_addr, "received duplicate transaction");
    }
    return true;
}

// Extract the block height.
static uint32_t block_height(struct buf *in)
{
    size_t len = pop_varint(in);
    if (len == 0)
        return 0;
    pop(in, uint32_t);                              // version
    size_t in_len = pop_varint(in);
    if (in_len != 1)
        return 0;
    pop(in, uint256_t);                             // hash
    pop(in, uint32_t);                              // index
    size_t script_len = pop_varint(in);
    if (script_len <= 4)
        return 0;
    uint8_t op = pop(in, uint8_t);
    if (op != 0x03)
        return 0;
    uint32_t height = (uint32_t)pop(in, uint8_t);   // BIP34 height
    height |= (uint32_t)pop(in, uint8_t) << 8;
    height |= (uint32_t)pop(in, uint8_t) << 16;
    return height;
}

// Clean-up transactions that were included in a new block.
static void cleanup_txs(struct state *S, struct buf *in)
{
    size_t len = pop_varint(in);

    for (size_t i = 0; i < len; i++)
    {
        size_t ptr0 = in->ptr;
        pop(in, uint32_t);                          // version
        size_t in_len = pop_varint(in);
        for (size_t j = 0; j < in_len; j++)
        {
            pop(in, uint256_t);                     // hash
            pop(in, uint32_t);                      // index
            size_t script_len = pop_varint(in);
            for (size_t k = 0; k < script_len; k++)
                pop(in, uint8_t);                   // script
            pop(in, uint32_t);                      // sequence
        }
        size_t out_len = pop_varint(in);
        for (size_t j = 0; j < out_len; j++)
        {
            pop(in, int64_t);                       // value
            size_t script_len = pop_varint(in);
            for (size_t k = 0; k < script_len; k++)
                pop(in, uint8_t);                   // script
        }
        pop(in, uint32_t);                          // lock_time

        uint256_t tx_hsh = hash(in->data + ptr0, in->ptr - ptr0);
        delete(S->table, tx_hsh);
    }
}

// Calculate the Merkle root.  This is necessary to verify blocks are correct.
static uint256_t merkle_root(struct buf *in)
{
    size_t len = pop_varint(in);
    struct buf *tx_hshs = alloc_buf(NULL);

    // Compute all tx hashes.
    for (size_t i = 0; i < len; i++)
    {
        size_t ptr0 = in->ptr;
        pop(in, uint32_t);                          // version
        size_t in_len = pop_varint(in);
        for (size_t j = 0; j < in_len; j++)
        {
            pop(in, uint256_t);                     // hash
            pop(in, uint32_t);                      // index
            size_t script_len = pop_varint(in);
            for (size_t k = 0; k < script_len; k++)
                pop(in, uint8_t);                   // script
            pop(in, uint32_t);                      // sequence
        }
        size_t out_len = pop_varint(in);
        for (size_t j = 0; j < out_len; j++)
        {
            pop(in, int64_t);                       // value
            size_t script_len = pop_varint(in);
            for (size_t k = 0; k < script_len; k++)
                pop(in, uint8_t);                   // script
        }
        pop(in, uint32_t);                          // lock_time

        uint256_t tx_hsh = hash(in->data + ptr0, in->ptr - ptr0);
        push(tx_hshs, tx_hsh);
    }
    uint256_t zero;
    memset(&zero, 0, sizeof(zero));
    push(tx_hshs, zero);
    uint256_t *hshs = (uint256_t *)tx_hshs->data;

    // Check for duplicate transactions (CVE-2012-2459)
    for (size_t i = 0; i < len; i++)
    {
        for (size_t j = i+1; j < len; j++)
        {
            if (memcmp(hshs+i, hshs+j, sizeof(uint256_t)) == 0)
            {
                deref_buf(tx_hshs);
                return zero;                        // Cause failure.
            }
        }
    }

    // Calculate the Merkle root:
    while (len > 1)
    {
        if (len % 2 == 1)
        {
            len++;
            hshs[len-1] = hshs[len-2];
        }
        len = len / 2;
        for (size_t i = 0; i < len; i++)
        {
            uint256_t hsh = hash(hshs + 2*i, 2*sizeof(uint256_t));
            hshs[i] = hsh;
        }
    }
    uint256_t root = hshs[0];
    deref_buf(tx_hshs);
    return root;
}
 
// Handle "block".  If OK, cache the block (if not old) and forward it to any
// delayed peers.
static bool handle_block(struct peer *peer, struct state *S,
    struct buf *in, unsigned len)
{
    if (len < sizeof(struct block))
    {
        warning(S, peer->to_addr, "bad block (too small)");
        return false;
    }
    char *block = pop_data(in, len);
    uint256_t blk_hsh = hash(block, sizeof(struct block));
    struct block *header = (struct block *)block;
    in->ptr = sizeof(struct header) + sizeof(struct block);

    // Check that we actually requested the block, otherwise ignore.
    if (get_state(S->table, blk_hsh) < FETCHING)
    {
        mem_free(block);
        warning(S, peer->to_addr, "ignoring unsolicited block "
            HASH_FORMAT_SHORT, HASH_SHORT(blk_hsh));
        return false;   // Disconnect because peer is wasting bandwidth.
    }

    // The Merkle root must be checked otherwise the tx data may be invalid.
    uint256_t root = merkle_root(in);
    if (memcmp(&root, &header->merkle_root, sizeof(uint256_t)) != 0)
    {
        mem_free(block);
        warning(S, peer->to_addr, "bad block (merkle root does not match)");
        return false;
    }

    // Get the new height (BIP34):
    uint32_t height = 0;
    bool is_new = false;
    if (header->version >= 2)
    {
        in->ptr = sizeof(struct header) + sizeof(struct block);
        height = block_height(in);
        is_new = clobber_height(S, height);
    }

    // Run the callback & cleanup txs (for new blocks only)
    time_t curr_time = time(NULL);
    time_t blk_time = header->timestamp;
    int diff = curr_time-blk_time;
    if (is_new && (diff < 600 && diff > -600))
    {
        char *block0 = block;
        if (S->cb_block != NULL)
            block = (char *)S->cb_block((struct PN *)S, PN_CALLBACK_BLOCK,
                peer->to_addr, (unsigned char *)block, &len);
        if (block != block0)
        {
            mem_free(block);
            delete(S->table, blk_hsh);
            return true;
        }

        in->ptr = sizeof(struct header) + sizeof(struct block);
        cleanup_txs(S, in);
    }

    struct delay *delays = get_delays(S->table, blk_hsh);
    if (delays != NULL)
    {
        struct buf *out = alloc_buf(NULL);
        make_block(S, out, block, len);
        wake_delays(S, blk_hsh, delays, out, "blk");
        deref_buf(out);
    }

    // Cache recent blocks:
    if (diff > 900 || diff < -900)
    {
        // Ignore old block:
        delete(S->table, blk_hsh);
        mem_free(block);
        return true;
    }
    if (!set_data(S->table, blk_hsh, block, len))
    {
        mem_free(block);
        warning(S, peer->to_addr, "received duplicate block");
        return true;
    }

    return true;
}

// Handle "getaddr".
static bool handle_getaddr(struct peer *peer, struct state *S, struct buf *in)
{
    static const size_t MAX_ADDRESSES = 8000;
    struct buf *addrs = alloc_buf(NULL);
    size_t len = queue_get_addresses(S, addrs, MAX_ADDRESSES);
    if (len == 0)
    {
        deref_buf(addrs);
        return true;
    }
    static size_t NETADDR_SIZE = sizeof(uint32_t) + sizeof(uint64_t) +
        sizeof(struct in6_addr) + sizeof(uint16_t);
    static const size_t MAX_ADDR = 1000;
    for (size_t i = 0; i < len; i += MAX_ADDR)
    {
        size_t num_addr = (len - i >= MAX_ADDR? MAX_ADDR: len - i);
        void *data = addrs->data + i * NETADDR_SIZE;
        struct buf *out = alloc_buf(NULL);
        make_addr(S, out, num_addr, data, num_addr * NETADDR_SIZE);
        send_message(peer, out);
        deref_buf(out);
        action(S, peer->to_addr, "send: %u addresses", num_addr);
    }
    deref_buf(addrs);
    return true;
}

// Handle "getdata".
static bool handle_getdata(struct peer *peer, struct state *S, struct buf *in)
{
    size_t len = pop_varint(in);
    static const size_t MAX_LEN = 50000;
    if (len > MAX_LEN)
        return false;

    bool ok = true;
    for (size_t i = 0; ok && i < len; i++)
    {
        uint32_t type = pop(in, uint32_t);
        uint256_t hsh = pop(in, uint256_t);
        unsigned state = get_state(S->table, hsh);
        size_t data_len = 0;
        void *data = NULL;
        retry:
        switch (state)
        {
            case OBSERVED:
                // OBSERVED = inv packets seen, but data is not available
                // yet.  Therefore set state to FETCHING and fetch the data.
                if (get_tally(S->table, hsh) < S->threshold)
                    goto not_found;
                score_peer(S, peer, 10);
                state = set_state(S->table, hsh, FETCHING);
                if (state != OBSERVED)
                    goto retry;
                set_delay(S->table, hsh, peer->index, peer->nonce);
                if (!fetch_data(S, peer, type, hsh, false,
                        get_vote(S->table, hsh), TTL_INIT))
                    goto not_found;
                continue;
            case FETCHING:
                // FETCHING = data is not available, but "getdata" has been
                // sent (and we are waiting for the reply).  Delay this
                // request on the condition that the data is available.
                set_delay(S->table, hsh, peer->index, peer->nonce);
                continue;
            case AVAILABLE:
                // AVAILABLE = data is available, complete the request.
                data = get_data(S->table, hsh, &data_len);
                if (data != NULL)
                    break;
                goto not_found;
            case MISSING:
                // MISSING = data has not been observed at all.
                if (type == MSG_BLOCK)
                {
                    // Request for an block that was never advertised:
                    score_peer(S, peer, 10);
                    insert(S->table, hsh, BLOCK, S);
                    state = set_state(S->table, hsh, FETCHING);
                    if (state != OBSERVED)
                        goto retry;
                    set_delay(S->table, hsh, peer->index, peer->nonce);
                    if (!fetch_data(S, peer, type, hsh, true, UINT64_MAX,
                            TTL_INIT))
                        goto not_found;
                    continue;
                }
                // Fall through:
            default:
            not_found:
            {
                struct buf *out = alloc_buf(NULL);
                make_notfound(S, out, type, hsh);
                send_message(peer, out);
                deref_buf(out);
                continue;
            }
        }

        // If we reach here then the data is available.  We therefore complete
        // the "getdata" request.
        assert(data != NULL);
        struct buf *out = alloc_buf(NULL);
        switch (type)
        {
            case MSG_TX:
            {
                make_tx(S, out, data, data_len);
                action(S, peer->to_addr, "send: " HASH_FORMAT_SHORT " (tx)",
                    HASH_SHORT(hsh));
                break;
            }
            case MSG_BLOCK:
            {
                make_block(S, out, data, data_len);
                action(S, peer->to_addr, "send: " HASH_FORMAT_SHORT " (blk)",
                    HASH_SHORT(hsh));
                break;
            }
            default:
                // NYI:
                break;
        }
        send_message(peer, out);
        deref_buf(out);
        deref_data(S->table, hsh);
    }
    return ok;
}

// Handle "getheaders".  Forward it to a suitable peer.
static bool handle_getheaders(struct peer *peer, struct state *S,
    struct buf *in)
{
    pop(in, uint32_t);
    size_t count = pop_varint(in);
    static size_t MAX_COUNT = 2000;
    if (count < 1 || count > MAX_COUNT)
    {
        warning(S, peer->to_addr, "count is out-of-range for getheaders");
        return false;
    }
    uint256_t hsh = pop(in, uint256_t);
    for (size_t i = 0; i < count; i++)
        pop(in, uint256_t);
    hsh = headers_hash(S, hsh);
    insert(S->table, hsh, HEADERS, S);
    unsigned state = get_state(S->table, hsh);
    retry:
    switch (state)
    {
        case OBSERVED:
        {
            score_peer(S, peer, 10);
            state = set_state(S->table, hsh, FETCHING);
            if (state != OBSERVED)
                goto retry;
            set_delay(S->table, hsh, peer->index, peer->nonce);
            break;
        }
        case FETCHING:
            set_delay(S->table, hsh, peer->index, peer->nonce);
            return true;
        default:
            return true;    // Should never happen.
    }

    // Forward the request.  Care must be taken not for forward back to the
    // same peer.
    uint64_t mask = UINT64_MAX;
    struct peer *p = find_peer(S, peer, true, mask, hsh);
    if (p == NULL)
    {
        warning(S, peer->to_addr, "failed to forward getheaders request; no "
            "suitable peer");
        delete(S->table, hsh);
        return false;
    }
    struct buf *out = alloc_buf(NULL);
    push_buf(out, in);
    send_message(p, out);
    deref_peer(p);
    deref_buf(out);
    return true;
}

// Handle "headers".  Forward it to any delayed peers.
static bool handle_headers(struct peer *peer, struct state *S, struct buf *in)
{
    size_t count = pop_varint(in);
    static size_t MAX_COUNT = 2000;
    if (count < 1 || count > MAX_COUNT)
    {
        warning(S, peer->to_addr, "count is out-of-range for headers");
        return false;
    }
    struct block block = pop(in, struct block);
    uint256_t hsh = block.prev_block;
    uint256_t req_hsh = headers_hash(S, hsh);

    // Validate the chain (check is not random data).
    size_t zero = pop_varint(in);
    if (zero != 0)
    {
bad_block:
        warning(S, peer->to_addr, "invalid block header (expected zero "
            "length)");
        return false;
    }
    count--;
    hsh = hash(&block, sizeof(block));
    for (size_t i = 0; i < count; i++)
    {
        block = pop(in, struct block);
        zero = pop_varint(in);
        if (zero != 0)
            goto bad_block;
        if (memcmp(&block.prev_block, &hsh, sizeof(uint256_t)) != 0)
        {
            warning(S, peer->to_addr, "invalid block header sequence (not a "
                "chain)");
            return false;
        }
        hsh = hash(&block, sizeof(block));
    }

    // Forward response back to originating peer.
    struct delay *delays = get_delays(S->table, req_hsh);
    if (delays != NULL)
    {
        struct buf *out = alloc_buf(NULL);
        push_buf(out, in);
        wake_delays(S, req_hsh, delays, out, "hdrs");
        deref_buf(out);
    }
    delete(S->table, req_hsh);
    return true;
}

// Handle "version".
static bool handle_version(struct peer *peer, struct state *S, struct buf *in,
    size_t len)
{
    uint32_t version = pop(in, uint32_t);
    if (version < 70001)
    {
        warning(S, peer->to_addr, "ignoring peer (protocol version %u too "
            "old)");
        return false;
    }
    uint64_t services = pop(in, uint64_t);
    if ((services & NODE_NETWORK) == 0 && peer->outbound)
    {
        warning(S, peer->to_addr, "ignoring peer (not a full node)");
        return false;
    }
    uint64_t curr_time = time(NULL);
    uint64_t peer_time = pop(in, uint64_t);
    if (peer_time < curr_time - 3600 || peer_time > curr_time + 3600)
    {
        warning(S, peer->to_addr, "ignoring peer (clock mis-match)");
        return false;
    }
    pop(in, uint64_t);          // addr_recv
    struct in6_addr addr = pop(in, struct in6_addr);
    bool relay = false;
    pop(in, uint16_t);
    pop(in, uint64_t);          // addr_from
    pop(in, struct in6_addr);
    pop(in, uint16_t);
    uint64_t nonce = pop(in, uint64_t);
    for (size_t i = 0; !peer->outbound && i <= S->num_peers; i++)
    {
        struct peer *p = get_peer(S, i, nonce);
        if (p != NULL)
        {
            p->error = true;
            deref_peer(p);
            warning(S, peer->to_addr, "ignoring peer (peer is self)");
            return false;
        }
    }
    if (peer->outbound)
        relay = set_my_addr(S, addr);
    char *agent = pop_varstr(in);
    action(S, peer->to_addr, "connect: peer of type \"%s\"", agent);
    mem_free(agent);
    int32_t h = pop(in, uint32_t);
    if (peer->outbound)
        set_height(S, h);
    if (h > S->init_height && h >= get_height(S))
        peer->sync = true;
    bool use_relay = false;
    if (S->use_relay && !is_empty(in))
        use_relay = true;
    struct buf *out = alloc_buf(NULL);
    make_verack(S, out);
    send_message(peer, out);
    deref_buf(out);
    if (!peer->outbound)
    {
        struct buf *out = alloc_buf(NULL);
        make_version(S, out, peer, rand64(S), use_relay);
        send_message(peer, out);
        deref_buf(out);
    }
    peer->ready = true;
    if (relay)
        relay_address(S, peer, time(NULL), addr);
    return true;
}

// Process a message.
static bool process_message(struct peer *peer, struct state *S,
    struct buf *in)
{
    if (S->cb_raw != NULL &&
            !callback_buf(S, PN_CALLBACK_RAW, peer->to_addr, in, S->cb_raw))
        return true;

    struct header hdr = pop(in, struct header);
    size_t len = hdr.length;

    bool ok = true;
    if (strcmp(hdr.command, "version") == 0)
        ok = handle_version(peer, S, in, len);
    else if (strcmp(hdr.command, "verack") == 0)
        ok = true;
    else if (strcmp(hdr.command, "addr") == 0)
        ok = handle_addr(peer, S, in);
    else if (strcmp(hdr.command, "getaddr") == 0)
        ok = handle_getaddr(peer, S, in);
    else if (strcmp(hdr.command, "inv") == 0)
        ok = handle_inv(peer, S, in);
    else if (strcmp(hdr.command, "tx") == 0)
        ok = handle_tx(peer, S, in, len);
    else if (strcmp(hdr.command, "block") == 0)
        ok = handle_block(peer, S, in, len);
    else if (strcmp(hdr.command, "getdata") == 0)
        ok = handle_getdata(peer, S, in);
    else if (strcmp(hdr.command, "getheaders") == 0)
        ok = handle_getheaders(peer, S, in);
    else if (strcmp(hdr.command, "headers") == 0)
        ok = handle_headers(peer, S, in);
    else if (strcmp(hdr.command, "notfound") == 0)
        ok = handle_notfound(peer, S, in);
    else if (strcmp(hdr.command, "ping") == 0)
    {
        uint64_t nonce = pop(in, uint64_t);
        struct buf *out = alloc_buf(NULL);
        make_pong(S, out, nonce);
        send_message(peer, out);
        deref_buf(out);
    }
    else if (strcmp(hdr.command, "filterload") == 0)
        ok = false;         // NYI so drop connection.
    else if (strcmp(hdr.command, "reject") == 0)
    {
        score_peer(S, peer, 16);
        char *message = pop_varstr(in);
        pop(in, uint8_t);
        char *reason = pop_varstr(in);
        warning(S, peer->to_addr, "message (%s) rejected by peer (%s)",
            message, reason);
        mem_free(message);
        mem_free(reason);
    }
    else if (strcmp(hdr.command, "getblocks") == 0)
        ok = true;          // Safe to ignore.
    else
        warning(S, peer->to_addr, "ignoring unknown or NYI command \"%s\"",
            hdr.command);

    return ok;
}

/*****************************************************************************/
// MAIN

// Open a peer.
static struct peer *open_peer(struct state *S, int s, bool outbound,
    struct in6_addr addr, in_port_t port, size_t idx)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));

    // Peer churn:
    time_t curr_time = time(NULL);
    time_t timeout = curr_time + 300;   // 5 mins min
    uint32_t h = get_height(S);
    if (h < S->init_height)
        timeout += rand64(S) % 300;     // +5 mins max.
    else
        timeout += rand64(S) % 7200;    // +2 hours max.

    struct peer *peer = (struct peer *)mem_alloc(sizeof(struct peer));
    peer->msg_head = NULL;
    peer->msg_tail = NULL;
    peer->msg_len = 0;
    peer->sock = s;
    mutex_init(&peer->lock);
    event_init(&peer->event);
    peer->outbound = outbound;
    peer->error = false;
    peer->ready = false;
    peer->sync  = false;
    peer->local_sync = (h > S->init_height);
    peer->ref_count = 2;        // 2 for both threads
    peer->score = 0;
    peer->inv_score = 0;
    peer->alive = curr_time;
    peer->timeout = timeout;
    peer->nonce = rand64(S);
    peer->to_addr = addr;
    peer->to_port = port;
    peer->from_addr = get_my_addr(S);
    peer->from_port = S->port;
    peer->index = idx;
    peer->name = (char *)mem_alloc(strlen(name)+1);
    strcpy(peer->name, name);
    struct send_info *info = mem_alloc(sizeof(struct send_info));
    info->state = S;
    info->peer = peer;
    spawn_thread(send_message_worker, (void *)info);
    set_peer(S, peer->index, peer);
    return peer;
}

static void deref_peer(struct peer *peer)
{
    if (peer == NULL)
        return;
    ssize_t ref_count = atomic_sub(&peer->ref_count, 1);
    if (ref_count > 1)
        return;
    socket_close(peer->sock, peer->error);
    mutex_free(&peer->lock);
    event_free(&peer->event);
    struct msg *msg = peer->msg_head;
    while (msg != NULL)
    {
        struct msg *prev = msg;
        msg = msg->next;
        deref_buf(prev->buf);
        mem_free(prev);
    }
    mem_free(peer->name);
    mem_free(peer);
}

// Close a peer.
static void close_peer(struct state *S, struct peer *peer)
{
    struct in6_addr addr = peer->to_addr;
    del_peer(S, peer->index);
    peer->error = true;
    deref_peer(peer);
    if (rand64(S) % 8 != 0)     // Maybe re-use peer?
        insert_address(S, addr, time(NULL) - rand64(S) % 3000);
}

// Handle a peer.
static void *peer_worker(void *arg)
{
    assert(arg != NULL);
    struct info *info = (struct info *)arg;
    struct state *S = info->state;
    size_t peer_idx = info->peer_idx;
    int s = info->sock;
    bool outbound = info->outbound;
    struct in6_addr addr = info->addr;
    mem_free(info);

    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    if (outbound)
        action(S, addr, "open: outbound peer [%s] (%u/%u)", name, peer_idx+1,
            S->num_peers);
    else
        action(S, addr, "open: inbound peer [%s] (%u/oo)", name,
            peer_idx+1-S->num_peers);

    if (outbound)
    {
        // Open socket for outbound peer.
        s = socket_open();
        if (s == INVALID_SOCKET)
        {
            warning(S, addr, "failed to open socket: %s", get_error());
            del_peer(S, peer_idx);
            return NULL;
        }
        if (!socket_connect(s, addr, S->port))
        {
            warning(S, addr, "failed to connect to peer: %s", get_error());
            socket_close(s, true);
            del_peer(S, peer_idx);
            return NULL;
        }
    }

    // Open the peer.
    struct peer *peer = open_peer(S, s, outbound, addr, S->port, peer_idx);
    if (peer == NULL)
    {
        socket_close(s, false);
        uint256_t addr_hsh = addr_hash(S, addr);
        delete(S->table, addr_hsh);
        del_peer(S, peer_idx);
        return NULL;
    }
    jmp_buf env;
    struct buf *in = alloc_buf(&env);
    if (setjmp(env))
    {
        warning(S, addr, "peer sent truncated message");
        close_peer(S, peer);
        deref_buf(in);
        return NULL;
    }
    if (outbound)
    {
        // Send version message first for outbound peer.
        struct buf *out = alloc_buf(NULL);
        make_version(S, out, peer, rand64(S), true);
        send_message(peer, out);
        deref_buf(out);
    }

    // Read the version message.
    if (!read_message(S, peer, in) || !process_message(peer, S, in))
    {
        close_peer(S, peer);
        deref_buf(in);
        return NULL;
    }
    if (!peer->ready)
    {
        warning(S, peer->to_addr, "peer failed to send version message");
        close_peer(S, peer);
        deref_buf(in);
        return NULL;
    }
    if (outbound && queue_need_addresses(S))
    {
        // Get new addresses if necessary.
        struct buf *out = alloc_buf(NULL);
        make_getaddr(S, out);
        send_message(peer, out);
        deref_buf(out);
    }

    // Read message loop:
    while (read_message(S, peer, in) && process_message(peer, S, in))
        ;
    deref_buf(in);
    close_peer(S, peer);
    return NULL;
}

// Manage all peers.  Create new connections if necessary.
static void *manager(void *arg)
{
    struct state *S = (struct state *)arg;
    sock s = socket_open();
    if (s == INVALID_SOCKET)
        fatal("failed to create socket: %s", get_error());
    if (!socket_bind(s, S->port))
        fatal("failed to bind socket: %s", get_error());
    if (!socket_listen(s))
        fatal("failed to listen socket: %s", get_error());

    while (true)
    {
        ssize_t idx = alloc_peer(S, true);
        if (idx >= 0)
        {
            bool ok;
            struct in6_addr addr = queue_pop_address(S, &ok);
            if (ok)
            {
                struct info *info = (struct info *)mem_alloc(
                    sizeof(struct info));
                memset(info, 0, sizeof(struct info));
                info->state = S;
                info->addr = addr;
                info->peer_idx = idx;
                info->outbound = true;
                if (!spawn_thread(peer_worker, (void *)info))
                    mem_free(info);
            }
            else
                del_peer(S, idx);
        }

        size_t t = 100 + rand64(S) % 300;
        struct timeval tv;
        tv.tv_sec  = t / 1000;
        tv.tv_usec = (t % 1000) * 1000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s, &fds);
        int r = select(s+1, &fds, NULL, NULL, &tv);
        if (r < 0)
        {
            struct in6_addr addr;
            memset(&addr, 0, sizeof(addr));
            warning(S, addr, "failed to wait for socket: %s", get_error());
            msleep(10);
        }
        else if (r > 0)
        {   
            struct in6_addr addr;
            int s1 = socket_accept(s, &addr);
            if (s1 == INVALID_SOCKET)
            {
                warning(S, addr, "failed to accept inbound connection: %s",
                    get_error());
                continue;
            }
            ssize_t idx = alloc_peer(S, false);
            if (idx < 0)
            {
                warning(S, addr, "too many inbound connections");
                socket_close(s1, true);
                continue;
            }
            struct info *info = (struct info *)mem_alloc(sizeof(struct info));
            info->state = S;
            info->peer_idx = idx;
            info->sock = s1;
            info->addr = addr;
            info->outbound = false;
            if (!spawn_thread(peer_worker, (void *)info))
            {
                socket_close(s1, true);
                mem_free(info);
            }
        }

        // Re-fetch any stalled data:
        refetch_data(S);
    }
}

// Find addresses via DNS seeds.  This is how PseudoNode finds an initial
// set of peers.  Other peers can be discovered via "getaddr" messages.
static void *bootstrap(void *arg)
{
    struct state *S = (struct state *)arg;
    assert(S != NULL);
    time_t curr_time = time(NULL);

    size_t seeds_len;
    for (seeds_len = 0; seeds_len < MAX_SEEDS && S->seeds[seeds_len] != NULL;
            seeds_len++)
        ;
    if (seeds_len == 0)
        return NULL;

    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    size_t decay = 2;
    while (queue_need_addresses(S))
    {
        size_t stagger = rand64(S) % 100;
        const char *seed = S->seeds[rand64(S) % seeds_len];
        struct addrinfo *res;
        if (getaddrinfo(seed, NULL, &hint, &res) != 0)
        {
            struct in6_addr addr;
            memset(&addr, 0, sizeof(addr));
            warning(S, addr, "failed to get address info for %s: %s", seed,
                get_error());
            msleep(100 + stagger);
            continue;
        }
        struct addrinfo *info = res;
        while (info != NULL)
        {
            struct in6_addr addr;
            switch (info->ai_family)
            {
                case AF_INET6:
                {
                    struct sockaddr_in6 *sockaddr =
                        (struct sockaddr_in6 *)info->ai_addr;
                    addr = sockaddr->sin6_addr;
                    break;
                }
                case AF_INET:
                {
                    struct sockaddr_in *sockaddr =
                        (struct sockaddr_in *)info->ai_addr;
                    memset(&addr, 0, sizeof(addr));
                    addr.s6_addr16[5] = 0xFFFF;
                    memcpy(addr.s6_addr16 + 6, &sockaddr->sin_addr.s_addr,
                        sizeof(uint32_t));
                    break; 
                }
                default:
                    info = info->ai_next;
                    continue;
            }
            time_t addr_time = curr_time - rand64(S) % 3000;
            insert_address(S, addr, addr_time);
            info = info->ai_next;
        }
        freeaddrinfo(res);
        queue_shuffle(S);
        decay = (decay > 30000? 30000: (3 * decay) / 2);
        msleep(1000 + stagger + decay);
    }

    return NULL;
}

#include "port_map.c"

/*****************************************************************************/
// LIBRARY

struct PN
{
    int dummy;
};

// Create a PseudoNode based on the given configuration.
extern struct PN *PN_create(const struct PN_coin *coin,
    const struct PN_callbacks *callbacks, const struct PN_config *config,
    int ret)
{
    if (!system_init())
        return NULL;

#ifdef LINUX
    signal(SIGPIPE, SIG_IGN);
#endif

    struct state *S = alloc_state();
    rand64_init(S);
    S->addr_salt = rand64(S);
    S->headers_salt = rand64(S);
    struct table *table = alloc_table();
    S->table = table;

    if (coin == NULL)
        coin = BITCOIN;

    S->protocol_version = coin->version;
    S->magic            = coin->magic;
    S->port             = htons(coin->port);
    S->use_relay        = (coin->relay != 0);
    S->init_height      = coin->height - rand64(S) % (coin->height / 5);
    S->height = S->height_inc = S->height_0 = S->height_1 = S->init_height;
    size_t i;
    for (i = 0; i < MAX_SEEDS && coin->seeds[i] != NULL; i++)
        S->seeds[i] = strdup(coin->seeds[i]);
    S->seeds[i] = NULL;

    S->cb_block   = NULL;
    S->cb_tx      = NULL;
    S->cb_inv     = NULL;
    S->cb_version = NULL;
    S->cb_raw     = NULL;
    S->cb_log     = NULL;
    S->cb_warning = NULL;
    if (callbacks != NULL)
    {
        S->cb_block = callbacks->block;
        S->cb_tx = callbacks->tx;
        S->cb_inv = callbacks->inv;
        S->cb_version = callbacks->version;
        S->cb_raw = callbacks->raw;
        S->cb_log = callbacks->log;
        S->cb_warning = callbacks->warning;
    }

    S->user_agent = "/PseudoNode:0.6.0/";
    S->services = NODE_NETWORK;
    S->threshold = 2;
    S->prefetch = false;
    S->num_peers = 8;
    S->queue_len = 4096;
    if (config != NULL)
    {
        S->user_agent = (config->user_agent != NULL?
            strdup(config->user_agent): S->user_agent);
        S->services = (config->services | NODE_NETWORK);
        S->threshold = (config->threshold == 0? 2: config->threshold);
        S->prefetch = (config->prefetch != 0);
        S->num_peers = (config->num_peers == 0? 8: config->num_peers);
        S->queue_len = (config->num_addrs == 0? 4096: config->num_addrs);
        if (S->threshold > S->num_peers)
            S->threshold = S->num_peers;
        if (config->peers != NULL)
        {
            struct in6_addr zero;
            memset(&zero, 0, sizeof(zero));
            for (size_t i = 0; i < 64; i++)
            {
                if (memcmp(config->peers + i, &zero, sizeof(zero)) == 0)
                    break;
                insert_address(S, config->peers[i], time(NULL));
            }
        }
    }
    S->queue = mem_alloc(S->queue_len * sizeof(struct in6_addr));
    memset(S->queue, 0, S->queue_len * sizeof(struct in6_addr));
    S->peers_len = 32 + S->num_peers;
    S->peers = mem_alloc(S->peers_len * sizeof(struct peer *));
    memset(S->peers, 0, S->peers_len * sizeof(struct peer *));

    spawn_thread(port_map, (void *)S);
    spawn_thread(bootstrap, (void *)S);

    if (ret != 0)
        spawn_thread(manager, (void *)S);
    else
        manager((void *)S);
    return (struct PN *)S;
}

// Broadcast the given transaction.
extern int PN_broadcast_tx(struct PN *node, const unsigned char *tx0,
    unsigned len)
{
    if (node == NULL || tx0 == NULL || len == 0 || len > MAX_MESSAGE_LEN)
        return -1;
    uint8_t *tx = (uint8_t *)mem_alloc(len);
    memcpy(tx, tx0, len);
    struct state *S = (struct state *)node;
    uint256_t tx_hsh = hash(tx, len);
    insert(S->table, tx_hsh, TX, S);
    if (!set_data(S->table, tx_hsh, tx, len))
    {
        mem_free(tx);
        return -1;
    }
    relay_transaction(S, NULL, 0, tx_hsh);
    return 0;
}

// SHA256
extern void PN_sha256(const void *data, unsigned len, void *res)
{
    uint256_t hsh = sha256(data, len);
    memcpy(res, hsh.i8, sizeof(hsh));
}

// SHA256d
extern void PN_sha256d(const void *data, unsigned len, void *res)
{
    uint256_t hsh = hash(data, len);
    memcpy(res, hsh.i8, sizeof(hsh));
}

// Get information.
extern int PN_get_info(struct PN *node, int what)
{
    if (node == NULL)
        return 0;
    struct state *S = (struct state *)node;
    switch (what)
    {
        case PN_HEIGHT:
            return (int)get_height(S);
        case PN_NUM_IN_PEERS:
            return (int)S->num_ins;
        case PN_NUM_OUT_PEERS:
            return (int)S->num_outs;
        case PN_NUM_SEND_BYTES:
            return (int)S->send_bytes;
        case PN_NUM_RECV_BYTES:
            return (int)S->recv_bytes;
        default:
            return 0;
    }
}

/*
 * Pre-define crypto-currencies:
 */
static const char *bitcoin_dns_seeds[] =
{
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "bitseed.xf2.org",
    "seed.bitcoin.jonasschnelli.ch",
    NULL
};
static const struct PN_coin bitcoin =
{
    "bitcoin", bitcoin_dns_seeds, 
    8333, 70002, 0xD9B4BEF9, 390000, true
};
const struct PN_coin * const BITCOIN = &bitcoin;

static const char *testnet_dns_seeds[] =
{
    "testnet-seed.bitcoin.petertodd.org",
    "testnet-seed.bluematt.me",
    NULL
};
static const struct PN_coin testnet =
{
    "testnet", testnet_dns_seeds,
    18333, 70002, 0x0709110B, 466000, true
};
const struct PN_coin * const TESTNET = &testnet;

static const char *litecoin_dns_seeds[] =
{
    "dnsseed.litecointools.com",
    "dnsseed.litecoinpool.org",
    "dnsseed.ltc.xurious.com",
    "dnsseed.koin-project.com",
    NULL
};
static const struct PN_coin litecoin =
{
    "litecoin", litecoin_dns_seeds,
    9333, 70002, 0xDBB6C0FB, 797000, false
};
const struct PN_coin * const LITECOIN = &litecoin;

