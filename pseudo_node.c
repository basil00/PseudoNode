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

// Configuration:
static size_t THRESHOLD = 2;
static size_t MAX_OUTBOUND_PEERS = 8;
static const char *USER_AGENT = NULL;
static bool STEALTH = false;
static bool SERVER = false;
static bool PREFETCH = false;

struct coin_info
{
    uint32_t protocol_version;      // Coin protocol version
    uint32_t magic;                 // Coin protocol magic number
    char *user_agent;               // Coin default user agent (for stealth)
    uint16_t port;                  // Coin port number.
    uint32_t height;                // Coin height guess.
    const char **seeds;             // Coin DNS seeds.
    size_t seeds_len;               // Coin DNS seeds length.
    bool use_relay;                 // Coin protocol use relay flag in
                                    // "version" message.
};

static const struct coin_info *COIN = NULL;

// Coin DNS seeds:
const char *seeds_bitcoin[] =
{
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitnodes.io",
    "bitseed.xf2.org"
};
const char *seeds_testnet[] =
{
    "testnet-seed.bitcoin.petertodd.org",
    "testnet-seed.bluematt.me"
};
const char *seeds_litecoin[] =
{
    "dnsseed.litecointools.com",
    "dnsseed.litecoinpool.org",
    "dnsseed.ltc.xurious.com",
    "dnsseed.koin-project.com"
};
const char *seeds_dogecoin[] =
{
    "seed.dogecoin.com",
    "seed.mophides.com",
    "seed.dglibrary.org",
    "seed.dogechain.info"
};
const char *seeds_paycoin[] =
{
    "dnsseed.paycoin.com"
};
const char *seeds_flappycoin[] =
{
    "dnsseed.flap.so"
};

// Supported coins:
const struct coin_info bitcoin =
    {70002, 0xD9B4BEF9, "/Satoshi:0.9.3/", 8333, 340000,
     seeds_bitcoin, sizeof(seeds_bitcoin) / sizeof(char *), true};
const struct coin_info testnet =
    {70002, 0x0709110B, "/Satoshi:0.9.3/", 18333, 320000,
     seeds_testnet, sizeof(seeds_testnet) / sizeof(char *), true};
const struct coin_info litecoin =
    {70002, 0xDBB6C0FB, "/Satoshi:0.8.7.5/", 9333, 720000,
     seeds_litecoin, sizeof(seeds_litecoin) / sizeof(char *), false};
const struct coin_info dogecoin =
    {70003, 0xC0C0C0C0, "/Shibetoshi:1.8.0/", 22556, 576000,
     seeds_dogecoin, sizeof(seeds_dogecoin) / sizeof(char *), true};
const struct coin_info paycoin =
    {70001, 0xAAAAAAAA, "/Satoshi:0.1.2/", 8998, 53000,
     seeds_paycoin, sizeof(seeds_paycoin) / sizeof(char *), false};
const struct coin_info flappycoin =
    {70003, 0xC1C1C1C1, "/Flaptoshi:3.2.1/", 11556, 490000,
     seeds_flappycoin, sizeof(seeds_flappycoin) / sizeof(char *), false};


#define PROTOCOL_VERSION            (COIN->protocol_version)
#define MAGIC                       (COIN->magic)
#define PORT                        htons(COIN->port)
#define HEIGHT                      (COIN->height)
#define SEEDS                       (COIN->seeds)
#define SEEDS_LENGTH                (COIN->seeds_len)
#define USE_RELAY                   (COIN->use_relay)

#define NODE_NETWORK                1

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

static uint64_t rand64(void);

#ifdef MACOSX
#define LINUX
#endif

#ifdef LINUX
#include "linux.c"
#endif

#ifdef WINDOWS
#include "windows.c"
#endif

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
    struct msg *head;           // Message queue head.
    struct msg *tail;           // Message queue tail.
    time_t alive;               // Peer last message time (alive or not?)
    struct in6_addr to_addr;    // Peer remote address.
    in_port_t to_port;          // Peer remote port.
    struct in6_addr from_addr;  // Peer local address.
    in_port_t from_port;        // Peer local port.
    char *name;                 // Peer name (string version of to_addr).
    uint32_t index;             // Peer index.
    int16_t reqs;               // Peer request limit.
    int16_t invs;               // Peer inv limit.
    bool ready;                 // Peer is ready? (have seen version message?)
    bool sync;                  // Peer is synced? (up-to-date height?)
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
    struct table *table;        // The big table.
    size_t peer_idx;            // The peer's index.
    int sock;                   // The peer's socket.
    struct in6_addr addr;       // The peer's remote address.
    bool outbound;              // Is the peer outbound?
};

// Entry states:
#define MISSING         0
#define OBSERVED        1
#define FETCHING        2
#define AVAILABLE       3

static void deref_peer(struct peer *peer);

/****************************************************************************/
// HEIGHT

static mutex height_lock;
static uint32_t height;
static uint32_t height_0;
static uint32_t height_1;
static uint32_t height_inc;

// Set the current height.
static void set_height(uint32_t h)
{
    mutex_lock(&height_lock);
    if (h > height)
    {
        height_1 = height_0;
        height_0 = h;
        static const uint32_t MAX_DIFF = 6;
        uint32_t diff = (height_0 < height_1? height_1 - height_0:
            height_0 - height_1);
        if (diff <= MAX_DIFF)
        {
            height = (height_0 < height_1? height_0: height_1);
            height_inc = height;
        }
        else if (h <= height_inc && height_inc - h < MAX_DIFF)
        {
            height = h;
            height_inc = height;
        }
    }
    mutex_unlock(&height_lock);
}

// Increment the height for a new block.  This is tricky because of orphan
// blocks, so care must be taken not to overtake the real height.
static void inc_height(void)
{
    mutex_lock(&height_lock);
    if (height > HEIGHT)
    {
        height_inc++;
        static const uint32_t MAX_DIFF = 6;
        if (height + MAX_DIFF < height_inc)
            height = height_inc - MAX_DIFF;
    }
    mutex_unlock(&height_lock);
}

// Get the current height.
static uint32_t get_height(void)
{
    mutex_lock(&height_lock);
    uint32_t h = height;
    mutex_unlock(&height_lock);
    return h;
}

/****************************************************************************/
// ADDRESS
//
// PseudoNode thinks its address is A if 2 or more outbound peers agree.

static mutex addr_lock;
static struct in6_addr myaddr;
static struct in6_addr myaddr_0;
static struct in6_addr myaddr_1;

// Set address.
static bool set_my_addr(struct in6_addr addr)
{
    mutex_lock(&addr_lock);
    myaddr_1 = myaddr_0;
    myaddr_0 = addr;
    bool new = false;
    if (memcmp(&myaddr_0, &myaddr_1, sizeof(myaddr_0)) == 0)
    {
        new = (memcmp(&myaddr, &myaddr_1, sizeof(myaddr)) != 0);
        myaddr = myaddr_1;
    }
    mutex_unlock(&addr_lock);
    return new;
}

// Get address.
static struct in6_addr get_my_addr(void)
{
    mutex_lock(&addr_lock);
    struct in6_addr addr = myaddr;
    mutex_unlock(&addr_lock);
    return addr;
}

/****************************************************************************/
// LOGGING

static mutex log_lock;

#define ACTION      0
#define LOG         1
#define WARNING     2
#define FATAL       3

// Print fancy log message.
static void print_log(int type, const char *action, const char *format, ...)
{
    if (SERVER)
        return;
    va_list ap;
    va_start(ap, format);
    mutex_lock(&log_lock);
    FILE *stream = (type == ACTION || type == LOG? stdout: stderr);
    switch (type)
    {
        case ACTION:
            color_log(stream);
            fprintf(stream, "%s", action);
            break;
        case LOG:
            break;
        case WARNING:
            color_warning(stream);
            fprintf(stream, "warning");
            break;
        case FATAL:
            color_error(stream);
            fprintf(stream, "fatal error");
            break;
    }
    color_clear(stream);
    if (type != LOG)
        fprintf(stream, ": ");
    vfprintf(stream, format, ap);
    fputc('\n', stream);
    if (type == FATAL)
    {
#ifdef WINDOWS
        fprintf(stderr, "This program will exit in 10 seconds.\n");
        msleep(10000);
#endif
        abort();
    }
    mutex_unlock(&log_lock);
    va_end(ap);
}

#define action(act, format, ...)    \
    print_log(ACTION, act, format, ##__VA_ARGS__)
#define log(format, ...)            \
    print_log(LOG, NULL, format, ##__VA_ARGS__)
#define warning(format, ...)        \
    print_log(WARNING, NULL, format, ##__VA_ARGS__)
#define fatal(format, ...)          \
    print_log(FATAL, NULL, format, ##__VA_ARGS__)

/****************************************************************************/
// MEMORY ALLOCATION
//
// For large buffers we attempt to immediately return memory to the OS on
// free.

// #define USE_MALLOC 

#ifndef USE_MALLOC
struct mem
{
    size_t size;
};
#define MAX_SMALL_ALLOC     (4096 - sizeof(struct mem))
#define BUFFER_SIZE         (4096 - sizeof(struct mem))

static void *mem_alloc(size_t size)
{
    struct mem *mem;
    if (size < MAX_SMALL_ALLOC)
        mem = (struct mem *)malloc(sizeof(struct mem) + size);
    else
        mem = (struct mem *)system_alloc(sizeof(struct mem) + size);
    if (mem == NULL)
       fatal("failed to alloc %u bytes: %s", size, get_error());
    mem->size = size;
    return (void *)(mem + 1);
}

static void mem_free(void *ptr)
{
    if (ptr == NULL)
        return;
    struct mem *mem = (struct mem *)ptr;
    mem = mem - 1;
    unsigned size = mem->size;
    if (size < MAX_SMALL_ALLOC)
        free(mem);
    else
        system_free(sizeof(struct mem) + size, mem);
}
#else
#define BUFFER_SIZE         4096
#define mem_alloc           malloc
#define mem_free            free
#endif

/****************************************************************************/
// HASH FUNCTIONS

static uint64_t addr_salt;
static uint64_t headers_salt;

// See sha256.c
extern void sha256_hash(const void *data, size_t len, void *res);

static uint256_t sha256(const void *data, size_t len)
{
    uint256_t res;
    sha256_hash(data, len, &res);
    return res;
}

static uint256_t hash(const void *data, size_t len)
{
    uint256_t res = sha256(data, len);
    res = sha256(&res, sizeof(res));
    return res;
}

static uint256_t addr_hash(struct in6_addr addr)
{
    addr.s6_addr16[0] ^= (uint16_t)addr_salt;
    addr.s6_addr16[1] ^= (uint16_t)(addr_salt >> 16);
    addr.s6_addr16[2] ^= (uint16_t)(addr_salt >> 32);
    addr.s6_addr16[3] ^= (uint16_t)(addr_salt >> 48);
    return sha256(&addr, sizeof(addr));
}

static uint256_t headers_hash(uint256_t hsh)
{
    hsh.i64[0] ^= headers_salt;
    return sha256(&hsh, sizeof(hsh));
}

/****************************************************************************/
// RANDOM NUMBERS

static mutex rand_lock;
static uint64_t state[2];
static uint256_t rnum;
static size_t rnum_idx = SIZE_MAX;

// Initialize random numbers.
static void rand64_init(void)
{
    if (!rand_init(state))
        fatal("failed to initialize random numbers");
}

// Return a 64-bit random number.
static uint64_t rand64(void)
{
    mutex_lock(&rand_lock);
    if (rnum_idx > sizeof(uint256_t) / sizeof(uint64_t))
    {
        state[0]++;
        if (state[0] == 0)
            state[1]++;
        rnum = sha256(state, sizeof(state));
        rnum_idx = 0;
    }
    uint64_t r = rnum.i64[rnum_idx++];
    mutex_unlock(&rand_lock);
    return r;
}

/****************************************************************************/
// SIMPLE DATA BUFFERS
//
// Data buffer are mainly used to store/construct/deconstruct messages.  They
// are analogous to C++'s vector<> type.

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
    ref(&buf->ref_count);
}

static void deref_buf(struct buf *buf)
{
    if (buf == NULL)
        return;
    ssize_t ref_count = deref(&buf->ref_count);
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
        buf->len = (3 * buf->len) / 2;
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
        return pop(buf, uint16_t);
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
size_t popcount(uint64_t x)
{
    int count;
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
static size_t vote(struct table *table, uint256_t hsh, unsigned type,
    uint64_t vote_idx)
{
    if (vote_idx >= MAX_OUTBOUND_PEERS)
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
        return popcount(new_vote);
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
        return 1;
    }
}

// Insert is similar to voting, except for data where the vote count is
// irrelevant.
#define insert(table, hsh, type)        vote((table), (hsh), (type), 0)

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

// Get the vote mask associated with `hsh'.
static uint64_t get_vote_mask(struct table *table, uint256_t hsh)
{
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    uint64_t vote = (entry != NULL? entry->vote: 0);
    mutex_unlock(&table->lock);
    return vote;
}

// Get the vote tally associated with `hsh'.
#define get_vote(table, hsh)    popcount(get_vote_mask((table), (hsh)))

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
            int diff = abs(curr_time - entry->time);
            bool del = false;
            switch (entry->type)
            {
                case TX:
                    del = (entry->state != FETCHING || diff > 5);
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
    action("cleanup", "%u txs, %u blocks, %u addresses, %u bytes", num_tx,
        num_blk, num_addr, num_bytes);
}

/****************************************************************************/
// Address queue.

#define MAX_QUEUE       8192

static mutex queue_lock;
static ssize_t queue_head = 0;
static ssize_t queue_tail = 0;
static struct in6_addr queue[MAX_QUEUE];

// Queue a new address to be used later as a peer.
static void queue_push_address(struct table *table, struct in6_addr addr)
{
    mutex_lock(&queue_lock);
    if (queue_head - queue_tail < MAX_QUEUE)
    {
        queue[queue_head % MAX_QUEUE] = addr;
        queue_head++;
    }
    mutex_unlock(&queue_lock);
}

// Get a queued address.
static struct in6_addr queue_pop_address(struct table *table, bool *ok)
{
    struct in6_addr addr;
    uint256_t addr_hsh;
    *ok = true;
    memset(&addr, 0, sizeof(addr));
    do
    {
        bool found = false;
        mutex_lock(&queue_lock);
        if (queue_tail < queue_head)
        {
            found = true;
            addr = queue[queue_tail % MAX_QUEUE];
            queue_tail++;
        }
        mutex_unlock(&queue_lock);
        if (!found)
        {
            *ok = false;
            return addr;
        }
        addr_hsh = addr_hash(addr);
    }
    while (get_time(table, addr_hsh) == 0);
    return addr;
}

// Get a collection of addresses to service a getaddr message.
static size_t queue_get_addresses(struct table *table, struct buf *buf,
    size_t maxlen)
{
    mutex_lock(&queue_lock);
    ssize_t start = queue_tail, end = queue_head;
    mutex_unlock(&queue_lock);

    time_t curr_time = time(NULL);
    size_t num_addr = 0;
    for (ssize_t i = start; i < end && num_addr < maxlen; i++)
    {
        mutex_lock(&queue_lock);
        struct in6_addr addr = queue[i % MAX_QUEUE];
        mutex_unlock(&queue_lock);
        
        uint256_t addr_hsh = addr_hash(addr);
        time_t addr_time = get_time(table, addr_hsh);
        if (addr_time == 0 || abs(addr_time - curr_time) > 10800)
            continue;

        push(buf, addr_time);
        uint64_t services = NODE_NETWORK;
        push(buf, services);
        push(buf, addr);
        uint16_t port = PORT;
        push(buf, port);
        num_addr++;
    }
    return num_addr;
}

// Return `true' if we need more addresses.
static bool queue_need_addresses(void)
{
    mutex_lock(&queue_lock);
    bool ok = ((queue_head - queue_tail) < MAX_QUEUE);
    mutex_unlock(&queue_lock);
    return ok;
}

// Shuffle the queue.
static void queue_shuffle(void)
{
    uint64_t r = rand64();
    mutex_lock(&queue_lock);
    ssize_t n = queue_head - queue_tail;
    for (size_t i = n-1; i >= 1; i--)
    {
        size_t j = r % i;
        struct in6_addr tmp = queue[(queue_tail+i) % MAX_QUEUE];
        queue[(queue_tail+i) % MAX_QUEUE] = queue[(queue_tail+j) % MAX_QUEUE];
        queue[(queue_tail+j) % MAX_QUEUE] = tmp;
        r = r * 333333333323 + 123456789;
    }
    mutex_unlock(&queue_lock);
}

/****************************************************************************/
// PEER STORAGE
//
// Peers 0..maxpeers-1 are reserved for outbound connections.
// Peers maxpeers..oo are for inbound connections.

#define MAX_PEERS       256

#define PEER_RESERVE    ((struct peer *)1)

static mutex peer_lock;
static struct peer *peers[MAX_PEERS] = {NULL};
static size_t last_idx = 0;

// Get the total number of peers (approx.)
static size_t get_num_peers(void)
{
    mutex_lock(&peer_lock);
    size_t num_peers = last_idx+1;
    mutex_unlock(&peer_lock);
    return num_peers;
}

// Allocate a slot for a new peer.
static ssize_t alloc_peer(bool outbound)
{
    ssize_t start = (outbound? 0: MAX_OUTBOUND_PEERS);
    ssize_t end   = (outbound? MAX_OUTBOUND_PEERS: MAX_PEERS);
    ssize_t idx = -1;
    mutex_lock(&peer_lock);
    for (size_t i = start; i < end; i++)
    {
        if (peers[i] == NULL)
        {
            peers[i] = PEER_RESERVE;
            idx = i;
            if (idx > last_idx)
                last_idx = idx;
            break;
        }
    }
    mutex_unlock(&peer_lock);
    return idx;
}

// Get the peer associated with a slot.  Also check the nonce if non-zero.
static struct peer *get_peer(size_t idx, uint64_t nonce)
{
    mutex_lock(&peer_lock);
    struct peer *peer = peers[idx];
    mutex_unlock(&peer_lock);
    if (peer == NULL)
        return NULL;
    if (peer == PEER_RESERVE)
        return NULL;
    if (nonce != 0 && peer->nonce != nonce)
        return NULL;
    ref(&peer->ref_count);
    return peer;
}

// Set the peer for a slot.
static void set_peer(size_t idx, struct peer *peer)
{
    mutex_lock(&peer_lock);
    peers[idx] = peer;
    mutex_unlock(&peer_lock);
}

// Delete a slot making it available again.
static void del_peer(size_t idx)
{
    mutex_lock(&peer_lock);
    peers[idx] = NULL;
    if (idx == last_idx)
    {
        for (ssize_t i = (ssize_t)idx-1; i >= 0; i--)
        {
            last_idx = i;
            if (peers[i] != NULL)
                break;
        }
    }
    mutex_unlock(&peer_lock);
}

// Reset the state of all peers.
static void reset_peers(void)
{
    mutex_lock(&peer_lock);
    for (size_t i = 0; i < last_idx; i++)
    {
        if (peers[i] == NULL)
            continue;
        if (peers[i] == PEER_RESERVE)
            continue;
        peers[i]->invs = 0;
        peers[i]->reqs = 0;
    }
    mutex_unlock(&peer_lock);
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

static void make_version(struct buf *buf, struct peer *peer, uint64_t nonce,
    uint32_t height, bool use_relay)
{
    struct header hdr = {MAGIC, "version", 0, 0};
    push(buf, hdr);
    uint32_t version = PROTOCOL_VERSION;
    push(buf, version);
    uint64_t services = NODE_NETWORK;
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
    push_varstr(buf, USER_AGENT);
    push(buf, height);
    if (use_relay && USE_RELAY)
    {
        uint8_t relay = 1;
        push(buf, relay);
    }
    finalize_message(buf);
}

static void make_verack(struct buf *buf)
{
    struct header hdr = {MAGIC, "verack", 0, 0};
    push(buf, hdr);
    finalize_message(buf);
}

static void make_addr(struct buf *buf, size_t num_addr, void *data, size_t len)
{
    struct header hdr = {MAGIC, "addr", 0, 0};
    push(buf, hdr);
    push_varint(buf, num_addr);
    push_data(buf, len, data);
    finalize_message(buf);
}

static void make_addr_0(struct buf *buf, uint32_t time, struct in6_addr addr)
{
    struct header hdr = {MAGIC, "addr", 0, 0};
    push(buf, hdr);
    push_varint(buf, 1);
    push(buf, time);
    uint64_t services = NODE_NETWORK;
    push(buf, services);
    push(buf, addr);
    uint16_t port = PORT;
    push(buf, port);
    finalize_message(buf);
}

static void make_tx(struct buf *buf, const void *data, size_t len)
{
    struct header hdr = {MAGIC, "tx", 0, 0};
    push(buf, hdr);
    push_data(buf, len, data);
    finalize_message(buf);
}

static void make_block(struct buf *buf, const void *data, size_t len)
{
    struct header hdr = {MAGIC, "block", 0, 0};
    push(buf, hdr);
    push_data(buf, len, data);
    finalize_message(buf);
}

static void make_getaddr(struct buf *buf)
{
    struct header hdr = {MAGIC, "getaddr", 0, 0};
    push(buf, hdr);
    finalize_message(buf);
}

static void make_getdata(struct buf *buf, uint32_t type, uint256_t hsh)
{
    struct header hdr = {MAGIC, "getdata", 0, 0};
    push(buf, hdr);
    push_varint(buf, 1);
    push(buf, type);
    push(buf, hsh);
    finalize_message(buf);
}

static void make_inv(struct buf *buf, uint32_t type, uint256_t hsh)
{
    struct header hdr = {MAGIC, "inv", 0, 0};
    push(buf, hdr);
    push_varint(buf, 1);
    push(buf, type);
    push(buf, hsh);
    finalize_message(buf);
}

static void make_pong(struct buf *buf, uint64_t nonce)
{
    struct header hdr = {MAGIC, "pong", 0, 0};
    push(buf, hdr);
    push(buf, nonce);
    finalize_message(buf);
}

static void make_notfound(struct buf *buf, uint32_t type, uint256_t hsh)
{
    struct header hdr = {MAGIC, "notfound", 0, 0};
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
    struct peer *peer = (struct peer *)arg;

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
            struct msg *msg = peer->head;
            if (msg == NULL)
            {
                mutex_unlock(&peer->lock);
                break;
            }
            peer->head = msg->next;
            if (peer->head == NULL)
                peer->tail = NULL;
            mutex_unlock(&peer->lock);
            struct buf *buf = msg->buf;
            ssize_t len = buf->ptr;
            ssize_t r = socket_send(peer->sock, buf->data, len);
            deref_buf(buf);
            mem_free(msg);
            if (r != len)
            {
                warning("[%s] failed to send message: %s", peer->name,
                    get_error());
                peer->error = true;
                deref_peer(peer);
                return NULL;
            }
        }
    }
}

// Send a message to the send_message_worker() thread.
static void send_message(struct peer *peer, struct buf *buf)
{
    if (buf == NULL || buf->ptr == 0 || buf->ptr > MAX_MESSAGE_LEN)
        return;
    struct msg *msg = (struct msg *)mem_alloc(sizeof(struct msg));
    ref_buf(buf);
    msg->buf = buf;
    msg->next = NULL;
    mutex_lock(&peer->lock);
    if (peer->tail == NULL)
    {
        peer->tail = msg;
        peer->head = msg;
    }
    else
    {
        peer->tail->next = msg;
        peer->tail = msg;
    }
    mutex_unlock(&peer->lock);
    event_set(&peer->event);
}

// Read message data:
static bool read_message_data(struct peer *peer, char *buf, size_t len)
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
            warning("[%s] failed to recv message: %s", peer->name,
                get_error());
            return false;
        }
        if (r == 0 && !timeout)
        {
            warning("[%s] connection closed by peer", peer->name);
            return false;
        }
        if (r == len-i)
            break;
        time_t curr_time = time(NULL);
        if (timeout && peer->alive + TIMEOUT < curr_time)
        {
            warning("[%s] connection stalled", peer->name);
            return false;
        }
        if (curr_time > peer->timeout)
        {
            action("churn", "disconnect from old peer [%s]", peer->name);
            return false;
        }
        peer->alive = curr_time;
        i += r;
    }
    return true;
}

// Read a message:
static bool read_message(struct peer *peer, struct buf *in)
{
    reset_buf(in);
    char hdr0[sizeof(struct header)];
    if (!read_message_data(peer, hdr0, sizeof(hdr0)))
        return false;
    struct header hdr = *(struct header *)hdr0;
    if (hdr.magic != MAGIC)
    {
        warning("[%s] bad message (incorrect magic number)", peer->name);
        return false;
    }
    if (hdr.length > MAX_MESSAGE_LEN)
    {
        warning("[%s] bad message (too big)", peer->name);
        return false;
    }
    bool found = false;
    for (size_t i = 0; !found && i < sizeof(hdr.command); i++)
        found = (hdr.command[i] == '\0');
    if (!found)
    {
        warning("[%s] bad message (command not null-terminated)", peer->name);
        return false;
    }
    push(in, hdr);
    if (hdr.length == 0)
    {
        uint256_t checksum = hash(NULL, 0);
        if (checksum.i32[0] != hdr.checksum)
        {
            warning("[%s] bad message (checksum failed)", peer->name);
            return false;
        }
        in->len = in->ptr;
        in->ptr = 0;
        return true;
    }

    size_t len = hdr.length;
    grow_buf(in, len);
    if (!read_message_data(peer, in->data + in->ptr, len))
        return false;

    uint256_t checksum = hash(in->data + in->ptr, len);
    if (checksum.i32[0] != hdr.checksum)
    {
        warning("[%s] bad message (checksum failed)", peer->name);
        return false;
    }

    in->len = in->ptr+len;
    in->ptr = 0;
    return true;
}

// Relay a message to all peers.
static void relay_message(struct table *table, struct peer *peer,
    struct buf *buf)
{
    size_t num_peers = get_num_peers();
    for (size_t i = 0; i < num_peers; i++)
    {
        struct peer *p = get_peer(i, 0);
        if (p != NULL && p != peer && p->ready)
            send_message(p, buf);
        deref_peer(p);
    }
}

// Relay a transaction.
static void relay_transaction(struct table *table, struct peer *peer,
    uint256_t tx_hsh)
{
    action("relay", HASH_FORMAT " (tx)", HASH(tx_hsh));
    struct buf *out = alloc_buf(NULL);
    make_inv(out, MSG_TX, tx_hsh);
    relay_message(table, peer, out);
    deref_buf(out);
}

// Relay a block.
static void relay_block(struct table *table, struct peer *peer,
    uint256_t blk_hsh)
{
    action("relay", HASH_FORMAT " (blk)", HASH(blk_hsh));
    struct buf *out = alloc_buf(NULL);
    make_inv(out, MSG_BLOCK, blk_hsh);
    relay_message(table, peer, out);
    deref_buf(out);
}

// Relay an address.
static void relay_address(struct table *table, struct peer *peer,
    time_t time, struct in6_addr addr)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    uint16_t port = PORT;
    action("relay", "%s:%u", name, ntohs(port));
    struct buf *out = alloc_buf(NULL);
    make_addr_0(out, (uint32_t)time, addr);
    relay_message(table, peer, out);
    deref_buf(out);
}

// Find a suitable peer to forward "getdata" requests to.  The peer must be
// outbound, ready, synced (if sync=true) and must be different than `peer'.
// The peer must also match the given `mask'.  Return NULL if no suitable peer
// is found.
static struct peer *find_peer(struct table *table, struct peer *peer,
    bool sync, uint64_t mask, uint256_t hsh)
{
    size_t offset = rand64();
    struct peer *p = NULL;
    for (size_t i = 0; p == NULL && i < MAX_OUTBOUND_PEERS; i++)
    {
        size_t idx = (i + offset) % MAX_OUTBOUND_PEERS;
        if (((1 << idx) & mask) == 0)
            continue;
        p = get_peer(idx, 0);
        if (p != NULL && p != peer && p->ready && (!sync || p->sync))
            break;
        deref_peer(p);
        p = NULL;
    }
    return p;
}

// Fetch some data by sending a "getdata" request to a "suitable" peer.  See
// find_peer() for the definition of "suitable peer".
static bool fetch_data(struct table *table, struct peer *peer, uint32_t type,
    uint256_t hsh, bool sync, uint64_t mask)
{
    struct peer *p = find_peer(table, peer, sync, mask, hsh);
    if (p == NULL)
    {
        warning("[%s] failed to get data " HASH_FORMAT_SHORT "; no suitable"
            " peer", peer->name, HASH_SHORT(hsh));
        return false;
    }
    struct buf *out = alloc_buf(NULL);
    make_getdata(out, type, hsh);
    send_message(p, out);
    deref_buf(out);
    deref_peer(p);
    return true;
}

// Wake all delayed peers (set by set_delay()) that are waiting on some
// message data,  Also clears all delays.  The message to send is stored in
// `out'.
static void wake_delays(struct table *table, uint256_t hsh, 
    struct delay *delays, struct buf *out, const char *type)
{
    while (delays != NULL)
    {
        struct delay *d = delays;
        struct peer *p = get_peer(d->index, d->nonce);
        if (p != NULL)
        {
            action("send", HASH_FORMAT_SHORT " (%s) to [%s]", HASH_SHORT(hsh),
                type, p->name);
            send_message(p, out);
            deref(&p->reqs);
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
                return (addrv4[3] != 255);                      // Broadcast
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
static bool insert_address(struct table *table, struct in6_addr addr,
    time_t time)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    if (!is_good_address(addr))
    {
        warning("ignoring bad address [%s]", name);
        return false;
    }
    uint256_t addr_hsh = addr_hash(addr);
    if (get_vote(table, addr_hsh) != 0)
        return false;
    insert(table, addr_hsh, ADDRESS);
    set_time(table, addr_hsh, time);
    queue_push_address(table, addr);
//    action("found", "address [%s]", name);
    return true;
}

/*****************************************************************************/
// HANDLE MESSAGES

// Handle "addr".  Add the new addresses to the table & address queue.
static bool handle_addr(struct peer *peer, struct table *table, struct buf *in)
{
    size_t len = pop_varint(in);
    const size_t MAX_ADDRESSES = 1000;
    if (len > MAX_ADDRESSES)
    {
        warning("[%s] too many addresses (got %u, max=%u)", peer->name, len,
            MAX_ADDRESSES);
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
        if (port != PORT)
            continue;   // Simplification: ignore any non-standard port.
        if (time < curr_time && curr_time - time >= 10800)  // 3 hours
            continue;   // Too old.
        if (time > curr_time + 600)                         // 10 mins
            continue;   // Too far in the future.
        if (insert_address(table, addr, curr_time) && len == 1)
            relay_address(table, peer, curr_time, addr);
    }
    return true;
}

// Handle "inv".  Each inv message is treated as a vote as to the validity
// of the data.  Once the vote tally reaches THRESHOLD, then the data is
// considered valid.
static bool handle_inv(struct peer *peer, struct table *table, struct buf *in)
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

        // For each type (tx or block), register the vote.  If we have reached
        // the THRESHOLD number of votes, then PseudoNode treats the data as
        // valid, and relay it to other peers.
        if (type != MSG_TX && type != MSG_BLOCK)
        {
            warning("[%s] NYI inv type (%u)", peer->name, type);
            continue;
        }
        size_t count = vote(table, hsh, (type == MSG_TX? TX: BLOCK),
            peer->index);
        if (count == 1)
        {
            int16_t invs = peer->invs++;
            if (invs > MAX_INVS)
            {
                // This peer is inv-flooding, disconnect.
                warning("[%s] too many invs", peer->name);
                return false;
            }
        }
        if (count != THRESHOLD)
            continue;

        // Vote threshold reached; take some action.
        if (type == MSG_TX)
            relay_transaction(table, peer, hsh);
        else
        {
            size_t count = vote(table, hsh, BLOCK, peer->index);
            if (count != THRESHOLD)
                continue;

            // PseudoNode assumes only new blocks are actively advertised.
            // This seems to work well in practice for THRESHOLD >= 2.
            log("----------------------------------NEW BLOCK"
                "-----------------------------------");
            inc_height();
            garbage_collect(table);             // Clean-up stale data.
            reset_peers();
            queue_shuffle();
            relay_block(table, peer, hsh);
        }

        // If enabled, we prefetch data rather than waiting for a node to
        // explicitly request it.  Consumes more bandwidth but makes
        // PseudoNode faster.
        if (PREFETCH)
        {
            unsigned state = set_state(table, hsh, FETCHING);
            if (state != OBSERVED)
                continue;
            if (!fetch_data(table, peer, type, hsh, false,
                    get_vote_mask(table, hsh)))
                delete(table, hsh);     // Fail-safe (unlikely)
        }
    }
    return true;
}

// Handle "notfound".  Such messages are forwarded to delayed peers if
// necessary.
static bool handle_notfound(struct peer *peer, struct table *table,
    struct buf *in)
{
    if (!peer->outbound)
        return true;
    size_t num_ent = pop_varint(in);
    for (size_t i = 0; i < num_ent; i++)
    {
        uint32_t type = pop(in, uint32_t);
        uint256_t hsh = pop(in, uint256_t);

        struct delay *delays = get_delays(table, hsh);
        if (delays == NULL)
            continue;
        struct buf *out = alloc_buf(NULL);
        make_notfound(out, type, hsh);
        while (delays != NULL)
        {
            struct delay *d = delays;
            struct peer *p = get_peer(d->index, d->nonce);
            if (p != NULL && p != peer)
            {
                action("notfound", HASH_FORMAT_SHORT " (%s) to [%s]",
                    HASH_SHORT(hsh), (type == MSG_TX? "tx": "blk"),
                    p->name);
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
static bool handle_tx(struct peer *peer, struct table *table, struct buf *in,
    size_t len)
{
    char *tx = pop_data(in, len);
    uint256_t tx_hsh = hash(tx, len);

    // Check that we actually requested the tx, otherwise ignore.
    if (get_state(table, tx_hsh) < FETCHING)
    {
        mem_free(tx);
        warning("[%s] ignoring unsolicited transaction " HASH_FORMAT_SHORT,
            peer->name, HASH_SHORT(tx_hsh));
        return true;
    }

    // Forward the tx.
    struct delay *delays = get_delays(table, tx_hsh);
    if (delays != NULL)
    {
        struct buf *out = alloc_buf(NULL);
        make_tx(out, tx, len);
        wake_delays(table, tx_hsh, delays, out, "tx");
        deref_buf(out);
    }

    // Cache the tx.
    if (!set_data(table, tx_hsh, tx, len))
    {
        mem_free(tx);
        warning("[%s] received duplicate transaction", peer->name);
    }
    return true;
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
        if (COIN == &paycoin)
            pop(in, uint32_t);                      // time (paycoin)
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
static bool handle_block(struct peer *peer, struct table *table,
    struct buf *in, uint32_t len)
{
    if (len < sizeof(struct block))
    {
        warning("[%s] bad block (too small)", peer->name);
        return false;
    }
    char *block = pop_data(in, len);
    uint256_t blk_hsh = hash(block, sizeof(struct block));
    struct block *header = (struct block *)block;
    in->ptr = sizeof(struct header) + sizeof(struct block);

    // The Merkle root must be checked otherwise the tx data may be invalid.
    uint256_t root = merkle_root(in);
    if (memcmp(&root, &header->merkle_root, sizeof(uint256_t)) != 0)
    {
        mem_free(block);
        warning("[%s] bad block (merkle root does not match)", peer->name);
        return false;
    }

    // Check that we actually requested the block, otherwise ignore.
    if (get_state(table, blk_hsh) < FETCHING)
    {
        mem_free(block);
        warning("[%s] ignoring unsolicited block " HASH_FORMAT_SHORT,
            peer->name, HASH_SHORT(blk_hsh));
        return false;   // Disconnect because peer is wasting bandwidth.
    }

    struct delay *delays = get_delays(table, blk_hsh);
    if (delays != NULL)
    {
        struct buf *out = alloc_buf(NULL);
        make_block(out, block, len);
        wake_delays(table, blk_hsh, delays, out, "blk");
        deref_buf(out);
    }

    // Cache recent blocks:
    time_t curr_time = time(NULL);
    time_t blk_time = header->timestamp;
    int diff = curr_time-blk_time;
    if (diff > 900 || diff < -900)
    {
        // Ignore old block:
        delete(table, blk_hsh);
        mem_free(block);
        return true;
    }
    if (!set_data(table, blk_hsh, block, len))
    {
        mem_free(block);
        warning("[%s] received duplicate block", peer->name);
        return true;
    }

    return true;
}

// Handle "getaddr".
static bool handle_getaddr(struct peer *peer, struct table *table,
    struct buf *in)
{
    static const size_t MAX_ADDRESSES = 8000;
    struct buf *addrs = alloc_buf(NULL);
    size_t len = queue_get_addresses(table, addrs, MAX_ADDRESSES);
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
        make_addr(out, num_addr, data, num_addr * NETADDR_SIZE);
        send_message(peer, out);
        deref_buf(out);
        action("send", "%u addresses to [%s]", num_addr, peer->name);
    }
    deref_buf(addrs);
    return true;
}

// Handle "getdata".
static bool handle_getdata(struct peer *peer, struct table *table,
    struct buf *in)
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
        unsigned state = get_state(table, hsh);
        size_t data_len = 0;
        void *data = NULL;
        retry:
        switch (state)
        {
            case OBSERVED:
                // OBSERVED = inv packets seen, but data is not available
                // yet.  Therefore set state to FETCHING and fetch the data.
                if (get_vote(table, hsh) < THRESHOLD)
                    goto not_found;
                int16_t reqs = ref(&peer->reqs);
                if (reqs >= MAX_REQUESTS)
                {
                    warning("[%s] too many requests", peer->name);
                    return false;
                }
                state = set_state(table, hsh, FETCHING);
                if (state != OBSERVED)
                    goto retry;
                set_delay(table, hsh, peer->index, peer->nonce);
                if (!fetch_data(table, peer, type, hsh, false,
                        get_vote_mask(table, hsh)))
                    goto not_found;
                continue;
            case FETCHING:
                // FETCHING = data is not available, but "getdata" has been
                // sent (and we are waiting for the reply).  Delay this
                // request on the condition that the data is available.
                set_delay(table, hsh, peer->index, peer->nonce);
                continue;
            case AVAILABLE:
                // AVAILABLE = data is available, complete the request.
                data = get_data(table, hsh, &data_len);
                if (data != NULL)
                    break;
                goto not_found;
            case MISSING:
                // MISSING = data has not been observed at all.
                if (type == MSG_BLOCK)
                {
                    // Request for an block that was never advertised:
                    int16_t reqs = ref(&peer->reqs);
                    if (reqs >= MAX_REQUESTS)
                    {
                        warning("[%s] too many requests", peer->name);
                        return false;
                    }
                    insert(table, hsh, BLOCK);
                    state = set_state(table, hsh, FETCHING);
                    if (state != OBSERVED)
                        goto retry;
                    set_delay(table, hsh, peer->index, peer->nonce);
                    if (!fetch_data(table, peer, type, hsh, true, UINT64_MAX))
                        goto not_found;
                    continue;
                }
                // Fall through:
            default:
            not_found:
            {
                struct buf *out = alloc_buf(NULL);
                make_notfound(out, type, hsh);
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
                make_tx(out, data, data_len);
                action("send", HASH_FORMAT_SHORT " (tx) to [%s]",
                    HASH_SHORT(hsh), peer->name);
                break;
            }
            case MSG_BLOCK:
            {
                make_block(out, data, data_len);
                action("send", HASH_FORMAT_SHORT " (blk) to [%s]",
                    HASH_SHORT(hsh), peer->name);
                break;
            }
            default:
                // NYI:
                break;
        }
        send_message(peer, out);
        deref_buf(out);
        deref_data(table, hsh);
    }
    return ok;
}

// Handle "getheaders".  Forward it to a suitable peer.
static bool handle_getheaders(struct peer *peer, struct table *table,
    struct buf *in)
{
    pop(in, uint32_t);
    size_t count = pop_varint(in);
    static size_t MAX_COUNT = 2000;
    if (count < 1 || count > MAX_COUNT)
    {
        warning("[%s] count is out-of-range for getheaders", peer->name);
        return false;
    }
    uint256_t hsh = pop(in, uint256_t);
    for (size_t i = 0; i < count; i++)
        pop(in, uint256_t);
    hsh = headers_hash(hsh);
    insert(table, hsh, HEADERS);
    unsigned state = get_state(table, hsh);
    retry:
    switch (state)
    {
        case OBSERVED:
        {
            int16_t reqs = ref(&peer->reqs);
            if (reqs >= MAX_REQUESTS)
            {
                warning("[%s] too many requests", peer->name);
                return false;
            }
            state = set_state(table, hsh, FETCHING);
            if (state != OBSERVED)
                goto retry;
            set_delay(table, hsh, peer->index, peer->nonce);
            break;
        }
        case FETCHING:
            set_delay(table, hsh, peer->index, peer->nonce);
            return true;
        default:
            return true;    // Should never happen.
    }

    // Forward the request.  Care must be taken not for forward back to the
    // same peer.
    uint64_t mask = UINT64_MAX;
    if (peer->index >= MAX_OUTBOUND_PEERS)
        mask = mask & ~(1 << peer->index);
    struct peer *p = find_peer(table, peer, true, mask, hsh);
    if (p == NULL)
    {
        warning("[%s] failed to forward getheaders request; no suitable peer",
            peer->name);
        delete(table, hsh);
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
static bool handle_headers(struct peer *peer, struct table *table,
    struct buf *in)
{
    size_t count = pop_varint(in);
    static size_t MAX_COUNT = 2000;
    if (count < 1 || count > MAX_COUNT)
    {
        warning("[%s] count is out-of-range for headers", peer->name);
        return false;
    }
    struct block block = pop(in, struct block);
    uint256_t hsh = block.prev_block;
    uint256_t req_hsh = headers_hash(hsh);

    // Validate the chain (check is not random data).
    size_t zero = pop_varint(in);
    if (zero != 0)
    {
bad_block:
        warning("[%s] invalid block header (expected zero length)",
            peer->name);
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
            warning("[%s] invalid block header sequence (not a chain)",
                peer->name);
            return false;
        }
        hsh = hash(&block, sizeof(block));
    }

    // Forward response back to originating peer.
    struct delay *delays = get_delays(table, req_hsh);
    if (delays != NULL)
    {
        struct buf *out = alloc_buf(NULL);
        push_buf(out, in);
        wake_delays(table, req_hsh, delays, out, "hdrs");
        deref_buf(out);
    }
    delete(table, req_hsh);
    return true;
}

// Handle "version".
static bool handle_version(struct peer *peer, struct table *table,
    struct buf *in, size_t len)
{
    uint32_t version = pop(in, uint32_t);
    if (version < 70001)
    {
        warning("[%s] ignoring peer (protocol version %u too old)",
            peer->name, version);
        return false;
    }
    uint64_t services = pop(in, uint64_t);
    if ((services & NODE_NETWORK) == 0 && peer->outbound)
    {
        warning("[%s] ignoring peer (not a full node)", peer->name);
        return false;
    }
    uint64_t curr_time = time(NULL);
    uint64_t peer_time = pop(in, uint64_t);
    if (peer_time < curr_time - 3600 || peer_time > curr_time + 3600)
    {
        warning("[%s] ignoring peer (clock mis-match)", peer->name);
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
    for (size_t i = 0; !peer->outbound && i <= MAX_OUTBOUND_PEERS; i++)
    {
        struct peer *p = get_peer(i, nonce);
        if (p != NULL)
        {
            p->error = true;
            deref_peer(p);
            warning("[%s] ignoring peer (peer is self)", peer->name);
            return false;
        }
    }
    if (peer->outbound)
        relay = set_my_addr(addr);
    char *agent = pop_varstr(in);
    action("connect", "peer [%s] of type \"%s\"", peer->name, agent);
    mem_free(agent);
    int32_t h = pop(in, uint32_t);
    if (peer->outbound)
        set_height(h);
    if (h > HEIGHT && h >= get_height())
        peer->sync = true;
    bool use_relay = false;
    if (USE_RELAY && !is_empty(in))
        use_relay = true;
    struct buf *out = alloc_buf(NULL);
    make_verack(out);
    send_message(peer, out);
    deref_buf(out);
    if (!peer->outbound)
    {
        struct buf *out = alloc_buf(NULL);
        make_version(out, peer, rand64(), get_height(), use_relay);
        send_message(peer, out);
        deref_buf(out);
    }
    peer->ready = true;
    if (relay)
        relay_address(table, peer, time(NULL), addr);
    return true;
}

// Process a message.
static bool process_message(struct peer *peer, struct table *table,
    struct buf *in)
{
    struct header hdr = pop(in, struct header);
    size_t len = hdr.length;

    bool ok = true;
    if (strcmp(hdr.command, "version") == 0)
        ok = handle_version(peer, table, in, len);
    else if (strcmp(hdr.command, "verack") == 0)
        ok = true;
    else if (strcmp(hdr.command, "addr") == 0)
        ok = handle_addr(peer, table, in);
    else if (strcmp(hdr.command, "getaddr") == 0)
        ok = handle_getaddr(peer, table, in);
    else if (strcmp(hdr.command, "inv") == 0)
        ok = handle_inv(peer, table, in);
    else if (strcmp(hdr.command, "tx") == 0)
        ok = handle_tx(peer, table, in, len);
    else if (strcmp(hdr.command, "block") == 0)
        ok = handle_block(peer, table, in, len);
    else if (strcmp(hdr.command, "getdata") == 0)
        ok = handle_getdata(peer, table, in);
    else if (strcmp(hdr.command, "getheaders") == 0)
        ok = handle_getheaders(peer, table, in);
    else if (strcmp(hdr.command, "headers") == 0)
        ok = handle_headers(peer, table, in);
    else if (strcmp(hdr.command, "notfound") == 0)
        ok = handle_notfound(peer, table, in);
    else if (strcmp(hdr.command, "ping") == 0)
    {
        uint64_t nonce = pop(in, uint64_t);
        struct buf *out = alloc_buf(NULL);
        make_pong(out, nonce);
        send_message(peer, out);
        deref_buf(out);
    }
    else if (strcmp(hdr.command, "filterload") == 0)
        ok = false;         // NYI so drop connection.
    else if (strcmp(hdr.command, "reject") == 0)
    {
        char *message = pop_varstr(in);
        pop(in, uint8_t);
        char *reason = pop_varstr(in);
        warning("[%s] message (%s) rejected by peer (%s)", peer->name,
            message, reason);
        mem_free(message);
        mem_free(reason);
    }
    else if (strcmp(hdr.command, "getblocks") == 0)
        ok = true;          // Safe to ignore.
    else
        warning("[%s] ignoring unknown or NYI command \"%s\"", peer->name,
            hdr.command);

    return ok;
}

/*****************************************************************************/
// MAIN

// Open a peer.
static struct peer *open_peer(int s, bool outbound, struct in6_addr addr,
    in_port_t port, size_t idx)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));

    // Peer churn:
    time_t curr_time = time(NULL);
    time_t timeout = curr_time + 300;   // 5 mins min
    uint32_t h = get_height();
    if (h < HEIGHT)
        timeout += rand64() % 300;      // +5 mins max.
    else
        timeout += rand64() % 7200;     // +2 hours max.

    struct peer *peer = (struct peer *)mem_alloc(sizeof(struct peer));
    peer->head = NULL;
    peer->tail = NULL;
    peer->sock = s;
    mutex_init(&peer->lock);
    event_init(&peer->event);
    peer->outbound = outbound;
    peer->error = false;
    peer->ready = false;
    peer->sync  = false;
    peer->ref_count = 2;        // 2 for both threads
    peer->reqs = 0;
    peer->invs = 0;
    peer->alive = curr_time;
    peer->timeout = timeout;
    peer->nonce = rand64();
    peer->to_addr = addr;
    peer->to_port = port;
    peer->from_addr = get_my_addr();
    peer->from_port = PORT;
    peer->index = idx;
    peer->name = (char *)mem_alloc(strlen(name)+1);
    strcpy(peer->name, name);
    spawn_thread(send_message_worker, (void *)peer);
    set_peer(peer->index, peer);
    return peer;
}

static void deref_peer(struct peer *peer)
{
    if (peer == NULL)
        return;
    ssize_t ref_count = deref(&peer->ref_count);
    if (ref_count > 1)
        return;
    socket_close(peer->sock);
    mutex_free(&peer->lock);
    event_free(&peer->event);
    struct msg *msg = peer->head;
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
static void close_peer(struct table *table, struct peer *peer)
{
    struct in6_addr addr = peer->to_addr;
    del_peer(peer->index);
    peer->error = true;
    deref_peer(peer);
    if (rand64() % 8 != 0)      // Maybe re-use peer?
        insert_address(table, addr, time(NULL) - rand64() % 3000);
}

// Handle a peer.
static void *peer_worker(void *arg)
{
    assert(arg != NULL);
    struct info *info = (struct info *)arg;
    struct table *table = info->table;
    size_t peer_idx = info->peer_idx;
    int s = info->sock;
    bool outbound = info->outbound;
    struct in6_addr addr = info->addr;
    mem_free(info);

    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    if (outbound)
        action("open", "outbound peer [%s] (%u/%u)", name, peer_idx+1,
            MAX_OUTBOUND_PEERS);
    else
        action("open", "inbound peer [%s] (%u/oo)", name,
            peer_idx+1-MAX_OUTBOUND_PEERS);

    if (outbound)
    {
        // Open socket for outbound peer.
        s = socket_open();
        if (s == INVALID_SOCKET)
        {
            warning("[%s] failed to open socket: %s", name, get_error());
            del_peer(peer_idx);
            return NULL;
        }
        if (!socket_connect(s, addr))
        {
            warning("[%s] failed to connect to peer: %s", name, get_error());
            socket_close(s);
            del_peer(peer_idx);
            return NULL;
        }
    }

    // Open the peer.
    struct peer *peer = open_peer(s, outbound, addr, PORT, peer_idx);
    if (peer == NULL)
    {
        socket_close(s);
        uint256_t addr_hsh = addr_hash(addr);
        delete(table, addr_hsh);
        del_peer(peer_idx);
        return NULL;
    }
    jmp_buf env;
    struct buf *in = alloc_buf(&env);
    if (setjmp(env))
    {
        warning("[%s] peer sent truncated message", peer->name);
        close_peer(table, peer);
        deref_buf(in);
        return NULL;
    }
    if (outbound)
    {
        // Send version message first for outbound peer.
        struct buf *out = alloc_buf(NULL);
        make_version(out, peer, rand64(), get_height(), true);
        send_message(peer, out);
        deref_buf(out);
    }
    // Read the version message.
    if (!read_message(peer, in) || !process_message(peer, table, in))
    {
        close_peer(table, peer);
        deref_buf(in);
        return NULL;
    }
    if (!peer->ready)
    {
        warning("[%s] peer failed to send version message", peer->name);
        close_peer(table, peer);
        deref_buf(in);
        return NULL;
    }
    if (outbound && queue_need_addresses())
    {
        // Get new addresses if necessary.
        struct buf *out = alloc_buf(NULL);
        make_getaddr(out);
        send_message(peer, out);
        deref_buf(out);
    }

    // Read message loop:
    while (read_message(peer, in) && process_message(peer, table, in))
        ;
    deref_buf(in);
    close_peer(table, peer);
    return NULL;
}

// Manage all peers.  Create new connections if necessary.
static void manager(struct table *table)
{
    sock s = socket_open();
    if (s == INVALID_SOCKET)
        fatal("failed to create socket: %s", get_error());
    if (!socket_bind(s, PORT))
        fatal("failed to bind socket: %s", get_error());
    if (!socket_listen(s))
        fatal("failed to listen socket: %s", get_error());

    while (true)
    {
        ssize_t idx = alloc_peer(true);
        if (idx >= 0)
        {
            bool ok;
            struct in6_addr addr = queue_pop_address(table, &ok);
            if (ok)
            {
                struct info *info = (struct info *)mem_alloc(
                    sizeof(struct info));
                memset(info, 0, sizeof(struct info));
                info->table = table;
                info->addr = addr;
                info->peer_idx = idx;
                info->outbound = true;
                if (!spawn_thread(peer_worker, (void *)info))
                    mem_free(info);
            }
        }

        size_t t = 300 + rand64() % 200;
        struct timeval tv;
        tv.tv_sec  = t / 1000;
        tv.tv_usec = (t % 1000) * 1000;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s, &fds);
        int r = select(s+1, &fds, NULL, NULL, &tv);
        if (r < 0)
        {
            warning("failed to wait for socket: %s", get_error());
            msleep(10);
        }
        else if (r > 0)
        {   
            struct in6_addr addr;
            int s1 = socket_accept(s, &addr);
            if (s1 == INVALID_SOCKET)
            {
                warning("failed to accept inbound connection: %s",
                    get_error());
                continue;
            }
            ssize_t idx = alloc_peer(false);
            if (idx < 0)
            {
                warning("too many inbound connections");
                socket_close(s1);
                continue;
            }
            struct info *info = (struct info *)mem_alloc(
                sizeof(struct info));
            info->table = table;
            info->peer_idx = idx;
            info->sock = s1;
            info->addr = addr;
            info->outbound = false;
            if (!spawn_thread(peer_worker, (void *)info))
            {
                socket_close(s1);
                mem_free(info);
            }
        }
    }
}

// Find addresses via DNS seeds.  This is how PseudoNode finds an initial
// set of peers.  Other peers can be discovered via "getaddr" messages.
static void *bootstrap(void *arg)
{
    struct table *table = (struct table *)arg;
    assert(table != NULL);
    time_t curr_time = time(NULL);

    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    size_t decay = 2;
    while (queue_need_addresses())
    {
        size_t stagger = rand64() % 100;
        const char *seed = SEEDS[rand64() % SEEDS_LENGTH];
        struct addrinfo *res;
        if (getaddrinfo(seed, NULL, &hint, &res) != 0)
        {
            warning("failed to get address info for %s: %s", seed,
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
            time_t addr_time = curr_time - rand64() % 3000;
            insert_address(table, addr, addr_time);
            info = info->ai_next;
        }
        freeaddrinfo(res);
        queue_shuffle();
        decay = (decay > 30000? 30000: (3 * decay) / 2);
        msleep(1000 + stagger + decay);
    }

    return NULL;
}

#include "port_map.c"

#define OPTION_CLIENT       1
#define OPTION_COIN         2
#define OPTION_HELP         3
#define OPTION_MAX_PEERS    4
#define OPTION_PEER         5
#define OPTION_PREFETCH     6
#define OPTION_SERVER       7
#define OPTION_STEALTH      8
#define OPTION_THRESHOLD    9

// main:
int main(int argc, char **argv)
{
#ifdef LINUX
    signal(SIGPIPE, SIG_IGN);
#endif

    mutex_init(&log_lock);
    mutex_init(&queue_lock);
    mutex_init(&height_lock);
    mutex_init(&addr_lock);
    mutex_init(&peer_lock);
    mutex_init(&rand_lock);
    if (!system_init())
        fatal("OS-dependant init failed");
    rand64_init();
    addr_salt = rand64();
    headers_salt = rand64();
    memset(queue, 0, sizeof(queue));
    struct table *table = alloc_table();
   
    static struct option long_options[] =
    {
        {"client",    1, 0, OPTION_CLIENT},
        {"coin",      1, 0, OPTION_COIN},
        {"help",      0, 0, OPTION_HELP},
        {"max-peers", 1, 0, OPTION_MAX_PEERS},
        {"peer",      1, 0, OPTION_PEER},
        {"prefetch",  0, 0, OPTION_PREFETCH},
        {"server",    0, 0, OPTION_SERVER},
        {"stealth",   0, 0, OPTION_STEALTH},
        {"threshold", 1, 0, OPTION_THRESHOLD},
        {NULL, 0, 0, 0}
    };
    COIN = &bitcoin;
    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_CLIENT:
                USER_AGENT = strdup(optarg);
                break;
            case OPTION_COIN:
                if (strcmp(optarg, "bitcoin") == 0)
                    COIN = &bitcoin;
                else if (strcmp(optarg, "testnet") == 0)
                    COIN = &testnet;
                else if (strcmp(optarg, "litecoin") == 0)
                    COIN = &litecoin;
                else if (strcmp(optarg, "dogecoin") == 0)
                    COIN = &dogecoin;
                else if (strcmp(optarg, "paycoin") == 0)
                    COIN = &paycoin;
                else if (strcmp(optarg, "flappycoin") == 0)
                    COIN = &flappycoin;
                else
                    fatal("unknown coin \"%s\"", optarg);
                break;
            case OPTION_PEER:
            {
                struct in6_addr addr;
                if (inet_pton(AF_INET6, optarg, &addr) != 1)
                {
                    uint32_t addr32;
                    if (inet_pton(AF_INET, optarg, &addr32) != 1)
                        fatal("failed to parse IP address \"%s\"", optarg);
                    memset(&addr, 0, sizeof(addr));
                    addr.s6_addr16[5] = 0xFFFF;
                    memcpy(addr.s6_addr16+6, &addr32, sizeof(addr32));
                }
                insert_address(table, addr, time(NULL));
                break;
            }
            case OPTION_MAX_PEERS:
                MAX_OUTBOUND_PEERS = atoi(optarg);
                if (MAX_OUTBOUND_PEERS < 1 || MAX_OUTBOUND_PEERS > 64)
                    fatal("maximum peers is out of range");
                break;
            case OPTION_SERVER:
                SERVER = true;
                break;
            case OPTION_STEALTH:
                STEALTH = true;
                break;
            case OPTION_PREFETCH:
                PREFETCH = true;
                break;
            case OPTION_THRESHOLD:
                THRESHOLD = atoi(optarg);
                break;
            case OPTION_HELP:
            default:
                fprintf(stderr, "usage: %s [--help] [--client=NAME] "
                    "[--threshold=VAL] [--server] [--stealth] [--peer=PEER] "
                    "[--prefetch] [--max-peers=MAX_PEERS] [--coin=COIN]\n\n",
                    argv[0]);
                fprintf(stderr, "WHERE:\n");
                fprintf(stderr, "\t--client=CLIENT\n");
                fprintf(stderr, "\t\tUse CLIENT as the client name "
                    "(default=PseudoNode).\n");
                fprintf(stderr, "\t--threshold=VAL\n");
                fprintf(stderr, "\t\tData (blocks, tx) is considered valid "
                    "if VAL peers agree\n");
                fprintf(stderr, "\t\t(default=2).\n");
                fprintf(stderr, "\t--peer=PEER\n");
                fprintf(stderr, "\t\tAdd PEER (ipv6 address) to the list of "
                    "potential peers.\n");
                fprintf(stderr, "\t--max-peers=MAX_PEERS\n");
                fprintf(stderr, "\t\tMaximum outbound connections "
                    "(default=8).\n");
                fprintf(stderr, "\t--server\n");
                fprintf(stderr, "\t\tRun as a server (default=false).\n");
                fprintf(stderr, "\t--stealth\n");
                fprintf(stderr, "\t\tIdentify as a normal client "
                    "(default=false).\n");
                fprintf(stderr, "\t--prefetch\n");
                fprintf(stderr, "\t\tPrefetch tx and block data "
                    "(default=false).\n");
                fprintf(stderr, "\t--coin=COIN\n");
                fprintf(stderr, "\t\tAttach to COIN network "
                    "(default=bitcoin).  Supported coins are:\n");
                fprintf(stderr, "\t\tbitcoin, testnet, litecoin, dogecoin, "
                    "paycoin, flappycoin\n");
                return 0;
        }
    }
    if (SERVER)
        server();
    if (USER_AGENT == NULL)
        USER_AGENT = "/PseudoNode:0.4.0/";
    if (STEALTH)
        USER_AGENT = COIN->user_agent;
    if (THRESHOLD < 1 || THRESHOLD > MAX_OUTBOUND_PEERS)
        fatal("threshold must be within the range 1..max_peers");
    height_inc = height_0 = height_1 = height =
        HEIGHT - rand64() % (HEIGHT / 5);
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr_0 = myaddr_1 = myaddr;

    spawn_thread(port_map, NULL);
    if (!spawn_thread(bootstrap, (void *)table))
        fatal("failed to spawn bootstrap thread: %s", get_error());
    manager(table);

    return 0;
}

