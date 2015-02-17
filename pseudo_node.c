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

static size_t THRESHOLD = 2;
static size_t MAX_OUTBOUND_PEERS = 8;
static const char *USER_AGENT = NULL;
static bool STEALTH = false;
static bool SERVER = false;
static bool PREFETCH = false;

struct coin_info
{
    uint32_t protocol_version;
    uint32_t magic;
    char *user_agent;
    uint16_t port;
    uint32_t height;
    const char **seeds;
    size_t seeds_len;
    bool use_relay;
};

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

static const struct coin_info *coin = NULL;
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


#define PROTOCOL_VERSION            (coin->protocol_version)
#define MAGIC                       (coin->magic)
#define PORT                        htons(coin->port)
#define HEIGHT                      (coin->height)
#define SEEDS                       (coin->seeds)
#define SEEDS_LENGTH                (coin->seeds_len)
#define USE_RELAY                   (coin->use_relay)

#define NODE_NETWORK                1

#define MAX_MESSAGE_LEN             0x00FFFFFF

#define MSG_TX                      1
#define MSG_BLOCK                   2
#define MSG_FILTERED_BLOCK          3

#define TX                          1
#define BLOCK                       2
#define ADDRESS                     3
#define HEADERS                     4
#define PEER                        5
#define QUEUE                       6

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

struct header
{
    uint32_t magic;
    char command[12];
    uint32_t length;
    uint32_t checksum;
} __attribute__((__packed__));

struct block
{
    uint32_t version;
    uint256_t prev_block;
    uint256_t merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} __attribute__((__packed__));

struct buf
{
    struct peer *peer;
    char *data;
    uint32_t ptr;
    uint32_t len;
    int32_t ref_count;
};

struct msg
{
    struct buf *buf;
    struct msg *next;
};

struct peer
{
    sock sock;
    mutex lock;
    event event;
    uint32_t height;
    int32_t ref_count;
    struct buf *buf;
    struct msg *head;
    struct msg *tail;
    time_t alive;
    struct in6_addr to_addr;
    in_port_t to_port;
    struct in6_addr from_addr;
    in_port_t from_port;
    char *name;
    uint32_t index;
    bool outbound;
    bool error;
    jmp_buf *env;
};

struct delay
{
    size_t index;
    struct delay *next;
};

struct entry
{
    uint256_t hash;
    uint64_t vote;
    time_t time;
    uint8_t type;
    uint8_t state;
    uint16_t ref_count;
    uint32_t len;
    void *data;
    struct delay *delays;
    struct entry *next;
};

struct table
{
    size_t len;
    size_t count;
    mutex lock;
    struct entry **entries;
};

struct info
{
    struct table *table;
    size_t peer_idx;
    int sock;
    struct in6_addr addr;
};

// Entry states:
#define MISSING         0
#define OBSERVED        1
#define FETCHING        2
#define AVAILABLE       3

static void deref_peer(struct peer *peer);
static void finalize_message(struct buf *buf);

/****************************************************************************/

static mutex height_lock;
static uint32_t height;
static uint32_t height_0;
static uint32_t height_1;

static void set_height(uint32_t h)
{
    mutex_lock(&height_lock);
    if (h > height)
    {
        height_1 = height_0;
        height_0 = h;
        if (height_1 == height_0)
            height = height_0;
    }
    mutex_unlock(&height_lock);
}

static uint32_t get_height(void)
{
    mutex_lock(&height_lock);
    uint32_t h = height;
    mutex_unlock(&height_lock);
    return h;
}

/****************************************************************************/

static mutex addr_lock;
static struct in6_addr myaddr;
static struct in6_addr myaddr_0;
static struct in6_addr myaddr_1;

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

static struct in6_addr get_my_addr(void)
{
    mutex_lock(&addr_lock);
    struct in6_addr addr = myaddr;
    mutex_unlock(&addr_lock);
    return addr;
}

/****************************************************************************/

static mutex log_lock;

#define ACTION      0
#define LOG         1
#define WARNING     2
#define FATAL       3

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

static uint64_t addr_salt;
static uint64_t peer_salt;
static uint64_t queue_salt;
static uint64_t headers_salt;

extern void sha256(const void *data, size_t len, void *res);
static uint256_t hash(const void *data, size_t len)
{
    uint256_t res;
    sha256(data, len, &res);
    sha256(&res, sizeof(res), &res);
    return res;
}

static uint256_t addr_hash(struct in6_addr addr)
{
    addr.s6_addr16[0] ^= (uint16_t)addr_salt;
    addr.s6_addr16[1] ^= (uint16_t)(addr_salt >> 16);
    addr.s6_addr16[2] ^= (uint16_t)(addr_salt >> 32);
    addr.s6_addr16[3] ^= (uint16_t)(addr_salt >> 48);
    return hash(&addr, sizeof(addr));
}

static uint256_t peer_hash(size_t idx)
{
    size_t key[2] = {peer_salt, idx};
    return hash(key, sizeof(key));
}

static uint256_t queue_hash(size_t idx)
{
    size_t key[2] = {queue_salt, idx};
    return hash(key, sizeof(key));
}

static uint256_t headers_hash(uint256_t hsh)
{
    hsh.i64[0] ^= headers_salt;
    return hash(&hsh, sizeof(hsh));
}

/****************************************************************************/

static mutex rand_lock;
static uint64_t state[2];

static void rand64_init(void)
{
    if (!rand_init(state))
        fatal("failed to initialize random numbers");
}

static uint64_t rand64(void)
{
    uint64_t tmp[2];
    mutex_lock(&rand_lock);
    tmp[0] = state[0];
    tmp[1] = state[1];
    state[0]++;
    if (state[0] == 0)
        state[1]++;
    mutex_unlock(&rand_lock);
    uint256_t r;
    sha256(tmp, sizeof(tmp), &r);
    return r.i64[0];
}

/****************************************************************************/
// Simple data buffers

static struct buf *alloc_buf(struct peer *peer)
{
    struct buf *buf = (struct buf *)mem_alloc(sizeof(struct buf));
    size_t len = BUFFER_SIZE;
    char *data = (char *)mem_alloc(len);
    buf->peer      = peer;
    buf->data      = data;
    buf->len       = len;
    buf->ptr       = 0;
    buf->ref_count = 1;
    return buf;
}

static void reset_buf(struct buf *buf)
{
    if (buf->len > BUFFER_SIZE)
    {
        mem_free(buf->data);
        buf->len = BUFFER_SIZE;
        buf->data = (char *)mem_alloc(buf->len);
    }
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

static void grow_buf(struct buf *buf, size_t len)
{
    if (buf->len - buf->ptr < len)
    {
        size_t old_len = buf->len;
        while (buf->len - buf->ptr < len)
            buf->len *= 2;
        char *old_data = buf->data;
        buf->data = (char *)mem_alloc(buf->len);
        memcpy(buf->data, old_data, old_len);
        mem_free(old_data);
    }
}

#define push(buf, v)                                                    \
    do {                                                                \
        grow_buf((buf), sizeof(v));                                     \
        memcpy((buf)->data + (buf)->ptr, &(v), sizeof(v));              \
        (buf)->ptr += sizeof(v);                                        \
    } while (false)

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

static void push_varstr(struct buf *buf, const char *str)
{
    size_t len = strlen(str);
    push_varint(buf, len);
    grow_buf(buf, len);
    memcpy(buf->data + buf->ptr, str, len);
    buf->ptr += len;
}

static void push_buf(struct buf *buf, const struct buf *data)
{
    grow_buf(buf, data->ptr);
    memcpy(buf->data + buf->ptr, data->data, data->ptr);
    buf->ptr += data->ptr;
}

static void push_data(struct buf *buf, size_t len, const void *data)
{
    grow_buf(buf, len);
    memcpy(buf->data + buf->ptr, data, len);
    buf->ptr += len;
}

static int pop_error(struct peer *peer, size_t len)
{
    warning("[%s] message parse error (failed to pop %u bytes)", peer->name,
        len);
    longjmp(*peer->env, 1);
}

#define pop(buf, type)                                                      \
    (((buf)->ptr + sizeof(type) <= (buf)->len? 0:                           \
        pop_error((buf)->peer, sizeof(type))),                              \
     (buf)->ptr += sizeof(type),                                            \
     *(type *)((buf->data + (buf)->ptr - sizeof(type))))

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

static char *pop_data(struct buf *buf, size_t len)
{
    if ((buf)->ptr + (len) > (buf)->len)
        pop_error(buf->peer, len);
    char *data = mem_alloc(len);
    memcpy(data, buf->data + buf->ptr, len);
    buf->ptr += len;
    return data;
}

static char *pop_varstr(struct buf *buf)
{
    size_t len = pop_varint(buf);
    if (buf->ptr + len > buf->len)
        pop_error(buf->peer, len);
    char *s = (char *)mem_alloc(len+1);
    memcpy(s, buf->data + buf->ptr, len);
    s[len] = '\0';
    buf->ptr += len;
    return s;
}

static bool is_empty(struct buf *buf)
{
    return (buf->ptr == buf->len);
}

/****************************************************************************/
// The monolithic data "table".  Stores blocks, tx, peers, addrs, etc., etc.

static struct table *alloc_table(void)
{
    struct table *table = (struct table *)mem_alloc(sizeof(struct table));
    size_t len = 1024;
    struct entry **entries = (struct entry **)mem_alloc(
        len * sizeof(struct entry *));
    memset(entries, 0, len * sizeof(struct entry *));
    table->len = len;
    table->count = 0;
    table->entries = entries;
    mutex_init(&table->lock);
    return table;
}

// Population count:
size_t popcount(uint64_t x)
{
    int count;
    for (count = 0; x; count++)
        x &= x - 1;
    return count;
}

#define get_index(table, hsh)       ((size_t)(hsh).i32[4] % (table)->len)

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
            size_t idx = get_index(table, entry->hash);
            e->next = table->entries[idx];
            table->entries[idx] = e;
        }
    }
    mem_free(entries);
}

static size_t insert(struct table *table, uint256_t hash, unsigned type,
    uint64_t vote_idx)
{
    size_t vote = (vote_idx >= MAX_OUTBOUND_PEERS? 0:
        (1 << (vote_idx % (sizeof(uint64_t) * 8))));

    time_t curr_time = time(NULL);
    mutex_lock(&table->lock);
    size_t idx = get_index(table, hash);
    struct entry *entry = table->entries[idx];
    while (entry != NULL)
    {
        if (memcmp(&hash, &entry->hash, sizeof(hash)) == 0)
        {
            entry->vote |= vote;
            size_t new_vote = entry->vote;
            mutex_unlock(&table->lock);
            return popcount(new_vote);
        }
        entry = entry->next;
    }
    {
        grow_table(table);
        struct entry *entry = (struct entry *)mem_alloc(sizeof(struct entry));
        entry->hash = hash;
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
    }
    mutex_unlock(&table->lock);
    return (vote != 0? 1: 0);
}

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

static struct entry *get_entry(struct table *table, uint256_t hash)
{
    size_t idx = get_index(table, hash);
    struct entry *entry = table->entries[idx];
    while (entry != NULL)
    {
        if (memcmp(&hash, &entry->hash, sizeof(hash)) == 0)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

static bool set_data(struct table *table, uint256_t hash, void *data,
    size_t len)
{
    assert(len <= UINT32_MAX);
    bool ok = true;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hash);
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

static void *get_data(struct table *table, uint256_t hash, size_t *lenptr)
{
    void *data = NULL;
    if (lenptr != NULL)
        *lenptr = 0;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hash);
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

static bool deref_data(struct table *table, uint256_t hash)
{
    mutex_lock(&table->lock);
    size_t idx = get_index(table, hash);
    struct entry *entry = table->entries[idx], *prev = NULL;
    while (entry != NULL)
    {
        if (memcmp(&hash, &entry->hash, sizeof(hash)) == 0)
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

static unsigned set_state(struct table *table, uint256_t hash, unsigned state)
{
    time_t curr_time = time(NULL);
    unsigned old_state = MISSING;
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hash);
    if (entry != NULL && entry->state < state)
    {
        old_state = entry->state;
        entry->state = state;
        entry->time = curr_time;
    }
    mutex_unlock(&table->lock);
    return old_state;
}

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

static void set_time(struct table *table, uint256_t hsh, time_t time)
{
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hsh);
    if (entry != NULL)
        entry->time = time;
    mutex_unlock(&table->lock);
}

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

static uint64_t get_vote_mask(struct table *table, uint256_t hash)
{
    mutex_lock(&table->lock);
    struct entry *entry = get_entry(table, hash);
    uint64_t vote = (entry != NULL? entry->vote: 0);
    mutex_unlock(&table->lock);
    return vote;
}

#define get_vote(table, hsh)    popcount(get_vote_mask((table), (hsh)))

static void set_delay(struct table *table, uint256_t hsh, size_t idx)
{
    struct delay *d = (struct delay *)mem_alloc(sizeof(struct delay));
    d->index = idx;
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

static bool delete(struct table *table, uint256_t hash)
{
    return deref_data(table, hash);
}

// Stop-the-world and clean-up all "stale" objects.  This is done everytime a
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

static mutex queue_lock;
static size_t queue_head = 0;
static size_t queue_tail = 0;

// Queue a new address to be used later as a peer.
static void queue_push_address(struct table *table, struct in6_addr addr)
{
    size_t idx;
    mutex_lock(&queue_lock);
    idx = queue_tail;
    queue_tail++;
    mutex_unlock(&queue_lock);

    struct in6_addr *addr1 = (struct in6_addr *)mem_alloc(sizeof(addr));
    *addr1 = addr;
    uint256_t q_hsh = queue_hash(idx);
    insert(table, q_hsh, QUEUE, 1);
    if (!set_data(table, q_hsh, addr1, sizeof(addr)))
        mem_free(addr1);
}

// Get a queued address.
static struct in6_addr queue_pop_address(struct table *table)
{
    ssize_t idx = 0;
    mutex_lock(&queue_lock);
    if (queue_head < queue_tail)
    {
        idx = queue_head;
        queue_head++;
    }
    mutex_unlock(&queue_lock);

    uint256_t q_hsh = queue_hash(idx);
    struct in6_addr *addr = (struct in6_addr *)get_data(table, q_hsh, NULL);
    struct in6_addr res;
    if (addr == NULL)
    {
        memset(&res, 0, sizeof(res));
        return res;
    }
    res = *addr;
    deref_data(table, q_hsh);
    delete(table, q_hsh);
    return res;
}

// Get a collection of addresses to service a getaddr message.
static size_t queue_get_addresses(struct table *table, struct buf *buf,
    size_t maxlen)
{
    mutex_lock(&queue_lock);
    size_t start = queue_head, end = queue_tail;
    mutex_unlock(&queue_lock);

    time_t curr_time = time(NULL);
    size_t num_addr = 0;
    for (; start < end && num_addr < maxlen; start++)
    {
        uint256_t q_hsh = queue_hash(start);
        struct in6_addr *addr = (struct in6_addr *)get_data(table, q_hsh,
            NULL);
        if (addr != NULL)
        {
            struct in6_addr a = *addr;
            deref_data(table, q_hsh);
            uint256_t a_hsh = addr_hash(a);
            time_t time = get_time(table, a_hsh);
            if (time == 0 || abs(time - curr_time) > 10800)
                continue;
            push(buf, time);
            uint64_t services = NODE_NETWORK;
            push(buf, services);
            push(buf, a);
            uint16_t port = PORT;
            push(buf, port);
            num_addr++;
        }
    }
    return num_addr;
}

static bool queue_need_addresses(void)
{
    mutex_lock(&queue_lock);
    bool r = ((queue_tail - queue_head) < 100);
    mutex_unlock(&queue_lock);
    return r;
}

/****************************************************************************/
// Peer storage.  Peers 0..maxpeers-1 are for outbound connections.

static mutex peer_lock;
static size_t num_peers = 0;

static void add_peer(struct table *table, size_t idx)
{
    uint256_t peer_hsh = peer_hash(idx);
    insert(table, peer_hsh, PEER, 1);
}

static void set_peer(struct table *table, size_t idx, struct peer *peer)
{
    struct peer **wrap = (struct peer **)mem_alloc(sizeof(struct peer *));
    *wrap = peer;
    uint256_t peer_hsh = peer_hash(idx);
    if (!set_data(table, peer_hsh, wrap, sizeof(struct peer *)))
        mem_free(wrap);
}

static struct peer *get_peer(struct table *table, size_t idx)
{
    uint256_t peer_hsh = peer_hash(idx);
    struct peer **wrap = (struct peer **)get_data(table, peer_hsh, NULL);
    if (wrap == NULL)
        return NULL;
    struct peer *peer = *wrap;
    ref(&peer->ref_count);
    deref_data(table, peer_hsh);
    return peer;
}

static bool have_peer(struct table *table, size_t idx)
{
    uint256_t peer_hsh = peer_hash(idx);
    return (get_vote(table, peer_hsh) != 0);
}

static void del_peer(struct table *table, size_t idx)
{
    uint256_t peer_hsh = peer_hash(idx);
    delete(table, peer_hsh);
}

static size_t get_num_peers(void)
{
    mutex_lock(&peer_lock);
    num_peers = (num_peers < MAX_OUTBOUND_PEERS? MAX_OUTBOUND_PEERS:
        num_peers);
    size_t r = num_peers;
    mutex_unlock(&peer_lock);
    return r;
}

static ssize_t get_free_idx(struct table *table, bool inbound)
{
    size_t start = (inbound? MAX_OUTBOUND_PEERS: 0);
    size_t end = (inbound? get_num_peers(): MAX_OUTBOUND_PEERS);
    for (size_t i = start; i < end; i++)
    {
        if (!have_peer(table, i))
            return i;
    }
    if (!inbound)
        return -1;
    mutex_lock(&peer_lock);
    size_t idx = num_peers;
    num_peers++;
    mutex_unlock(&peer_lock);
    return idx;
}

/****************************************************************************/
// Make messages:

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

static void make_addr(struct buf *buf, size_t len, struct buf *data)
{
    struct header hdr = {MAGIC, "addr", 0, 0};
    push(buf, hdr);
    push_varint(buf, len);
    push_buf(buf, data);
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
// Sending & receiving messages:

// Finalize a message (set length & calculate checksums).
static void finalize_message(struct buf *buf)
{
    assert(buf->ptr >= sizeof(struct header) && buf->ptr <= UINT32_MAX);
    struct header *hdr = (struct header *)buf->data;
    void *payload = (void *)(hdr + 1);
    uint32_t payload_len = buf->ptr - sizeof(struct header);
    hdr->length = payload_len;
    uint256_t checksum = hash(payload, payload_len);
    hdr->checksum = checksum.i32[0];
}

// Send message handler:
static void *send_message_worker(void *arg)
{
    struct peer *peer = (struct peer *)arg;

    while (true)
    {
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

// Send a message:
static void send_message(struct peer *peer, struct buf *buf)
{
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
    const time_t TIMEOUT = 300;     // 5mins
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
        peer->alive = curr_time;
        i += r;
    }
    return true;
}

// Read a message:
static bool read_message(struct peer *peer)
{
    struct buf *buf = peer->buf;
    reset_buf(buf);

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
    push(buf, hdr);
    if (hdr.length == 0)
    {
        uint256_t checksum = hash(NULL, 0);
        if (checksum.i32[0] != hdr.checksum)
        {
            warning("[%s] bad message (checksum failed)", peer->name);
            return false;
        }
        buf->len = buf->ptr;
        buf->ptr = 0;
        return true;
    }

    size_t len = hdr.length;
    grow_buf(buf, len);
    if (!read_message_data(peer, buf->data + buf->ptr, len))
        return false;

    uint256_t checksum = hash(buf->data + buf->ptr, len);
    if (checksum.i32[0] != hdr.checksum)
    {
        warning("[%s] bad message (checksum failed)", peer->name);
        return false;
    }

    buf->len = buf->ptr+len;
    buf->ptr = 0;
    return true;
}

static void relay_message(struct table *table, struct peer *peer,
    struct buf *buf)
{
    size_t num_peers = get_num_peers();
    for (size_t i = 0; i < num_peers; i++)
    {
        struct peer *p = get_peer(table, i);
        if (p != NULL && p != peer)
            send_message(p, buf);
        deref_peer(p);
    }
}

static void relay_transaction(struct table *table, struct peer *peer,
    uint256_t tx_hsh)
{
    action("relay", HASH_FORMAT " (tx)", HASH(tx_hsh));
    struct buf *out = alloc_buf(NULL);
    make_inv(out, MSG_TX, tx_hsh);
    relay_message(table, peer, out);
    deref_buf(out);
}

static void relay_block(struct table *table, struct peer *peer,
    uint256_t blk_hsh)
{
    action("relay", HASH_FORMAT " (blk)", HASH(blk_hsh));
    struct buf *out = alloc_buf(NULL);
    make_inv(out, MSG_BLOCK, blk_hsh);
    relay_message(table, peer, out);
    deref_buf(out);
}

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

static struct peer *find(struct table *table, struct peer *peer,
    bool any, uint256_t hsh)
{
    // Find a suitable peer:
    uint64_t mask = (any? UINT64_MAX: get_vote_mask(table, hsh));
    size_t offset = rand64();
    struct peer *p = NULL;
    for (size_t i = 0; (p == NULL) && i < MAX_OUTBOUND_PEERS; i++)
    {
        size_t idx = (i + offset) % MAX_OUTBOUND_PEERS;
        if (((1 << idx) & mask) == 0)
            continue;
        p = get_peer(table, idx);
        if (p == peer)
        {
            deref_peer(p);
            p = NULL;
        }
        else if (p != NULL)
            break;
    }
    return p;
}

static void fetch(struct table *table, struct peer *peer,
    bool any, uint32_t type, uint256_t hsh)
{
    struct peer *p = find(table, peer, any, hsh);
    if (p == NULL)
    {
        warning("[%s] failed to fetch " HASH_FORMAT_SHORT "; no suitable peer",
            peer->name, HASH_SHORT(hsh));
        return;
    }
    struct buf *out = alloc_buf(NULL);
    make_getdata(out, type, hsh);
    send_message(p, out);
    deref_buf(out);
    deref_peer(p);
}

static void wake(struct table *table, uint256_t hsh, struct buf *out,
    const char *type)
{
    struct delay *delays = get_delays(table, hsh);
    while (delays != NULL)
    {
        struct delay *d = delays;
        struct peer *p = get_peer(table, d->index);
        if (p != NULL)
        {
            action("send", HASH_FORMAT_SHORT " (%s) to [%s]", HASH_SHORT(hsh),
                type, p->name);
            send_message(p, out);
        }
        deref_peer(p);
        delays = delays->next;
        mem_free(d);
    }
}

static bool insert_address(struct table *table, struct in6_addr addr,
    time_t time)
{
    uint256_t addr_hsh = addr_hash(addr);
    if (get_vote(table, addr_hsh) != 0)
        return false;
    insert(table, addr_hsh, ADDRESS, 1);
    set_time(table, addr_hsh, time);
    queue_push_address(table, addr);
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    action("found", "address [%s]", name);
    return true;
}

static bool have_address(struct table *table, struct in6_addr addr)
{
    uint256_t addr_hsh = addr_hash(addr);
    return (get_vote(table, addr_hsh) != 0);
}

/*****************************************************************************/
// Handle messages:

static bool handle_addr(struct peer *peer, struct table *table, size_t len)
{
    struct buf *in = peer->buf;
    time_t curr_time = time(NULL);
    size_t num_addr = pop_varint(in);
    const size_t MAX_ADDRESSES = 1000;
    if (num_addr > MAX_ADDRESSES)
        return true;
    for (size_t i = 0; i < num_addr; i++)
    {
        time_t time = pop(in, uint32_t);
        uint64_t services = pop(in, uint64_t);
        struct in6_addr addr = pop(in, struct in6_addr);
        uint16_t port = pop(in, uint16_t);
        if ((services & NODE_NETWORK) == 0)
            continue;
        if (port != PORT)
            continue;
        if (time < curr_time && curr_time - time >= 10800)  // 3 hours
            continue;
        if (time > curr_time + 600)                         // 10 mins
            continue;
        if (insert_address(table, addr, curr_time) && num_addr == 1)
            relay_address(table, peer, curr_time, addr);
    }
    return true;
}

static bool handle_inv(struct peer *peer, struct table *table, size_t len)
{
    struct buf *in = peer->buf;
    size_t num_ent = pop_varint(in);
    if (!peer->outbound)    // Inbound peers are not trusted. 
        return true;
    for (size_t i = 0; i < num_ent; i++)
    {
        uint32_t type = pop(in, uint32_t);
        uint256_t hsh = pop(in, uint256_t);

        switch (type)
        {
            case MSG_TX:
            {
                size_t count = insert(table, hsh, TX, peer->index);
                if (count != THRESHOLD)
                    continue;
                relay_transaction(table, peer, hsh);
                break;
            }
            case MSG_BLOCK:
            {
                size_t count = insert(table, hsh, BLOCK, peer->index);
                if (count != THRESHOLD)
                    continue;
                log("----------------------------------NEW BLOCK"
                    "-----------------------------------");
                uint32_t h = get_height();
                set_height(h+1);
                garbage_collect(table);
                relay_block(table, peer, hsh);
                break;
            }
            default:
                // NYI:
                continue;
        }

        if (PREFETCH)
        {
            unsigned state = set_state(table, hsh, FETCHING);
            if (state != OBSERVED)
                continue;
            fetch(table, peer, false, type, hsh);
        }
    }
    return true;
}

static bool handle_notfound(struct peer *peer, struct table *table)
{
    if (!peer->outbound)
        return true;
    struct buf *in = peer->buf;
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
            struct peer *p = get_peer(table, d->index);
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

static bool handle_tx(struct peer *peer, struct table *table, size_t len)
{
    struct buf *in = peer->buf;
    char *tx = pop_data(in, len);
    uint256_t tx_hsh = hash(tx, len);

    if (get_vote(table, tx_hsh) == 0)
        return true;

    struct buf *out = alloc_buf(NULL);
    make_tx(out, tx, len);
    wake(table, tx_hsh, out, "tx");
    deref_buf(out);

    // Cache tx
    if (!set_data(table, tx_hsh, tx, len))
        mem_free(tx);
    return true;
}

// Calculate the Merkle root.  This is necessary to verify blocks are correct.
static uint256_t merkle_root(struct buf *in)
{
    size_t len = pop_varint(in);
    struct buf *tx_hshs = alloc_buf(NULL);

    for (size_t i = 0; i < len; i++)
    {
        size_t ptr0 = in->ptr;
        pop(in, uint32_t);                          // version
        if (coin == &paycoin)
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
 
static bool handle_block(struct peer *peer, struct table *table, uint32_t len)
{
    if (len < sizeof(struct block))
    {
        warning("[%s] bad block (too small)", peer->name);
        return false;
    }
    struct buf *in = peer->buf;
    char *block = pop_data(in, len);
    uint256_t blk_hsh = hash(block, sizeof(struct block));
    struct block *header = (struct block *)block;
    in->ptr = sizeof(struct header) + sizeof(struct block);
    uint256_t root = merkle_root(in);
    if (memcmp(&root, &header->merkle_root, sizeof(uint256_t)) != 0)
    {
        mem_free(block);
        warning("[%s] bad block (merkle root does not match)", peer->name);
        return false;
    }

    struct buf *out = alloc_buf(NULL);
    make_block(out, block, len);
    wake(table, blk_hsh, out, "blk");
    deref_buf(out);

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

static bool handle_getaddr(struct peer *peer, struct table *table)
{
    static size_t MAX_ADDRESSES = 1000;
    struct buf *addrs = alloc_buf(NULL);
    size_t num_addr = queue_get_addresses(table, addrs, MAX_ADDRESSES);
    if (num_addr == 0)
    {
        deref_buf(addrs);
        return false;
    }
    struct buf *out = alloc_buf(NULL);
    make_addr(out, num_addr, addrs);
    deref_buf(addrs);
    send_message(peer, out);
    deref_buf(out);
    return true;
}

static bool handle_getdata(struct peer *peer, struct table *table)
{
    struct buf *in = peer->buf;
    size_t len = pop_varint(in);
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
                if (get_vote(table, hsh) < THRESHOLD)
                    goto not_found;
                state = set_state(table, hsh, FETCHING);
                if (state != OBSERVED)
                    goto retry;
                set_delay(table, hsh, peer->index);
                fetch(table, peer, false, type, hsh);
                continue;
            case FETCHING:
                set_delay(table, hsh, peer->index);
                continue;
            case AVAILABLE:
                data = get_data(table, hsh, &data_len);
                if (data != NULL)
                    break;
                goto not_found;
            case MISSING:
                if (type == MSG_BLOCK)
                {
                    // Possible request for old block:
                    insert(table, hsh, BLOCK, 0);
                    state = set_state(table, hsh, FETCHING);
                    if (state != OBSERVED)
                        goto retry;
                    set_delay(table, hsh, peer->index);
                    fetch(table, peer, true, type, hsh);
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

        struct buf *out = alloc_buf(NULL);
        switch (type)
        {
            case MSG_TX:
            {
                make_tx(out, data, data_len);
                send_message(peer, out);
                action("send", HASH_FORMAT_SHORT " (tx) to [%s]",
                    HASH_SHORT(hsh), peer->name);
                break;
            }
            case MSG_BLOCK:
            {
                make_block(out, data, data_len);
                send_message(peer, out);
                action("send", HASH_FORMAT_SHORT " (blk) to [%s]",
                    HASH_SHORT(hsh), peer->name);
                break;
            }
            default:
                // NYI:
                break;
        }
        deref_buf(out);
        deref_data(table, hsh);
    }
    return ok;
}

static bool handle_getheaders(struct peer *peer, struct table *table)
{
    struct buf *in = peer->buf;
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
    insert(table, hsh, HEADERS, peer->index);

    unsigned state = get_state(table, hsh);
    retry:
    switch (state)
    {
        case OBSERVED:
            state = set_state(table, hsh, FETCHING);
            if (state != OBSERVED)
                goto retry;
            set_delay(table, hsh, peer->index);
            break;
        case FETCHING:
            set_delay(table, hsh, peer->index);
            return true;
        default:
            return true;    // Should never happen.
    }

    struct peer *p = find(table, peer, true, hsh);
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

static bool handle_headers(struct peer *peer, struct table *table)
{
    struct buf *in = peer->buf;
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

    struct buf *out = alloc_buf(NULL);
    push_buf(out, in);
    wake(table, req_hsh, out, "hdrs");
    deref_buf(out);
    delete(table, req_hsh);
    return true;
}

static bool handle_version(struct peer *peer, struct table *table, size_t len)
{
    struct buf *in = peer->buf;
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
    if (peer->outbound)
        relay = set_my_addr(addr);
    pop(in, uint16_t);
    pop(in, uint64_t);          // addr_from
    pop(in, struct in6_addr);
    pop(in, uint16_t);
    pop(in, uint64_t);          // Nonce
    char *agent = pop_varstr(in);
    action("connect", "peer [%s] of type \"%s\"", peer->name, agent);
    mem_free(agent);
    int32_t h = pop(in, uint32_t);
    if (peer->outbound)
        set_height(h);
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
    if (relay)
        relay_address(table, peer, time(NULL), addr);
    return true;
}

static bool process_message(struct peer *peer, struct table *table)
{
    struct buf *in = peer->buf;
    struct header hdr = pop(in, struct header);
    size_t len = hdr.length;

    bool ok = true;
    if (strcmp(hdr.command, "version") == 0)
        ok = handle_version(peer, table, len);
    else if (strcmp(hdr.command, "verack") == 0)
        ok = true;
    else if (strcmp(hdr.command, "addr") == 0)
        ok = handle_addr(peer, table, len);
    else if (strcmp(hdr.command, "getaddr") == 0)
        ok = handle_getaddr(peer, table);
    else if (strcmp(hdr.command, "inv") == 0)
        ok = handle_inv(peer, table, len);
    else if (strcmp(hdr.command, "tx") == 0)
        ok = handle_tx(peer, table, len);
    else if (strcmp(hdr.command, "block") == 0)
        ok = handle_block(peer, table, len);
    else if (strcmp(hdr.command, "getdata") == 0)
        ok = handle_getdata(peer, table);
    else if (strcmp(hdr.command, "getheaders") == 0)
        ok = handle_getheaders(peer, table);
    else if (strcmp(hdr.command, "headers") == 0)
        ok = handle_headers(peer, table);
    else if (strcmp(hdr.command, "notfound") == 0)
        ok = handle_notfound(peer, table);
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
        ok = true;      // Safe to ignore.
    else
        warning("[%s] ignoring unknown or NYI command \"%s\"", peer->name,
            hdr.command);

    return ok;
}

/*****************************************************************************/
// MAIN:

static struct peer *open_peer(struct table *table, int s, bool outbound,
    struct in6_addr addr, in_port_t port, size_t idx)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
   
    struct peer *peer = (struct peer *)mem_alloc(sizeof(struct peer));
    peer->buf = alloc_buf(peer);
    peer->head = NULL;
    peer->tail = NULL;
    peer->sock = s;
    mutex_init(&peer->lock);
    event_init(&peer->event);
    peer->outbound = outbound;
    peer->error = false;
    peer->ref_count = 2;        // 2 for both threads
    peer->height = 0;
    peer->alive = time(NULL);
    peer->to_addr = addr;
    peer->to_port = port;
    peer->from_addr = get_my_addr();
    peer->from_port = PORT;
    peer->index = idx;
    peer->name = (char *)mem_alloc(strlen(name)+1);
    strcpy(peer->name, name);
    peer->env = NULL;
    spawn_thread(send_message_worker, (void *)peer);
    set_peer(table, peer->index, peer);
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
    deref_buf(peer->buf);
    mem_free(peer->name);
    mem_free(peer);
}

static void close_peer(struct table *table, struct peer *peer)
{
    del_peer(table, peer->index);
    peer->error = true;
    deref_peer(peer);
}

// Handle an inbound peer.
static void *inbound_worker(void *arg)
{
    assert(arg != NULL);
    struct info *info = (struct info *)arg;
    struct table *table = info->table;
    size_t peer_idx = info->peer_idx;
    int s = info->sock;
    struct in6_addr addr = info->addr;
    mem_free(info);

    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    action("open", "inbound peer [%s] (%u/oo)", name,
        peer_idx+1-MAX_OUTBOUND_PEERS);

    struct peer *peer = open_peer(table, s, false, addr, PORT, peer_idx);
    if (peer == NULL)
    {
        socket_close(s);
        uint256_t addr_hsh = addr_hash(addr);
        delete(table, addr_hsh);
        goto worker_exit;
    }
    jmp_buf env;
    if (setjmp(env))
    {
        warning("[%s] message parse error", peer->name);
        close_peer(table, peer);
        return NULL;
    }
    peer->env = &env;
    if (queue_need_addresses())
    {
        struct buf *out = alloc_buf(NULL);
        make_getaddr(out);
        send_message(peer, out);
        deref_buf(out);
    }
    while (read_message(peer))
    {
        if (!process_message(peer, table))
            break;
    }
    close_peer(table, peer);
    return NULL;

worker_exit:
    del_peer(table, peer_idx);
    return NULL;
}

// Handle an outbound peer.
static void *outbound_worker(void *arg)
{
    assert(arg != NULL);
    struct info *info = (struct info *)arg;
    struct table *table = info->table;
    struct in6_addr addr = info->addr;
    size_t peer_idx = info->peer_idx;
    mem_free(info);

    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    action("open", "outbound peer [%s] (%u/%u)", name, peer_idx+1,
        MAX_OUTBOUND_PEERS);

    sock s = socket_open(false);
    if (s == INVALID_SOCKET)
    {
        warning("[%s] failed to open socket: %s", name, get_error());
        goto worker_exit;
    }
    if (!socket_connect(s, addr))
    {
        warning("[%s] failed to connect to peer: %s", name, get_error());
        socket_close(s);
        goto worker_exit;
    }
    struct peer *peer = open_peer(table, s, true, addr, PORT, peer_idx);
    if (peer == NULL)
    {
        socket_close(s);
        uint256_t addr_hsh = addr_hash(addr);
        delete(table, addr_hsh);
        goto worker_exit;
    }
    jmp_buf env;
    if (setjmp(env))
    {
        warning("[%s] message parse error", peer->name);
        close_peer(table, peer);
        return NULL;
    }
    peer->env = &env;
    struct buf *out = alloc_buf(NULL);
    make_version(out, peer, rand64(), get_height(), true);
    send_message(peer, out);
    deref_buf(out);
    if (queue_need_addresses())
    {
        struct buf *out = alloc_buf(NULL);
        make_getaddr(out);
        send_message(peer, out);
        deref_buf(out);
    }
    while (read_message(peer))
    {
        if (!process_message(peer, table))
            break;
    }
    close_peer(table, peer);
    return NULL;

worker_exit:
    del_peer(table, peer_idx);
    return NULL;
}

// Manage all peers.  Create new connections if necessary.
static void manager(struct table *table)
{
    sock s = socket_open(true);
    if (s == INVALID_SOCKET)
        fatal("failed to create socket: %s", get_error());
    if (!socket_bind(s, PORT))
        fatal("failed to bind socket: %s", get_error());
    if (!socket_listen(s))
        fatal("failed to listen socket: %s", get_error());

    while (true)
    {
        ssize_t idx = get_free_idx(table, false);
        if (idx >= 0)
        {
            struct in6_addr addr = queue_pop_address(table);
            struct in6_addr zero;
            memset(&zero, 0, sizeof(zero));
            if (memcmp(&zero, &addr, sizeof(addr)) != 0)
            {
                add_peer(table, idx);
                struct info *info = (struct info *)mem_alloc(
                    sizeof(struct info));
                memset(info, 0, sizeof(struct info));
                info->table = table;
                info->addr = addr;
                info->peer_idx = idx;
                if (!spawn_thread(outbound_worker, (void *)info))
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
            if (s1 < 0)
            {
                warning("failed to accept inbound connection: %s",
                    get_error());
                continue;
            }
            ssize_t idx = get_free_idx(table, true);
            add_peer(table, idx);
            struct info *info = (struct info *)mem_alloc(
                sizeof(struct info));
            info->table = table;
            info->peer_idx = idx;
            info->sock = s1;
            info->addr = addr;
            if (!spawn_thread(inbound_worker, (void *)info))
            {
                socket_close(s1);
                mem_free(info);
            }
        }
    }
}

// Find addresses via DNS seeds.
static void *bootstrap(void *arg)
{
    struct table *table = (struct table *)arg;
    assert(table != NULL);
    time_t curr_time = time(NULL);

    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    size_t decay = 2;
    for (size_t i = 0; queue_need_addresses(); )
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
            if (have_address(table, addr))
            {
                info = info->ai_next;
                continue;
            }
            i++;
            time_t addr_time = curr_time - rand64() % 3000;
            insert_address(table, addr, addr_time);
            info = info->ai_next;
        }
        freeaddrinfo(res);
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
    peer_salt = rand64();
    queue_salt = rand64();
    headers_salt = rand64();
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
        {"threshold", 1, 0, OPTION_THRESHOLD}
    };
    coin = &bitcoin;
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
                    coin = &bitcoin;
                else if (strcmp(optarg, "testnet") == 0)
                    coin = &testnet;
                else if (strcmp(optarg, "litecoin") == 0)
                    coin = &litecoin;
                else if (strcmp(optarg, "dogecoin") == 0)
                    coin = &dogecoin;
                else if (strcmp(optarg, "paycoin") == 0)
                    coin = &paycoin;
                else if (strcmp(optarg, "flappycoin") == 0)
                    coin = &flappycoin;
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
        USER_AGENT = "/PseudoNode:0.1.0/";
    if (STEALTH)
        USER_AGENT = coin->user_agent;
    if (THRESHOLD < 1 || THRESHOLD > MAX_OUTBOUND_PEERS)
        fatal("threshold must be within the range 1..max_peers");
    height_0 = height_1 = height = HEIGHT - rand64() % (HEIGHT / 5);
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr_0 = myaddr_1 = myaddr;

    spawn_thread(port_map, NULL);
    if (!spawn_thread(bootstrap, (void *)table))
        fatal("failed to spawn bootstrap thread: %s", get_error());
    manager(table);

    return 0;
}

