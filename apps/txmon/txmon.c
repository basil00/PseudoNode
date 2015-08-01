/*
 * Bitcoin TX Monitor
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
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <time.h>

#include "pseudo_node.h"

#include "ripemd160.c"

typedef struct
{
    uint8_t i8[32];
} hash256_t;

static bool option_color = true;

/***************************************************************************/
/* CRUFT:                                                                  */
/***************************************************************************/

#ifdef LINUX

#include <arpa/inet.h>
#include <pthread.h>

#define color_clear()           if (option_color) fputs("\33[0m", stdout)
#define color_value()           if (option_color) fputs("\33[31m", stdout)
#define color_input()           if (option_color) fputs("\33[33m", stdout)
#define color_output()          if (option_color) fputs("\33[32m", stdout)
#define color_hash()            if (option_color) fputs("\33[34m", stdout)
#define color_warning()         if (option_color) fputs("\33[35m", stdout)

typedef pthread_mutex_t mutex;

static inline void mutex_init(mutex *m)
{
    int res = pthread_mutex_init(m, NULL);
    assert(res == 0);
}

static inline void mutex_lock(mutex *m)
{
    int res = pthread_mutex_lock(m);
    assert(res == 0);
}

static inline void mutex_unlock(mutex *m)
{
    int res = pthread_mutex_unlock(m);
    assert(res == 0);
}

#endif      /* LINUX */

#ifdef WINDOWS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define STDERR              GetStdHandle(STD_ERROR_HANDLE)
#define color_clear(_)      SetConsoleTextAttribute(STDERR, FOREGROUND_RED | \
                                FOREGROUND_GREEN | FOREGROUND_BLUE)
#define color_value(_)      SetConsoleTextAttribute(STDERR, FOREGROUND_RED)
#define color_input(_)      SetConsoleTextAttribute(STDERR, FOREGROUND_RED | \
    FOREGROUND_GREEN)
#define color_output(_)     SetConsoleTextAttribute(STDERR, FOREGROUND_GREEN)
#define color_hash(_)       SetConsoleTextAttribute(STDERR, FOREGROUND_BLUE)
#define color_warning(_)    SetConsoleTextAttribute(STDERR, FOREGROUND_RED | \
                                FOREGROUND_BLUE)

extern const char *inet_ntop(int af, const void *src, char *dst,
    socklen_t size);

typedef HANDLE mutex;

static inline void mutex_init(mutex *m)
{
    *m = CreateMutex(NULL, FALSE, NULL);
    assert(*m != NULL);
}

static inline void mutex_lock(mutex *m)
{
    DWORD res = WaitForSingleObject(*m, INFINITE);
    assert(res == WAIT_OBJECT_0);
}

static inline void mutex_unlock(mutex *m)
{
    BOOL res = ReleaseMutex(*m);
    assert(res);
}

#endif      /* WINDOWS */

// Print mutex
static mutex lock;

/****************************************************************************/
/* RATES                                                                    */
/****************************************************************************/

struct rate_info
{
    time_t time;
    uint64_t value;
    size_t size;
    struct rate_info *next;
};

static bool rate_init = false;
static time_t rate_time0 = 0;
static struct rate_info *rates;

#define MIN(a, b)       ((a) > (b)? (b): (a))

static void get_rate_info(time_t t, uint64_t v, size_t s, double *vps,
    double *sps, double *txps)
{
    if (!rate_init)
    {
        rate_time0 = t;
        rate_init = true;
    }

    struct rate_info *info =
        (struct rate_info *)malloc(sizeof(struct rate_info));
    assert(info != NULL);
    info->time = t;
    info->value = v;
    info->size = s;
    info->next = rates;
    rates = info;

    uint64_t total_v = 0;
    size_t total_tx = 0, total_s = 0;
    struct rate_info *prev = NULL;
    for (info = rates; info != NULL; info = info->next)
    {
        if (info->time + 60 < t)
        {
            // Old data:
            if (prev == NULL)
                rates = NULL;
            else
                prev->next = NULL;
            while (info != NULL)
            {
                prev = info;
                info = info->next;
                free(prev);
            }
            break;
        }
        total_v += info->value;
        total_tx++;
        total_s += info->size;
        prev = info;
    }
    double span = MIN(60.0, (double)(t - rate_time0));
    span = (span == 0.0? 0.5: span);
    *vps = (total_v / span);
    *sps = (total_s / span);
    *txps = (total_tx / span);
}

/****************************************************************************/
/* STATS                                                                    */
/****************************************************************************/

static size_t num_tx = 0;
static size_t num_blocks = 0;
static size_t num_tx_bytes = 0;
static uint64_t total_val = 0;
static bool option_verbose = false;
static bool prev_msg = false;

/****************************************************************************/
/* TX PARSING                                                               */
/****************************************************************************/

// Data buffer.
struct buf
{
    const uint8_t *data;
    size_t ptr;
    size_t len;
    jmp_buf *env;
};

// Pop data of `type' from the buffer.
#define pop(buf, type)                                                      \
    (((buf)->ptr + sizeof(type) <= (buf)->len? 0:                           \
        longjmp(*(buf)->env, 1)),                                           \
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

#define MAX_INPUTS          2500
#define MAX_OUTPUTS         12000

#define OP_PUSHDATA1        76
#define OP_PUSHDATA2        77
#define OP_DUP              118
#define OP_HASH160          169
#define OP_EQUAL            135
#define OP_EQUALVERIFY      136
#define OP_CHECKSIG         172
#define OP_RETURN           106

// Parse a transaction.
static bool parse_tx(struct buf *buf, uint8_t **ins, size_t *inlens,
    size_t *num_ins, uint8_t **outs, size_t *outlens, uint64_t *outvals,
    size_t *num_outs)
{
    pop(buf, uint32_t);                     // Version.
    size_t num_inputs = pop_varint(buf);    // #inputs.
    if (num_ins != NULL)
        *num_ins = num_inputs;
    if (num_inputs == 0 || num_inputs >= MAX_INPUTS)
        return false;
    for (size_t i = 0; i < num_inputs; i++)
    {
        pop(buf, hash256_t);                // UTXO hash.
        pop(buf, uint32_t);                 // UTXO index.
        size_t slen = pop_varint(buf);      // scriptSig length.
        if (ins != NULL)
            ins[i] = buf->data + buf->ptr;
        if (inlens != NULL)
            inlens[i] = slen;
        for (size_t j = 0; j < slen; j++)
            pop(buf, uint8_t);
        pop(buf, uint32_t);                 // Sequence.
    }

    size_t num_outputs = pop_varint(buf);   // #outputs.
    if (num_outs != NULL)
        *num_outs = num_outputs;
    if (num_outputs == 0 || num_outputs >= MAX_OUTPUTS)
        return false;
    for (size_t i = 0; i < num_outputs; i++)
    {
        uint64_t val = pop(buf, uint64_t);  // Value.
        if (outvals != NULL)
            outvals[i] = val;
        size_t slen = pop_varint(buf);      // scriptPubKey length.
        if (outs != NULL)
            outs[i] = buf->data + buf->ptr;
        if (outlens != NULL)
            outlens[i] = slen;
        for (size_t j = 0; j < slen; j++)
            pop(buf, uint8_t);
    }

    pop(buf, uint32_t);                     // nLockTime.
    return true;
}

// Test if a scriptSig is a P2PKH input:
static bool script_is_p2pkh_input(uint8_t *script, size_t slen,
    uint8_t *pub_key)
{
    if (slen == 0)
        return false;
    size_t i = 0;
    if (script[i] < 0x09 || script[i] > 73)
        return false;
    i += script[i] + 1;
    if (i >= slen)
        return false;
    size_t len = script[i];
    if (len != 33 && len != 65)
        return false;
    i++;
    if (i + len != slen)
        return false;
    for (size_t j = 0; j < len; j++)
        pub_key[j] = script[i + j];
    return true;
}

// Test if a scriptSig is a P2SH input:
static bool script_is_p2sh_input(uint8_t *script, size_t slen,
    uint8_t *redeem, size_t *rlen)
{
    ssize_t found = -1, len = 0; 
    for (size_t i = 0; i < slen; )
    {
        uint8_t op = script[i];
        if (op < 76)
        {
            i++;
            len = op;
        }
        else if (op == OP_PUSHDATA1)
        {
            i++;
            if (i >= slen)
                return false;
            len = script[i];
            i++;
        }
        else if (op == OP_PUSHDATA2)
        {
            i++;
            if (i + 1 >= slen)
                return false;
            len = *(uint16_t *)(script + i);
            i += 2;
        }
        else
            return false;
        if (i + len > slen)
            return false;
        if (i + len == slen)
        {
            found = i;
            break;
        }
        i += len;
    }
    if (found < 0)
        return false;
    if (len > 520)
        return false;
    for (size_t i = 0; i < len; i++)
        redeem[i] = script[found+i];
    *rlen = (size_t)len;
    return true;
}

// Test if a scriptPubKey is a P2PKH output:
static bool script_is_p2pkh_output(uint8_t *script, size_t slen,
    uint8_t *pub_key_hash)
{
    if (slen != 25)
        return false;
    if (script[0] != OP_DUP || script[1] != OP_HASH160 || script[2] != 0x14 ||
            script[23] != OP_EQUALVERIFY || script[24] != OP_CHECKSIG)
        return false;
    for (int i = 0; i < 20; i++)
        pub_key_hash[i] = script[i + 3];
    return true;
}

// Test if a scriptPubKey is a P2SH output:
static bool script_is_p2sh_output(uint8_t *script, size_t slen,
    uint8_t *script_hash)
{
    if (slen != 23)
        return false;
    if (script[0] != OP_HASH160 || script[1] != 0x14 || script[22] != OP_EQUAL)
        return false;
    for (int i = 0; i < 20; i++)
        script_hash[i] = script[i + 2];
    return true;
}

// Test if a scriptPubKey is data:
static bool script_is_data_output(uint8_t *script, size_t slen,
    uint8_t *data, size_t *dlen)
{
    if (slen == 0)
        return false;
    if (script[0] != OP_RETURN)
        return false;
    if (slen == 1)
        goto strange;
    uint8_t op = script[1];
    if (op > 0 && op < 76)
    {
        if (1 + op + 1 != slen)
            goto strange;
        for (size_t i = 0; i < op; i++)
            data[i] = script[1 + 1 + i];
        *dlen = op;
        return true;
    }

strange:
    *dlen = 0;
    return true;
}

/***************************************************************************/
/* OUTPUT                                                                  */
/***************************************************************************/

/*
 * Base58 encode
 */
static const char* base58str =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static bool base58_encode(char *str, size_t slen, const uint8_t *data,
    size_t dlen)
{
    size_t i = 0;
    for (; i < dlen && data[i] == 0x0; i++)
        ;
    size_t zeroes = i;      // Retained zeroes.
    char b58[(dlen - i) * 138 / 100 + 1];
    memset(b58, 0, sizeof(b58));
    for (; i < dlen; i++)
    {
        int carry = (int)data[i];
        for (ssize_t j = sizeof(b58)-1; j >= 0; j--)
        {
            carry += 256 * b58[j];
            b58[j] = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
    }
    for (i = 0; i < sizeof(b58) && b58[i] == 0; i++)
        ;
    size_t zeroes2 = i;     // Dropped zeroes.
    if (zeroes + sizeof(b58) - zeroes2 + 1 > slen)
        return false;
    memset(str, '1', zeroes);
    size_t j;
    for (j = zeroes; i < sizeof(b58); i++, j++)
        str[j] = base58str[b58[i]];
    str[j] = '\0';
    return true;
}

/*
 * Base58check encode.
 */
static bool base58check_encode(char *str, size_t slen, const uint8_t *data,
    size_t dlen)
{
    uint8_t res[32];
    PN_sha256d(data, dlen, res);
    uint8_t tmp[dlen + 4];
    memcpy(tmp, data, dlen);
    tmp[dlen+0] = res[0];
    tmp[dlen+1] = res[1];
    tmp[dlen+2] = res[2];
    tmp[dlen+3] = res[3];
    return base58_encode(str, slen, tmp, sizeof(tmp));
}

/*
 * Create an output address.
 */
static void make_output_addr(uint8_t *hsh160, uint8_t prefix, char *addr)
{
    char tmp[1 + 20];
    tmp[0] = prefix;
    memcpy(tmp+1, hsh160, 20);
    base58check_encode(addr, 35, tmp, sizeof(tmp));
}

/*
 * Create an input address.
 */
static void make_input_addr(uint8_t *object, size_t olen, uint8_t prefix,
    char *addr)
{
    uint8_t hsh256[32];
    PN_sha256(object, olen, hsh256);
    uint8_t hsh160[20];
    ripemd160(hsh256, sizeof(hsh256), hsh160);
    make_output_addr(hsh160, prefix, addr);
}

#define MAX(a, b)       ((a) < (b)? (b): (a))
#define GET_BTC(x)      ((double)(x) * 0.00000001)

/*
 * Print a transaction.
 */
static void print_tx(struct PN *node, const uint8_t *tx, size_t len)
{
    uint8_t *ins[MAX_INPUTS];
    size_t inlens[MAX_INPUTS];
    uint8_t *outs[MAX_OUTPUTS];
    size_t outlens[MAX_OUTPUTS];
    uint64_t outvals[MAX_OUTPUTS];

    jmp_buf env;
    struct buf buf0 = {tx, 0, len, &env};
    struct buf *buf = &buf0;
    if (setjmp(env))
    {
parse_error:
        fprintf(stderr, "error: unable to parse transaction\n");
        return;
    }

    size_t num_ins, num_outs;
    if (!parse_tx(buf, ins, inlens, &num_ins, outs, outlens, outvals,
            &num_outs))
        goto parse_error;

    // Formatting constraints:
    size_t lines = MAX(num_ins, num_outs);
    size_t in_d = lines - num_ins;
    size_t out_d = lines - num_outs;
    size_t in_s = 0 + in_d / 2;
    size_t in_e = lines - (in_d + 1) / 2;
    size_t out_s = 0 + out_d / 2;
    size_t out_e = lines - (out_d + 1) / 2;
    size_t mid = (in_s + in_e) / 2;

    time_t t = time(NULL);

    mutex_lock(&lock);

    putchar('\n');
    num_tx++;
    num_tx_bytes += len;
    for (size_t i = 0; i < lines; i++)
    {
        if (i >= in_s && i < in_e)
        {
            size_t idx = i - in_s;
            uint8_t pub_key[65];
            uint8_t script[520];
            size_t script_len;
            char addr[35];
            addr[0] = '\0';
            if (script_is_p2pkh_input(ins[idx], inlens[idx], pub_key))
            {
                size_t pub_key_len = (pub_key[0] == 0x04? 65: 33);
                make_input_addr(pub_key, pub_key_len, 0x00, addr);
            }
            else if (script_is_p2sh_input(ins[idx], inlens[idx], script,
                    &script_len))
                make_input_addr(script, script_len, 0x05, addr);
            
            if (addr[0] != '\0')
            {
                color_input();
                printf("%s", addr);
                color_clear();
                size_t len = strlen(addr);
                for (size_t j = 0; j < 34 - len; j++)
                    putchar(' ');
            }
            else
                printf("[UNKNOWN]                         ");
        }
        else
        {
            for (size_t i = 0; i < 34; i++)
                putchar(' ');
        }
        putchar(' ');

        if (i >= out_s && i < out_e)
        {
            size_t idx = i - out_s;
            uint8_t hash160[20];
            char addr[35];
            uint8_t data[80];
            size_t dlen;
            bool is_data = false;
            addr[0] = '\0';
            if (script_is_p2pkh_output(outs[idx], outlens[idx], hash160))
                make_output_addr(hash160, 0x00, addr);
            else if (script_is_p2sh_output(outs[idx], outlens[idx], hash160))
                make_output_addr(hash160, 0x05, addr);
            else if (script_is_data_output(outs[idx], outlens[idx], data,
                    &dlen))
                is_data = true;
            
            if (addr[0] != '\0')
            {
                color_output();
                printf("%s", addr);
                color_clear();
                size_t len = strlen(addr);
                for (size_t j = 0; j < 34 - len; j++)
                    putchar(' ');
            }
            else if (is_data)
            {
                color_output();
                printf("[DATA] \"");
                size_t space = 26, j;
                for (j = 0; j < dlen && j < 22; j++)
                {
                    if (isprint(data[j]))
                        putchar(data[j]);
                    else
                        putchar('?');
                    space--;
                }
                if (j < dlen)
                {
                    printf("...");
                    space -= 3;
                }
                putchar('\"');
                space--;
                for (j = 0; j < space; j++)
                    putchar(' ');
                color_clear();
            }
            else
                printf("[UNKNOWN]                         ");
            
            // The following is complicated way to ensure the number fits:
            color_value(); 
            double val = GET_BTC(outvals[idx]);
            double btc_val = (double)(unsigned)(val);
            char buf[32];
            size_t len = snprintf(buf, sizeof(buf)-1, "%u", (unsigned)btc_val);
            if (len > 8)
            {
                printf("UNKNOWN\n");
                color_clear();
                continue;
            }
            printf(" %s", buf);
            double mant = val - btc_val;
            if (mant == 0.0)
            {
                color_clear();
                putchar('\n');
                continue;
            }
            size_t prec = 8 - len;
            switch (prec)
            {
                case 1:
                    len = snprintf(buf, sizeof(buf)-1, "%.1f", mant);
                    break;
                case 2:
                    len = snprintf(buf, sizeof(buf)-1, "%.2f", mant);
                    break;
                case 3:
                    len = snprintf(buf, sizeof(buf)-1, "%.3f", mant);
                    break;
                case 4:
                    len = snprintf(buf, sizeof(buf)-1, "%.4f", mant);
                    break;
                case 5:
                    len = snprintf(buf, sizeof(buf)-1, "%.5f", mant);
                    break;
                case 6:
                    len = snprintf(buf, sizeof(buf)-1, "%.6f", mant);
                    break;
                case 7:
                    len = snprintf(buf, sizeof(buf)-1, "%.7f", mant);
                    break;
                case 8:
                    len = snprintf(buf, sizeof(buf)-1, "%.8f", mant);
                    break;
                default:
                    buf[1] = '\0';
                    len = 0;
                    break;
            }
            while (len >= 2 && buf[len-1] == '0')
            {
                buf[len-1] = '\0';
                len--;
            }
            printf("%s", buf+1);
            color_clear();
        }
        putchar('\n');
    }
    if (option_verbose)
    {
        printf("NODE  : height=%u in=%u out=%u sent=%.2gMB recv=%.2gMB\n",
            PN_get_info(node, PN_HEIGHT),
            PN_get_info(node, PN_NUM_IN_PEERS),
            PN_get_info(node, PN_NUM_OUT_PEERS),
            (double)PN_get_info(node, PN_NUM_SEND_BYTES) / 1000000.0,
            (double)PN_get_info(node, PN_NUM_RECV_BYTES) / 1000000.0);
        printf("TX    : hash=");
        hash256_t hash;
        PN_sha256d(tx, len, &hash);
        for (size_t i = 0; i < sizeof(hash); i++)
            printf("%.2x", hash.i8[32 - i - 1]);
        uint64_t tx_val = 0;
        for (size_t i = 0; i < num_outs; i++)
            tx_val += outvals[i];
        total_val += tx_val;
        printf("\n        size=%uB inputs=%u outputs=%u val=%gBTC\n",
            (unsigned)len, (unsigned)num_ins, (unsigned)num_outs,
            GET_BTC(tx_val));
        printf("TOTALS: #tx=%u #block=%u size=%uB val=%gBTC\n",
            (unsigned)num_tx, (unsigned)num_blocks, (unsigned)num_tx_bytes,
            GET_BTC(total_val));
        double vps, sps, txps;
        get_rate_info(t, tx_val, len, &vps, &sps, &txps);
        printf("RATES : tx/s=%.3g bytes/s=%g BTC/s=%g\n",
            txps, sps, GET_BTC(vps));
    }
    prev_msg = false;
    mutex_unlock(&lock);
}

#define MAX_BLOCK_TXS       50000

/*
 * Print a block.
 */
static void print_block(struct PN *node, const uint8_t *block, size_t len)
{
    const size_t hdrlen = 80;
    jmp_buf env;
    struct buf buf0 = {block + hdrlen, 0, len - hdrlen, &env};
    struct buf *buf = &buf0;
    if (len <= hdrlen || setjmp(env))
    {
parse_error:
        fprintf(stderr, "error: unable to parse block\n");
        return;
    }

    size_t num_tx = pop_varint(buf);
    if (num_tx >= MAX_BLOCK_TXS)
        goto parse_error;

    hash256_t hashes[num_tx];
    for (size_t i = 0; i < num_tx; i++)
    {
        size_t start = buf->ptr;
        if (!parse_tx(buf, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
            goto parse_error;
        size_t end = buf->ptr;
        PN_sha256d(buf->data + start, end - start, hashes + i);
    }

    mutex_lock(&lock);
    num_blocks++;
    putchar('\n');
    printf("     "
        "+----------------------------------------------------------------+\n");
    for (size_t i = 0; i < num_tx; i++)
    {
        printf("     |");
        color_hash();
        for (size_t j = 0; j < 32; j++)
            printf("%.2x", hashes[i].i8[32 - j - 1]);
        color_clear();
        printf("|\n");
    }
    printf("     "
        "+----------------------------------------------------------------+\n");
    if (option_verbose)
    {
        printf("NODE  : height=%u in=%u out=%u sent=%.2gMB recv=%.2gMB\n",
            PN_get_info(node, PN_HEIGHT),
            PN_get_info(node, PN_NUM_IN_PEERS),
            PN_get_info(node, PN_NUM_OUT_PEERS),
            (double)PN_get_info(node, PN_NUM_SEND_BYTES) / 1000000.0,
            (double)PN_get_info(node, PN_NUM_RECV_BYTES) / 1000000.0);
        printf("BLOCK : hash=");
        hash256_t hash;
        PN_sha256d(block, 80, &hash);
        for (size_t i = 0; i < sizeof(hash); i++)
            printf("%.2x", hash.i8[32 - i - 1]);
        printf("\n        size=%uB #tx=%u\n", (unsigned)len, (unsigned)num_tx);
        printf("TOTALS: #tx=%u #block=%u size=%uB val=%gBTC\n",
            (unsigned)num_tx, (unsigned)num_blocks, (unsigned)num_tx_bytes,
            GET_BTC(total_val));
    }
    prev_msg = false;
    mutex_unlock(&lock);
}

/*
 * Print a message.
 */
static void print_msg(struct in6_addr addr, const char *msg)
{
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    mutex_lock(&lock);
    if (!prev_msg)
        putchar('\n');
    color_warning();
    printf("warning");
    color_clear();
    printf(": [%s] %s\n", name, msg);
    prev_msg = true;
    mutex_unlock(&lock);
}

// Transaction callback
static unsigned char *tx_callback(struct PN *node, unsigned type,
    struct in6_addr addr, unsigned char *data, unsigned *len)
{
    print_tx(node, (uint8_t *)data, (size_t)*len);
    return data;
}

// Block callback
static unsigned char *block_callback(struct PN *node, unsigned type,
    struct in6_addr addr, unsigned char *data, unsigned *len)
{
    print_block(node, (uint8_t *)data, (size_t)*len);
    return data;
}

// Message callback
static unsigned char *msg_callback(struct PN *node, unsigned type,
    struct in6_addr addr, unsigned char *data, unsigned *len)
{
    print_msg(addr, (const char *)data);
    return data;
}

#include <getopt.h>
#define OPTION_HELP         1
#define OPTION_STEALTH      2
#define OPTION_VERBOSE      3

// Main:
int main(int argc, char **argv)
{
    mutex_init(&lock);

    static const struct option long_options[] =
    {
        {"help",    0, 0, OPTION_HELP},
        {"stealth", 0, 0, OPTION_STEALTH},
        {"verbose", 0, 0, OPTION_VERBOSE},
        {NULL, 0, 0, 0}
    };
    bool option_stealth = false;
    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_STEALTH:
                option_stealth = true;
                break;
            case OPTION_VERBOSE:
                option_verbose = true;
                break;
            case OPTION_HELP:
            default:
                fprintf(stderr, "usage: %s [--help] [--stealth] "
                    "[--verbose]\n", argv[0]);
                fprintf(stderr, "WHERE:\n");
                fprintf(stderr, "\t--stealth\n");
                fprintf(stderr, "\t\tIdentify as a normal client "
                    "(default=false).\n");
                fprintf(stderr, "\t--verbose\n");
                fprintf(stderr, "\t\tPrint more detailed information "
                    "(default=false).\n");
                return 0;
        }
    }
    if (!isatty(1))
        option_color = false;

    struct PN_callbacks CALLBACKS;
    memset(&CALLBACKS, 0, sizeof(CALLBACKS));
    CALLBACKS.tx    = tx_callback;
    CALLBACKS.block = block_callback;
    if (option_verbose)
        CALLBACKS.warning = msg_callback;

    struct PN_config CONFIG;
    memset(&CONFIG, 0, sizeof(CONFIG));
    if (option_stealth)
        CONFIG.user_agent = "/Satoshi:0.11.0/";
    else
        CONFIG.user_agent = "/TXMON:0.1.0/PseudoNode:0.6.0/";
    CONFIG.prefetch = true;

    unsigned ret = 0;       // Don't return.
    struct PN *node = PN_create(NULL, &CALLBACKS, &CONFIG, ret);

    return 0;
}

