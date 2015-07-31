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

#ifndef PSEUDONODE_H
#define PSEUDONODE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TL;DR
 *
 * The call:
 *
 *     struct PN *node = PN_create(NULL, NULL, NULL, 1);
 *
 * creates a basic Bitcoin PseudoNode using all the default settings.  See the
 * documentation below for more advanced usage.
 *
 */

/*
 * A PseudoNode
 */
struct PN;

/****************************************************************************/
/*
 * COIN CONFIGUATION.
 */

// PseudoNode supports multiple cryptocurrencies provided they are
// based on the Bitcoin network protocol.  The PN_coin structure lets you
// specify new currency configurations.  Note that some altcoins (e.g.
// Dogecoin, Peercoin, etc.) have introduced subtle incompatibilities with the
// Bitcoin protocol.

struct PN_coin
{
    const char *name;               // Coin name, e.g. "bitcoin"
    const char **seeds;             // NULL-terminated array of DNS seeds.
    unsigned port;                  // Protocol port.
    unsigned version;               // Protocol version (70002 supported).
    unsigned magic;                 // Protocol magic number.
    unsigned height;                // Block height guess (<= real height).
    unsigned relay;                 // Non-zero if the protocol version
                                    // message should the relay flag.
};

// Pre-defined coins.
extern const struct PN_coin * const BITCOIN;    // Bitcoin (the default).
extern const struct PN_coin * const TESTNET;    // Bitcoin testnet.
extern const struct PN_coin * const LITECOIN;   // Litecoin.

/****************************************************************************/
/*
 * CALLBACK CONFIGURATION.
 */

// Callback function type.
// - node: The PseudoNode instance.
// - type: Callback type (one of the PN_CALLBACK_* values).
// - addr: The address of the peer for which the message concerns.  Otherwise
//   will be an all-zero address.
// - data: The data (e.g. message, tx, block, etc.).  The data may be modified
//   by the callback, left unchanged, or blocked.  The memory will be malloc()
//   allocated.
// - len: The length of `data'.
// - return value: return NULL if the message should be blocked or ignored.
//   Otherwise return the original `data', or a modified `data' using
//   (re)malloc()'ed memory.  If the length has changed then update `len'.  If
//   the data is changed, then the old data should be free()'ed.
typedef unsigned char *(*PN_callback)(struct PN *node, int type,
    struct in6_addr addr, unsigned char *data, unsigned *len);

#define PN_CALLBACK_BLOCK       1
#define PN_CALLBACK_TX          2
#define PN_CALLBACK_INV         3
#define PN_CALLBACK_VERSION     4
#define PN_CALLBACK_RAW         5
#define PN_CALLBACK_LOG         6
#define PN_CALLBACK_WARNING     7

// NOTE: each field may be NULL.
struct PN_callbacks
{
    // HIGH-LEVEL:
    PN_callback block;          // Called for each new BLOCK message.
    PN_callback tx;             // Called for each TX message.
    PN_callback inv;            // Called for each INV message.
                                // The data will be an inventory vector of
                                // length 1.
    PN_callback version;        // Called for each VERSION message.

    // LOW-LEVEL:
    PN_callback raw;            // Called for each inbound raw protocol
                                // message.  Each message contains the message
                                // header.  If modified, it is not necessary
                                // to recalculate the checksum.

    // LOGGING:
    PN_callback log;            // Log message (as a string).
    PN_callback warning;        // Warning message (as a string).
};

/****************************************************************************/
/*
 * NODE CONFIGURATION.
 */

#define NODE_NETWORK            1
#define NODE_GETUTXOS           2       // NOTE: functionality not implemented.
#define NODE_REPLACE_BY_FEE     0x04000000
#define NODE_PSEUDO             0x80000000  // Not enabled by default.

struct PN_config
{
    const char *user_agent;     // The user agent to use (default: PseudoNode).
    unsigned long long services;// Extra services flags beyond NODE_NETWORK
                                // (default: 0).
    unsigned threshold;         // Data validation threshold (default: 2).
    unsigned prefetch;          // Prefetch data? (default: 0).
    unsigned num_peers;         // Number of outbound peers (default: 8).
    unsigned num_addrs;         // Size of the peer address queue
                                // (default: 4096).
    const struct in6_addr *peers;
                                // Optional list of peers to connect to.
                                // Zero-address terminated.
                                // (default: NULL=empty).
};

/*****************************************************************************/
/*
 * PseudoNode API.
 */

/*
 * Create a PseudoNode.
 * - coin: Coin configuration. Pass NULL to default to BITCOIN.
 * - callbacks: Callback configuration.  Pass NULL for no callbacks.
 * - config: Node configuration.  Pass NULL to use the defaults.
 * - ret: Return from this call if non-zero.  Otherwise this function will
 *   assume control over the current thread and never return.
 */
extern struct PN *PN_create(
    const struct PN_coin *_coin,
    const struct PN_callbacks *_callbacks,
    const struct PN_config *_config,
    int _ret
);

/*
 * Broadcast a transaction to the network.  Note that it is up to the caller
 * to ensure that `tx' is valid, as PseudoNode does no validation.
 * Broadcasting an invalid transaction may cause your node to be DoS banned.
 * Returns 0 on success, non-zero otherwise.
 *
 * WARNING: this functionality has never been tested...
 */
extern int PN_broadcast_tx(
    struct PN *_node,
    const unsigned char *_tx,
    unsigned _len);

/*
 * Not-yet-implemented functions:
 */
#if 0
extern int PN_broadcast_block(
    struct PN *_node,
    const unsigned char *_block,
    unsigned len);

void PN_destroy(struct PN *node);
#endif

/*****************************************************************************/
/*
 * PseudoNode helper API.
 */

/*
 * SHA256
 */
extern void PN_sha256(
    const void *_data,
    unsigned _len,
    void *_res);

/*
 * SHA256d
 */
extern void PN_sha256d(
    const void *_data,
    unsigned _len,
    void *_res);

/*
 * Get information (as defined by the constants below).
 */
#define PN_HEIGHT                   1001        // Block height.
#define PN_NUM_IN_PEERS             1002        // # inbound connections.
#define PN_NUM_OUT_PEERS            1003        // # outbound connections.
#define PN_NUM_SEND_BYTES           1004        // # sent bytes.
#define PN_NUM_RECV_BYTES           1005        // # recv bytes.
extern int PN_get_info(
    struct PN *_node,
    int _what);

#ifdef __cplusplus
}
#endif

#endif
