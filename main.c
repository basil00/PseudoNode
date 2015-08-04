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

/*
 * PseudoNode (classic)
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

#ifdef MACOSX
#define LINUX
#endif

#ifdef LINUX
#include <pwd.h>
#include <arpa/inet.h>

#ifdef MACOSX
#define s6_addr16       __u6_addr.__u6_addr16
#endif

#endif      /* LINUX */

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define s6_addr16  u.Word
extern int inet_pton(int af, const char *src, void *dst);
#endif      /* WINDOWS */

#include "pseudo_node.h"

#define OPTION_CLIENT       1
#define OPTION_COIN         2
#define OPTION_HELP         3
#define OPTION_NUM_PEERS    4
#define OPTION_PEER         5
#define OPTION_PREFETCH     6
#define OPTION_SERVER       7
#define OPTION_STEALTH      8
#define OPTION_THRESHOLD    9

static unsigned char *print_log_message(struct PN *node, unsigned type,
    struct in6_addr addr, unsigned char *message, unsigned *len)
{
    if (type == PN_CALLBACK_WARNING)
        printf("warning: ");
    char name[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &addr, name, sizeof(name));
    printf("[%s] %s\n", name, message);
    return message;
}

// main:
int main(int argc, char **argv)
{
    static struct option long_options[] =
    {
        {"client",    1, 0, OPTION_CLIENT},
        {"coin",      1, 0, OPTION_COIN},
        {"help",      0, 0, OPTION_HELP},
        {"num-peers", 1, 0, OPTION_NUM_PEERS},
        {"peer",      1, 0, OPTION_PEER},
        {"prefetch",  0, 0, OPTION_PREFETCH},
        {"server",    0, 0, OPTION_SERVER},
        {"stealth",   0, 0, OPTION_STEALTH},
        {"threshold", 1, 0, OPTION_THRESHOLD},
        {NULL, 0, 0, 0}
    };
    const struct PN_coin *COIN = BITCOIN;
    unsigned MAX_OUTBOUND_PEERS = 8;
    bool SERVER = false;
    bool STEALTH = false;
    bool PREFETCH = false;
    unsigned THRESHOLD = 2;
    const char *USER_AGENT = NULL;
    struct in6_addr peers[32];
    size_t peers_idx = 0;
    memset(peers, 0, sizeof(peers));
    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_CLIENT:
                USER_AGENT = optarg;
                break;
            case OPTION_COIN:
                if (strcmp(optarg, "bitcoin") == 0)
                    COIN = BITCOIN;
                else if (strcmp(optarg, "testnet") == 0)
                    COIN = TESTNET;
                else if (strcmp(optarg, "litecoin") == 0)
                    COIN = LITECOIN;
                else
                {
                    fprintf(stderr, "fatal: unknown coin \"%s\"\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            case OPTION_PEER:
            {
                if (peers_idx >= sizeof(peers) / sizeof(peers[0]) - 1)
                    break;
                struct in6_addr addr;
                if (inet_pton(AF_INET6, optarg, &addr) != 1)
                {
                    uint32_t addr32;
                    if (inet_pton(AF_INET, optarg, &addr32) != 1)
                    {
                        fprintf(stderr, "fatal: failed to parse IP address "
                            "\"%s\"", optarg);
                        return EXIT_FAILURE;
                    }
                    memset(&addr, 0, sizeof(addr));
                    addr.s6_addr16[5] = 0xFFFF;
                    memcpy(addr.s6_addr16+6, &addr32, sizeof(addr32));
                }
                peers[peers_idx++] = addr;
                break;
            }
            case OPTION_NUM_PEERS:
                MAX_OUTBOUND_PEERS = atoi(optarg);
                if (MAX_OUTBOUND_PEERS < 1 || MAX_OUTBOUND_PEERS > 64)
                {
                    fprintf(stderr, "fatal: number-of-peers is out of "
                        "range\n");
                    return EXIT_FAILURE;
                }
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
                    "[--prefetch] [--num-peers=NUM_PEERS] [--coin=COIN]\n\n",
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
                fprintf(stderr, "\t--num-peers=NUM_PEERS\n");
                fprintf(stderr, "\t\tMaximum number of outbound connections "
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
    {
#ifdef LINUX
        daemon(1, 0);
        struct passwd *entry = getpwnam("nobody");
        if (entry == NULL)
        {
            fprintf(stderr, "fatal: failed to change user/group to nobody\n");
            return EXIT_FAILURE;
        }
        setgid(entry->pw_gid);
        setuid(entry->pw_uid);
#endif
    }
    if (STEALTH)
    {
        if (COIN == BITCOIN)
            USER_AGENT = "/Satoshi:0.11.0/";
        else if (COIN == TESTNET)
            USER_AGENT = "/Satoshi:0.11.0/";
        else if (COIN == LITECOIN)
            USER_AGENT = "/Satoshi:0.8.7.5/";
    }
    if (THRESHOLD < 1 || THRESHOLD > MAX_OUTBOUND_PEERS)
    {
        fprintf(stderr, "fatal: threshold must be within the range "
            "1..max_peers\n");
        return EXIT_FAILURE;
    }

#ifdef LINUX
        signal(SIGPIPE, SIG_IGN);
#endif

    struct PN_config CONFIG;
    memset(&CONFIG, 0, sizeof(CONFIG));
    CONFIG.user_agent = USER_AGENT;
    CONFIG.threshold = THRESHOLD;
    CONFIG.prefetch  = PREFETCH;
    CONFIG.num_peers = MAX_OUTBOUND_PEERS;
    struct PN_callbacks CALLBACKS;
    memset(&CALLBACKS, 0, sizeof(CALLBACKS));
    CALLBACKS.log = print_log_message;
    CALLBACKS.warning = print_log_message;
    unsigned ret = 0;
    struct PN *node = PN_create(COIN, &CALLBACKS, &CONFIG, ret);

    return 0;
}

