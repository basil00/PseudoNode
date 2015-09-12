LibPseudoNode 0.6.0
===================

PseudoNode is a cryptocurrency full node "emulator".

To the network, PseudoNode behaves the same way as a full node by relaying
transactions, blocks, addresses, etc.  However, unlike a normal full
node, PseudoNode does *not* verify data (txs & blocks) itself.  Rather,
PseudoNode relies on neighboring peers (with configurable confidence levels)
to do the verification on PseudoNode's behalf.  As a result, PseudoNode is
very lightweight.

Compared to a normal full node:

* PseudoNode *does not require the blockchain to be downloaded*.
* PseudoNode can "sync" with the network in seconds.
* PseudoNode supports multiple cryptocurrencies that are Bitcoin derivatives.
* PseudoNode uses no disk space (sans the executable), negligible RAM, and
  negligible CPU time.  PseudoNode also consumes less network resources
  (data usage/bandwidth) than a normal full node.

PseudoNode can be downloaded from here (the official release):

* [https://github.com/basil00/PseudoNode/releases](https://github.com/basil00/PseudoNode/releases)

Usage
=====

As of version 0.6.0, PseudoNode is a library (a.k.a. LibPseudoNode).  The
PseudoNode library can be used for many applications that would otherwise
require a full node, but without the inconvenience of a large/slow blockchain
download and sync.

To create a basic Bitcoin PseudoNode using the library, simply call the
function:

    struct PN *node = PN_create(NULL, NULL, NULL, 0);

See the `pseudo_node.h` file for more detail documentation about the
PseudoNode configuration.  Various parameters can be controlled, such
as:

* Which cryptocurrency PseudoNode connects to (default is Bitcoin).
* Protocol and node configuration (e.g. extra services bits).
* Configuration to intercept various networks events, such as the broadcast
  of a new transaction or block.
* Whether or not `PN_create` assumes control of the calling thread.

The PseudoNode library supports a callbacks for various events.  For example,
to intercepting transactions can be achieved via the following pseudo-code:

    struct PN_callbacks CALLBACKS;
    memset(&CALLBACKS, 0, sizeof(CALLBACKS));
    CALLBACKS.tx = tx_callback;         // Set transaction call-back
    struct PN *node = PN_create(NULL, &CALLBACKS, NULL, 0);

The function `tx_callback` will be called for each transaction broadcast on
the network.  See the sample application `apps/txmon` for an example of how
this can be used to build a simple transaction monitor.

In addition to the above, PseudoNode can broadcast raw transactions using
using the following function call:

    PN_broadcast_tx(node, tx_data, tx_len);

Reference Program
=================

A reference PseudoNode is currently implemented as a command-line tool.

By default it will connect to the Bitcoin network:

    pseudonode

You can connect to different networks using the --coin=COIN option, e.g.:

    pseudonode --coin=testnet
    pseudonode --coin=litecoin
    pseudonode --coin=bitcoin-xt

The current implementation supports the following cryptocurrencies: bitcoin,
testnet (bitcoin), litecoin and bitcoin XT.

To identify as a standard full node, add the `--stealth` option to the command
line, e.g.:

    pseudonode --stealth

By default, PseudoNode considers data (tx or blocks) valid if 2 other nodes
also believe so.  This value can be configured via the --threshold=VAL option,
e.g.:

    pseudonode --threshold=3

Higher values will slow the node down.  Lower values make it more likely the
node will relay erroneous data.  The default of 2 is a good compromise.

By default PseudoNode will fetch objects (txs and blocks) only if other nodes
explicitly request for them.  It is possible to configure PseudoNode to fetch
objects immediately via the option:

    pseudonode --prefetch

Note that enabling this option will cause PseudoNode to consume more bandwidth
(on par with a normal full node).

To run PseudoNode as a background process use the --server option.  Currently
only works for Linux:

    pseudonode --server

Building
========

For Linux simply run make:

    make

Windows can be built via Linux cross compilation and MinGW.  Run the command:

    make -f Makefile.windows

For MacOSX, run the command:

    make -f Makefile.macosx

LICENSE
=======

PseudoNode has been released under the MIT license:

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

