#!/bin/sh
wget https://sourceforge.net/projects/levent/files/libevent/libevent-2.0/libevent-2.0.22-stable.tar.gz
cp libevent-2.0.22-stable.tar.gz /tmp
cd /tmp
tar zxvf libevent*
cd libevent*
./configure
make & sudo make install
