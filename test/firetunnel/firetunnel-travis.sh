#!/bin/bash
# This file is part of Firetunnel project
# Copyright (C) 2018 Firetunnel Authors
# License GPL v2

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

echo "abcdefg" > /etc/firetunnel/firetunnel.secret

echo "TESTING: server startup (test/server-startup.exp)"
./server-startup.exp

echo "TESTING: connect (test/connect.exp)"
./connect.exp

echo "TESTING: connect custom overlay (test/connect-addr.exp)"
./connect-addr.exp

echo "TESTING: disconnect (test/disconnect.exp - it will take a about 1 minute to run)"
./disconnect.exp

echo "TESTING: multiple clients (test/multiple-clients.exp)"
./multiple-clients.exp

# somehow sandbox-*.exp programs won't work on Travis CI
# installing a firejail instance in .travis.yml:
#  - (wget https://github.com/netblue30/firejail/archive/0.9.56-rc1.tar.gz && tar -xzvf 0.9.56-rc1.tar.gz  && cd firejail-0.9.56-rc1 && ./configure --prefix=/usr && make && sudo make install)

