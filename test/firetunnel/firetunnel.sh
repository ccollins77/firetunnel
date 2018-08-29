#!/bin/bash
# This file is part of Firetunnel project
# Copyright (C) 2018 Firetunnel Authors
# License GPL v2

export MALLOC_CHECK_=3
export MALLOC_PERTURB_=$(($RANDOM % 255 + 1))

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

echo "TESTING: sandbox ping (test/sandbox-ping.exp)"
./sandbox-ping.exp

echo "TESTING: sandbox dns (test/sandbox-dns.exp)"
./sandbox-dns.exp

echo "TESTING: sandbox tcp (test/sandbox-tcp.exp)"
./sandbox-tcp.exp
