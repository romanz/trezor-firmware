#!/bin/bash
set -eux

# make clean
CC=clang make build_unix
nm ./build/unix/micropython | grep " secp256k1_" 1> symbols.txt

killall micropython || true
TREZOR_PATH=udp:127.0.0.1:21324 OPTLEVEL=0 ./build/unix/micropython src/main.py 2> call-graph.txt &

sleep 2
py.test -m liquid -v

python3 plot-graph.py &
python3 top-stack-users.py
