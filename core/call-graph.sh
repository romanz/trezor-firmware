#!/bin/bash
set -eux

export CC=clang
# make clean
make build_unix
nm ./build/unix/micropython | grep " secp256k1_" 1> symbols.txt

OPTLEVEL=0 ./build/unix/micropython src/main.py 2> call-graph.txt &

sleep 2
python3 test_liquid.py

python3 plot-graph.py &
python3 top-stack-users.py
