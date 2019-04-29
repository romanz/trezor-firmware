#!/bin/bash
cd `dirname $0`
set -eux

PYOPT=0 CC=clang make build_unix | tee build.txt
nm ./build/unix/micropython > symbols.txt

../run.sh -vvxsk test_send_p2sh_confidential_to_confidential_sign

python3 plot-graph.py ../micro.err &
python3 top-stack-users.py symbols.txt ../micro.err
