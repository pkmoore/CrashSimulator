#!/bin/sh
cd .. > /dev/null;
python main.py \
       -c "nc -l 6666" \
       -t sample_traces/netcat_receive.strace
echo "This test does no checking! Watch for exceptions!"
cd - > /dev/null;
