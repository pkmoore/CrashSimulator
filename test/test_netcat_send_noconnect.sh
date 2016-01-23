#!/bin/sh
cd .. > /dev/null;
python main.py \
       -c "netcat 127.0.0.1 6666" \
       -t sample_traces/netcat_send_noconnect.strace
echo "This is a sad unit test. If no exception it probably worked."
cd - > /dev/null;
