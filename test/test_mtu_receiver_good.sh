#!/bin/sh
cd .. > /dev/null;
python main.py \
       -c sample_programs/mtu_receiver_good \
       -t sample_programs/mtu_receiver_good.strace
echo "This test does no checking! Watch for exceptions!"
cd - > /dev/null;
