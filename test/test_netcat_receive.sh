#!/bin/sh
cd .. > /dev/null;
if [ -f .co.log ]
then echo "$0 would stomp on existing file: .co.log";
exit 1;
fi
python main.py \
       -c "nc -l 6666" \
       -t sample_traces/netcat_receive.strace\
       -o .co.log;
if ! grep -q "hhhhhhhffffffffkkdkkfoksoekfokdokfokeoskfokeokwokdofkeo" .co.log
then echo "$0: failed!";
fi
rm .co.log;
cd - > /dev/null;
