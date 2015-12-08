#!/bin/sh
cd .. > /dev/null;
if [ -f .co.log ]
then echo "$0 would stomp on existing file: .co.log";
exit 1;
fi
python main.py \
       -c sample_programs/opensocket \
       -t sample_programs/opensocket_failure.strace\
       -o .co.log;
if ! grep -q "Failure!" .co.log
then echo "$0: failed!";
fi
rm .co.log;
cd - > /dev/null;
