#!/bin/sh
cd .. > /dev/null;
if [ -f .co.log ]
then echo "$0 would stomp on existing file: .co.log";
exit 1;
fi
python main.py \
       -c sample_programs/callread \
       -t sample_programs/callread.strace\
       -o .co.log;
if ! grep -q "hXXXXXr" .co.log
then echo "$0: failed!";
fi
rm .co.log;
cd - > /dev/null;
