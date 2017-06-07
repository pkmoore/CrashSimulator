#!/bin/sh
trace_name=telnet_google.strace

cd ../sample_programs  > /dev/null;
^ | strace -f -s 9999 -vvvvv -o $trace_name telnet www.google.com 80;
cd .. > /dev/null;
#OUTPUT=$(python main.py -f ./sample_traces/telnet_google.ini);
OUTPUT=$(python main.py \
       -c "['telnet', 'www.google.com', '80']"  \
       -t sample_programs/$trace_name);
RET=$?
echo $OUTPUT | grep -q "HTTP/1.0 200 OK"
FOUND=$?
rm sample_programs/$trace_name;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
