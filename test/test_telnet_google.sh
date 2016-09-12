#!/bin/sh
cd .. > /dev/null;
OUTPUT=$(python main.py -f ./sample_traces/telnet_google.ini);
RET=$?
echo $OUTPUT | grep -q "HTTP/1.0 200 OK"
FOUND=$?
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1
fi
