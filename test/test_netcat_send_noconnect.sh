#!/bin/sh
cd ../sample_traces > /dev/null;
strace -f -s 9999 -vvvvv -o netcat_send_noconnect.strace netcat -v localhost 6666;
cd .. > /dev/null;
OUTPUT=$(python main.py \
       -c "netcat -v localhost 6666" \
       -t sample_traces/netcat_send_noconnect.strace);
RET=$?;
echo $OUTPUT | grep -q "Connection refused";
FOUND=$?;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1;
fi
