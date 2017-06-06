#!/bin/sh
cd .. > /dev/null;
#strace -f -s 9999 -vvvvv -o netcat_receive.strace netcat -v -l 6666 &
#sleep 5s;
echo "asdfasdf" | netcat localhost 6666;
OUTPUT=$(python main.py \
         -c "['netcat -v -l 6666']" \
         -t sample_traces/netcat_receive.strace 2>&1);
RET=$?;
echo $OUTPUT | grep -q "asdfasdf";
FOUND=$?;
#rm netcat_receive.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1;
fi
