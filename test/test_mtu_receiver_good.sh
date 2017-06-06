#!/bin/sh
# Care must be taken to send enough bytes to the listener that it meets its
# shutdown condition. I think this is > 15 bytes. Otherwise it keeps running and
# the test fails.
cd ../sample_programs > /dev/null;
# Ugly cleanup
killall mtu_receiver_good;
strace -f -s 9999 -vvvvv -o mtu_receiver_good.strace ./mtu_receiver_good &
sleep 5s;
echo "asdfawefasdf1234123412341234" | nc localhost 8888
cd .. > /dev/null;
OUTPUT=$(python main.py \
         -c "['sample_programs/mtu_receiver_good']" \
         -t sample_programs/mtu_receiver_good.strace);
RET=$?
echo $OUTPUT | grep -q "asdf";
FOUND=$?;
rm sample_programs/mtu_receiver_good.strace;
cd test > /dev/null;
if [ $RET -ne 0 ] || [ $FOUND -ne 0 ];
   then exit 1;
fi
