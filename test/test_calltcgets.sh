#!/bin/sh
cd .. > /dev/null;
output=$(python main.py \
       -c sample_programs/calltcgets \
       -t sample_programs/calltcgets.strace)
if ! echo $output | grep -q "03 1c 7f 15 04 00 01 00 11 13 1a ff 12 0f 17 16 ff 00 00 e4 fb ff bf ec fb ff bf 1c 93 04 08 0c"
then echo "$0: failed!";
fi
cd - > /dev/null;
