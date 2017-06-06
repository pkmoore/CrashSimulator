#!/bin/sh
cd .. > /dev/null;
python main.py \
       -c "['./sample_programs/callselect']" \
       -t ./sample_programs/callselect.strace
echo "This test does no checking! Watch for exceptions!"
cd - > /dev/null;
