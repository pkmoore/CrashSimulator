#!/bin/sh

cd ../sample_programs > /dev/null;
strace -f -s 9999 -vvvvv -o ../sample_programs/timer_tests.strace ./timer_tests
cd .. > /dev/null;

 python main.py -c "['sample_programs/timer_tests']" -t sample_programs/timer_tests.strace;# -l DEBUG;
