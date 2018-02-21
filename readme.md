# Requirements
* Supported OS:
    uname -a
    Linux dev.local 3.19.0-49-generic #55-Ubuntu SMP Fri Jan 22 02:09:44 UTC 2016 i686 i686 i686 GNU/Linux

* ASLR Disabled
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

    kernel.randomize_va_space = 0 #in /etc/sysctl.d/01-disable-aslr.conf

* Disable VDSO
    Adding the kernel parameter vdso=0 in /etc/default/grub

* Python 2.7.9


# Installation
1. Clone CrashSimulator Repository
2. Clone https://github.com/pkmoore/posix-omni-parser into python_modules directory
3. Clone https://github.com/ssavvides/parse-syscall-definitions into python_modules directory
4. Generate system call definitions pickle file --- inside parse-syscall-definitions folder:
    python ./parse_syscall_definitions.py
5. Copy syscall_definitions.pickle into CrashSimulator root directory
7. Install python development materials
    sudo apt-get install python-dev
6. Install tracereplay python module in python_modules directory using
    sudo python setup.py install


# Running Tests
1. Compile programs used in testing by building all targets specified in the make file in sample_programs directory
2. Execute test scripts in tests directory


# Recoding a System Call Trace With Sufficient Detail

    strace -f -s 65535 -vvvvv -o <filename>.strace <command>


# Replaying a Recorded System Call Trace

    python main.py -c "['<command>']" -t <system call trace>

Note:  The "command" portion is a Python list of python strings containing the elements of the commands (command, switches, switch parameters, etc.).
For example:
    python main.py -c "['wget', '-q0', '-', 'http://www.google.com']" -t wget_google.strace
