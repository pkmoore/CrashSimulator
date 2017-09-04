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
