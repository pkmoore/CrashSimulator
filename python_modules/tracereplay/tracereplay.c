#define _GNU_SOURCE
#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <Python.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <termios.h>
#include <sys/statfs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static PyObject* TraceReplayError;

bool DEBUG = false;
bool INFO = false;

int copy_buffer_into_child_process_memory(pid_t child,
                                          void* addr,
                                          const char* const buffer,
                                          size_t buf_length){
    size_t writes = buf_length - (sizeof(int) - 1 );
    int i;
    if(DEBUG) {
        printf("C: copy_buffer: number of writes: %d\n", writes);
        printf("C: copy_buffer: buffer data: \n");
        for(i = 0; i < buf_length; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
    }
    for(i = 0; i < writes; i++) {
        if(DEBUG) {
            printf("C: copy_buffer: poking (%p)%08X into %p\n", &buffer[i],
                   *((int*)&buffer[i]), addr);
        }
        if((ptrace(PTRACE_POKEDATA, child, addr, *((int*)&buffer[i])) == -1)) {
            PyErr_SetString(TraceReplayError, "Failed to poke select data\n");
        }
        addr++;
    }
    return 0;
}

static PyObject* tracereplay_populate_timespec_structure(PyObject* self,
                                                         PyObject* args) {
    pid_t child;
    void* addr;
    time_t seconds;
    long nanoseconds;
    if(!PyArg_ParseTuple(args, "iiil", &child, &addr, &seconds, &nanoseconds)) {
        PyErr_SetString(TraceReplayError,
                        "copy_bytes failed parse failed");
    }
    if(DEBUG) {
        printf("C: timespec: child: %d\n", child);
        printf("C: timespec: addr: %p\n", addr);
        printf("C: timespec: seconds: %d\n", (int)seconds);
        printf("C: timespec: nanoseconds: %ld\n", nanoseconds);
        printf("C: timespec: sizeof(seconds): %d\n", sizeof(seconds));
        printf("C: timespec: sizeof(nanoseconds): %d\n", sizeof(nanoseconds));
    }
    struct timespec t;
    t.tv_sec = seconds;
    t.tv_nsec = nanoseconds;
    if(DEBUG) {
        printf("C: timespec: tv_sec: %d\n", (int)t.tv_sec);
        printf("C: timespec: tv_nsec: %ld\n", t.tv_nsec);
    }
    copy_buffer_into_child_process_memory(child, addr, (char*)&t, sizeof(t));
    Py_RETURN_NONE; 
}

static PyObject* tracereplay_populate_timeval_structure(PyObject* self,
                                                        PyObject* args) {
    pid_t child;
    void* addr;
    time_t seconds;
    suseconds_t microseconds;
    if(!PyArg_ParseTuple(args, "iiil", &child, &addr, &seconds, &microseconds)) {
        PyErr_SetString(TraceReplayError,
                        "copy_bytes failed parse failed");
    }
    if(DEBUG) {
        printf("C: timeval: child: %d\n", child);
        printf("C: timeval: addr: %p\n", addr);
        printf("C: timeval: seconds: %d\n", (int)seconds);
        printf("C: timeval: microseconds: %ld\n", microseconds);
        printf("C: timeval: sizeof(seconds): %d\n", sizeof(seconds));
        printf("C: timeval: sizeof(microseconds): %d\n", sizeof(microseconds));
    }
    struct timeval t;
    t.tv_sec = seconds;
    t.tv_usec = microseconds;
    if(DEBUG) {
        printf("C: timeval: tv_sec: %d\n", (int)t.tv_sec);
        printf("C: timeval: tv_usec: %ld\n", t.tv_usec);
    }
    copy_buffer_into_child_process_memory(child, addr, (char*)&t, sizeof(t));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_copy_bytes_into_child_process(PyObject* self,
                                                          PyObject* args) {
    pid_t child;
    void* addr;
    unsigned char* bytes;
    Py_ssize_t num_bytes;
    if(!PyArg_ParseTuple(args, "iis#", &child, &addr, &bytes, &num_bytes)) {
        PyErr_SetString(TraceReplayError,
                        "copy_bytes failed parse failed");
    }
    if(DEBUG) {
        printf("C: copy_bytes: child: %d\n", child);
        printf("C: copy_bytes: addr: %x\n", (int)addr);
        printf("C: copy_bytes: num_bytes %d\n", num_bytes);
    } 
        copy_buffer_into_child_process_memory(child, addr, (char*)bytes, num_bytes);
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_af_inet_sockaddr(PyObject* self,
                                                       PyObject* args) {
    pid_t child;
    void* addr;
    char* ip;
    short port;
    void* length_addr;
    socklen_t length;

    PyArg_ParseTuple(args, "iihsii", &child, &addr,
                     &port, &ip, &length_addr, &length);
    if(DEBUG) {
        printf("C: pop af_inet: sizeof(socklen_t): %d\n", sizeof(socklen_t));
        printf("C: pop af_inet: child: %d\n", child);
        printf("C: pop af_inet: addr: %p\n", addr);
        printf("C: pop af_inet: ip: %s\n", ip);
        printf("C: pop af_inet: port: %d\n", port);
        printf("C: pop af_inet: length: %d\n", length);
    }
    struct sockaddr_in s;    
    if(DEBUG) {
        printf("C: pop af_inet: sizeof(s.sin_port): %d\n", sizeof(s.sin_port));
    }
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    inet_aton(ip, &s.sin_addr); 
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&s,
                                          sizeof(s));

    copy_buffer_into_child_process_memory(child,
                                          length_addr,
                                          (char*)&length,
                                          sizeof(length));
    Py_RETURN_NONE;
}

static PyObject* tracreplay_populate_statfs64_structure(PyObject* self,
                                                        PyObject* args) {
    pid_t child;
    void* addr;
    long f_type;
    long f_bsize;
    long f_blocks;
    long f_bfree;
    long f_bavail;
    long f_files;
    long f_ffree;
    long f_fsid1;
    long f_fsid2;
    long f_namelen;
    long f_frsize;
    long f_flags;

    PyArg_ParseTuple(args, "iikkkkkkkkkkkk", &child, &addr, &f_type, &f_bsize,
                     &f_blocks, &f_bfree, &f_bavail, &f_files, &f_ffree,
                     &f_fsid1, &f_fsid2, &f_namelen, &f_frsize, &f_flags);
    if(DEBUG) {
        printf("C: statfs64: child: %d\n", child);
        printf("C: statfs64: addr: %p\n", addr);
        printf("C: statfs64: f_type: %lx\n", f_type);
        printf("C: statfs64: f_bsize: %ld\n", f_bsize);
        printf("C: statfs64: f_blocks: %ld\n", f_blocks);
        printf("C: statfs64: f_bfree: %ld\n", f_bfree);
        printf("C: statfs64: f_bavail: %ld\n", f_bavail);
        printf("C: statfs64: f_files: %ld\n", f_files);
        printf("C: statfs64: f_ffree: %ld\n", f_ffree);
        printf("C: statfs64: f_fsid1: %ld\n", f_fsid1);
        printf("C: statfs64: f_fsid2: %ld\n", f_fsid2);
        printf("C: statfs64: f_namelen: %ld\n", f_namelen);
        printf("C: statfs64: f_frsize: %ld\n", f_frsize);
        printf("C: statfs64: f_flags: %ld\n", f_flags);
    }
    struct statfs64 s;
    memset(&s, 0x0, sizeof(s));
    s.f_type = f_type;
    s.f_bsize = f_bsize;
    s.f_blocks = f_blocks;
    s.f_bfree = f_bfree;
    s.f_bavail = f_bavail;
    s.f_files = f_files;
    s.f_ffree = f_ffree;
    //NOTICE: fsid is not set here
    s.f_namelen = f_namelen;
    s.f_frsize = f_frsize;
    s.f_flags = f_flags;

    copy_buffer_into_child_process_memory(child, addr, (char*)&s, sizeof(s));
    Py_RETURN_NONE;
}


static PyObject* tracereplay_populate_tcgets_response(PyObject* self,
						      PyObject* args) {
    pid_t child;
    void* addr;
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    unsigned char* cc_bytes;
    Py_ssize_t cc_bytes_length;
    int i; 

    PyArg_ParseTuple(args, "iiIIIIbs#", (int*)&child, (int*)&addr, (unsigned int*)&c_iflag,
                     (unsigned int*)&c_oflag, (unsigned int*)&c_cflag, (unsigned int*)&c_lflag,
                     (unsigned char*)&c_line, &cc_bytes, &cc_bytes_length);
    if(DEBUG) {
        printf("C: tcgets: child %d\n", child);
        printf("C: tcgets: addr %p\n", addr);
        printf("C: tcgets: c_iflag %x\n", c_iflag);
        printf("C: tcgets: c_oflag %x\n", c_oflag);
        printf("C: tcgets: c_cflag %x\n", c_cflag);
        printf("C: tcgets: c_lflag %x\n", c_lflag);
        printf("C: tcgets: c_line %x\n", c_line);
        printf("C: tcgets: cc_bytes_length %d\n", cc_bytes_length);
        printf("C: tcgets: cc_bytes %p\n", cc_bytes);
        for(i = 0; i < cc_bytes_length; i++) {
            printf("%02X", cc_bytes[i]);
        }
        printf("\n");
    }
    struct termios t;
    t.c_iflag = c_iflag;
    t.c_oflag = c_oflag;
    t.c_cflag = c_cflag;
    t.c_lflag = c_lflag;
    t.c_line = c_line;
    memcpy(&t.c_cc, cc_bytes, cc_bytes_length);
    if(DEBUG) {
        printf("C: tcgets: sizeof(struct termios) %d\n", sizeof(struct termios));
        printf("C: tcgets: sizeof(t.c_cc) %d\n", sizeof(t.c_cc));
        printf("C: tcgets: t.c_iflag %x\n", t.c_iflag);
        printf("C: tcgets: t.c_oflag %x\n", t.c_oflag);
        printf("C: tcgets: t.c_cflag %x\n", t.c_cflag);
        printf("C: tcgets: t.c_lflag %x\n", t.c_lflag);
        printf("C: tcgets: t.c_line %x\n", t.c_line);
        printf("C: tcgets: t.cc_c addr %p\n", &t.c_cc);
        for(i = 0; i < cc_bytes_length; i++) {
            printf("%02X", t.c_cc[i]);
        }
        printf("\n");
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&t,
                                          17 + 19);
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_rlimit_structure(PyObject* self,
                                                       PyObject* args) {
    pid_t child;
    void* addr;
    rlim_t rlim_cur;
    rlim_t rlim_max;

    PyArg_ParseTuple(args, "iiLL", (int*)&child, (int*)&addr,
                     (long long*)&rlim_cur, (long long*)&rlim_max);
    if(DEBUG) {
        printf("C: getrlimit: child %d\n", (int)child);
        printf("C: getrlimit: addr %d\n", (int)addr);
        printf("C: getrlimit: rlim_cur %lld\n", (long long)rlim_cur);
        printf("C: getrlimit: rlim_max %llx\n", (long long)rlim_max);
        printf("C: getrlimit: sizeof rlimit %d\n", sizeof(struct rlimit));
    }
    struct rlimit64 s;
    s.rlim_cur = rlim_cur;
    s.rlim_max = rlim_cur+100;
    printf("C: sizeof(rlimit64) %d\n", sizeof(struct rlimit64));
    printf("C: sizeof(rlimit) %d\n", sizeof(struct rlimit));
    printf("C: sizeof(cur) %d\n", sizeof(s.rlim_cur));
    printf("C: cur %llx\n", s.rlim_cur);
    printf("C: sizeof(max) %d\n", sizeof(s.rlim_max));
    printf("C: max %llx\n", s.rlim_max);
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&s,
                                          sizeof(s));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_uname_structure(PyObject* self,
                                                     PyObject* args) {
    pid_t child;
    void* addr;
    char* sysname;
    char* nodename;
    char* release;
    char* version;
    char* machine;
    char* domainname;
    PyArg_ParseTuple(args, "iissssss", (int*)&child, (int*)&addr, &sysname,
                     &nodename, &release, &version, &machine, &domainname);
    if(DEBUG) {
        printf("C: uname: child %d\n", (int)child);
        printf("C: uname: addr %d\n", (int)addr);
        printf("C: uname: sysname %s\n", sysname);
        printf("C: uname: nodename %s\n", nodename);
        printf("C: uname: release %s\n", release);
        printf("C: uname: version %s\n", version);
        printf("C: uname: machine %s\n", machine);
        printf("C: uname: domainname %s\n", domainname);
    }
    struct utsname s;
    strncpy(s.sysname, sysname, 64);
    strncpy(s.nodename, nodename, 64);
    strncpy(s.release, release, 64);
    strncpy(s.version, version, 64);
    strncpy(s.machine, machine, 64);
    strncpy(s.domainname, domainname, 64);
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&s,
                                          sizeof(s));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_char_buffer(PyObject* self,
                                                  PyObject* args) {
    pid_t child;
    void* addr;
    char* data;
    long int data_length;
    PyArg_ParseTuple(args, "iisl", (int*)&child, (int*)&addr, 
                     &data, &data_length);
    if(DEBUG) {
        printf("C: pop_char_buf: child: %d\n", child);
        printf("C: pop_char_buf: addr: %d\n", (int)addr);
        printf("C: pop_char_buf: data: %s\n", data);
        printf("C: pop_char_buf: data_length %ld\n", data_length);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          data,
                                          data_length);
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_int(PyObject* self,
                                          PyObject* args) {
    pid_t child;
    void* addr;
    int data;
    PyArg_ParseTuple(args, "iii", (int*)&child, (int*)&addr, &data);
    if(DEBUG) {
        printf("C: pop_char_buf: child: %d\n", child);
        printf("C: pop_char_buf: addr: %d\n", (int)addr);
        printf("C: pop_char_buf: data: %d\n", data);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&data,
                                          sizeof(int));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_llseek_result(PyObject* self,
                                                    PyObject* args) {
    pid_t child;
    void* addr;
    loff_t result;
    PyArg_ParseTuple(args, "iiL", (int*)&child, (int*)&addr, (int*)&result);
    if(DEBUG) {
        printf("C: llseek: child: %d\n", (int)child);
        printf("C: llseek: addr: %d\n", (int)addr);
        printf("C: llseek: result: %lld\n", (long long)result);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&result,
                                          sizeof(long long));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_stat64_struct(PyObject* self,
                                                    PyObject* args) {
    struct stat64 s;
    pid_t child;
    void* addr;
    int st_dev1;
    int st_dev2;
    int st_rdev1;
    int st_rdev2;
    dev_t     st_dev;     /* ID of device containing file */
    ino_t     st_ino;     /* inode number */
    mode_t    st_mode;    /* protection */
    nlink_t   st_nlink;   /* number of hard links */
    uid_t     st_uid;     /* user ID of owner */
    gid_t     st_gid;     /* group ID of owner */
    dev_t     st_rdev;    /* device ID (if special file) */
    off_t     st_size;    /* total size, in bytes */
    blksize_t st_blksize; /* blocksize for file system I/O */
    blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
    time_t st__ctime;
    time_t st__mtime;
    time_t st__atime;
    PyArg_ParseTuple(args, "iiiiiiiiiiiiiiiii", &child, &addr, &st_dev1, &st_dev2,
                    (int*)&st_blocks,    (int*)&st_nlink,  (int*)&st_gid,
                    (int*)&st_blksize,   (int*)&st_rdev1,  (int*)&st_rdev2,
                    (int*)&st_size,      (int*)&st_mode,
                    (int*)&st_uid,       (int*)&st_ino,    (int*)&st__ctime,
                    (int*)&st__mtime,    (int*)&st__atime);
    st_dev = makedev(st_dev1, st_dev2);
    st_rdev = makedev(st_rdev1, st_rdev2);
    s.st_dev = st_dev;
    s.st_ino = st_ino;
    s.st_mode = st_mode;
    s.st_nlink = st_nlink;
    s.st_uid = st_uid;
    s.st_gid = st_gid;
    s.st_rdev = st_rdev;
    s.st_size = st_size;
    s.st_blksize = st_blksize;
    s.st_blocks = st_blocks;
    s.st_ctime = st__ctime;
    s.st_mtime = st__mtime;
    s.st_atime = st__atime;

    if(DEBUG) {
        printf("s.st_dev: %d\n", (int)s.st_dev);
        printf("s.st_rdev: %d\n", (int)s.st_rdev);
        printf("s.st_ino: %d\n", (int)s.st_ino);
        printf("s.st_mode: %d\n", (int)s.st_mode);
        printf("s.st_nlink: %d\n", (int)s.st_nlink);
        printf("s.st_uid: %d\n", (int)s.st_uid);
        printf("s.st_gid: %d\n", (int)s.st_gid);
        printf("s.st_rdev: %d\n", (int)s.st_rdev);
        printf("s.st_size: %d\n", (int)s.st_size);
        printf("s.st_blksize: %d\n", (int)s.st_blksize);
        printf("s.st_blocks: %d\n", (int)s.st_blocks);

        char buffer[100];
        strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&s.st_ctime));
        printf("s.st_ctime: %s\n", buffer);
        strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&s.st_mtime));
        printf("s.st_mtime: %s\n", buffer);
        strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&s.st_atime));
        printf("s.st_atime: %s\n", buffer);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&s,
                                          sizeof(s));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_select_bitmaps(PyObject* self,
                                                     PyObject* args) {
    pid_t child;
    int fd;
    fd_set* addr;
    PyArg_ParseTuple(args, "iii", &child, &fd, &addr);
    if(DEBUG) {
        printf("C: Select: PID: %d\n", child);
        printf("C: Select: FD: %d\n", fd);
        printf("C: Select: addr: %d\n", (int)addr);
    }
    fd_set tmp;
    FD_ZERO(&tmp);
    FD_SET(fd, &tmp);
    if(DEBUG) {
        printf("C: Select: Is fd %d set?: %s\n",
               fd,
               FD_ISSET(fd, &tmp) ? "true" : "false");
        printf("C: Select: poking data\n");
    }
    errno = 0;
    if((ptrace(PTRACE_POKEDATA, child, addr, tmp) == -1)) {
        PyErr_SetString(TraceReplayError, "Failed to poke select data\n");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_enable_debug_output(PyObject* self, PyObject* args) {
    int numeric_level;
    PyArg_ParseTuple(args, "i", &numeric_level);
    switch(numeric_level) {
    case 10:
        DEBUG = true;
    case 20:
        INFO = true;
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_disable_debug_output(PyObject* self, PyObject* args) {
    DEBUG = false;
    INFO = false;
    Py_RETURN_NONE;
}

void init_constants(PyObject* m) {
    if(PyModule_AddIntConstant(m, "ORIG_EAX", ORIG_EAX) == -1) {
        return;
    }
    if(PyModule_AddIntConstant(m, "EAX", EAX) == -1) {
        return;
    }
    if(PyModule_AddIntConstant(m, "EBX", EBX) == -1) {
        return;
    }
    if(PyModule_AddIntConstant(m, "ECX", ECX) == -1) {
        return;
    }
    if(PyModule_AddIntConstant(m, "EDX", EDX) == -1) {
        return;
    }
    if(PyModule_AddIntConstant(m, "ESI", ESI) == -1) {
        return;
    }
    if(PyModule_AddIntConstant(m, "EDI", EDI) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "STDIN", STDIN_FILENO) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "STDOUT", STDOUT_FILENO) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "STDERR", STDERR_FILENO) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "PF_INET", PF_INET) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "POLLIN", POLLIN) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "POLLOUT", POLLOUT) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "POLLFDSIZE", sizeof(struct pollfd)) == -1) {
        return;
    }

    if(PyModule_AddIntConstant(m, "CLOCK_MONOTONIC", CLOCK_MONOTONIC) == -1) {
        return;
    }
}

static PyObject* tracereplay_peek_register(PyObject* self, PyObject* args) {
    pid_t child;
    int reg;
    long int extracted_register;
    PyArg_ParseTuple(args, "ii", &child, &reg);
    errno = 0;
    extracted_register = ptrace(PTRACE_PEEKUSER, child,
                                sizeof(long int) * reg, NULL);
    if(errno != 0) {
        perror("Register Peek Failed");
        return NULL;
    }
    return Py_BuildValue("i", extracted_register);
}

static PyObject* tracereplay_poke_register(PyObject* self, PyObject* args) {
    pid_t child;
    int reg;
    long int value;
    PyArg_ParseTuple(args, "iii", &child, &reg, &value);
    errno = 0;
    if(ptrace(PTRACE_POKEUSER, child, sizeof(long int) * reg, value) == -1){
        perror("Register Poke Failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_cont(PyObject* self, PyObject* args) {
    pid_t child;
    PyArg_ParseTuple(args, "i", &child);
    errno = 0;
    if(ptrace(PTRACE_CONT, child, NULL, NULL) == -1) {
        perror("Cont failed");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_traceme(PyObject* self, PyObject* args) {
    errno = 0;
    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("Traceme failed");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_wait(PyObject* self, PyObject* args) {
    int status;
    if(wait(&status) == -1) {
        perror("Wait failed");
    }
    return Py_BuildValue("i", status);
}

static PyObject* tracereplay_syscall(PyObject* self, PyObject* args) {
    pid_t child;
    PyArg_ParseTuple(args, "i", &child);
    errno = 0;
    if(ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
        perror("Cont failed");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_poke_address(PyObject* self, PyObject* args) {
    pid_t child;
    int address;
    int data;
    PyArg_ParseTuple(args, "iii", &child, &address, &data);
    if(DEBUG) {
        printf("C: poke_address: child: %d\n", child);
        printf("C: poke_address: address: %x\n", address);
        printf("C: poke_address: data: %d\n", data);
    }
    errno = 0;
    if(ptrace(PTRACE_POKEDATA, child, address, data) == -1) {
        perror("Poke into userspace failed");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_peek_address(PyObject* self, PyObject* args) {
    pid_t child;
    int address;
    long int value;
    PyArg_ParseTuple(args, "ii", &child, &address);
    errno = 0;
    if((value = ptrace(PTRACE_PEEKDATA, child, address, NULL)) == -1) {
        perror("Peek into userspace failed");
        return NULL;
    }
    return Py_BuildValue("i", value);
}

static PyObject* tracereplay_write_poll_result(PyObject* self, PyObject* args) {
    pid_t child;
    void* addr;
    short fd;
    short re;
    struct pollfd s;
    if(!PyArg_ParseTuple(args, "iihh", &child, (int*)&addr, &fd, &re)) {
        PyErr_SetString(TraceReplayError, "write_poll_result arg parse failed");
    }
    s.fd = fd;
    s.events = 0;
    s.revents = re;
    if(DEBUG) {
        printf("E Size: %d\n", sizeof(s.events));
        printf("FD Size: %d\n", sizeof(s.fd));
        printf("RE Size: %d\n", sizeof(s.revents));
        printf("C: sizeof(struct pollfd) = %d\n", sizeof(struct pollfd));
        printf("C: FD %d\n", s.fd);
        printf("C: E %d\n", s.events);
        printf("C: RE %d\n", s.revents);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&s,
                                          sizeof(struct pollfd));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_write_sendmmsg_lengths(PyObject* self,
                                                    PyObject* args) {
    pid_t child;
    void* addr;
    size_t num;
    PyObject* list_of_lengths;
    if(!PyArg_ParseTuple(args, "iiiO",
                         &child,
                         (int*)&addr,
                         &num,
                         &list_of_lengths)) {
        PyErr_SetString(TraceReplayError,
                        "write_sendmmsg_lengths arg parse failed");
    }
    if(DEBUG) {
        printf("C: sendmmsg_lengths: child: %d\n", child);
        printf("C: sendmmsg_lengths: addr: %x\n", (int)addr);
        printf("C: sendmmsg_lengths: num: %d\n", num);
    }
    if(!PyList_Check(list_of_lengths)) {
        PyErr_SetString(TraceReplayError,
                        "Object received in C code is not a list");
    }
    PyObject* iter;
    if(!(iter = PyObject_GetIter(list_of_lengths))) {
        PyErr_SetString(TraceReplayError,
                        "Couldn't get iterator for list of lengths");
    }
    PyObject* next = PyIter_Next(iter);
    Py_ssize_t length;
    struct mmsghdr m[num];
    int msghdr_index = 0;
    while(next) {
        if(!PyInt_Check(next)) {
            PyErr_SetString(TraceReplayError,
                              "Encountered non-Int in list of lengths");
        }
        length = PyInt_AsSsize_t(next);
        if(DEBUG) {
            printf("C: sendmmsg_lengths: got length %d\n", length);
        }
        m[msghdr_index].msg_len = length;
        next = PyIter_Next(iter);
        msghdr_index++;
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (char*)&m,
                                          (sizeof(struct mmsghdr) * num));
    Py_RETURN_NONE;
}

static PyMethodDef TraceReplayMethods[]  = {
    {"enable_debug_output", tracereplay_enable_debug_output,
     METH_VARARGS, "enable debug messages"},
    {"disable_debug_output", tracereplay_disable_debug_output,
     METH_VARARGS, "disable debug messages"},
    {"cont", tracereplay_cont, METH_VARARGS, "continue process under trace"},
    {"traceme", tracereplay_traceme, METH_VARARGS, "request tracing"},
    {"wait", tracereplay_wait, METH_VARARGS, "wait on child process"},
    {"syscall", tracereplay_syscall, METH_VARARGS, "wait for syscall"},
    {"peek_address", tracereplay_peek_address, METH_VARARGS, "peek address"},
    {"poke_address", tracereplay_poke_address, METH_VARARGS, "poke address"},
    {"peek_register", tracereplay_peek_register,
      METH_VARARGS, "peek register value"},
    {"poke_register", tracereplay_poke_register,
     METH_VARARGS, "poke register value"},
    {"write_poll_result", tracereplay_write_poll_result,
     METH_VARARGS, "write poll result"},
    {"populate_select_bitmaps", tracereplay_populate_select_bitmaps,
     METH_VARARGS, "populate select bitmaps"},
    {"populate_stat64_struct", tracereplay_populate_stat64_struct,
     METH_VARARGS, "populate stat64 struct"},
    {"populate_llseek_result", tracereplay_populate_llseek_result,
     METH_VARARGS, "populate llseek result"},
    {"populate_char_buffer", tracereplay_populate_char_buffer,
     METH_VARARGS, "populate char buffer"},
    {"populate_int", tracereplay_populate_int,
     METH_VARARGS, "populate int"},
    {"populate_uname_structure", tracereplay_populate_uname_structure,
     METH_VARARGS, "populate uname structure"},
    {"populate_rlimit_structure", tracereplay_populate_rlimit_structure,
     METH_VARARGS, "populate rlimit structure"},
    {"populate_tcgets_response", tracereplay_populate_tcgets_response,
     METH_VARARGS, "populate tcgets response"},
    {"populate_statfs64_structure",   tracreplay_populate_statfs64_structure,
     METH_VARARGS, "populate statfs64 structure"},
    {"populate_af_inet_sockaddr", tracereplay_populate_af_inet_sockaddr,
     METH_VARARGS, "populate AF_INET sockaddr"},
    {"write_sendmmsg_lengths", tracereplay_write_sendmmsg_lengths,
     METH_VARARGS, "populate sendmmsg lengths"},
    {"copy_bytes_into_child_process", tracereplay_copy_bytes_into_child_process,
     METH_VARARGS, "copy bytes into child process"},
    {"populate_timespec_structure", tracereplay_populate_timespec_structure,
     METH_VARARGS, "populate timespec structure"},
    {"populate_timeval_structure", tracereplay_populate_timeval_structure,
     METH_VARARGS, "populate timeval structure"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC inittracereplay(void) {
    PyObject* m;
    if((m = Py_InitModule("tracereplay", TraceReplayMethods)) == NULL) {
        return;
    }
    TraceReplayError = PyErr_NewException("tracereplay.TraceReplayError",
                                          NULL,
                                          NULL
                                         );
    Py_INCREF(TraceReplayError);
    PyModule_AddObject(m, "error", TraceReplayError);
    init_constants(m);
}
