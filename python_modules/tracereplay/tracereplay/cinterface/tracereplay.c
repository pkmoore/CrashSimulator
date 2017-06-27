#define _GNU_SOURCE
#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <python2.7/Python.h>
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
#include <sys/ioctl.h>
#include <dirent.h>
#include <sched.h>
#include <signal.h>
#include <sys/uio.h>

static PyObject* TraceReplayError;

bool DEBUG = false;
bool INFO = false;

int copy_child_process_memory_into_buffer(pid_t child,
                                          void* addr,
                                          unsigned char* buffer,
                                          size_t buf_length){
    unsigned char* buf_addr = buffer;
    size_t peeks = buf_length - (sizeof(int) - 1 );
    unsigned int i;
    if(DEBUG) {
        printf("C: peek_buffer: number of peeks: %d\n", peeks);
    }
    // Special case for buffers smaller than one 4 byte write
    if(buf_length < 4) {
        if(DEBUG) {
            printf("C: peek_buffer: got a small peek\n");
        }
        unsigned char temp_buffer[4];
        *((int*)&temp_buffer) = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
        if(DEBUG) {
            printf("Peeked data: ");
            for(i = 0; i < 4; i++) {
                printf("%02X ", temp_buffer[i]);
            }
            printf("\n");
        }
        for(i = sizeof(int); i > buf_length; i--) {
            temp_buffer[i-1] = buf_addr[i-1];
        }
        if(DEBUG) {
            printf("'Diff'd data: ");
            for(i = 0; i < 4; i++) {
                printf("%02X ", temp_buffer[i]);
            }
            printf("\n");
        }
        for(i = 0; i < buf_length; i++) {
            buf_addr[i] = temp_buffer[i];
        }
    }
    else {
        unsigned int t;
        for(i = 0; i < peeks; i++) {
            if(DEBUG) {
                printf("%d\n", peeks);
                printf("C: peek_buffer: peeking %p into %p\n", addr, &buf_addr[i]);
            }
            errno = 0;
            t = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
            if(errno != 0) {
                perror("C: peek_data: error string: ");
                PyErr_SetString(TraceReplayError,
                                "large peek failed in copy child\n");
            }
            if(DEBUG) {
                printf("%02X\n", t);
            }
            memcpy(&buf_addr[i], &t, sizeof(int));
            addr++;
        }
    }

    return 0;
}

int copy_buffer_into_child_process_memory(pid_t child,
                                          void* addr,
                                          const unsigned char* const buffer,
                                          size_t buf_length){
    size_t writes = buf_length - (sizeof(int) - 1 );
    unsigned int i;
    if(DEBUG) {
        printf("C: copy_buffer: number of writes: %d\n", writes);
        printf("C: copy_buffer: buffer data: \n");
        for(i = 0; i < buf_length; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("C: copy_buffer: buffer data(ASCII): \n");
        for(i = 0; i < buf_length; i++) {
                    printf("%c ", buffer[i]);
        }
        printf("\n");
    }
    // Special case for buffers smaller than one 4 byte write
    if(buf_length < 4) {
        if(DEBUG) {
            printf("C: copy_buffer: got a small write\n");
        }
        unsigned char temp_buffer[4];
        *((int*)&temp_buffer) = (int)ptrace(PTRACE_PEEKDATA, child, addr, NULL);
        if(DEBUG) {
            printf("Peeked data: ");
            for(i = 0; i < 4; i++) {
                printf("%02X ", temp_buffer[i]);
            }
            printf("\n");
        }
        for(i = 0; i < buf_length; i++) {
            temp_buffer[i] = buffer[i];
        }
        if(DEBUG) {
            printf("'Diff'd data: ");
            for(i = 0; i < 4; i++) {
                printf("%02X ", temp_buffer[i]);
            }
            printf("\n");
        }
        if((ptrace(PTRACE_POKEDATA, child, addr, *((int*)&temp_buffer)) == -1)) {
            PyErr_SetString(TraceReplayError,
                            "Failed to poke small buffer in copy buffer");
        }
    }
    else {
        for(i = 0; i < writes; i++) {
            if(DEBUG) {
                printf("C: copy_buffer: poking (%p)%08X into %p\n", &buffer[i],
                    *((int*)&buffer[i]), addr);
            }
            if((ptrace(PTRACE_POKEDATA, child, addr, *((int*)&buffer[i])) == -1)) {
                PyErr_SetString(TraceReplayError,
                                "Failed to poke large buffer in copy buffer\n");
            }
            addr++;
        }
    }
    return 0;
}

static PyObject* tracereplay_populate_readv_vectors(PyObject* self,
                                                    PyObject* args) {
    pid_t child;
    void* addr;
    PyObject* iovs;
    if(!PyArg_ParseTuple(args, "IIO", &child, &addr, &iovs)) {
        PyErr_SetString(TraceReplayError,
                        "populate_readv_vectors arg parse failed");
    }
    if(DEBUG) {
        printf("C: readv: pid: %d\n", child);
        printf("C: readv: addr: %p\n", addr);
    }
    if(!PyList_Check(iovs)) {
        PyErr_SetString(TraceReplayError,
                        "list of iovs is not a list");
    }
    PyObject* iter;
    PyObject* next;
    PyObject* iov_data_obj;
    PyObject* iov_len_obj;
    char* iov_data;
    unsigned int iov_struct_idx = 0;
    void* iov_base_ptr;
    unsigned int iov_len;
    size_t len_from_struct;
    
    iter = PyObject_GetIter(iovs);
    next = PyIter_Next(iter);

    while(next){
        if(!PyDict_Check(next)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-dict object in iovs list");
        }
        iov_data_obj = PyDict_GetItemString(next, "iov_data");
        if(!PyString_Check(iov_data_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-string object in iov_data");
        }
        iov_len_obj = PyDict_GetItemString(next, "iov_len");
        if(!PyInt_Check(iov_len_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in iov_len");
        }
        
        iov_data = PyString_AsString(iov_data_obj);
        iov_base_ptr = ((struct iovec*)addr)[iov_struct_idx].iov_base;
        len_from_struct = ((struct iovec*)addr)[iov_struct_idx].iov_len;
        iov_len = PyInt_AS_LONG(iov_len_obj);
        if(DEBUG) {
            printf("C: readv: iov_struct_idx: %d\n", iov_struct_idx);
            printf("C: readv: iov_base_ptr: %p\n", iov_base_ptr);
            printf("C: readv: iov_len: %d\n", iov_len);
            printf("C: readv: len_from_struct: %d\n", len_from_struct);
        }
        if(iov_len != 0) {
            copy_buffer_into_child_process_memory(child,
                                                  iov_base_ptr,
                                                  (unsigned char*)iov_data,
                                                  iov_len);
        }
        next = PyIter_Next(iter);
        iov_struct_idx++;
    }
    Py_RETURN_NONE;
}


struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static PyObject* tracereplay_populate_getdents64_structure(PyObject* self,
                                                           PyObject* args) {
    pid_t child;
    void* addr;
    PyObject* dents;
    size_t retlen;
    if(!PyArg_ParseTuple(args, "IIOI", &child, &addr, &dents, &retlen)) {
        PyErr_SetString(TraceReplayError,
                        "populate_getdents64_structure arg parse failed");
    }
    if(DEBUG) {
        printf("C: populate_getdents64: child %d\n", child);
        printf("C: populate_getdents64: addr %p\n", addr);
    }

    if(!PyList_Check(dents)) {
        PyErr_SetString(TraceReplayError,
                        "list of dents is not a list");
    }

    PyObject* iter;
    PyObject* next;

    PyObject* d_ino_obj;
    PyObject* d_name_obj;
    PyObject* d_reclen_obj;
    PyObject* d_type_obj;
    PyObject* d_off_obj;

    unsigned long d_ino;
    char* d_name;
    unsigned short d_reclen;
    char d_type;
    unsigned long d_off;



    unsigned char c_dents[retlen];
    memset(c_dents, 0, sizeof(c_dents));
    unsigned char* write_ptr = c_dents;
    iter = PyObject_GetIter(dents);
    next = PyIter_Next(iter);
    while(next) {
        if(!PyDict_Check(next)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-dict object in dents list");
        }
        d_ino_obj = PyDict_GetItemString(next, "d_ino");
        if(!PyInt_Check(d_ino_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_ino");
        }
        d_name_obj = PyDict_GetItemString(next, "d_name");
        if(!PyString_Check(d_name_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-string object in d_name");
        }
        d_reclen_obj = PyDict_GetItemString(next, "d_reclen");
        if(!PyInt_Check(d_reclen_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_reclen");
        }
        d_type_obj = PyDict_GetItemString(next, "d_type");
        if(!PyInt_Check(d_type_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_type");
        }
        d_off_obj = PyDict_GetItemString(next, "d_off");
        if(!PyInt_Check(d_off_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_off");
        }
        d_ino = (unsigned long)PyInt_AsLong(d_ino_obj);
        d_name = PyString_AsString(d_name_obj);
        d_off = (unsigned long)PyInt_AsLong(d_off_obj);
        d_reclen = (unsigned short)PyInt_AsLong(d_reclen_obj);
        d_type = (char)PyInt_AsLong(d_type_obj);
        if(DEBUG) {
            printf("C: populate_getdents64: d_ino: %lu\n", d_ino);
            printf("C: populate_getdents64: d_name: %s\n", d_name);
            printf("C: populate_getdents64: d_off: %lu\n", d_off);
            printf("C: populate_getdents64: d_reclen: %hu\n", d_reclen);
            printf("C: populate_getdents64: d_type: %d\n", (int)d_type);
            printf("C: populate_getdents64: strlen(d_name): %d\n",
                   strlen(d_name));
            printf("C: populate_getdents64: write_ptr: %p\n", write_ptr);
        }
        ((struct linux_dirent64*)write_ptr)->d_ino = d_ino;
        ((struct linux_dirent64*)write_ptr)->d_off = d_off;
        ((struct linux_dirent64*)write_ptr)->d_reclen = d_reclen;
        ((struct linux_dirent64*)write_ptr)->d_type = d_type;
        strcpy((((struct linux_dirent64*)write_ptr)->d_name),
               d_name);
        next = PyIter_Next(iter);
        if(DEBUG) {
            printf("C: populate_getdents64: d_ino: %llu\n",
                   ((struct linux_dirent64*)write_ptr)->d_ino);
            printf("C: populate_getdents64: d_name: %s\n",
                   ((struct linux_dirent64*)write_ptr)->d_name);
            printf("C: populate_getdents64: d_off: %lld\n",
                   ((struct linux_dirent64*)write_ptr)->d_off);
            printf("C: populate_getdents64: d_reclen: %hu\n",
                   ((struct linux_dirent64*)write_ptr)->d_reclen);
            printf("C: populate_getdents64: d_type: %d\n",
                   (int)((struct linux_dirent64*)write_ptr)->d_type);
            printf("C: populate_getdents64: strlen(d_name): %d\n",
                   strlen(d_name));
        }
        write_ptr += d_reclen;
        if(DEBUG) {
            printf("C: populate_getdents64: write_ptr: %p\n", write_ptr);
        }
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&c_dents,
                                          retlen);
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_getdents_structure(PyObject* self,
                                                         PyObject* args) {
    pid_t child;
    void* addr;
    PyObject* dents;
    size_t retlen;
    if(!PyArg_ParseTuple(args, "IIOI", &child, &addr, &dents, &retlen)) {
        PyErr_SetString(TraceReplayError,
                        "populate_getdents64_structure arg parse failed");
    }
    if(DEBUG) {
        printf("C: populate_getdents: child %d\n", child);
        printf("C: populate_getdents: addr %p\n", addr);
    }

    if(!PyList_Check(dents)) {
        PyErr_SetString(TraceReplayError,
                        "list of dents is not a list");
    }

    PyObject* iter;
    PyObject* next;

    PyObject* d_ino_obj;
    PyObject* d_name_obj;
    PyObject* d_reclen_obj;
    PyObject* d_type_obj;
    PyObject* d_off_obj;

    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char* d_name;
    char d_type;


    unsigned char c_dents[retlen];
    memset(c_dents, 0, sizeof(c_dents));
    unsigned char* write_ptr = c_dents;
    size_t s_offset;
    iter = PyObject_GetIter(dents);
    next = PyIter_Next(iter);
    while(next) {
        if(!PyDict_Check(next)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-dict object in dents list");
        }
        d_ino_obj = PyDict_GetItemString(next, "d_ino");
        if(!PyInt_Check(d_ino_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_ino");
        }
        d_name_obj = PyDict_GetItemString(next, "d_name");
        if(!PyString_Check(d_name_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-string object in d_name");
        }
        d_reclen_obj = PyDict_GetItemString(next, "d_reclen");
        if(!PyInt_Check(d_reclen_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_reclen");
        }
        d_type_obj = PyDict_GetItemString(next, "d_type");
        if(!PyInt_Check(d_type_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_type");
        }
        d_off_obj = PyDict_GetItemString(next, "d_off");
        if(!PyInt_Check(d_off_obj)) {
            PyErr_SetString(TraceReplayError,
                            "Encountered non-int object in d_off");
        }
        d_ino = (unsigned long)PyInt_AsLong(d_ino_obj);
        d_name = PyString_AsString(d_name_obj);
        d_off = (unsigned long)PyInt_AsLong(d_off_obj);
        d_reclen = (unsigned short)PyInt_AsLong(d_reclen_obj);
        d_type = (char)PyInt_AsLong(d_type_obj);
        if(DEBUG) {
            printf("C: populate_getdents: d_ino: %lu\n", d_ino);
            printf("C: populate_getdents: d_name: %s\n", d_name);
            printf("C: populate_getdents: d_off: %lu\n", d_off);
            printf("C: populate_getdents: d_reclen: %hu\n", d_reclen);
            printf("C: populate_getdents: d_type: %d\n", (int)d_type);
            printf("C: populate_getdents: strlen(d_name): %d\n",
                   strlen(d_name));
            printf("C: populate_getdents: write_ptr: %p\n", write_ptr);
        }
        s_offset = 0;
        memcpy(write_ptr + s_offset, &d_ino, sizeof(d_ino));
        s_offset += sizeof(d_ino);
        memcpy(write_ptr + s_offset, &d_off, sizeof(d_off)); 
        s_offset += sizeof(d_off);
        memcpy(write_ptr + s_offset, &d_reclen, sizeof(d_reclen));
        s_offset += sizeof(d_reclen);
        strcpy((char*)write_ptr + s_offset, d_name);
        s_offset += strlen(d_name);
        s_offset += 1;
        s_offset += 1;
        write_ptr[s_offset] = d_type;
        if(DEBUG) {
            printf("C: populate_getdents: s_offset: %d\n", s_offset);
        }
        next = PyIter_Next(iter);
        write_ptr += d_reclen;
        if(DEBUG) {
            printf("C: populate_getdents: write_ptr: %p\n", write_ptr);
        }
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&c_dents,
                                          retlen);
    Py_RETURN_NONE;
}
static PyObject* tracereplay_populate_pipefd_array(PyObject* self,
                                                   PyObject* args) {
    pid_t child;
    void* addr;
    unsigned int read_end;
    unsigned int write_end;
    if(!PyArg_ParseTuple(args, "IIII", &child, &addr, &read_end, &write_end)) {
        PyErr_SetString(TraceReplayError,
                        "populate_pipefd_array arg parse failed");
    }
    if(DEBUG) {
        printf("C: popiulate_pipefd_array: child %d\n", child);
        printf("C: popiulate_pipefd_array: addr %p\n", addr);
        printf("C: popiulate_pipefd_array: read_end: %d\n", read_end);
        printf("C: popiulate_pipefd_array: write_end %d\n", write_end);
    }
    int r[2];
    r[0] = read_end;
    r[1] = write_end;
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&r,
                                          (sizeof(int) * 2));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_copy_address_range(PyObject* self,
                                                PyObject* args) {
    // Unused paramater
    self = self;
    pid_t child;
    void* start;
    void* end;
    unsigned char* buf;
    if(!PyArg_ParseTuple(args, "III", &child, &start, &end)) {
        PyErr_SetString(TraceReplayError,
                        "copy_address_range arg parse failed");
    }
    if(DEBUG) {
        printf("C: copy_address_range: child: %d\n", child);
        printf("C: copy_address_range: start: %p\n", start);
        printf("C: copy_address_range: end: %p\n", end);
    }
    size_t size = end - start;
    if(DEBUG) {
        printf("C: copy_address_range: size: %d\n", size);
    }
    buf = (unsigned char*)malloc(size);
    copy_child_process_memory_into_buffer(child, start, buf, size);
    PyObject* result = Py_BuildValue("s#", buf, size);
    free(buf);
    return result;
}

static PyObject* tracereplay_populate_timespec_structure(PyObject* self,
                                                         PyObject* args) {
    // unused
    self = self;
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
    copy_buffer_into_child_process_memory(child, addr, (unsigned char*)&t, sizeof(t));
    Py_RETURN_NONE; 
}

static PyObject* tracereplay_populate_timeval_structure(PyObject* self,
                                                        PyObject* args) {
    // unused
    self = self;
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
    copy_buffer_into_child_process_memory(child, addr, (unsigned char*)&t, sizeof(t));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_copy_bytes_into_child_process(PyObject* self,
                                                          PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    unsigned char* bytes;
    Py_ssize_t num_bytes;
    if(!PyArg_ParseTuple(args, "iis#", &child, &addr, &bytes, &num_bytes)) {
        PyErr_SetString(TraceReplayError,
                        "copy_bytes failed parse failed");
    }
    int i;
    if(DEBUG) {
        printf("C: copy_bytes: child: %d\n", child);
        printf("C: copy_bytes: addr: %x\n", (int)addr);
        printf("C: copy_bytes: num_bytes %d\n", num_bytes);
        for(i = 0; i < num_bytes; i++) {
            printf("%02X ", bytes[i]);
        }
    } 
        copy_buffer_into_child_process_memory(child, addr, (unsigned char*)bytes, num_bytes);
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_winsize_structure(PyObject* self,
                                                        PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
    if(!PyArg_ParseTuple(args, "iihhhh", &child, &addr, &ws_row, &ws_col,
                         &ws_xpixel, &ws_ypixel)) {
        PyErr_SetString(TraceReplayError,
                        "pop_winsize parse fialed");
    }
    if(DEBUG) {
        printf("child: %d\n", child);
        printf("addr: %p\n", addr);
        printf("ws_row: %d\n", ws_row);
        printf("ws_col: %d\n", ws_col);
        printf("ws_xpixel: %d\n", ws_xpixel);
        printf("ws_ypixel: %d\n", ws_ypixel);
    }
    struct winsize w;
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&w, sizeof(w));
    w.ws_row = ws_row;
    w.ws_col = ws_col;
    w.ws_xpixel = ws_xpixel;
    w.ws_ypixel = ws_ypixel;
    if(DEBUG) {
        printf("w.ws_row: %d\n", w.ws_row);
        printf("w.ws_col: %d\n", w.ws_col);
        printf("w.ws_xpixel: %d\n", w.ws_xpixel);
        printf("w.ws_ypixel: %d\n", w.ws_ypixel);
    } 
    copy_buffer_into_child_process_memory(child, addr, (unsigned char*)&w, sizeof(w));
    struct winsize r;
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&r, sizeof(r));
    if(DEBUG) {
        printf("r.ws_row: %d\n", r.ws_row);
        printf("r.ws_col: %d\n", r.ws_col);
        printf("r.ws_xpixel: %d\n", r.ws_xpixel);
        printf("r.ws_ypixel: %d\n", r.ws_ypixel);
    } 
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_af_inet_sockaddr(PyObject* self,
                                                       PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    char* ip;
    unsigned short port;
    void* length_addr;
    socklen_t length;

    PyArg_ParseTuple(args, "iiHsii", &child, &addr,
                     &port, &ip, &length_addr, &length);
    if(DEBUG) {
        printf("C: pop af_inet: child: %d\n", child);
        printf("C: pop af_inet: addr: %p\n", addr);
        printf("C: pop af_inet: port: %d\n", port);
        printf("C: pop af_inet: ip: %s\n", ip);
        printf("C: pop af_inet: length: %d\n", length);
        printf("C: pop af_inet: sizeof(socklen_t): %d\n", sizeof(socklen_t));
    }
    struct sockaddr_in s;    
    if(DEBUG) {
        printf("C: pop af_inet: sizeof(s.sin_port): %d\n", sizeof(s.sin_port));
    }
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&s, sizeof(s));
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    inet_aton(ip, &s.sin_addr); 
    memset(&s.sin_zero, 0, 8);
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&s,
                                          sizeof(s));

    copy_buffer_into_child_process_memory(child,
                                          length_addr,
                                          (unsigned char*)&length,
                                          sizeof(length));
    Py_RETURN_NONE;
}

static PyObject* tracreplay_populate_statfs64_structure(PyObject* self,
                                                        PyObject* args) {
    // unused
    self = self;
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
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&s, sizeof(s));
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

    copy_buffer_into_child_process_memory(child, addr, (unsigned char*)&s, sizeof(s));
    Py_RETURN_NONE;
}


static PyObject* tracereplay_populate_tcgets_response(PyObject* self,
						      PyObject* args) {
    // unused
    self = self;
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

    struct k_termios
    {
        tcflag_t c_iflag;/* input mode flags */
        tcflag_t c_oflag;/* output mode flags */
        tcflag_t c_cflag;/* control mode flags */
        tcflag_t c_lflag;/* local mode flags */
        cc_t c_line;/* line discipline */
        cc_t c_cc[19];/* control characters */
    };

    struct k_termios t;
    t.c_iflag = c_iflag;
    t.c_oflag = c_oflag;
    t.c_cflag = c_cflag;
    t.c_lflag = c_lflag;
    t.c_line = c_line;
    for(i = 0; i < 19; i++) {
        t.c_cc[i] = cc_bytes[i];
    }
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
                                          (unsigned char*)&t,
                                          17 + 19);
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_rlimit_structure(PyObject* self,
                                                       PyObject* args) {
    // unused
    self = self;
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
    if(DEBUG) {
        printf("C: sizeof(rlimit64) %d\n", sizeof(struct rlimit64));
        printf("C: sizeof(rlimit) %d\n", sizeof(struct rlimit));
        printf("C: sizeof(cur) %d\n", sizeof(s.rlim_cur));
        printf("C: cur %llx\n", s.rlim_cur);
        printf("C: sizeof(max) %d\n", sizeof(s.rlim_max));
        printf("C: max %llx\n", s.rlim_max);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&s,
                                          sizeof(s));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_uname_structure(PyObject* self,
                                                     PyObject* args) {
    // unused
    self = self;
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
                                          (unsigned char*)&s,
                                          sizeof(s));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_char_buffer(PyObject* self,
                                                  PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    unsigned char* data;
    long int data_length;
    PyArg_ParseTuple(args, "iis#", (int*)&child, (int*)&addr,
                     &data, &data_length);
    if(DEBUG) {
        printf("C: pop_char_buf: child: %d\n", child);
        printf("C: pop_char_buf: addr: %x\n", (int)addr);
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
    // unused
    self = self;
    pid_t child;
    void* addr;
    int data;
    if(!PyArg_ParseTuple(args, "iii", &child, &addr, &data)) {
        PyErr_SetString(TraceReplayError,
                        "populate_int arg parse failed");
    }
    if(DEBUG) {
        printf("C: pop_int: child: %d\n", child);
        printf("C: pop_int: addr: %p\n", addr);
        printf("C: pop_int: data: %d\n", data);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&data,
                                          sizeof(int));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_unsigned_int(PyObject* self,
                                          PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    int data;
    if(!PyArg_ParseTuple(args, "III", &child, &addr, &data)) {
        PyErr_SetString(TraceReplayError,
                        "populate_int arg parse failed");
    }
    if(DEBUG) {
        printf("C: pop_unsigned_int: child: %d\n", child);
        printf("C: pop_unsigned_int: addr: %p\n", addr);
        printf("C: pop_unsigned_int: data: %d\n", data);
    }
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&data,
                                          sizeof(int));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_stack_structure(PyObject* self,
                                                      PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    void* ss_sp;
    int ss_flags;
    size_t ss_size;

    if(!PyArg_ParseTuple(args, "iiiiI", (int*)&child,
                         (int*)&addr,
                         (int*)&ss_sp,
                         (int*)&ss_flags,
                         (unsigned int*)&ss_size)) {
        PyErr_SetString(TraceReplayError,
                        "populate_stack arg parse failed");
    }
    if(DEBUG) {
        printf("C: populate_stack: child %d\n", (int)child);
        printf("C: populate_stack: addr: %d\n", (int)addr);
        printf("C: populate_stack: ss_sp: %d\n", (int)ss_sp);
        printf("C: populate_stack: ss_flags: %d\n", (int)ss_flags);
        printf("C: populate_stack: ss_size: %u\n", (unsigned int)ss_size);
    }

    stack_t s;
    s.ss_sp = ss_sp;
    s.ss_flags = ss_flags;
    s.ss_size = ss_size;
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&s,
                                          sizeof(s));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_cpu_set(PyObject* self,
                                              PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    int cpu_value;
    if(!PyArg_ParseTuple(args, "iii", (int*)&child,
                                      (int*)&addr,
                                      (int*)&cpu_value)) {
        PyErr_SetString(TraceReplayError,
                        "populate_cpu_set arg parse failed");
    }
    if(DEBUG) {
        printf("C: cpu_set: child: %d\n", (int)child);
        printf("C: cpu_set: addr: %d\n", (int)addr);
        printf("C: cpu_set: cpu_value: %d\n", (int)cpu_value);
    }
    cpu_set_t set;
    CPU_SET(cpu_value, &set);
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&set,
                                          sizeof(set));
    Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_llseek_result(PyObject* self,
                                                    PyObject* args) {
    // unused
    self = self;
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
                                          (unsigned char*)&result,
                                          sizeof(long long));
    Py_RETURN_NONE;
}

struct kernel_sigaction {
  __sighandler_t k_sa_handler;
  unsigned int sa_flags;
  void* sa_restorer;
  sigset_t sa_mask;
};

static PyObject* tracereplay_populate_rt_sigaction_struct(PyObject* self,
		 					  PyObject* args) {
  if (DEBUG) printf("C: Entering populate rt_sigaction_struct\n");

  self = self;
  pid_t child;

  struct kernel_sigaction oldact;
  void*         oldact_addr; 
  int           old_sa_handler; // this could also be void * but not yet implemented
  PyObject*     mask_sig_list;
  sigset_t      old_sa_mask;
  unsigned int  old_sa_flags;
  void*         old_sa_restorer;  // no longer used, but in sigaction struct when VDSO off
  //  void*     old_sa_sigaction = NULL; // use not implemented yet, see kernelhandlers.py

  bool argument_population_failed = !PyArg_ParseTuple(args,
  						      "IIIOII",
  						      &child,
    						      &oldact_addr,
    						      &old_sa_handler,
						      &mask_sig_list,
   						      &old_sa_flags,
						      &old_sa_restorer);

  if (argument_population_failed) {
    PyErr_SetString(TraceReplayError, "populate rt_sigaction data failed");
  }

  if (DEBUG) {
    printf("C: populate_sigaction: read arguments: child %d \n", child);
    printf("C: populate_sigaction: read arguments: oldact_addr %p \n", oldact_addr);
    printf("C: populate_sigaction: read arguments: sa_handler %d \n",  old_sa_handler);
    printf("C: populate_sigaction: read arguments: old_sa_flags %d at %p \n", old_sa_flags, &old_sa_mask);
    printf("C: populate_sigaction: read arguments: sa_restorer %p \n",  old_sa_restorer);
   }
  
  
  // setup memory for copying oldact in
    copy_child_process_memory_into_buffer(child, oldact_addr, (unsigned char*)&oldact, sizeof(oldact));

  // Note: cant set handler and sigaction at same time as use same memory
  oldact.k_sa_handler = (void*) old_sa_handler;
  oldact.sa_flags = old_sa_flags;
  oldact.sa_restorer = old_sa_restorer;
  
  // create sa_mask sigset_t from mask_sig_list
  sigemptyset(&oldact.sa_mask);

  PyObject* iter = PyObject_GetIter(mask_sig_list);
  PyObject* next = PyIter_Next(iter);
  while (next) {
    if (!PyInt_Check(next)) {
      PyErr_SetString(TraceReplayError, "Encountered non-Int in mask list");
    }
    
    int sig = (int)PyInt_AsLong(next);
    sigaddset(&oldact.sa_mask, sig);
   
    if (DEBUG) {
      printf("C: populate rt_sigation: signal %d added to mask \n", sig);
      printf("C: populate rt_sigaction: Mask: %x \n", &oldact.sa_mask);
    }
    
    next = PyIter_Next(iter);
  }

  // copy oldact into memory
  copy_buffer_into_child_process_memory(child, oldact_addr, (unsigned char*)&oldact, sizeof(oldact));

  // copy back out of memory to read / test values
  struct kernel_sigaction test;
  copy_child_process_memory_into_buffer(child, oldact_addr, (unsigned char*)&test, sizeof(test));


   if (DEBUG) {
     printf("C: Read sigaction: sigaction at %p \n", &test);
     printf("C: Read sigaction: sa_handler %d at %p \n", (int) test.k_sa_handler, &(test.k_sa_handler));
     printf("C: Read sigaction: sa_flags %d at %p \n", test.sa_flags, &(test.sa_flags));
     printf("C: Read sigaction: sa_mask 0x%x at %p \n", test.sa_mask, &test.sa_mask);     
     printf("C: Read sigaction: sa_restorer %p at %p \n", test.sa_restorer, &(test.sa_restorer));    
   }

  Py_RETURN_NONE;
}

static PyObject* tracereplay_populate_stat64_struct(PyObject* self,
                                                    PyObject* args) {
    // unused
    self = self;
    struct stat64 s;
    pid_t child;
    void* addr;
    int st_dev1;
    int st_dev2;
    int st_rdev1;
    int st_rdev2;
    dev_t     st_dev;     /*  8 ID of device containing file */
    ino_t     st_ino;     /* 8 inode number */
    mode_t    st_mode;    /* 4 protection */
    nlink_t   st_nlink;   /* 4 number of hard links */
    uid_t     st_uid;     /* 4 user ID of owner */
    gid_t     st_gid;     /* 4 group ID of owner */
    dev_t     st_rdev;    /* 8 device ID (if special file) */
    off_t     st_size;    /* 8 total size, in bytes */
    blksize_t st_blksize; /* 4 blocksize for file system I/O */
    blkcnt_t  st_blocks;  /* 8 number of 512B blocks allocated */
    time_t st__ctime;
    time_t st__mtime;
    time_t st__atime;
    char buffer[100];

    if(!PyArg_ParseTuple(args, "iiiiKiiiiiKiiKiii", &child, &addr, &st_dev1, &st_dev2,
                    &st_blocks,    (int*)&st_nlink,  (int*)&st_gid,
                    (int*)&st_blksize,   (int*)&st_rdev1,  (int*)&st_rdev2,
                    &st_size,      (int*)&st_mode,
                    (int*)&st_uid,       &st_ino,    (int*)&st__ctime,
                    (int*)&st__mtime,    (int*)&st__atime)) {
        PyErr_SetString(TraceReplayError,
                        "populate_stat64_struct arg parse fialed");
    }
    if(DEBUG) {
        printf("C: populate_stat64: child %d\n", child);
        printf("C: populate_stat64: addr %p\n", addr);
        printf("C: populate_stat64: s %p\n", &s);
        printf("C: populate_stat64: sizeof(s) %d\n", sizeof(s));
    }
    st_dev = makedev(st_dev1, st_dev2);
    st_rdev = makedev(st_rdev1, st_rdev2);

    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&s, sizeof(s));
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
    s.st_ctim.tv_nsec = 0;
    s.st_mtime = st__mtime;
    s.st_mtim.tv_nsec = 0;
    s.st_atime = st__atime;
    s.st_atim.tv_nsec = 0;


    if(DEBUG) {
        printf("sizeof(st.st_dev): %d\n", sizeof(s.st_dev));
        printf("s.st_dev: %llu\n", s.st_dev);
        printf("sizeof(s.st_rdev): %d\n", sizeof(s.st_rdev));
        printf("s.st_rdev: %llu\n", s.st_rdev);
        printf("sizeof(s.st_ino): %d\n", sizeof(s.st_ino));
        printf("s.st_ino: %llu\n", s.st_ino);
        printf("sizeof(s.st_mode): %d\n", sizeof(s.st_mode));
        printf("s.st_mode: %d\n", s.st_mode);
        printf("sizeof(s.st_nlink): %d\n", sizeof(s.st_nlink));
        printf("s.st_nlink: %d\n", s.st_nlink);
        printf("sizeof(s.st_uid): %d\n", sizeof(s.st_uid));
        printf("s.st_uid: %d\n", s.st_uid);
        printf("sizeof(s.st_gid): %d\n", sizeof(s.st_gid));
        printf("s.st_gid: %d\n", s.st_gid);
        printf("sizeof(s.st_size): %d\n", sizeof(s.st_size));
        printf("s.st_size: %llu\n", s.st_size);
        printf("sizeof(s.st_blksize): %d\n", sizeof(s.st_blksize));
        printf("s.st_blksize: %ld\n", s.st_blksize);
        printf("sizeof(s.st_blocks): %d\n", sizeof(s.st_blocks));
        printf("s.st_blocks: %llu\n", s.st_blocks);

        strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&s.st_ctime));
        printf("s.st_ctime: %s\n", buffer);
        strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&s.st_mtime));
        printf("s.st_mtime: %s\n", buffer);
        strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&s.st_atime));
        printf("s.st_atime: %s\n", buffer);
    }
    
    copy_buffer_into_child_process_memory(child,
                                          addr,
                                          (unsigned char*)&s,
                                          sizeof(s));
    if(DEBUG) {
        struct stat64 r;
        copy_child_process_memory_into_buffer(child, addr,
                                              (unsigned char*)&r, sizeof(r));
            strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&r.st_ctime));
            printf("r.st_ctime: %s\n", buffer);
            strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&r.st_mtime));
            printf("r.st_mtime: %s\n", buffer);
            strftime(buffer, 20, "%Y/%m/%d %H:%M:%S", localtime(&r.st_atime));
            printf("r.st_atime: %s\n", buffer);
            printf("!!!!!!\n");
            printf("r.st_ctime: %lld\n", (long long)r.st_ctime);
            printf("r.st_mtime: %lld\n", (long long)r.st_mtime);
            printf("r.st_atime: %lld\n", (long long)r.st_atime);
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_get_select_fds(PyObject* self,
                                            PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;

    if(!PyArg_ParseTuple(args, "ii", &child, &addr)) {
        PyErr_SetString(TraceReplayError,
                        "C: get_select_fds: arg parse failed");
    }
    if(DEBUG) {
        printf("C: get_select_fds: child: %d\n", child);
        printf("C: get_select_fds: addr: %p\n", addr);
    }
    PyObject* list = PyList_New(0);
    int i;
    fd_set t;
    copy_child_process_memory_into_buffer(child,
                                          addr,
                                          (unsigned char*)&t,
                                          sizeof(fd_set));
    for(i = 0; i < FD_SETSIZE; i++) {
        if(FD_ISSET(i, &t)) {
            if(DEBUG) {
                printf("C: get_select_fds: fd %d is set\n", i);
            }
            PyList_Append(list, PyInt_FromLong(i));
        }
    }
    return list;
}

static PyObject* tracereplay_populate_select_bitmaps(PyObject* self,
                                                     PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* readfds_addr;
    PyObject* readfds_list;
    void* writefds_addr;
    PyObject* writefds_list;
    void* exceptfds_addr;
    PyObject* exceptfds_list;

    PyArg_ParseTuple(args, "iiOiOiO",
                     &child,
                     &readfds_addr,
                     &readfds_list,
                     &writefds_addr,
                     &writefds_list,
                     &exceptfds_addr,
                     &exceptfds_list);
    if(DEBUG) {
        printf("C: Select: child: %d\n", child);
        printf("C: Select: readfds_addr: %p\n", readfds_addr);
        printf("C: Select: write_addr: %p\n", writefds_addr);
        printf("C: Select: exceptfds_addr: %p\n", exceptfds_addr);
    }
    fd_set tmp;
    PyObject* next;
    size_t fd;
    if(!PyList_Check(readfds_list)) {
        PyErr_SetString(TraceReplayError,
                        "readfds_list received in C code is not a list");
    }
    if(!PyList_Check(writefds_list)) {
        PyErr_SetString(TraceReplayError,
                        "writefds_list received in C code is not a list");
    }
    if(!PyList_Check(exceptfds_list)) {
        PyErr_SetString(TraceReplayError,
                        "except_list received in C code is not a list");
    }
    PyObject* iter;
    if(readfds_addr != 0) {
        if(!(iter = PyObject_GetIter(readfds_list))) {
            PyErr_SetString(TraceReplayError,
                            "Couldn't get iterator for list of readfds");
        }
        if(DEBUG) {
            printf("C: Select: About to parse readfds\n");
        }
        next = PyIter_Next(iter);
        copy_child_process_memory_into_buffer(child, readfds_addr,
                                               (unsigned char*)&tmp, sizeof(tmp));
        FD_ZERO(&tmp);
        while(next) {
            if(!PyInt_Check(next)) {
                PyErr_SetString(TraceReplayError,
                                "Encountered non-Int in list of readfds");
            }
            fd = PyInt_AsSsize_t(next);
            if(DEBUG) {
                printf("C: Socket: got readfd %d\n", fd);
            }
            FD_SET((int)fd, &tmp);
            next = PyIter_Next(iter);
        }
        copy_buffer_into_child_process_memory(child, readfds_addr,
                                            (unsigned char*)&tmp, sizeof(tmp));

    }
    if(writefds_addr != 0 ) {
        if(!(iter = PyObject_GetIter(writefds_list))) {
            PyErr_SetString(TraceReplayError,
                            "Couldn't get iterator for list of writefds");
        }
        if(DEBUG) {
            printf("C: Select: About to parse writefds\n");
        }
        next = PyIter_Next(iter);
        copy_child_process_memory_into_buffer(child, writefds_addr,
                                               (unsigned char*)&tmp, sizeof(tmp));

        FD_ZERO(&tmp);
        while(next) {
            if(!PyInt_Check(next)) {
                PyErr_SetString(TraceReplayError,
                                "Encountered non-Int in list of writefds");
            }
            fd = PyInt_AsSsize_t(next);
            if(DEBUG) {
                printf("C: select: got writefd %d\n", fd);
            }
            FD_SET((int)fd, &tmp);
            next = PyIter_Next(iter);
        }
        copy_buffer_into_child_process_memory(child, writefds_addr,
                                            (unsigned char*)&tmp, sizeof(tmp));
    }
    if(exceptfds_addr != 0) {
        if(!(iter = PyObject_GetIter(exceptfds_list))) {
            PyErr_SetString(TraceReplayError,
                            "Couldn't get iterator for list of exceptfds");
        }
        if(DEBUG) {
            printf("C: Select: About to parse except\n");
        }
        next = PyIter_Next(iter);
        copy_child_process_memory_into_buffer(child, exceptfds_addr,
                                               (unsigned char*)&tmp, sizeof(tmp));
        FD_ZERO(&tmp);
        while(next) {
            if(!PyInt_Check(next)) {
                PyErr_SetString(TraceReplayError,
                                "Encountered non-Int in list of exceptfds");
            }
            fd = PyInt_AsSsize_t(next);
            if(DEBUG) {
                printf("C: select: got exceptfd %d\n", fd);
            }
            FD_SET((int)fd, &tmp);
            next = PyIter_Next(iter);
        }
        copy_buffer_into_child_process_memory(child, exceptfds_addr,
                                            (unsigned char*)&tmp, sizeof(tmp));
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_is_select_fd_set(PyObject* self, PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* fdset_addr;
    int fd;
    if(!PyArg_ParseTuple(args, "iii", &child, &fdset_addr, &fd)) {
        PyErr_SetString(TraceReplayError,
                        "is_selet_fd_set arg parse failed");
    }
    if(DEBUG) {
        printf("C: is_select_fd: child: %d\n", child);
        printf("C: is_select_fd: fdset_addr: %p\n", fdset_addr);
        printf("C: is_select_fd: fd: %d\n", fd);
    }
    fd_set tmp;
    copy_child_process_memory_into_buffer(child,
                                          fdset_addr,
                                          (unsigned char*)&tmp,
                                          sizeof(tmp));
    unsigned int i;
    if(DEBUG) {
        printf("C: is_select_fd: ");
        for(i = 0; i < sizeof(tmp); i++) {
            printf("%02X ", *((unsigned char*)&tmp + i));
        }
    }
    if(FD_ISSET(fd, &tmp)) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}
        

static PyObject* tracereplay_enable_debug_output(PyObject* self, PyObject* args) {
    //unused
    self = self;
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
    //unused
    self = self;
    args = args;
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
    if(PyModule_AddIntConstant(m,
                               "CLOCK_PROCESS_CPUTIME_ID",
                               CLOCK_PROCESS_CPUTIME_ID) == -1) {
        return;
    }
}

static PyObject* tracereplay_peek_register(PyObject* self, PyObject* args) {
    // unused
    self = self;
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
    // unused
    self = self;
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
    // unused
    self = self;
    pid_t child;
    PyArg_ParseTuple(args, "i", &child);
    errno = 0;
    if(ptrace(PTRACE_CONT, child, NULL, NULL) == -1) {
        perror("Cont failed");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_traceme(PyObject* self, PyObject* args) {
    // unused
    self = self;
    args = args;
    errno = 0;
    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("Traceme failed");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_wait(PyObject* self, PyObject* args) {
    // unused
    self = self;
    args = args;
    int status;
    if(wait(&status) == -1) {
        perror("Wait failed");
    }
    return Py_BuildValue("i", status);
}

static PyObject* tracereplay_syscall(PyObject* self, PyObject* args) {
    // unused
    self = self;
    pid_t child;
    PyArg_ParseTuple(args, "i", &child);
    errno = 0;
    if(ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
        perror("Cont failed");
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_poke_address(PyObject* self, PyObject* args) {
    // unused
    self = self;
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
    // unused
    self = self;
    pid_t child;
    int address;
    long int value;
    PyArg_ParseTuple(args, "ii", &child, &address);
    errno = 0;
    value = ptrace(PTRACE_PEEKDATA, child, address, NULL);
    if(errno != 0) {
        perror("Peek into userspace failed");
        PyErr_SetString(TraceReplayError, "peek_address peek failed");
    }
    return Py_BuildValue("i", value);
}

static PyObject* tracereplay_write_poll_result(PyObject* self, PyObject* args) {
    // unused
    self = self;
    pid_t child;
    void* addr;
    short fd;
    short re;
    struct pollfd s;
    if(!PyArg_ParseTuple(args, "iihh", &child, (int*)&addr, &fd, &re)) {
        PyErr_SetString(TraceReplayError, "write_poll_result arg parse failed");
    }
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&s, sizeof(s));
    s.fd = fd;
    s.revents = re;
    if(DEBUG) {
        printf("POLLOUT: %d\n", POLLOUT);
        printf("POLLIN: %d\n", POLLIN);
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
                                          (unsigned char*)&s,
                                          sizeof(struct pollfd));
    struct pollfd r;
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&r, sizeof(r));
    if(DEBUG) {
        printf("C: FD %d\n", r.fd);
        printf("C: E %d\n", r.events);
        printf("C: RE %d\n", r.revents);
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_write_sendmmsg_lengths(PyObject* self,
                                                    PyObject* args) {
    // unused
    self = self;
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
    unsigned char* b = (unsigned char*)m;
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&m, (sizeof(struct mmsghdr) * num));
    unsigned int i;
    for(i = 0; i < sizeof(m); i++) {
        printf("%02X ", b[i]);
    }
    printf("\n");
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
                                          (unsigned char*)&m,
                                          (sizeof(struct mmsghdr) * num));
    struct mmsghdr r[num];
    copy_child_process_memory_into_buffer(child, addr, (unsigned char*)&r, sizeof(r));
    if(DEBUG) {
        for(i = 0; i < num; i++) {
            printf("C: sendmmsg_lengths: length %d: %d\n", i, r[i].msg_len);
        }
    }
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
    {"populate_rt_sigaction_struct", tracereplay_populate_rt_sigaction_struct,
     METH_VARARGS, "populate rt_sigaction struct"},
    {"populate_stat64_struct", tracereplay_populate_stat64_struct,
     METH_VARARGS, "populate stat64 struct"},
    {"populate_llseek_result", tracereplay_populate_llseek_result,
     METH_VARARGS, "populate llseek result"},
    {"populate_char_buffer", tracereplay_populate_char_buffer,
     METH_VARARGS, "populate char buffer"},
    {"populate_int", tracereplay_populate_int,
     METH_VARARGS, "populate int"},
    {"populate_unsigned_int", tracereplay_populate_unsigned_int,
     METH_VARARGS, "populate unsigned int"},
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
    {"populate_winsize_structure", tracereplay_populate_winsize_structure,
     METH_VARARGS, "populate winsize structure"},
    {"is_select_fd_set", tracereplay_is_select_fd_set,
     METH_VARARGS, "is select fd set"},
    {"copy_address_range", tracereplay_copy_address_range,
     METH_VARARGS, "copy address range"},
    {"populate_pipefd_array", tracereplay_populate_pipefd_array,
     METH_VARARGS, "populate pipefd array"},
    {"get_select_fds", tracereplay_get_select_fds,
     METH_VARARGS, "get select fds"},
    {"populate_getdents64_structure", tracereplay_populate_getdents64_structure,
     METH_VARARGS, "populate getdents64 structure"},
    {"populate_getdents_structure", tracereplay_populate_getdents_structure,
     METH_VARARGS, "populate getdents structure"},
    {"populate_cpu_set", tracereplay_populate_cpu_set,
     METH_VARARGS, "populate cpu_set"},
    {"populate_stack_structure", tracereplay_populate_stack_structure,
     METH_VARARGS, "populate_stack_structure"},
    {"populate_readv_vectors", tracereplay_populate_readv_vectors,
    METH_VARARGS, "populate_readv_vectors"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initcinterface(void) {
    PyObject* m;
    if((m = Py_InitModule("tracereplay.cinterface", TraceReplayMethods)) == NULL) {
        return;
    }
    TraceReplayError = PyErr_NewException("cinterface.TraceReplayError",
                                          NULL,
                                          NULL
                                         );
    Py_INCREF(TraceReplayError);
    PyModule_AddObject(m, "error", TraceReplayError);
    init_constants(m);
}
