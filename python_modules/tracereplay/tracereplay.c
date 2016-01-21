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

static PyObject* TraceReplayError;

bool DEBUG = false;

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
    DEBUG = true;
    Py_RETURN_NONE;
}

static PyObject* tracereplay_disable_debug_output(PyObject* self, PyObject* args) {
    DEBUG = false;
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
    int address;
    short fd;
    short re;
    char buffer[sizeof(struct pollfd)];
    struct pollfd* s = (struct pollfd*)buffer;
    size_t writes = sizeof(struct pollfd) / sizeof(void*);
    if(!PyArg_ParseTuple(args, "iihh", &child, &address, &fd, &re)) {
        PyErr_SetString(TraceReplayError, "write_poll_result arg parse failed");
    }
    s->fd = fd;
    s->events = 0;
    s->revents = re;
    int i = 0;
    if(DEBUG) {
        printf("E Size: %d\n", sizeof(s->events));
        printf("FD Size: %d\n", sizeof(s->fd));
        printf("RE Size: %d\n", sizeof(s->revents));
        printf("C: Buffer:\n");
        for(i = 0; i < sizeof(buffer); i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
        printf("C: sizeof(struct pollfd) = %d\n", sizeof(struct pollfd));
        printf("C: FD %d\n", s->fd);
        printf("C: E %d\n", s->events);
        printf("C: RE %d\n", s->revents);
        printf("C: Writes %d\n", writes);
    }
    int* writeptr;
    writeptr = (int*)buffer;
    if(DEBUG) {
        printf("Writing: %d\n", *writeptr);
    }
    if(ptrace(PTRACE_POKEDATA,
              child,
              address,
              *writeptr
              ) == -1) {
        PyErr_SetString(TraceReplayError,
                        "Failed to poke when writing pollfd struct");
    }
    writeptr = (int*)(&buffer[4]);
    if(DEBUG) {
        printf("Writing: %d\n", *writeptr);
    }
    if(ptrace(PTRACE_POKEDATA,
              child,
              address+4,
              *writeptr
              ) == -1) {
        PyErr_SetString(TraceReplayError,
                        "Failed to poke when writing pollfd struct");
    }
    char tmp_buf[4];
    int* tmp = (int*)tmp_buf;
    if(DEBUG) {
        printf("Values read back from child process:\n");
        *tmp = ptrace(PTRACE_PEEKDATA, child, address, NULL);
        for(i = 0; i < sizeof(tmp_buf); i++) {
            printf("%02X ", tmp_buf[i]);
        }
        printf("\n");
        *tmp = ptrace(PTRACE_PEEKDATA, child, address+4, NULL);
        for(i = 0; i < sizeof(tmp_buf); i++) {
            printf("%02X ", tmp_buf[i]);
        }
        printf("\n");
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
