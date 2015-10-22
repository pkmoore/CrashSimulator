#include <Python.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/reg.h>

static PyObject* tracereplay_get_EAX(PyObject* self, PyObject* args) {
    pid_t child;
    long int extracted_eax;
    PyArg_ParseTuple(args, "i", &child);
    errno = 0;
    extracted_eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, 0);
    if(errno != 0) {
        perror("Peek failed");
        return NULL;
    }
    return Py_BuildValue("i", extracted_eax);
}

static PyObject* tracereplay_set_EAX(PyObject* self, PyObject* args) {
    pid_t child;
    long int return_value;
    PyArg_ParseTuple(args, "ii", &child, &return_value);
    errno = 0;
    ptrace(PTRACE_POKEUSER, child, 4 * EAX, return_value);
    if(errno != 0) {
        perror("Poke failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject* tracereplay_get_EBX(PyObject* self, PyObject* args) {
    pid_t child;
    long int extracted_ebx;
    PyArg_ParseTuple(args, "i", &child);
    errno = 0;
    extracted_ebx = ptrace(PTRACE_PEEKUSER, child, 4 * EBX, 0);
    if(errno != 0) {
        perror("Peek failed");
        return NULL;
    }
    return Py_BuildValue("i", extracted_ebx);
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

static PyMethodDef TraceReplayMethods[]  = {
    {"cont", tracereplay_cont, METH_VARARGS, "continue process under trace"},
    {"traceme", tracereplay_traceme, METH_VARARGS, "request tracing"},
    {"wait", tracereplay_wait, METH_VARARGS, "wait on child process"},
    {"syscall", tracereplay_syscall, METH_VARARGS, "wait for syscall"},
    {"get_EAX", tracereplay_get_EAX, METH_VARARGS, "get EAX"},
    {"set_EAX", tracereplay_set_EAX, METH_VARARGS, "set EAX"},
    {"get_EBX", tracereplay_get_EBX, METH_VARARGS, "get EBX"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC inittracereplay(void) {
    Py_InitModule("tracereplay", TraceReplayMethods);
}
