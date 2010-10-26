from libc.stdlib cimport *
from libc.errno cimport *
from scribe_api cimport *
import os

cdef void on_backtrace(void *private_data, loff_t *log_offset, int num) with gil:
    # We can't use generators because of cython limitations
    log_offsets = list(log_offset[i] for i in range(num))
    (<Context>private_data).on_backtrace(log_offsets)

cdef void on_diverge(void *private_data, scribe_event_diverge *event) with gil:
    (<Context>private_data).on_diverge()

cdef scribe_operations ops = {
    'on_backtrace': on_backtrace,
    'on_diverge': on_diverge
}

cdef class Context:
    cdef scribe_context_t _ctx

    def __init__(self):
        err = scribe_context_create(&self._ctx, &ops, <void *>self)
        if err:
            raise OSError(errno, os.strerror(errno))

    def __del__(self):
        scribe_context_destroy(self._ctx)

    def record(self, logfile, args, custom_init_process=False):
        cdef char **_args
        flags = 0
        flags |= CUSTOM_INIT_PROCESS if custom_init_process else 0

        bargs = list(arg.encode() for arg in args)
        _args = <char **>malloc(sizeof(char *) * (len(args) + 1))
        if not _args:
            raise MemoryError
        try:
            for i, barg in zip(range(len(bargs)), bargs):
                _args[i] = barg
            _args[len(bargs)] = NULL

            err = scribe_record(self._ctx, flags, logfile.fileno(), _args)
            if err:
                raise OSError(errno, os.strerror(errno))

        finally:
            free(_args)

    def replay(self, logfile, backtrace_len=100):
        err = scribe_replay(self._ctx, 0, logfile.fileno(), backtrace_len)
        if err:
            raise OSError(errno, os.strerror(errno))

    def on_backtrace(self, log_offsets):
        pass

    def on_diverge(self):
        pass
