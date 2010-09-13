cimport scribe

class ScribeContext:
    def __init__(self):
        cdef int ctx
        err = scribe_ctx_create(&ctx)
        if err != 0:
            raise IOError
        self.ctx = ctx

    def __del__(self):
        scribe_ctx_destroy(self.ctx)
