cdef extern from "scribe.h":
    ctypedef int scribe_ctx_t

    cdef int scribe_ctx_create(scribe_ctx_t *scribe_ctx) nogil
    cdef int scribe_ctx_destroy(scribe_ctx_t scribe_ctx) nogil
