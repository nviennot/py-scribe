cdef extern from "linux/types.h":
    ctypedef long long loff_t
    ctypedef unsigned char __u8
    ctypedef unsigned short __u16
    ctypedef unsigned int __u32
    ctypedef unsigned long __u64
    ctypedef char __s8
    ctypedef short __s16
    ctypedef int __s32
    ctypedef long __s64
    ctypedef int pid_t

cdef extern from "linux/scribe_api.h" nogil:
    enum: EDIVERGE

    enum scribe_event_type:
        SCRIBE_EVENT_INIT = 1
        SCRIBE_EVENT_PID
        SCRIBE_EVENT_DATA
        SCRIBE_EVENT_SYSCALL
        SCRIBE_EVENT_SYSCALL_END
        SCRIBE_EVENT_QUEUE_EOF
        # userspace -> kernel commands
        SCRIBE_EVENT_ATTACH_ON_EXECVE
        SCRIBE_EVENT_RECORD
        SCRIBE_EVENT_REPLAY
        SCRIBE_EVENT_STOP
        # kernel -> userspace notifications
        SCRIBE_EVENT_BACKTRACE
        SCRIBE_EVENT_CONTEXT_IDLE
        SCRIBE_EVENT_DIVERGE_EVENT_TYPE
        SCRIBE_EVENT_DIVERGE_EVENT_SIZE
        SCRIBE_EVENT_DIVERGE_DATA_TYPE
        SCRIBE_EVENT_DIVERGE_DATA_PTR
        SCRIBE_EVENT_DIVERGE_DATA_CONTENT

    struct scribe_event:
        __u8 type

    struct scribe_event_sized:
        scribe_event h
        __u16 size

    struct scribe_event_diverge:
        scribe_event h
        __u32 pid

    struct scribe_event_init:
        scribe_event_sized h
        __u16 argc
        __u16 envc
        __u8 data[0]

    struct scribe_event_pid:
        scribe_event h
        __u32 pid

    enum: SCRIBE_DATA_INPUT
    enum: SCRIBE_DATA_STRING
    enum: SCRIBE_DATA_NON_DETERMINISTIC
    enum: SCRIBE_DATA_INTERNAL

    struct scribe_event_data:
        scribe_event_sized h
        __u32 user_ptr
        __u8 data_type
        __u8 data[0]
        __u32 ldata[0]

    struct scribe_event_syscall:
        scribe_event h
        __u32 ret
        __u16 nr

    struct scribe_event_syscall_end:
        scribe_event h

    struct scribe_event_queue_eof:
        scribe_event h

    struct scribe_event_attach_on_execve:
        scribe_event h
        __u8 enable

    struct scribe_event_record:
        scribe_event h
        __u32 log_fd

    struct scribe_event_replay:
        scribe_event h
        __u32 log_fd
        __s32 backtrace_len

    struct scribe_event_stop:
        scribe_event h

    struct scribe_event_backtrace:
        scribe_event h
        __u64 event_offset

    struct scribe_event_context_idle:
        scribe_event h
        __s32 error

    struct scribe_event_diverge_event_type:
        scribe_event_diverge h
        __u8 type

    struct scribe_event_diverge_event_size:
        scribe_event_diverge h
        __u16 size

    struct scribe_event_diverge_data_type:
        scribe_event_diverge h
        __u8 type

    struct scribe_event_diverge_data_ptr:
        scribe_event_diverge h
        __u32 user_ptr

    struct scribe_event_diverge_data_content:
        scribe_event_diverge h
        __u16 offset
        __u8 size
        __u8 data[128]

    bint is_sized_type(int type)
    bint is_diverge_type(int type)

    # XXX The additional payload of sized event is NOT accounted here.
    size_t sizeof_event_from_type(__u8 type)

    size_t sizeof_event(scribe_event *event)

cdef extern from "scribe.h" nogil:
    struct scribe_context
    ctypedef scribe_context *scribe_context_t
    ctypedef char * char_p_const "char *const"

    struct scribe_operations:
        void (*init_loader) (void *private_data, char_p_const *argv, char_p_const *envp)
        void (*on_backtrace) (void *private_data, loff_t *log_offset, int num)
        void (*on_diverge) (void *private_data, scribe_event_diverge *event)

    int scribe_context_create(scribe_context_t *pctx, scribe_operations *ops, void *private_data)
    int scribe_context_destroy(scribe_context_t ctx)

    pid_t scribe_record(scribe_context_t ctx, int flags, int log_fd,
                        char_p_const *argv, char_p_const *envp)
    pid_t scribe_replay(scribe_context_t ctx, int flags, int log_fd, int backtrace_len)
    int scribe_wait(scribe_context_t ctx)

    int scribe_stop(scribe_context_t ctx)
    char *scribe_get_event_str(char *str, size_t size, scribe_event *event)
