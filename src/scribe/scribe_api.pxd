from linux cimport *

cdef extern from "linux/scribe_api.h" nogil:
    enum: EDIVERGE

    enum: SCRIBE_SYSCALL_RET
    enum: SCRIBE_SYSCALL_EXTRA
    enum: SCRIBE_SIG_EXTRA
    enum: SCRIBE_SIG_COOKIE
    enum: SCRIBE_RES_EXTRA
    enum: SCRIBE_MEM_EXTRA
    enum: SCRIBE_DATA_EXTRA
    enum: SCRIBE_DATA_STRING_ALWAYS
    enum: SCRIBE_DATA_ALWAYS
    enum: SCRIBE_RES_ALWAYS
    enum: SCRIBE_FENCE_ALWAYS
    enum: SCRIBE_REGS
    enum: SCRIBE_ALL
    enum: SCRIBE_DEFAULT

    enum: SCRIBE_DISABLE_MM

    enum: SCRIBE_PS_RECORD
    enum: SCRIBE_PS_REPLAY
    enum: SCRIBE_PS_ATTACH_ON_EXEC
    enum: SCRIBE_PS_DETACHING
    enum: SCRIBE_PS_ENABLE_SYSCALL
    enum: SCRIBE_PS_ENABLE_DATA
    enum: SCRIBE_PS_ENABLE_RESOURCE
    enum: SCRIBE_PS_ENABLE_SIGNAL
    enum: SCRIBE_PS_ENABLE_TSC
    enum: SCRIBE_PS_ENABLE_MM
    enum: SCRIBE_PS_ENABLE_RET_CHECK
    enum: SCRIBE_PS_ENABLE_ALL

    enum: SCRIBE_DATA_INPUT
    enum: SCRIBE_DATA_STRING
    enum: SCRIBE_DATA_NON_DETERMINISTIC
    enum: SCRIBE_DATA_INTERNAL
    enum: SCRIBE_DATA_NEED_INFO
    enum: SCRIBE_DATA_ZERO

    enum: SCRIBE_BOOKMARK_PRE_SYSCALL
    enum: SCRIBE_BOOKMARK_POST_SYSCALL

    enum: SCRIBE_RES_TYPE_INODE
    enum: SCRIBE_RES_TYPE_FILE
    enum: SCRIBE_RES_TYPE_FILES_STRUCT
    enum: SCRIBE_RES_TYPE_PID
    enum: SCRIBE_RES_TYPE_FUTEX
    enum: SCRIBE_RES_TYPE_IPC
    enum: SCRIBE_RES_TYPE_MMAP
    enum: SCRIBE_RES_TYPE_PPID

    enum: __NR_socket
    enum: __NR_bind
    enum: __NR_connect
    enum: __NR_listen
    enum: __NR_accept
    enum: __NR_getsockname
    enum: __NR_getpeername
    enum: __NR_socketpair
    enum: __NR_send
    enum: __NR_recv
    enum: __NR_sendto
    enum: __NR_recvfrom
    enum: __NR_shutdown
    enum: __NR_setsockopt
    enum: __NR_getsockopt
    enum: __NR_sendmsg
    enum: __NR_recvmsg
    enum: __NR_accept4
    enum: __NR_recvmmsg2

    enum: __NR_futex_wait
    enum: __NR_futex_wake
    enum: __NR_futex_fd
    enum: __NR_futex_requeue
    enum: __NR_futex_cmp_requeue
    enum: __NR_futex_wake_op
    enum: __NR_futex_lock_pi
    enum: __NR_futex_unlock_pi
    enum: __NR_futex_trylock_pi
    enum: __NR_futex_wait_bitset
    enum: __NR_futex_wake_bitset
    enum: __NR_futex_wait_requeue_pi
    enum: __NR_futex_cmp_requeue_pi

    struct scribe_event:
        __u8 type

    struct scribe_event_sized:
        scribe_event h
        __u16 size

    struct scribe_event_diverge:
        scribe_event h
        __u32 pid
        __u64 last_event_offset

    bint is_sized_type(int type)
    bint is_diverge_type(int type)

    # XXX The additional payload of sized event is NOT accounted here.
    size_t sizeof_event_from_type(__u8 type)

    size_t sizeof_event(scribe_event *event)

cdef extern from "scribe.h" nogil:
    enum: SCRIBE_CUSTOM_INIT
    enum: SCRIBE_CLONE_NEWNET

    struct scribe_context
    ctypedef scribe_context *scribe_context_t

    struct scribe_operations:
        void (*init_loader) (void *private_data, char_p_const *argv, char_p_const *envp)
        void (*on_backtrace) (void *private_data, loff_t *log_offset, int num)
        void (*on_diverge) (void *private_data, scribe_event_diverge *event)
        void (*on_bookmark) (void *private_data, int id, int npr)
        void (*on_attach) (void *private_data, pid_t real_pid, pid_t scribe_pid)

    void scribe_default_init_loader(char_p_const *argv, char_p_const *envp)

    int scribe_context_create(scribe_context_t *pctx, scribe_operations *ops, void *private_data)
    int scribe_context_destroy(scribe_context_t ctx)

    pid_t scribe_record(scribe_context_t ctx, int flags, int log_fd,
                        char_p_const *argv, char_p_const *envp,
                        char *cwd, char *chroot)
    pid_t scribe_replay(scribe_context_t ctx, int flags, int log_fd,
                        int backtrace_len)

    int scribe_wait(scribe_context_t ctx)

    int scribe_stop(scribe_context_t ctx)
    int scribe_resume(scribe_context_t ctx)
    int scribe_bookmark(scribe_context_t ctx)
    int scribe_check_deadlock(scribe_context_t ctx)

    char *scribe_get_event_str(char *str, size_t size, scribe_event *event)
