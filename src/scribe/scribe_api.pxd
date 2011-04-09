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

    enum: SCRIBE_RES_TYPE_INODE
    enum: SCRIBE_RES_TYPE_FILE
    enum: SCRIBE_RES_TYPE_FILES_STRUCT
    enum: SCRIBE_RES_TYPE_PID
    enum: SCRIBE_RES_TYPE_FUTEX
    enum: SCRIBE_RES_TYPE_IPC
    enum: SCRIBE_RES_TYPE_MMAP
    enum: SCRIBE_RES_TYPE_PPID
    enum: SCRIBE_RES_TYPE_MASK
    enum: SCRIBE_RES_SPINLOCK

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

    enum scribe_event_type:
        SCRIBE_EVENT_INIT
        SCRIBE_EVENT_PID
        SCRIBE_EVENT_DATA_INFO
        SCRIBE_EVENT_DATA
        SCRIBE_EVENT_DATA_EXTRA
        SCRIBE_EVENT_SYSCALL
        SCRIBE_EVENT_SYSCALL_EXTRA
        SCRIBE_EVENT_SYSCALL_END
        SCRIBE_EVENT_QUEUE_EOF
        SCRIBE_EVENT_RESOURCE_LOCK
        SCRIBE_EVENT_RESOURCE_LOCK_INTR
        SCRIBE_EVENT_RESOURCE_LOCK_EXTRA
        SCRIBE_EVENT_RESOURCE_UNLOCK
        SCRIBE_EVENT_RDTSC
        SCRIBE_EVENT_SIGNAL
        SCRIBE_EVENT_FENCE
        SCRIBE_EVENT_MEM_OWNED_READ
        SCRIBE_EVENT_MEM_OWNED_WRITE
        SCRIBE_EVENT_MEM_OWNED_READ_EXTRA
        SCRIBE_EVENT_MEM_OWNED_WRITE_EXTRA
        SCRIBE_EVENT_MEM_PUBLIC_READ
        SCRIBE_EVENT_MEM_PUBLIC_WRITE
        SCRIBE_EVENT_MEM_ALONE
        SCRIBE_EVENT_REGS
        SCRIBE_EVENT_BOOKMARK
        SCRIBE_EVENT_SIG_SEND_COOKIE
        SCRIBE_EVENT_SIG_RECV_COOKIE
        SCRIBE_EVENT_SIG_HANDLED_COOKIE
        SCRIBE_EVENT_SIG_HANDLED
        # userspace -> kernel commands
        SCRIBE_EVENT_ATTACH_ON_EXECVE
        SCRIBE_EVENT_RECORD
        SCRIBE_EVENT_REPLAY
        SCRIBE_EVENT_STOP
        SCRIBE_EVENT_BOOKMARK_REQUEST
        SCRIBE_EVENT_GOLIVE_ON_NEXT_BOOKMARK
        SCRIBE_EVENT_GOLIVE_ON_BOOKMARK_ID
        SCRIBE_EVENT_CHECK_DEADLOCK
        # kernel -> userspace notifications
        SCRIBE_EVENT_BACKTRACE
        SCRIBE_EVENT_CONTEXT_IDLE
        SCRIBE_EVENT_DIVERGE_EVENT_TYPE
        SCRIBE_EVENT_DIVERGE_EVENT_SIZE
        SCRIBE_EVENT_DIVERGE_DATA_TYPE
        SCRIBE_EVENT_DIVERGE_DATA_PTR
        SCRIBE_EVENT_DIVERGE_DATA_CONTENT
        SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE
        SCRIBE_EVENT_DIVERGE_SYSCALL
        SCRIBE_EVENT_DIVERGE_SYSCALL_RET
        SCRIBE_EVENT_DIVERGE_FENCE_SERIAL
        SCRIBE_EVENT_DIVERGE_MEM_OWNED
        SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED
        SCRIBE_EVENT_DIVERGE_REGS

    struct scribe_event:
        __u8 type

    struct scribe_event_sized:
        scribe_event h
        __u16 size

    struct scribe_event_diverge:
        scribe_event h
        __u32 pid
        __u64 last_event_offset

    struct scribe_event_init:
        scribe_event_sized h
        __u32 flags
        __u16 argc
        __u16 envc
        __u8 data[0]

    struct scribe_event_pid:
        scribe_event h
        __u32 pid

    struct scribe_event_data_info:
        scribe_event h
        __u32 user_ptr
        __u16 size
        __u8 data_type

    struct scribe_event_data:
        scribe_event_sized h
        __u8 data[0]
        __u32 ldata[0]

    struct scribe_event_data_extra:
        scribe_event_sized h
        __u32 user_ptr
        __u8 data_type
        __u8 data[0]
        __u32 ldata[0]

    struct scribe_event_syscall:
        scribe_event h
        __s32 ret

    struct scribe_event_syscall_extra:
        scribe_event h
        __s32 ret
        __u16 nr

    struct scribe_event_syscall_end:
        scribe_event h

    struct scribe_event_queue_eof:
        scribe_event h

    struct scribe_event_resource_lock:
        scribe_event h
        __u32 serial

    struct scribe_event_resource_lock_intr:
        scribe_event h

    struct scribe_event_resource_lock_extra:
        scribe_event_sized h
        __u8 type
        __u8 write_access
        __u32 id
        __u32 serial
        __u8 desc[0]

    struct scribe_event_resource_unlock:
        __u32 id
        scribe_event h

    struct scribe_event_rdtsc:
        scribe_event h
        __u64 tsc

    struct scribe_event_signal:
        scribe_event_sized h
        __u8 nr
        __u8 deferred
        __u8 info[0]

    struct scribe_event_fence:
        scribe_event h
        __u32 serial

    struct scribe_event_mem_owned_read:
        scribe_event h
        __u32 serial

    struct scribe_event_mem_owned_write:
        scribe_event h
        __u32 serial

    struct scribe_event_mem_owned_read_extra:
        scribe_event h
        __u32 address
        __u32 serial

    struct scribe_event_mem_owned_write_extra:
        scribe_event h
        __u32 address
        __u32 serial

    struct scribe_event_mem_public_read:
        scribe_event h
        __u32 address

    struct scribe_event_mem_public_write:
        scribe_event h
        __u32 address

    struct scribe_event_mem_alone:
        scribe_event h

    struct scribe_event_regs:
        scribe_event h
        pt_regs regs

    struct scribe_event_bookmark:
        scribe_event h
        __u32 id
        __u32 npr

    struct scribe_event_sig_send_cookie:
        scribe_event h
        __u32 cookie

    struct scribe_event_sig_recv_cookie:
        scribe_event h
        __u32 cookie

    struct scribe_event_sig_handled_cookie:
        scribe_event h
        __u32 cookie

    struct scribe_event_sig_handled:
        scribe_event h
        __u8 nr


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

    struct scribe_event_diverge_resource_type:
        scribe_event_diverge h
        __u8 type

    struct scribe_event_diverge_syscall:
        scribe_event_diverge h
        __u16 nr

    struct scribe_event_diverge_syscall_ret:
        scribe_event_diverge h
        __s32 ret

    struct scribe_event_diverge_fence_serial:
        scribe_event_diverge h
        __u32 serial

    struct scribe_event_diverge_mem_owned:
        scribe_event_diverge h
        __u32 address
        __u8 write_access

    struct scribe_event_diverge_mem_not_owned:
        scribe_event_diverge h

    struct scribe_event_diverge_regs:
        scribe_event_diverge h
        pt_regs regs

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
