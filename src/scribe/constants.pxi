cimport scribe_api

SCRIBE_SYSCALL_RET            = scribe_api.SCRIBE_SYSCALL_RET
SCRIBE_SYSCALL_EXTRA          = scribe_api.SCRIBE_SYSCALL_EXTRA
SCRIBE_SIG_EXTRA              = scribe_api.SCRIBE_SIG_EXTRA
SCRIBE_SIG_COOKIE             = scribe_api.SCRIBE_SIG_COOKIE
SCRIBE_RES_EXTRA              = scribe_api.SCRIBE_RES_EXTRA
SCRIBE_MEM_EXTRA              = scribe_api.SCRIBE_MEM_EXTRA
SCRIBE_DATA_EXTRA             = scribe_api.SCRIBE_DATA_EXTRA
SCRIBE_DATA_STRING_ALWAYS     = scribe_api.SCRIBE_DATA_STRING_ALWAYS
SCRIBE_DATA_ALWAYS            = scribe_api.SCRIBE_DATA_ALWAYS
SCRIBE_RES_ALWAYS             = scribe_api.SCRIBE_RES_ALWAYS
SCRIBE_FENCE_ALWAYS           = scribe_api.SCRIBE_FENCE_ALWAYS
SCRIBE_REGS                   = scribe_api.SCRIBE_REGS
SCRIBE_ALL                    = scribe_api.SCRIBE_ALL
SCRIBE_DEFAULT                = scribe_api.SCRIBE_DEFAULT

SCRIBE_DISABLE_MM             = scribe_api.SCRIBE_DISABLE_MM

SCRIBE_PS_RECORD              = scribe_api.SCRIBE_PS_RECORD
SCRIBE_PS_REPLAY              = scribe_api.SCRIBE_PS_REPLAY
SCRIBE_PS_ATTACH_ON_EXEC      = scribe_api.SCRIBE_PS_ATTACH_ON_EXEC
SCRIBE_PS_DETACHING           = scribe_api.SCRIBE_PS_DETACHING
SCRIBE_PS_ENABLE_SYSCALL      = scribe_api.SCRIBE_PS_ENABLE_SYSCALL
SCRIBE_PS_ENABLE_DATA         = scribe_api.SCRIBE_PS_ENABLE_DATA
SCRIBE_PS_ENABLE_RESOURCE     = scribe_api.SCRIBE_PS_ENABLE_RESOURCE
SCRIBE_PS_ENABLE_SIGNAL       = scribe_api.SCRIBE_PS_ENABLE_SIGNAL
SCRIBE_PS_ENABLE_TSC          = scribe_api.SCRIBE_PS_ENABLE_TSC
SCRIBE_PS_ENABLE_MM           = scribe_api.SCRIBE_PS_ENABLE_MM
SCRIBE_PS_ENABLE_RET_CHECK    = scribe_api.SCRIBE_PS_ENABLE_RET_CHECK
SCRIBE_PS_ENABLE_ALL          = scribe_api.SCRIBE_PS_ENABLE_ALL

SCRIBE_DATA_INPUT             = scribe_api.SCRIBE_DATA_INPUT
SCRIBE_DATA_STRING            = scribe_api.SCRIBE_DATA_STRING
SCRIBE_DATA_NON_DETERMINISTIC = scribe_api.SCRIBE_DATA_NON_DETERMINISTIC
SCRIBE_DATA_INTERNAL          = scribe_api.SCRIBE_DATA_INTERNAL
SCRIBE_DATA_NEED_INFO         = scribe_api.SCRIBE_DATA_NEED_INFO
SCRIBE_DATA_ZERO              = scribe_api.SCRIBE_DATA_ZERO

SCRIBE_BOOKMARK_PRE_SYSCALL  = scribe_api.SCRIBE_BOOKMARK_PRE_SYSCALL
SCRIBE_BOOKMARK_POST_SYSCALL = scribe_api.SCRIBE_BOOKMARK_POST_SYSCALL

SCRIBE_RES_TYPE_INODE         = scribe_api.SCRIBE_RES_TYPE_INODE
SCRIBE_RES_TYPE_FILE          = scribe_api.SCRIBE_RES_TYPE_FILE
SCRIBE_RES_TYPE_FILES_STRUCT  = scribe_api.SCRIBE_RES_TYPE_FILES_STRUCT
SCRIBE_RES_TYPE_PID           = scribe_api.SCRIBE_RES_TYPE_PID
SCRIBE_RES_TYPE_FUTEX         = scribe_api.SCRIBE_RES_TYPE_FUTEX
SCRIBE_RES_TYPE_IPC           = scribe_api.SCRIBE_RES_TYPE_IPC
SCRIBE_RES_TYPE_MMAP          = scribe_api.SCRIBE_RES_TYPE_MMAP
SCRIBE_RES_TYPE_PPID          = scribe_api.SCRIBE_RES_TYPE_PPID

__NR_socket                   = scribe_api.__NR_socket
__NR_bind                     = scribe_api.__NR_bind
__NR_connect                  = scribe_api.__NR_connect
__NR_listen                   = scribe_api.__NR_listen
__NR_accept                   = scribe_api.__NR_accept
__NR_getsockname              = scribe_api.__NR_getsockname
__NR_getpeername              = scribe_api.__NR_getpeername
__NR_socketpair               = scribe_api.__NR_socketpair
__NR_send                     = scribe_api.__NR_send
__NR_recv                     = scribe_api.__NR_recv
__NR_sendto                   = scribe_api.__NR_sendto
__NR_recvfrom                 = scribe_api.__NR_recvfrom
__NR_shutdown                 = scribe_api.__NR_shutdown
__NR_setsockopt               = scribe_api.__NR_setsockopt
__NR_getsockopt               = scribe_api.__NR_getsockopt
__NR_sendmsg                  = scribe_api.__NR_sendmsg
__NR_recvmsg                  = scribe_api.__NR_recvmsg
__NR_accept4                  = scribe_api.__NR_accept4
# Not defined yet in my userspace headers
#__NR_recvmmsg2                = scribe_api.__NR_recvmmsg2

__NR_futex_wait               = scribe_api.__NR_futex_wait
__NR_futex_wake               = scribe_api.__NR_futex_wake
__NR_futex_fd                 = scribe_api.__NR_futex_fd
__NR_futex_requeue            = scribe_api.__NR_futex_requeue
__NR_futex_cmp_requeue        = scribe_api.__NR_futex_cmp_requeue
__NR_futex_wake_op            = scribe_api.__NR_futex_wake_op
__NR_futex_lock_pi            = scribe_api.__NR_futex_lock_pi
__NR_futex_unlock_pi          = scribe_api.__NR_futex_unlock_pi
__NR_futex_trylock_pi         = scribe_api.__NR_futex_trylock_pi
__NR_futex_wait_bitset        = scribe_api.__NR_futex_wait_bitset
__NR_futex_wake_bitset        = scribe_api.__NR_futex_wake_bitset
# Not defined yet in my userspace headers
# __NR_futex_wait_requeue_pi    = scribe_api.__NR_futex_wait_requeue_pi
# __NR_futex_cmp_requeue_pi     = scribe_api.__NR_futex_cmp_requeue_pi

SCRIBE_CUSTOM_INIT            = scribe_api.SCRIBE_CUSTOM_INIT
SCRIBE_CLONE_NEWNET           = scribe_api.SCRIBE_CLONE_NEWNET
