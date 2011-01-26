cdef extern from "errno.h":
    enum: EINTR

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
    ctypedef char * char_p_const "char *const"

cdef extern from "asm/ptrace.h":
    struct pt_regs:
        pass

