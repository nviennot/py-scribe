from libc.stdlib cimport *
from libc.errno cimport *
from libc.string cimport *
cimport scribe_api
cimport cpython
import os

def Event_from_bytes(bytes buffer):
    cls, _, _ = Event_get_type_info(ord(buffer[0:1]))
    return cls(buffer)

def Event_get_type_info(type):
    return Event.class_of[type], \
            scribe_api.sizeof_event_from_type(type), \
            scribe_api.is_sized_type(type)

def Event_register(event_class, type):
    Event.class_of[type] = event_class
    return type

cpdef inline size_t Event_size_from_type(int type) except -1:
    return scribe_api.sizeof_event_from_type(type)

cdef class Event:
    class_of = dict()

    get_type_info = staticmethod(Event_get_type_info)
    register = staticmethod(Event_register)
    size_from_type = staticmethod(Event_size_from_type)
    from_bytes = staticmethod(Event_from_bytes)

    # We need to keep the event reference because event_struct won't
    cdef bytes event
    cdef scribe_api.scribe_event *event_struct

    def __init__(self, bytes event=None, int extra_size=0):
        cdef scribe_api.scribe_event h
        cdef int type = self.type
        # We prefer to use the cdef version for performance reasons.
        cdef size_t event_size = Event_size_from_type(type) + extra_size
        if event is None:
            h = {'type': type}
            header = cpython.PyBytes_FromStringAndSize(<char *>&h,
                                                       sizeof(scribe_api.scribe_event))
            self.event = header + bytes(bytearray(event_size - len(header)))
        else:
            assert event_size == len(event)
            self.event = event

        # XXX We cannot modify the struct as we are using
        # underlying bytes, and not a bytearray.
        self.event_struct = <scribe_api.scribe_event *>cpython.PyBytes_AsString(self.event)
        assert self.event_struct.type == type

    def __len__(self):
        return len(self.event)

    def __str__(self):
        cdef char buffer[4096]
        return scribe_api.scribe_get_event_str(buffer, sizeof(buffer),
                                    self.event_struct).decode()

    def encode(self):
        return self.event

cdef class EventSized(Event):
    pass

cdef class EventDiverge(Event):

    property pid:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge *>self.event_struct).pid
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge *>self.event_struct).pid = value

    property last_event_offset:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge *>
                        self.event_struct).last_event_offset
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge *>self.event_struct).last_event_offset = value

cdef class EventInit(EventSized):
    type = Event.register(EventInit, scribe_api.SCRIBE_EVENT_INIT)

cdef class EventPid(Event):
    type = Event.register(EventPid, scribe_api.SCRIBE_EVENT_PID)

    property pid:
        def __get__(self):
            return (<scribe_api.scribe_event_pid *>self.event_struct).pid
        def __set__(self, value):
            (<scribe_api.scribe_event_pid *>self.event_struct).pid = value

cdef class EventDataInfo(Event):
    type = Event.register(EventDataInfo, scribe_api.SCRIBE_EVENT_DATA_INFO)

    property user_ptr:
        def __get__(self):
            return (<scribe_api.scribe_event_data_info *>self.event_struct).user_ptr
        def __set__(self, value):
            (<scribe_api.scribe_event_data_info *>self.event_struct).user_ptr = value

    property size:
        def __get__(self):
            return (<scribe_api.scribe_event_data_info *>self.event_struct).size
        def __set__(self, value):
            (<scribe_api.scribe_event_data_info *>self.event_struct).size = value

    property data_type:
        def __get__(self):
            return (<scribe_api.scribe_event_data_info *>self.event_struct).data_type
        def __set__(self, value):
            (<scribe_api.scribe_event_data_info *>self.event_struct).data_type = value

cdef class EventData(EventSized):
    type = Event.register(EventData, scribe_api.SCRIBE_EVENT_DATA)

    property data:
        def __get__(self):
            return cpython.PyBytes_FromStringAndSize(
                    <char *>(<scribe_api.scribe_event_data *>self.event_struct).data,
                    (<scribe_api.scribe_event_data *>self.event_struct).h.size)

cdef class EventDataExtra(EventSized):
    type = Event.register(EventDataExtra, scribe_api.SCRIBE_EVENT_DATA_EXTRA)

    property user_ptr:
        def __get__(self):
            return (<scribe_api.scribe_event_data_extra *>self.event_struct).user_ptr
        def __set__(self, value):
            (<scribe_api.scribe_event_data_extra *>self.event_struct).user_ptr = value

    property data_type:
        def __get__(self):
            return (<scribe_api.scribe_event_data_extra *>self.event_struct).data_type
        def __set__(self, value):
            (<scribe_api.scribe_event_data_extra *>self.event_struct).data_type = value

    property data:
        def __get__(self):
            return cpython.PyBytes_FromStringAndSize(
                    <char *>(<scribe_api.scribe_event_data_extra *>self.event_struct).data,
                    (<scribe_api.scribe_event_data_extra *>self.event_struct).h.size)

cdef class EventSyscall(Event):
    type = Event.register(EventSyscall, scribe_api.SCRIBE_EVENT_SYSCALL)

    property ret:
        def __get__(self):
            return (<scribe_api.scribe_event_syscall *>self.event_struct).ret
        def __set__(self, value):
            (<scribe_api.scribe_event_syscall *>self.event_struct).ret = value

cdef class EventSyscallExtra(Event):
    type = Event.register(EventSyscallExtra, scribe_api.SCRIBE_EVENT_SYSCALL_EXTRA)

    property ret:
        def __get__(self):
            return (<scribe_api.scribe_event_syscall_extra *>self.event_struct).ret
        def __set__(self, value):
            (<scribe_api.scribe_event_syscall_extra *>self.event_struct).ret = value

    property nr:
        def __get__(self):
            return (<scribe_api.scribe_event_syscall_extra *>self.event_struct).nr
        def __set__(self, value):
            (<scribe_api.scribe_event_syscall_extra *>self.event_struct).nr = value

cdef class EventSyscallEnd(Event):
    type = Event.register(EventSyscallEnd, scribe_api.SCRIBE_EVENT_SYSCALL_END)

cdef class EventQueueEof(Event):
    type = Event.register(EventQueueEof, scribe_api.SCRIBE_EVENT_QUEUE_EOF)

cdef class EventResourceLock(Event):
    type = Event.register(EventResourceLock, scribe_api.SCRIBE_EVENT_RESOURCE_LOCK)

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_resource_lock *>self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_resource_lock *>self.event_struct).serial = value

cdef class EventResourceLockIntr(Event):
    type = Event.register(EventResourceLockIntr,
                          scribe_api.SCRIBE_EVENT_RESOURCE_LOCK_INTR)

cdef class EventResourceLockExtra(Event):
    type = Event.register(EventResourceLockExtra,
                          scribe_api.SCRIBE_EVENT_RESOURCE_LOCK_EXTRA)

    property resource_type:
        def __get__(self):
            return (<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).type
        def __set__(self, value):
            (<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).type = value

    property write_access:
        def __get__(self):
            return bool((<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).write_access)
        def __set__(self, value):
            (<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).write_access = value

    property id:
        def __get__(self):
            return (<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).id
        def __set__(self, value):
            (<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).id = value

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_resource_lock_extra *>self.event_struct).serial = value

cdef class EventResourceUnlock(Event):
    type = Event.register(EventResourceUnlock, scribe_api.SCRIBE_EVENT_RESOURCE_UNLOCK)

    property id:
        def __get__(self):
            return (<scribe_api.scribe_event_resource_unlock *>self.event_struct).id
        def __set__(self, value):
            (<scribe_api.scribe_event_resource_unlock *>self.event_struct).id = value

cdef class EventRdtsc(Event):
    type = Event.register(EventRdtsc, scribe_api.SCRIBE_EVENT_RDTSC)

    property tsc:
        def __get__(self):
            return (<scribe_api.scribe_event_rdtsc *>self.event_struct).tsc
        def __set__(self, value):
            (<scribe_api.scribe_event_rdtsc *>self.event_struct).tsc = value

cdef class EventSignal(EventSized):
    type = Event.register(EventSignal, scribe_api.SCRIBE_EVENT_SIGNAL)

    property nr:
        def __get__(self):
            return (<scribe_api.scribe_event_signal *>self.event_struct).nr
        def __set__(self, value):
            (<scribe_api.scribe_event_signal *>self.event_struct).nr = value

    property deferred:
        def __get__(self):
            return (<scribe_api.scribe_event_signal *>self.event_struct).deferred
        def __set__(self, value):
            (<scribe_api.scribe_event_signal *>self.event_struct).deferred = value

    property info:
        def __get__(self):
            return cpython.PyBytes_FromStringAndSize(
                    <char *>(<scribe_api.scribe_event_signal *>self.event_struct).info,
                    (<scribe_api.scribe_event_signal *>self.event_struct).h.size)

cdef class EventFence(Event):
    type = Event.register(EventFence, scribe_api.SCRIBE_EVENT_FENCE)

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_fence *>self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_fence *>self.event_struct).serial = value

cdef class EventMemOwnedRead(Event):
    type = Event.register(EventMemOwnedRead, scribe_api.SCRIBE_EVENT_MEM_OWNED_READ)

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_owned_read *>self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_owned_read *>self.event_struct).serial = value

cdef class EventMemOwnedWrite(Event):
    type = Event.register(EventMemOwnedWrite, scribe_api.SCRIBE_EVENT_MEM_OWNED_WRITE)

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_owned_write *>self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_owned_write *>self.event_struct).serial = value

cdef class EventMemOwnedReadExtra(Event):
    type = Event.register(EventMemOwnedReadExtra,
                          scribe_api.SCRIBE_EVENT_MEM_OWNED_READ_EXTRA)

    property address:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_owned_read_extra *>
                    self.event_struct).address
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_owned_read_extra *>
                    self.event_struct).address = value

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_owned_read_extra *>
                    self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_owned_read_extra *>
                    self.event_struct).serial = value

cdef class EventMemOwnedWriteExtra(Event):
    type = Event.register(EventMemOwnedWriteExtra,
                          scribe_api.SCRIBE_EVENT_MEM_OWNED_WRITE_EXTRA)

    property address:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_owned_write_extra *>
                    self.event_struct).address
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_owned_write_extra *>
                    self.event_struct).address = value

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_owned_write_extra *>
                    self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_owned_write_extra *>
                    self.event_struct).serial = value

cdef class EventMemPublicRead(Event):
    type = Event.register(EventMemPublicRead, scribe_api.SCRIBE_EVENT_MEM_PUBLIC_READ)

    property address:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_public_read *>self.event_struct).address
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_public_read *>self.event_struct).address = value

cdef class EventMemPublicWrite(Event):
    type = Event.register(EventMemPublicWrite, scribe_api.SCRIBE_EVENT_MEM_PUBLIC_WRITE)

    property address:
        def __get__(self):
            return (<scribe_api.scribe_event_mem_public_write *>self.event_struct).address
        def __set__(self, value):
            (<scribe_api.scribe_event_mem_public_write *>self.event_struct).address = value

cdef class EventMemAlone(Event):
    type = Event.register(EventMemAlone, scribe_api.SCRIBE_EVENT_MEM_ALONE)

cdef class EventRegs(Event):
    type = Event.register(EventRegs, scribe_api.SCRIBE_EVENT_REGS)

cdef class EventBookmark(Event):
    type = Event.register(EventBookmark, scribe_api.SCRIBE_EVENT_BOOKMARK)

    property id:
        def __get__(self):
            return (<scribe_api.scribe_event_bookmark *>self.event_struct).id
        def __set__(self, value):
            (<scribe_api.scribe_event_bookmark *>self.event_struct).id = value

    property npr:
        def __get__(self):
            return (<scribe_api.scribe_event_bookmark *>self.event_struct).npr
        def __set__(self, value):
            (<scribe_api.scribe_event_bookmark *>self.event_struct).npr = value

cdef class EventSigSendCookie(Event):
    type = Event.register(EventSigSendCookie, scribe_api.SCRIBE_EVENT_SIG_SEND_COOKIE)

    property cookie:
        def __get__(self):
            return (<scribe_api.scribe_event_sig_send_cookie *>self.event_struct).cookie
        def __set__(self, value):
            (<scribe_api.scribe_event_sig_send_cookie *>self.event_struct).cookie = value

cdef class EventSigRecvCookie(Event):
    type = Event.register(EventSigRecvCookie, scribe_api.SCRIBE_EVENT_SIG_RECV_COOKIE)

    property cookie:
        def __get__(self):
            return (<scribe_api.scribe_event_sig_recv_cookie *>self.event_struct).cookie
        def __set__(self, value):
            (<scribe_api.scribe_event_sig_recv_cookie *>self.event_struct).cookie = value

cdef class EventDivergeEventType(EventDiverge):
    type = Event.register(EventDivergeEventType,
                          scribe_api.SCRIBE_EVENT_DIVERGE_EVENT_TYPE)

    property event_type:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_event_type *>self.event_struct).type
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_event_type *>self.event_struct).type = value

cdef class EventDivergeEventSize(EventDiverge):
    type = Event.register(EventDivergeEventSize,
                          scribe_api.SCRIBE_EVENT_DIVERGE_EVENT_SIZE)

    property size:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_event_size *>self.event_struct).size
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_event_size *>self.event_struct).size = value

cdef class EventDivergeDataType(EventDiverge):
    type = Event.register(EventDivergeDataType,
                          scribe_api.SCRIBE_EVENT_DIVERGE_DATA_TYPE)

    property data_type:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_data_type *>self.event_struct).type
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_data_type *>self.event_struct).type = value

cdef class EventDivergeDataPtr(EventDiverge):
    type = Event.register(EventDivergeDataPtr,
                          scribe_api.SCRIBE_EVENT_DIVERGE_DATA_PTR)

    property user_ptr:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_data_ptr *>self.event_struct).user_ptr
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_data_ptr *>self.event_struct).user_ptr = value

cdef class EventDivergeDataContent(EventDiverge):
    type = Event.register(EventDivergeDataContent,
                          scribe_api.SCRIBE_EVENT_DIVERGE_DATA_CONTENT)

    property offset:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_data_content *>
                    self.event_struct).offset
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_data_content *>
                    self.event_struct).offset = value

    property data:
        def __get__(self):
            return cpython.PyBytes_FromStringAndSize(
                    <char *>(<scribe_api.scribe_event_diverge_data_content *>
                        self.event_struct).data,
                    (<scribe_api.scribe_event_diverge_data_content *>
                        self.event_struct).size)

cdef class EventDivergeResourceType(EventDiverge):
    type = Event.register(EventDivergeResourceType,
                          scribe_api.SCRIBE_EVENT_DIVERGE_RESOURCE_TYPE)

cdef class EventDivergeSyscall(EventDiverge):
    type = Event.register(EventDivergeSyscall,
                          scribe_api.SCRIBE_EVENT_DIVERGE_SYSCALL)

    property nr:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_syscall *> self.event_struct).nr
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_syscall *> self.event_struct).nr = value


cdef class EventDivergeSyscallRet(EventDiverge):
    type = Event.register(EventDivergeSyscallRet,
                          scribe_api.SCRIBE_EVENT_DIVERGE_SYSCALL_RET)

    property ret:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_syscall_ret *> self.event_struct).ret
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_syscall_ret *> self.event_struct).ret = value

cdef class EventDivergeFenceSerial(EventDiverge):
    type = Event.register(EventDivergeFenceSerial,
                          scribe_api.SCRIBE_EVENT_DIVERGE_FENCE_SERIAL)

    property serial:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_fence_serial *>
                        self.event_struct).serial
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_fence_serial *>
                        self.event_struct).serial = value

cdef class EventDivergeMemOwned(EventDiverge):
    type = Event.register(EventDivergeMemOwned,
                          scribe_api.SCRIBE_EVENT_DIVERGE_MEM_OWNED)

    property address:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_mem_owned *>
                        self.event_struct).address
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_mem_owned *>
                        self.event_struct).address = value

    property write_access:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge_mem_owned *>
                        self.event_struct).write_access
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge_mem_owned *>
                        self.event_struct).write_access = value

cdef class EventDivergeMemNotOwned(EventDiverge):
    type = Event.register(EventDivergeMemNotOwned,
                          scribe_api.SCRIBE_EVENT_DIVERGE_MEM_NOT_OWNED)

cdef class EventDivergeRegs(EventDiverge):
    type = Event.register(EventDivergeRegs,
                          scribe_api.SCRIBE_EVENT_DIVERGE_REGS)
