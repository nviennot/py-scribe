from scribe_api cimport *
cimport cpython

cdef class EventsFromBuffer:
    cdef object buffer
    cdef loff_t offset

    def __init__(self, buffer):
        self.buffer = buffer

    def __iter__(self):
        self.offset = 0
        return self

    def __next__(self):
        if self.offset >= len(self.buffer):
            raise StopIteration

        type = self.buffer[self.offset]
        cls, size, is_sized_event = Event_get_type_info(type)

        if is_sized_event:
            event_sized = self.buffer[self.offset:
                                      sizeof(scribe_event_sized)+self.offset]
            extra_size = (<scribe_event_sized *>
                                    cpython.PyBytes_AsString(event_sized)).size
        else:
            extra_size = 0

        event = cls(self.buffer[self.offset:self.offset+size+extra_size],
                    extra_size)
        self.offset += size + extra_size
        return event

class EventInfo:
    def __init__(self, pid, in_syscall, res_depth, offset):
        self.pid = pid
        self.in_syscall = in_syscall
        self.res_depth = res_depth
        self.offset = offset

cdef class PidInfo:
    cdef bint in_syscall
    cdef int res_depth

    def __init__(self):
        self.in_syscall = 0
        self.res_depth = 0

cdef class AnnotatedEventsFromBuffer:
    cdef EventsFromBuffer raw_iter
    cdef int pid
    cdef dict pid_infos
    cdef PidInfo current_pid_info

    def __init__(self, buffer):
        self.raw_iter = EventsFromBuffer(buffer)

    def __iter__(self):
        self.raw_iter.__iter__()
        self.pid = 0
        self.pid_infos = {}
        self.current_pid_info = PidInfo()
        return self

    def __next__(self):
        while True:
            offset = self.raw_iter.offset
            event = self.raw_iter.__next__()
            pid_info = self.current_pid_info

            if isinstance(event, EventPid):
                self.pid_infos[self.pid] = self.current_pid_info
                self.pid = event.pid
                self.current_pid_info = self.pid_infos.get(self.pid)
                if self.current_pid_info is None:
                    self.current_pid_info = PidInfo()
                continue
            elif isinstance(event, EventSyscallEnd):
                pid_info.in_syscall = False
                continue
            elif isinstance(event, EventResourceUnlock):
                pid_info.res_depth = pid_info.res_depth - 1
                assert pid_info.res_depth >= 0
                continue

            event_info = EventInfo(pid = self.pid,
                                   in_syscall = pid_info.in_syscall,
                                   res_depth = pid_info.res_depth,
                                   offset = offset)

            if isinstance(event, EventSyscall):
                pid_info.in_syscall = True
            elif isinstance(event, EventResourceLock):
                pid_info.res_depth = pid_info.res_depth + 1
            elif isinstance(event, EventQueueEof):
                self.pid_infos[self.pid] = None
                self.current_pid_info = PidInfo()
                self.pid = 0

            return event_info, event
