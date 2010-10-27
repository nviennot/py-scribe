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
    def __init__(self, pid, in_syscall, offset):
        self.pid = pid
        self.in_syscall = in_syscall
        self.offset = offset

cdef class AnnotatedEventsFromBuffer:
    cdef EventsFromBuffer raw_iter
    cdef int pid
    cdef bint in_syscall

    def __init__(self, buffer):
        self.raw_iter = EventsFromBuffer(buffer)

    def __iter__(self):
        self.raw_iter.__iter__()
        self.pid = 0
        self.in_syscall = 0
        return self

    def __next__(self):
        while True:
            offset = self.raw_iter.offset
            event = self.raw_iter.__next__()

            if isinstance(event, EventPid):
                self.pid = event.pid
                continue

            if isinstance(event, EventSyscallEnd):
                self.in_syscall = False
                continue

            event_info = EventInfo(pid = self.pid,
                                   in_syscall = self.in_syscall,
                                   offset = offset)

            if isinstance(event, EventSyscall):
                self.in_syscall = True

            return event_info, event
