cimport scribe_api
cimport cpython

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

cdef class EventsFromBuffer:
    cdef object buffer
    cdef bint do_info
    cdef bint remove_annotations

    cdef loff_t offset
    cdef int pid
    cdef dict pid_infos
    cdef PidInfo current_pid_info

    def __init__(self, buffer, do_info=True, remove_annotations=True):
        self.buffer = buffer
        self.do_info = do_info
        self.remove_annotations = remove_annotations

    def __iter__(self):
        self.offset = 0
        self.pid = 0
        self.pid_infos = {}
        self.current_pid_info = PidInfo()
        return self

    cdef _next_raw(self):
        if self.offset >= len(self.buffer):
            raise StopIteration

        type = ord(self.buffer[self.offset:self.offset+1])
        cls, size, is_sized_event = Event_get_type_info(type)

        if is_sized_event:
            event_sized = self.buffer[self.offset:
                                      sizeof(scribe_api.scribe_event_sized)+self.offset]
            extra_size = (<scribe_api.scribe_event_sized *>
                                    cpython.PyBytes_AsString(event_sized)).size
        else:
            extra_size = 0

        event_buf = self.buffer[self.offset:self.offset+size+extra_size]
        event = cls(buffer=event_buf)
        self.offset += len(event_buf)
        return event

    cdef _next_info(self):
        while True:
            offset = self.offset
            event = self._next_raw()
            pid_info = self.current_pid_info

            if isinstance(event, EventPid):
                self.pid_infos[self.pid] = self.current_pid_info
                self.pid = event.pid
                self.current_pid_info = self.pid_infos.get(self.pid)
                if self.current_pid_info is None:
                    self.current_pid_info = PidInfo()

                if self.remove_annotations:
                    continue
            elif isinstance(event, EventSyscallEnd):
                pid_info.in_syscall = False
                if self.remove_annotations:
                    continue
            elif isinstance(event, EventResourceUnlock):
                pid_info.res_depth = pid_info.res_depth - 1
                assert pid_info.res_depth >= 0
                if self.remove_annotations:
                    continue

            event_info = EventInfo(pid = self.pid,
                                   in_syscall = pid_info.in_syscall,
                                   res_depth = pid_info.res_depth,
                                   offset = offset)

            if isinstance(event, EventSyscallExtra):
                pid_info.in_syscall = True
            elif isinstance(event, EventResourceLockExtra):
                pid_info.res_depth = pid_info.res_depth + 1
            elif isinstance(event, EventQueueEof):
                self.pid_infos[self.pid] = None
                self.current_pid_info = PidInfo()
                self.pid = 0

            return event_info, event

    def __next__(self):
        if self.do_info:
            return self._next_info()
        return self._next_raw()


cdef class Shrinker:
    cdef object events
    cdef object last_event
    cdef int flags_to_remove
    cdef bint remove_bookmarks

    def __init__(self, events, flags_to_remove, remove_bookmarks=False):

        # Some flags are not removable
        flags_to_remove &= ~SCRIBE_SYSCALL_RET
        flags_to_remove &= ~SCRIBE_RES_ALWAYS


        self.events = iter(events)
        self.flags_to_remove = flags_to_remove
        self.last_event = None
        self.remove_bookmarks = remove_bookmarks

    def __iter__(self):
        return self

    cdef _remove(self, f):
        return self.flags_to_remove & f

    cdef _next_event(self):
        while True:
            e = self.events.next()

            # SCRIBE_DATA_STRING_ALWAYS and SCRIBE_DATA_ALWAYS
            if isinstance(e, EventDataExtra):
                data_type = e.data_type
                user_ptr = e.user_ptr

                if self._remove(SCRIBE_DATA_STRING_ALWAYS):
                    if data_type & SCRIBE_DATA_STRING:
                        assert(not (data_type & SCRIBE_DATA_NEED_INFO))
                        continue

                if self._remove(SCRIBE_DATA_EXTRA) and \
                        not (data_type & SCRIBE_DATA_NEED_INFO):
                    new_e = EventData()
                    new_e.data = e.data
                    e = new_e

                if self._remove(SCRIBE_DATA_ALWAYS):
                    if not (data_type & (SCRIBE_DATA_NON_DETERMINISTIC | \
                                         SCRIBE_DATA_INTERNAL)):
                        # we can discard the data, it's useless

                        if data_type & SCRIBE_DATA_NEED_INFO:
                            new_e = EventDataInfo()
                            new_e.user_ptr = user_ptr
                            new_e.size = len(e.data)
                            new_e.data_type = data_type
                            e = new_e
                        else:
                            continue
                return e

            # SCRIBE_FENCE_ALWAYS
            if isinstance(e, EventFence) and \
                    self._remove(SCRIBE_FENCE_ALWAYS):
                # A first approximation is to never have two consecutive fences
                if isinstance(self.last_event, EventFence):
                    continue

            # SCRIBE_RES_EXTRA
            if isinstance(e, EventResourceLockExtra) and \
                    self._remove(SCRIBE_RES_EXTRA):
                new_e = EventResourceLock()
                new_e.serial = e.serial
                return new_e

            if isinstance(e, EventResourceUnlock) and \
                    self._remove(SCRIBE_RES_EXTRA):
                continue

            # SCRIBE_SYSCALL_EXTRA
            if isinstance(e, EventSyscallExtra) and \
                    self._remove(SCRIBE_SYSCALL_EXTRA):
                new_e = EventSyscall()
                new_e.ret = e.ret
                return new_e

            if isinstance(e, EventSyscallEnd) and \
                    self._remove(SCRIBE_SYSCALL_EXTRA):
                continue

            # SCRIBE_REGS
            if isinstance(e, EventRegs) and \
                    self._remove(SCRIBE_REGS):
                continue

            # SCRIBE_MEM_EXTRA
            if isinstance(e, EventMemOwnedReadExtra) and \
                    self._remove(SCRIBE_MEM_EXTRA):
                new_e = EventMemOwnedRead()
                new_e.serial = e.serial
                return new_e

            if isinstance(e, EventMemOwnedWriteExtra) and \
                    self._remove(SCRIBE_MEM_EXTRA):
                new_e = EventMemOwnedWrite()
                new_e.serial = e.serial
                return new_e

            # SCRIBE_SIG_COOKIE
            if (isinstance(e, EventSigSendCookie) or \
                    isinstance(e, EventSigRecvCookie)) and \
                    self._remove(SCRIBE_SIG_COOKIE):
                continue

            # Bookmarks
            if isinstance(e, EventBookmark) and \
                    self.remove_bookmarks:
                continue

            if isinstance(e, EventInit):
                e.flags &= ~self.flags_to_remove
                return e

            return e

    def __next__(self):
        e = self._next_event()
        self.last_event = e
        return e
