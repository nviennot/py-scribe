from libc.stdlib cimport *
from libc.errno cimport *
from libc.string cimport *
cimport scribe_api
cimport scribe_api_events
cimport cpython
import os

cpdef inline Event_get_type_info(type):
    return Event.class_of[type], \
            scribe_api.sizeof_event_from_type(type), \
            scribe_api.is_sized_type(type)

def Event_register(event_class, type):
    Event.class_of[type] = event_class
    return type

cpdef inline size_t Event_size_from_type(int type) except -1:
    return scribe_api.sizeof_event_from_type(type)

def Event_from_bytes(buffer, offset=0):
    type = ord(buffer[offset:offset+1])
    cls, size, is_sized_event = Event_get_type_info(type)

    extra_size = 0
    if is_sized_event:
        event_sized = buffer[offset:sizeof(scribe_api.scribe_event_sized)+offset]
        extra_size = (<scribe_api.scribe_event_sized *>
                                cpython.PyBytes_AsString(event_sized)).size

    event_buf = buffer[offset:offset+size+extra_size]
    return cls(buffer=event_buf)


cdef class Event:
    class_of = dict()

    get_type_info = staticmethod(Event_get_type_info)
    register = staticmethod(Event_register)
    size_from_type = staticmethod(Event_size_from_type)
    from_bytes = staticmethod(Event_from_bytes)

    cdef bytes _buffer
    cdef scribe_api.scribe_event *event_struct

    def __init__(self, bytes buffer):
        cdef scribe_api.scribe_event h
        cdef int type = self.native_type
        if buffer is None:
            h = {'type': type}
            header = cpython.PyBytes_FromStringAndSize(<char *>&h,
                                                       sizeof(scribe_api.scribe_event))
            self._buffer = header + bytes(bytearray(Event_size_from_type(type) - len(header)))
        else:
            assert Event_size_from_type(type) <= len(buffer)
            self._buffer = buffer

        # XXX We cannot modify the struct as we are using
        # underlying bytes, and not a bytearray.
        # Okey, we can but we need to break the COW mechanism (see __copy__())
        self.event_struct = <scribe_api.scribe_event *>cpython.PyBytes_AsString(self._buffer)
        assert self.event_struct.type == type

    def __len__(self):
        return len(self._buffer)

    def __str__(self):
        cdef char buffer[4096]
        return scribe_api.scribe_get_event_str(buffer, sizeof(buffer),
                                    self.event_struct).decode()

    def __copy__(self):
        # Breaking COW the dirty way
        new_event = self._buffer + b'\x00'
        new_event = new_event[0:-1]
        return self.__class__(buffer=new_event)

    def copy(self):
        return self.__copy__()

    def encode(self):
        return self._buffer

    def __richcmp__(_x, _y, int op):
        if op != 2 and op != 3:
            raise NotImplementedError()

        if not isinstance(_y, Event):
            return False

        cdef Event x = _x
        cdef Event y = _y

        if op == 2: # ==
            return x._buffer == y._buffer
        elif op == 3: # !=
            return x._buffer != y._buffer

    def __hash__(self):
        return hash(self._buffer)

cdef class EventSized(Event):
    property payload:
        def __get__(self):
            return cpython.PyBytes_FromStringAndSize(
                    (<char *>self.event_struct) + Event_size_from_type(self.native_type),
                    (<scribe_api.scribe_event_sized *>self.event_struct).size)
        def __set__(self, value):
            payload = bytes(value)
            assert(len(payload) <= 0xFFFF)
            self._buffer = self._buffer[0:Event_size_from_type(self.native_type)] + payload
            self.event_struct = <scribe_api.scribe_event *>cpython.PyBytes_AsString(self._buffer)
            (<scribe_api.scribe_event_sized *>self.event_struct).size = len(payload)

cdef class EventDiverge(Event):
    property pid:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge *>self.event_struct).pid
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge *>self.event_struct).pid = value

    property last_event_offset:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge *> self.event_struct).last_event_offset
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge *>self.event_struct).last_event_offset = value

    property fatal:
        def __get__(self):
            return (<scribe_api.scribe_event_diverge *> self.event_struct).fatal
        def __set__(self, value):
            (<scribe_api.scribe_event_diverge *>self.event_struct).fatal = value
