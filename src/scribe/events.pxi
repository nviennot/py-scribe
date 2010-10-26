from libc.stdlib cimport *
from libc.errno cimport *
from libc.string cimport *
from scribe_api cimport *
cimport cpython
import os

def Event_get_type_info(type):
    return (Event.class_of[type],
            sizeof_event_from_type(type),
            is_sized_type(type))

def Event_register(event_class, type):
    Event.class_of[type] = event_class
    return type

cpdef inline size_t Event_size_from_type(int type) except -1:
    return sizeof_event_from_type(type)

cdef class Event:
    class_of = dict()

    get_type_info = staticmethod(Event_get_type_info)
    register = staticmethod(Event_register)
    size_from_type = staticmethod(Event_size_from_type)

    # We need to keep the event reference because event_struct won't
    cdef bytes event
    cdef scribe_event *event_struct

    def __init__(self, bytes event=None, int extra_size=0):
        cdef int type = self.type
        # We prefer to use the cdef version for performance reasons.
        cdef size_t event_size = Event_size_from_type(type) + extra_size
        if event is None:
            # XXX Assuming typeof(event_struct->type) is __u8
            self.event = bytes((type,)) + bytes(event_size - 1)
        else:
            assert event_size == len(event)
            self.event = event

        # XXX We cannot modify the struct as we are using
        # underlying bytes, and not a bytearray.
        self.event_struct = <scribe_event *>cpython.PyBytes_AsString(self.event)
        assert self.event_struct.type == type

    def describe(self, int max_size=100):
        cdef char buffer[4096]
        if (max_size > sizeof(buffer)):
            raise ValueError
        return scribe_get_event_str(buffer, max_size, self.event_struct).decode()

    cpdef size_t size(self):
        return sizeof_event(self.event_struct)

    def __str__(self):
        return self.describe()

    def encode(self):
        return self.event

cdef class EventSized(Event):
    pass

cdef class EventDiverge(Event):
    pass

cdef class EventInit(EventSized):
    type = Event.register(EventInit, SCRIBE_EVENT_INIT)

cdef class EventPid(Event):
    type = Event.register(EventPid, SCRIBE_EVENT_PID)

    property pid:
        def __get__(self):
            return (<scribe_event_pid *>self.event_struct).pid

