#!/usr/bin/python

from distutils.core import setup
from distutils.extension import Extension
from distutils import dep_util
from Cython.Distutils import build_ext
import glob
from subprocess import *
import string

def parse_events():
    template = """
#define __SCRIBE_EVENT <<Error>>

#define SCRIBE_EVENT(name, ...) \
    {'name': #name, 'type': 'Event', 'fields': [ __VA_ARGS__]},

#define SCRIBE_EVENT_SIZED(name, ...) \
    {'name': #name, 'type': 'EventSized', 'fields': [ __VA_ARGS__]},

#define SCRIBE_EVENT_DIVERGE(name, ...) \
    {'name': #name, 'type': 'EventDiverge', 'fields': [ __VA_ARGS__]},

#define __field(type, name) { 'type': #type, 'native_name': #name },

[
#include <linux/scribe_events.h>
]
    """
    out = Popen('gcc -E -x c -'.split(), stdin=PIPE, stdout=PIPE).communicate(template)[0]
    events = eval(out)
    for event in events:
        if event['type'] == 'EventDiverge':
            event['name'] = 'diverge_' + event['name']
        for field in event['fields']:
            field['name'] = field['native_name'].split('[')[0]
    return events

def camel_case(str):
    return ''.join(map(lambda e: e[0].upper() + e[1:], str.split('_')))

def field_getter(type, target, array_size):
    if array_size > 0:
        target = 'cpython.PyBytes_FromStringAndSize(<char *>(&%s[0]), sizeof(%s))' % (target, target)
    return ['            return %s' % target]

def field_setter(type, target, array_size):
    out = []
    value = 'value'
    if type == 'struct pt_regs':
        out.append('            cdef linux.pt_regs regs')
        out.append('            regs.ebx = value["ebx"]')
        out.append('            regs.ecx = value["ecx"]')
        out.append('            regs.edx = value["edx"]')
        out.append('            regs.esi = value["esi"]')
        out.append('            regs.edi = value["edi"]')
        out.append('            regs.ebp = value["ebp"]')
        out.append('            regs.eax = value["eax"]')
        out.append('            regs.xds = value["xds"]')
        out.append('            regs.xes = value["xes"]')
        out.append('            regs.xfs = value["xfs"]')
        out.append('            regs.xgs = value["xgs"]')
        out.append('            regs.orig_eax = value["orig_eax"]')
        out.append('            regs.eip = value["eip"]')
        out.append('            regs.xcs = value["xcs"]')
        out.append('            regs.eflags = value["eflags"]')
        out.append('            regs.esp = value["esp"]')
        out.append('            regs.xss = value["xss"]')
        value = 'regs'

    if array_size > 0:
        out.append('            raise NotImplementedError()')
        return out

    out.append('            %s = %s' % (target, value))
    return out


def gen_event_classes(events):
    out = []
    for event in events:
        class_name = 'Event' + camel_case(event['name'])
        scribe_type = 'scribe_api_events.SCRIBE_EVENT_' + event['name'].upper()
        scribe_struct = 'scribe_api_events.scribe_event_' + event['name']

        out.append('cdef class %s(%s):' % (class_name, event['type']))
        out.append('    native_type = Event.register(%s, %s)' % (class_name, scribe_type))

        fields = event['fields']
        args = ', '.join(
                ['self'] +
                map(lambda f: "%s=None" % f['name'], fields) +
                ['bytes buffer=None'])
        out.append('    def __init__(%s):' % args)
        out.append('        Event.__init__(self, buffer)')
        for field in fields:
            out.append('        if %s is not None:' % field['name'])
            out.append('            self.%s = %s' % (field['name'], field['name']))

        out.append('    def __repr__(self):')
        if fields:
            args   = ', '.join(map(lambda f: "%s=%%s" % f['name'], fields))
            values = ', '.join(map(lambda f: "repr(self.%s)" % f['name'], fields))
            out.append('        return "%s(%s)" %% (%s)' % (class_name, args, values))
        else:
            out.append('        return "%s()"' % class_name)

        for field in fields:
            target = '(<%s *>self.event_struct).%s' % (scribe_struct, field['name'])
            array_size = None

            if '[0]' in field['native_name']:
                array_size = 0
                target = 'self.payload'
            elif '[' in field['native_name']:
                array_size = 'sizeof(<%s *>self.event_struct).%s)' % (scribe_struct, field['name'])

            out.append('    property %s:' % field['name'])
            out.append('        def __get__(self):')
            out.extend(field_getter(field['type'], target, array_size))
            out.append('        def __set__(self, value):')
            out.extend(field_setter(field['type'], target, array_size))
        out.append('')
    return out

def gen_event_api(events):
    out = []
    out.append('cdef extern from "linux/scribe_api.h" nogil:')
    out.append('    enum scribe_event_type:')
    for event in events:
        scribe_type = 'SCRIBE_EVENT_' + event['name'].upper()
        out.append('        %s' % scribe_type)
    for event in events:
        scribe_struct = 'scribe_event_' + event['name']

        out.append('    struct %s:' % scribe_struct)
        if len(event['fields']) == 0:
            out.append('        pass')
        for field in event['fields']:
            field_type = field['type']
            field_type = string.replace(field_type, 'struct ', '')
            field_native_name = field['native_name']
            out.append('        %s %s' % (field_type, field_native_name))
    return out

events = parse_events()
sources = ['/usr/include/linux/scribe_events.h', 'setup.py']
if dep_util.newer_group(sources, 'src/scribe/events.pxi'):
    with open('src/scribe/events.pxi', 'w+') as f:
        f.write('# Autogenerated file\n')
        f.write('cimport scribe_api_events\n')
        f.write('cimport linux\n')
        f.write('\n'.join(gen_event_classes(events)))

if dep_util.newer_group(sources, 'src/scribe/scribe_api_events.pxd'):
    with open('src/scribe/scribe_api_events.pxd', 'w+') as f:
        f.write('# Autogenerated file\n')
        f.write('from linux cimport *\n')
        f.write('\n'.join(gen_event_api(events)))


################################################################################

scribe_src = sum((glob.glob('src/scribe/' + ext) \
                 for ext in '*.pyx *.pxd *.pxi'.split()), [])
setup(
    name = 'Scribe',
    description = 'Scribe python bindings',
    author = 'Nicolas Viennot',
    author_email = 'nicolas@viennot.biz',
    cmdclass = {'build_ext': build_ext},
    package_dir = {'': 'src'},
    ext_modules = [Extension('scribe',
                             extra_compile_args = ['-Wall', '-O2'],
                             sources = scribe_src,
                             depends = ['/usr/include/linux/scribe_api.h'],
                             libraries = ['scribe'])],
    scripts=['src/record', 'src/replay', 'src/profiler', 'src/shrink']
)
