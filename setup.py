#!/usr/bin/python

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
import glob

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
                             sources = scribe_src,
                             libraries = ['scribe'])],
    scripts=['src/record', 'src/replay']
)
