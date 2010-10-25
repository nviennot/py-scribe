#!/usr/bin/python

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
import glob

SCRIBE_PATH='src/scribe/'
scribe_src = sum((glob.glob(SCRIBE_PATH + ext) \
                 for ext in '*.pyx *.pxd'.split()), [])

setup(
    name = 'Scribe',
    description = 'Scribe python bindings',
    author = 'Nicolas Viennot',
    author_email = 'nicolas@viennot.biz',
    cmdclass = {'build_ext': build_ext},
    package_dir = {'': 'src'},
    packages = ['scribe'],
    ext_modules = [Extension('scribe',
                             sources = scribe_src,
                             libraries = ['scribe'])]
)

