from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

setup(
	name='Scribe',
	description='Scribe python bindings',
	author='Nicolas Viennot',
	author_email='nicolas@viennot.biz',
	cmdclass = {'build_ext': build_ext},
	ext_modules = [Extension("scribe",
		["src/scribe.pyx"],
		libraries=["scribe"])]
)

