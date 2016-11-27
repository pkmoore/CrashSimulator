from distutils.core import setup, Extension


setup(name='tracereplay',
      version='0.1',
      description='Replay a system call trace through an application',
      packages=['tracereplay', 'tracereplay.checker'],
      ext_modules=[Extension('tracereplay.cinterface',
                             ['tracereplay/cinterface/tracereplay.c'])])
