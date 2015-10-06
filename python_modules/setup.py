from distutils.core import setup, Extension

module1 = Extension('tracereplay', sources = ['tracereplay.c'])

setup(name = 'tracereplay',
      version = '0.1',
      description = 'Replay a system call trace through an application',
      ext_modules = [module1])
