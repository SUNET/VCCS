#!/usr/bin/env python
#
from setuptools import setup, find_packages
import sys, os
from distutils import versionpredicate

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()

version = '0.1dev'

install_requires = [
    'pyhsm >= 1.0.3',
    'ndnkdf >= 0.1',
    'py-bcrypt >= 0.3',
    'cherrypy >= 3.2.0',
    'simplejson >= 2.6.2',
    'pyserial >= 2.6',
    'pycrypto >= 2.6',
    'pymongo >= 2.4.2',
]

setup(name='VCCS',
      version=version,
      description="Very Complicated Credential System",
      long_description=README,
      classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        ],
      keywords='security password hashing bcrypt PBKDF2',
      author='Fredrik Thulin',
      author_email='fredrik@thulin.net',
      license='BSD',
      packages=find_packages('src'),
      package_dir = {'': 'src'},
      include_package_data=True,
      package_data = { },
      zip_safe=False,
      install_requires=install_requires,
      entry_points={
        'console_scripts': ['vccs_authbackend=vccs_auth.vccs_authbackend:main',
                            ]
        }
      )
