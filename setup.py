# -*- coding: utf-8 -*-
from setuptools import setup, find_packages


tests_require = [
    'nose>=1.1.2',
    'mock>=1.0b1'
]

install_requires = [
    'raven>=2.0.3',
]


setup(
    name='raven_mailru',
    version='0.2.1',
    author='Pavel Zinovkin',
    author_email='pzinovkin@gmail.com',
    url='https://github.com/pzinovkin/raven-mailru',
    description='Data processor for Raven',
    packages=find_packages(exclude=['tests']),
    zip_safe=False,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={'test': tests_require},
    include_package_data=True,
)
