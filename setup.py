#!/usr/bin/env python

from setuptools import setup, find_packages

tests_require = ["coverage", "flake8", "wheel"]

setup(
    name="exile",
    version="0.1.1",
    url="https://github.com/pyauth/exile",
    license="Apache Software License",
    author="Andrey Kislyuk",
    author_email="kislyuk@gmail.com",
    description="Python YubiKey AWS signature library",
    long_description=open("README.rst").read(),
    install_requires=[],
    tests_require=tests_require,
    extras_require={
        "test": tests_require,
    },
    packages=find_packages(exclude=["test"]),
    include_package_data=True,
    test_suite="test",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
