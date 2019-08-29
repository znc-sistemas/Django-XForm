import os
import re

from setuptools import find_packages, setup


def read(f):
    return open(f, 'r', encoding='utf-8').read()


def get_version(package):
    init_py = open(os.path.join(package, '__init__.py')).read()
    return re.search("__version__ = ['\"]([^'\"]+)['\"]", init_py).group(1)


setup(
    name='djangoxform',
    version=get_version('xform'),
    url='https://github.com/znc-sistemas/Django-XForm',
    license='MIT',
    description='OpenRosa for Django.',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    author='NECTO',
    author_email='contato@nectosystems.com.br',  # SEE NOTE BELOW (*)
    packages=find_packages(exclude=['tests*']),
    include_package_data=True,
    install_requires=[
        'requests==2.21.0',
        'pyxform==0.13.1',
        'xlrd==1.2.0',
        'djangorestframework==3.9.2',
        'djangorestframework-xml==1.4.0',
    ],
    python_requires=">=3.5",
    zip_safe=False,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Internet :: WWW/HTTP',
    ]
)
