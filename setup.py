from setuptools import setup, find_packages

setup(
    name='backend-test',
    version='0.1.8',
    packages=find_packages(exclude=['tests', 'tests.*']),
    zip_safe=False,
    include_package_data=True,
    package_dir={
        'lib': 'simple_backend',
        'lib/auth': 'simple_backend.auth',
        'lib/util': 'simple_backend.util',
    },
    url='https://github.com/YnkDK/simple-backend',
    license='MIT',
    author='Martin Storgaard',
    author_email='martin_simple_backend@dont.dk',
    description='A simple Flask backend, which (in the future) would conform to OWASP',
    install_requires=[
        'setuptools',
        'Flask == 0.10.1',
        'Flask-RESTful == 0.3.4',
        'Flask-Security == 1.7.4',
        'Flask-SQLAlchemy == 2.0',
        'SQLAlchemy-Utils == 0.31.0'
    ]
)
