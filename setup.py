from setuptools import find_packages, setup

setup(
    name='crowbar',
    version='4.1',
    entry_points={
        'console_scripts': [
            'crowbar = crowbar:main',
        ],
    },
    install_requires=[
        'paramiko',
    ],
    packages=find_packages(),
    python_requires='>=3.6',
)
