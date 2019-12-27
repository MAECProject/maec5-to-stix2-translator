from setuptools import setup, find_packages
setup(
    name="maec2stix",
    version="1.0",
    packages=find_packages(),
    author="Mitre",
    description="Translate MAEC 5.0 packages to STIX 2.1",
    python_version=">= 2.7",
    install_requires=[
        "stix2-elevator>=2",
        "six"
    ],
    extras_require={
        # TODO: update this to require the earliest released version of stix2
        # to support the STIX 2.1 specification.
        "stix2": ["stix2"]
    },

    entry_points={
        "console_scripts": [
            "maec2stix = maec2stix.cli:main"
        ]
    }
)
