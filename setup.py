from setuptools import setup, find_packages
setup(
    name="maec2stix",
    version="1.0",
    packages=find_packages(),
    author="Mitre",
    description="Translate MAEC 5.0 packages to STIX 2.1",
    python_version=">= 2.7",

    entry_points={
        "console_scripts": [
            "maec2stix = maec2stix.cli:main"
        ]
    }
)
