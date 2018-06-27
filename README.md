## maec5-to-stix2-translator
Translates MAEC 5.0 Packages into STIX 2.1 Bundles.

### Details
More specifically, version 1.0 translates the following:

* MAEC Malware Instance (`malware-instance`) objects and Malware Family (`malware-family`) objects into STIX Malware (`malware`) objects.
* MAEC AV classifications (`x-maec-avclass`) into STIX AV results (`av-results-type`).
* MAEC analysis metadata (`analysis-metadata`), static features (`static-features`), and dynamic features (`dynamic-features`) into STIX analysis results (`analysis-type`).
* MAEC Relationships into STIX Relationships.

### Usage

This library may be used in one of two ways: programmatically, or as a
commandline tool.  Some additional functionality is available if the
python-stix2 library is installed, and it supports STIX 2.1.  As of this
writing, no released version of python-stix2 supports STIX 2.1.

Note that this library isn't designed to validate MAEC content.  It mostly
assumes the content is correct.  If it isn't, results are unpredictable.
Exceptions might be thrown, or some components of the MAEC package could be
silently dropped in the translation.  The results might not be what you expect.

#### Commandline Usage

    usage: maec2stix [-h] [-o OUT] [-e ENCODING] [-p] in

    Translates MAEC 5.0 packages to STIX 2.1 bundles.

    positional arguments:
      in           Path to file with a MAEC package (as JSON) to translate. Use
                   "-" to read from stdin.

    optional arguments:
      -h, --help   show this help message and exit
      -o OUT       Path to file to write the translated STIX to (as JSON).
                   (Default: write to stdout)
      -e ENCODING  Encoding to use for reading/writing files (Default: utf8). Does
                   not apply to stdin/out.
      -p           Process the translated STIX bundle using the stix2 library.
                   This can catch additional translation or data problems.

The commandline tool is named `maec2stix`, and may be used for testing and
experimentation.  It reads a MAEC package and writes a STIX bundle.  As noted
above, the `-p` option is *only* visible if python-stix2 is installed.

#### Programmatic Usage

Two public functions are available in the `maec2stix.translator` package:
* `translate_package()`: accepts a MAEC package as a dict (parsed JSON) and
returns a STIX 2.1 bundle as a dict (which may be serialized to JSON if
desired).
* `translate_package_to_object()`: same as above, but returns a python-stix2
Bundle object.  If python-stix2 isn't installed, this function just raises an
exception.  If the installed python-stix2 library doesn't support STIX 2.1,
it's likely to fail to process the bundle data, and a variety of errors could
result.

### Translation

This tool performs the following translation from MAEC 5.0 into the STIX 2.1 Malware SDO (based on the STIX 2.1 Malware SDO as of 5/31/2018):

* MAEC 5.0 Package --> STIX 2.1 Bundle
  * MAEC Malware Instance Object --> STIX Malware SDO
  * MAEC Malware Family Object --> STIX Malware SDO
  * MAEC Analysis Metadata Type --> STIX Analysis Type
  * MAEC Static Features Type --> STIX Analysis Type
  * MAEC Dynamic Features Type --> STIX Analysis Type
  * MAEC Name Type --> STIX External Reference Type
  * MAEC External Reference Type --> STIX External Reference Type
  * MAEC AV Classification Extension --> STIX AV Results Type
  * MAEC Binary Obfuscation Type --> STIX Software Object Type
  * MAEC Relationships --> STIX Relationships

##### Object/Property Mappings

The following table provides details on the object/property mappings between MAEC 5.0 and the STIX 2.1 Malware SDO, as performed by the translator:

|MAEC 5.0 Object|MAEC 5.0 Type|MAEC 5.0 Property|STIX 2.1 Malware Type|STIX 2.1 Malware Property|
|---------------|-------------|-----------------|---------------------|-------------------------|
||||||


##### Vocabulary Mappings
