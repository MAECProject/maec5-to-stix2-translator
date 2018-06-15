## maec5-to-stix2-translator
Translates MAEC 5.0 Packages into STIX 2.1 Bundles.

### Details
More specifically, version 1.0 translates the following:

* MAEC Malware Instance (`malware-instance`) objects and Malware Family (`malware-family`) objects into STIX Malware (`malware`) objects.
* MAEC AV classifications (`x-maec-avclass`) into STIX AV results (`av-results-type`).
* MAEC analysis metadata (`analysis-metadata`), static features (static-features), and dynamic features (`dynamic-features`) into STIX analysis results (`analysis-type`).
* MAEC Relationships into STIX Relationships.

### Usage


