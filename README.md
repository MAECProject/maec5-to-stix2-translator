## maec5-to-stix2-translator
Translates MAEC 5.0 Packages into STIX 2.1 Bundles.

### Details
More specifically, version 1.0 translates the following:

* MAEC Malware Instance (`malware-instance`) objects and Malware Family (`malware-family`) objects into STIX Malware (`malware`) objects.
* MAEC AV classifications (`x-maec-avclass`) into STIX `malware-analysis` SDOs.
* MAEC analysis metadata (`analysis-metadata`), static features (`static-features`), and dynamic features (`dynamic-features`) into STIX `malware-analysis` SDOs.
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

    usage: maec2stix [-h] [-o OUT] [-e ENCODING] [-n] in

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
      -n           Don't parse the translated STIX bundle using the stix2 library.
                   Only applicable when that library is installed. Otherwise, the
                   option is ignored.

The commandline tool is named `maec2stix`, and may be used for testing and
experimentation.  It reads a MAEC package and writes a STIX bundle.

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

This tool performs the following translation from MAEC 5.0 into the STIX 2.1 Malware and Malware Analysis SDOs (based on the STIX 2.1 SDOs as of 1/23/2020):

* MAEC 5.0 Package --> STIX 2.1 Bundle
  * MAEC Malware Instance Object --> STIX Malware SDO
  * MAEC Malware Family Object --> STIX Malware SDO
  * MAEC Malware Action Object --> STIX Malware Analysis SDO
  * MAEC Analysis Metadata Type --> STIX Malware Analysis SDO
  * MAEC Static Features Type --> STIX Malware Analysis SDO
  * MAEC Dynamic Features Type --> STIX Malware Analysis SDO
  * MAEC External Reference Type --> STIX External Reference Type
  * MAEC AV Classification Extension --> STIX AV Results Type
  * MAEC Binary Obfuscation Type --> STIX Malware SDO
  * MAEC Relationships --> STIX Relationships
  
Accordingly, the following major MAEC 5.0 objects and features are **not** translated in this release:

* **Top-level Objects**
  * Behaviors
  * Collections
* **Types/Features**
  * OS Features (Malware Instance)
  * Triggered Signatures (Malware Instance)
  * Process Tree (Dynamic Features)
  * Development Environment (Static Features)
  * Configuration Parameters (Static Features)

##### Object/Property Mappings

The following table provides details on the object/property mappings between MAEC 5.0 and the STIX 2.1 Malware SDO, as performed by the translator:

|MAEC Object|MAEC Type|MAEC Property|STIX Malware Type|STIX Malware Property|
|---------------|-------------|-----------------|---------------------|-------------------------|
|Malware Instance|---|labels|---|malware_types|
|Malware Instance|---|name|---|name|
|Malware Instance|---|aliases|---|aliases|
|Malware Instance|---|description|---|description|
|Malware Instance|`field-data`|first_seen|---|first_seen|
|Malware Instance|`field-data`|last_seen|---|last_seen|
|Malware Instance|---|architecture_execution_envs|---|architecture_execution_envs|
|Malware Instance|---|instance_object_refs|---|sample_refs|
|Malware Instance|---|capabilities|---|capabilities|
|Malware Instance|`binary-obfuscation`|non-"packing" obfuscation methods + encryption algorithms|---|labels|
|Malware Family|---|labels|---|malware_types|
|Malware Family|---|name|---|name|
|Malware Family|---|aliases|---|aliases|
|Malware Family|---|description|---|description|
|Malware Family|---|references|---|external_references|
|Malware Family|`field-data`|first_seen|---|first_seen|
|Malware Family|`field-data`|last_seen|---|last_seen|
|Malware Family|---|common_capabilities|---|capabilities|
|Malware Family|---|common_code_refs|---|sample_refs|

The following table provides details on the object/property mappings between MAEC 5.0 and the STIX 2.1 Malware Analysis SDO, as performed by the translator:

|MAEC Type|MAEC Property|STIX Malware Analysis Property|
|---------|-------------|------------------------------|
|`analysis-metadata`|tool_refs\[0\].name or "unknown"|product|
|`analysis-metadata`|start_time|analysis_started|
|`analysis-metadata`|end_time|analysis_ended|
|`analysis-metadata`|tool_refs + analysis_environment.installed-software|installed_software_refs|
|`analysis-metadata`|conclusion|av_result|
|`analysis-metadata`|analysis_environment.operating-system|operating_system_ref|
|`analysis-metadata`|analysis_environment.host-vm|host_vm_ref|
|`static-features`|certificates + file_headers|analysis_sco_refs|
|`dynamic-features`|action_refs.output_object_refs + network_traffic_refs|analysis_sco_refs|
|`x-maec-avclass`|av_vendor or "unknown"|product|
|`x-maec-avclass`|av_engine_version|analysis_engine_version|
|`x-maec-avclass`|av_definition_version|analysis_definition_version|
|`x-maec-avclass`|scan_date|analysis_started, analysis_ended|
|`x-maec-avclass`|is_detected|av_result|

Static, dynamic, and x-maec-avclass analysis metadata/features produce distinct STIX Malware Analysis SDOs, and are related to Malware SDOs in the following ways:

|MAEC Analysis Type|STIX Relationship Type|
|-------------|-----------------|
|static|static-analysis-of|
|dynamic|dynamic-analysis-of|
|x-maec-avclass|av-analysis-of|


##### Vocabulary Mappings

##### MAEC malware-label-ov --> STIX malware-type-ov

|MAEC Vocabulary Value|STIX Vocabulary Value|
|---------------------|---------------------|
|adware|adware|
|backdoor|backdoor|
|bot|bot|
|ddos|ddos|
|dropper|dropper|
|exploit-kit|exploit-kit|
|keylogger|keylogger|
|ransomware|ransomware|
|remote-access-trojan|remote-access-trojan|
|resource-exploiter|resource-exploitation|
|rogue-security-software|rogue-security-software|
|rootkit|rootkit|
|screen-capture|screen-capture|
|spyware|spyware|
|trojan|trojan|
|virus|virus|
|worm|worm|

#### Relationship Mappings

|MAEC Relationship|STIX Relationship|
|-----------------|-----------------|
|malware-instance `variant-of` malware-instance|malware `variant-of` malware|
|malware-instance `variant-of` malware-family|malware `variant-of` malware|
|malware-instance-1 `dropped-by` malware-instance-2|malware-2 `drops` malware-1|
|malware-instance-1 `dropped-by` malware-family-2|malware-2 `drops` malware-1|
|malware-instance `derived-from` malware-instance|malware `derived-from` malware|
|malware-instance `derived-from` malware-family|malware `derived-from` malware|
|malware-instance `related-to` malware-instance|malware `related-to` malware|
|malware-instance `related-to` malware-family|malware `related-to` malware|
|malware-instance-1 `downloaded-by` malware-instance-2|malware-2 `downloads` malware-1|
|malware-instance-1 `downloaded-by` malware-family-2|malware-2 `downloads` malware-1|
