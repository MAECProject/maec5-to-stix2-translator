from __future__ import unicode_literals

import collections
import copy
import datetime
import itertools
import re
import six
import stix2elevator.stix_stepper
import stix2elevator.ids
import uuid

try:
    import stix2
except ImportError:
    stix2 = None


class TranslationError(Exception):
    """
    Represents a translation error.  In particular, an error condition which
    was specifically checked for by the translator.  The translator doesn't
    try to be an exhaustive MAEC "validator", so many types of problems will
    be incidental and cause other types of exceptions.  This can be used where
    a more MAEC-specific exception makes sense.
    """
    pass


# Maps MAEC capabilities and refined capabilities to STIX capabilities.
# Since it's all one map, the implication is that either the MAEC capability
# sets are mutually exclusive, or the translation doesn't depend on whether a
# MAEC capability is "refined" or not.
_MAEC_STIX_CAPABILITY_MAP = {
    "anti-debugging": "anti-debugging",
    "anti-disassembly": "anti-disassembly",
    "anti-emulation": "anti-emulation",
    "anti-memory-forensics": "anti-memory-forensics",
    "anti-sandbox": "anti-sandbox",
    "anti-virus-evasion": "evades-av",
    "anti-vm": "anti-vm",
    "authentication-credentials-theft": "steals-authentication-credentials",
    "clean-traces-of-infection": "cleans-traces-of-infection",
    "communicate-with-c2-server": "communicates-with-c2",
    "compromise-data-availability": "compromises-data-availability",
    "compromise-system-availability": "compromises-system-availability",
    "data-integrity-violation": "compromises-data-integrity",
    "determine-c2-server": "determines-c2-server",
    "email-spam": "emails-spam",
    "exfiltration": "exfiltrates-data",
    "file-infection": "infects-files",
    "fraud": "commits-fraud",
    "hide-artifacts": "hides-artifacts",
    "hide-executing-code": "hides-executing-code",
    "input-peripheral-capture": "captures-input-peripherals",
    "install-other-components": "installs-other-components",
    "local-machine-control": "controls-local-machine",
    "network-environment-probing": "probes-network-environment",
    "output-peripheral-capture": "captures-output-peripherals",
    "persistence": "persists-after-system-reboot",
    "prevent-artifact-access": "prevents-artifact-access",
    "prevent-artifact-deletion": "prevents-artifact-deletion",
    "privilege-escalation": "escalates-privileges",
    "remote-machine-access": "accesses-remote-machines",
    "remote-machine-infection": "infects-remote-machines",
    "security-software-degradation": "degrades-security-software",
    "self-modification": "self-modifies",
    "system-operational-integrity-violation":
        "violates-system-operational-integrity",
    "system-state-data-capture": "captures-system-state-data",
    "system-update-degradation": "degrades-system-updates"
}


class SCOMapping(object):

    _SCOGraphNode = collections.namedtuple("SCOGraphNode", "sco outgoing_sros")

    def __init__(self, maec_observable_objects, creation_timestamp):
        """
        Initialize the internal structures from a MAEC package's observable
        objects.

        :param maec_observable_objects: The value of the "observable_objects"
            property of a MAEC package.  This is a mapping from ID to a
            STIX 2.0 SCO.
        :param creation_timestamp: A timestamp to use for versioning properties
            for any objects which may need to be created while translating
            SCOs from STIX 2.0 to 2.1.
        """
        self.__by_maec_id, self.__by_stix_id, self.__sco_graph = \
            self.__make_mappings(
                maec_observable_objects, creation_timestamp
            )

    def __remove_maec_avclass_extension(self, sco):
        """
        Guidance is that the "x-maec-avclass" extension in observables embedded
        in a MAEC package should always be stripped in the translation to STIX.
        So this method does that stripping.  This side-effects the given sco.

        :param sco: The SCO to strip (a dict)
        """
        if sco["type"] == "file" and "extensions" in sco:
            extensions = sco["extensions"]
            if "x-maec-avclass" in extensions:
                del extensions["x-maec-avclass"]
            if not extensions:
                del sco["extensions"]

    def __make_mappings(self, maec_observable_objects, creation_timestamp):
        """
        Create the bookkeeping structures for this mapping object.  Three maps
        are created:  by_maec_id, by_stix_id, sco_graph.

        by_maec_id: maps a MAEC SCO ID to a list of STIX 2.1 SCO IDs.  These
            are the non-SRO direct 2.0->2.1 translation results.

        by_stix_id: maps a STIX 2.1 ID to the corresponding 2.1 object.

        sco_graph: this conceptually stores an SCO graph, where nodes are
            STIX 2.1 SCOs and edges are SROs connecting them.  The
            data structure is a mapping from STIX 2.1 ID to a 2-tuple, where
            the first element is the node SCO, and the second element is a
            list of SROs which are the node's outgoing edges.  So it is a kind
            of adjacency-list representation: IDs of adjacent nodes can be
            obtained from the SROs via their "target_ref" properties.

        :param maec_observable_objects: The value of the "observable_objects"
            property of a MAEC package.  This is a mapping from ID to a
            STIX 2.0 SCO.
        :param creation_timestamp: A timestamp to use for versioning properties
            for any objects which may need to be created while translating
            SCOs from STIX 2.0 to 2.1.
        """

        # Elevator "steps" (translates from STIX 2.0 to 2.1) SCOs by
        # side-effecting them, but I don't want to modify the input MAEC
        # package.  So make copies first.  Also need to make the minimal
        # structure required for the stepper.  The stepper wasn't written with
        # this kind of programmatic usage in mind, so it's kind of awkward...
        observed_data = {
            "created": creation_timestamp
        }
        observed_data["objects"] = objs = {
            maec_sco_id: copy.deepcopy(maec_sco)
            for maec_sco_id, maec_sco in maec_observable_objects.items()
        }

        # Add IDs: required for the elevator's SCO conversion.  While we're
        # at it, also look for and strip the x-maec-avclass extension.
        # spec_version is necessary for the stix2 parser to interpret the
        # stepped SCOs as STIX version 2.1, in the context of a bundle.
        # The v21 Bundle class doesn't provide any associated STIX version
        # context, so the SCO's must self-identify their STIX version.
        for obj in objs.values():
            self.__remove_maec_avclass_extension(obj)
            obj["id"] = stix2elevator.ids.generate_sco_id(obj["type"], obj)
            obj["spec_version"] = "2.1"

        by_maec_id = {}
        by_stix_id = {}
        sco_graph = {}
        for maec_sco_id, maec_sco in objs.items():
            results = stix2elevator.stix_stepper.step_cyber_observable(
                maec_sco, observed_data
            )

            # Update mappings for SCO results; collect SRO results.
            # The latter will be used to update the "outgoing edge" lists for
            # the former.
            sro_results = []
            for result in results:
                by_stix_id[result["id"]] = result

                if result["type"] == "relationship":
                    sro_results.append(result)
                else:
                    by_maec_id.setdefault(maec_sco_id, []).append(result["id"])
                    sco_graph[result["id"]] = SCOMapping._SCOGraphNode(
                        result, []  # fill in any outgoing edges below
                    )

            for sro in sro_results:
                source_ref = sro["source_ref"]
                source_graph_node = sco_graph.get(source_ref)

                if not source_graph_node:
                    raise TranslationError(
                        "SCO conversion produced a '{}' relationship from an "
                        "unknown object: {}".format(
                            sro["relationship_type"],
                            source_ref
                        )
                    )

                source_graph_node.outgoing_sros.append(sro)

        return by_maec_id, by_stix_id, sco_graph

    def get_stix_object(self, stix_id):
        """
        Look up STIX 2.1 object by its ID.

        :param stix_id: The ID of the object to look up.
        :return: The object
        :raise KeyError: If the ID isn't recognized
        """
        return self.__by_stix_id[stix_id]

    def get_stix_objects(self, stix_ids):
        """
        Look up STIX 2.1 objects by their IDs.

        :param stix_ids: A single or iterable of STIX 2.1 IDs.
        :return: The list of matching objects.  If a single ID is given,
            the result will nevertheless be a list (of length 1).
        :raise KeyError: If any ID isn't recognized
        """
        if isinstance(stix_ids, six.text_type):
            stix_ids = [stix_ids]

        return [
            self.__by_stix_id[stix_id] for stix_id in stix_ids
        ]

    def get_stix_object_closure_for_maec_ids(
        self, maec_ids, tlo_type_filter=None
    ):
        """
        Get STIX 2.1 IDs of objects related to the given STIX 2.0 IDs.
        "Related" objects are those connected via either SRO or _ref/_refs
        property.  Two sets of IDs are returned: IDs of "top-level" objects
        and IDs of all objects.  The distinction is necessary because a
        *_refs property for example should only contain the directly relevant
        values.  Other objects should accompany them in the bundle so that there
        are no dangling references or lost information, but the property should
        not refer to them directly.

        If tlo_type_filter is given, filter the top-level objects to be only
        those of the given types.  This allows the caller to ask only for
        those objects which satisfy STIX spec requirements.  The returned
        tuple's second value is not directly subject to the filter, but will
        contain only those objects related to top-level objects which pass the
        filter.  In that way, the filter indirectly affects the latter set too.

        :param maec_ids: A single or list of STIX 2.0 IDs
        :param tlo_type_filter: An iterable of strings giving allowed STIX
            types of the top-level objects.
        :return: A 2-tuple consisting of (1) set of STIX 2.1 IDs of top-level
            objects, and (2) set of STIX 2.1 IDs of all objects, including
            the top-level objects and any others which are related.
        """
        if isinstance(maec_ids, six.text_type):
            maec_ids = [maec_ids]

        tlo_ids = set()
        visited_stix_ids = set()

        for maec_id in maec_ids:

            if tlo_type_filter:
                stix_ids = (
                    stix_id
                    for stix_id in self.__by_maec_id[maec_id]
                    if self.__by_stix_id[stix_id]["type"]
                    in tlo_type_filter
                )
            else:
                stix_ids = self.__by_maec_id[maec_id]

            for stix_id in stix_ids:
                tlo_ids.add(stix_id)

                self.get_stix_object_closure_for_stix_ids(
                    stix_id, visited_stix_ids
                )

        return tlo_ids, visited_stix_ids

    def get_stix_object_closure_for_stix_ids(
        self, stix_ids, visited_stix_ids=None
    ):
        """
        Get the STIX 2.1 IDs of all objects "related" to objects with the given
        IDs.  This includes relationships via SROs and *_ref/refs properties.

        :param stix_ids: The STIX 2.1 IDs of objects to start the search from
        :param visited_stix_ids: A set of IDs already visited, to prevent
            redundant searches, or None to start a new set.  This is updated
            as the search proceeds, and doubles as the returned closure set.
        :return: The visited_stix_ids parameter
        """
        if isinstance(stix_ids, six.text_type):
            stix_ids = [stix_ids]

        if visited_stix_ids is None:
            visited_stix_ids = set()

        for stix_id in stix_ids:
            if stix_id not in visited_stix_ids:
                visited_stix_ids.add(stix_id)

                sco, outgoing_sros = self.__sco_graph[stix_id]

                for prop_name in sco:
                    if prop_name.endswith("_ref") or \
                            prop_name.endswith("_refs"):
                        self.get_stix_object_closure_for_stix_ids(
                            sco[prop_name], visited_stix_ids
                        )

                for sro in outgoing_sros:
                    visited_stix_ids.add(sro["id"])
                    self.get_stix_object_closure_for_stix_ids(
                        sro["target_ref"], visited_stix_ids
                    )

        return visited_stix_ids


def _uuid_from_id(id_):
    """Extract the uuid from a MAEC identifier"""
    dd_idx = id_.find("--")
    if dd_idx == -1:
        raise TranslationError(
            "Invalid ID: {}.  Must have format <type>--<uuid>.".format(id_)
        )
    return id_[dd_idx+2:]


def _get_timestamp():
    """Get a timestamp string for the current time (as UTC)"""
    ts = datetime.datetime.utcnow()

    # Ensure exactly 3 digits after the decimal point, as required by STIX
    # for timestamps used for versioning.
    if ts.microsecond == 0:
        ts_iso_str = ts.isoformat() + ".000Z"
    else:
        ts_iso_str = ts.isoformat()[:-3] + "Z"

    return ts_iso_str


def _make_sro(source_id, target_id, relationship_type, timestamp, id_=None):
    """
    Make an SRO dict from components.

    :param source_id: The value for the source_ref property
    :param target_id: The value for the target_ref property
    :param relationship_type: A relationship type (string)
    :param timestamp: A timestamp string
    :param id_: An ID to use for the SRO, or None to generate one from a uuid4.
    :return: The SRO dict
    """
    return {
        "id": id_ or "relationship--" + six.text_type(uuid.uuid4()),
        "type": "relationship",
        "spec_version": "2.1",
        "relationship_type": relationship_type,
        "source_ref": source_id,
        "target_ref": target_id,
        "created": timestamp,
        "modified": timestamp
    }


def _name_from_malware_instance(maec_malware_instance, maec_package):
    """
    Derive a STIX malware object name from a MAEC malware instance.

    :param maec_malware_instance: A MAEC malware instance
    :param maec_package: The containing MAEC package
    :return: A name, or None if one could not be determined
    """
    name = None

    if "name" in maec_malware_instance:
        name = maec_malware_instance["name"]["value"]

    else:
        # This is only a simple attempt to obtain a name.  The MAEC spec allows
        # references to any type of observable, although files and urls are
        # typical.  We won't try to handle every type.
        object_ref = maec_malware_instance["instance_object_refs"][0]
        observable = maec_package["observable_objects"][object_ref]

        obs_type = observable["type"]
        if obs_type == "file":
            if "name" in observable:
                name = observable["name"]
            else:
                hashes = observable["hashes"]

                # In order of preference...
                if "MD5" in hashes:
                    name = hashes["MD5"]
                elif "SHA-256" in hashes:
                    name = hashes["SHA-256"]
                else:
                    # otherwise, just use whatever's there?
                    k = next(iter(hashes))
                    name = hashes[k]

        elif obs_type == "url":
            name = observable["value"]

    return name


def _normalize_for_stix_malware_analysis_product(value):
    """
    Normalize a string according to STIX 2.1 malware-analysis/product
    requirements.

    From STIX 2.1 spec, malware-analysis "product" value "SHOULD be all
    lowercase with words separated by a dash".  So ensure that format.

    :param value: The value to normalize
    :return: The normalized value
    """
    value = re.sub(r"[^a-z0-9-]+", "-", value, flags=re.I)

    # coalesce multiple dashes to one
    value = re.sub(r"--+", "-", value)

    # strip leading/trailing dashes, lowercase
    value = value.strip("-").lower()

    return value


def _translate_maec_analysis_conclusion(conclusion):
    """
    Translate from MAEC analysis conclusion (analysis-conclusion-ov) to
    STIX malware-analysis result (malware-av-result-ov).

    :param conclusion: The MAEC conclusion value
    :return: The STIX result value
    """
    # Mapping is simple enough not to need a table; just hardcode the one
    # change: indeterminate -> unknown
    return "unknown" if conclusion == "indeterminate" else conclusion


def _product_name_from_analysis_metadata(maec_analysis_metadata, sco_mapping):
    """
    Get a value for the required "product" property of a malware-analysis SDO,
    from MAEC analysis-metadata.

    :param maec_analysis_metadata: Some MAEC analysis metadata
    :param sco_mapping: The STIX 2.0->2.1 SCO mapping object
    :return: A product value, or "unknown" if one could not otherwise be found
    """
    product = "unknown"

    if maec_analysis_metadata:
        tool_refs = maec_analysis_metadata.get("tool_refs")
        if tool_refs:
            # There may be many "tool_refs" values, but we have no
            # criteria to choose one.  Just pick the first one.  Each must refer
            # to a "software" SCO.
            software_sco_ids, _ = \
                sco_mapping.get_stix_object_closure_for_maec_ids(tool_refs[0])

            # As of this writing, a single STIX 2.0 software SCO (used in MAEC)
            # translates to a single STIX 2.1 software SCO.
            first_sco_id = software_sco_ids.pop()
            software_sco = sco_mapping.get_stix_object(first_sco_id)

            product = software_sco["name"]

    return product


def _start_stix_malware_analysis(timestamp, product):
    """
    Create a basic starter malware-analysis SDO, with the given timestamp
    for its versioning properties, and a "product" property value derived from
    the given product.  The product value will be normalized according to STIX
    requirements.

    :param timestamp: The timestamp string used for the versioning properties
    :param product: The product value to normalize and use
    :return: A malware-analysis SDO dict
    """
    return {
        "type": "malware-analysis",
        "spec_version": "2.1",
        "id": "malware-analysis--" + six.text_type(uuid.uuid4()),
        "created": timestamp,
        "modified": timestamp,
        "product": _normalize_for_stix_malware_analysis_product(product)
    }


def _start_stix_malware_analysis_from_maec_analysis(
    timestamp, sco_mapping, maec_analysis=None
):
    """
    Both MAEC and STIX can represent both static and dynamic analyses, and in
    both specs, both types of analyses are represented with a common type
    (analysis-metadata in MAEC and the malware-analysis SDO in STIX).  So there
    is some common metadata for all analyses, in both specs.  This translates
    some commonalities from MAEC to STIX.

    :param maec_analysis: The MAEC analysis (static or dynamic)
    :return: A 2-tuple consisting of (1) The beginnings of a new STIX analysis
        SDO (a dict), and (2) all STIX 2.1 IDs of SCOs which must be included
        in the eventual bundle the SDO will be included in.
    """

    all_stix_ids = set()

    product = _product_name_from_analysis_metadata(
        maec_analysis, sco_mapping
    )
    stix_malware_analysis = _start_stix_malware_analysis(timestamp, product)

    if maec_analysis:
        if "start_time" in maec_analysis:
            stix_malware_analysis["analysis_started"] = \
                maec_analysis["start_time"]

        if "end_time" in maec_analysis:
            stix_malware_analysis["analysis_ended"] = maec_analysis["end_time"]

        if "tool_refs" in maec_analysis:
            tlo_ids, stix_ids = \
                sco_mapping.get_stix_object_closure_for_maec_ids(
                    maec_analysis["tool_refs"], ["software"]
                )

            if tlo_ids:
                stix_malware_analysis["installed_software_refs"] = \
                    list(tlo_ids)
                all_stix_ids |= stix_ids

        if "conclusion" in maec_analysis:
            stix_malware_analysis["result"] = \
                _translate_maec_analysis_conclusion(
                    maec_analysis["conclusion"]
                )

        if "analysis_environment" in maec_analysis:
            analysis_environment = maec_analysis["analysis_environment"]

            if "operating-system" in analysis_environment:
                tlo_ids, stix_ids = \
                    sco_mapping.get_stix_object_closure_for_maec_ids(
                        analysis_environment["operating-system"],
                        ["software"]
                    )

                if tlo_ids:
                    stix_malware_analysis["operating_system_ref"] = \
                        tlo_ids.pop()
                    all_stix_ids |= stix_ids

            if "host-vm" in analysis_environment:
                tlo_ids, stix_ids = \
                    sco_mapping.get_stix_object_closure_for_maec_ids(
                        analysis_environment["host-vm"],
                        ["software"]
                    )

                if tlo_ids:
                    stix_malware_analysis["host_vm_ref"] = \
                        tlo_ids.pop()
                    all_stix_ids |= stix_ids

            if "installed-software" in analysis_environment:
                tlo_ids, stix_ids = \
                    sco_mapping.get_stix_object_closure_for_maec_ids(
                        analysis_environment["installed-software"],
                        ["software"]
                    )

                if tlo_ids:
                    stix_malware_analysis.setdefault(
                        "installed_software_refs", []
                    ).extend(tlo_ids)
                    all_stix_ids |= stix_ids

    return stix_malware_analysis, all_stix_ids


def _start_stix_malware_analysis_from_sco_extension(
    extension, timestamp
):
    """
    Start a malware-analysis SDO from an x-maec-avclass extension on a SCO from
    a MAEC package.

    :param extension: The extension dict
    :param timestamp: A timestamp string to use for the new SDO's versioning
        properties
    :return: The malware-analysis SDO dict
    """
    # Guidance is to use vendor for the "product", not the name.
    av_vendor = extension.get("av_vendor", "unknown")
    stix_malware_analysis = _start_stix_malware_analysis(timestamp, av_vendor)

    stix_malware_analysis["analysis_started"] = \
        stix_malware_analysis["analysis_ended"] = extension["scan_date"]

    # The extension has boolean yes/no detection value, so we can't distinguish
    # between "malicious" and "suspicious".  Just use "malicious" if detected
    # and "benign" if not.
    stix_malware_analysis["result"] = "malicious" if \
        extension["is_detected"] else "benign"

    if "av_version" in extension:
        stix_malware_analysis["version"] = extension["av_version"]

    if "av_engine_version" in extension:
        stix_malware_analysis["analysis_engine_version"] = \
            extension["av_engine_version"]

    if "av_definition_version" in extension:
        stix_malware_analysis["analysis_definition_version"] = \
            extension["av_definition_version"]

    return stix_malware_analysis


def _translate_static_features(maec_static_features, sco_mapping):
    """
    Translate MAEC static features to STIX 2.1 SCOs.

    :param maec_static_features: The MAEC static features
    :return: A 3-tuple: (1) The STIX 2.1 IDs of SCOs to be directly referenced
        from a malware-analysis SDO, (2) All IDs of SCOs to be included in the
        eventual bundle, (3) set of additional malware SDO labels derived from
        certain aspects of the MAEC static features
    """
    additional_labels = set()
    all_tlo_ids = set()
    all_stix_ids = set()

    if maec_static_features:
        obfuscation_methods = maec_static_features.get("obfuscation_methods")
        certificates = maec_static_features.get("certificates")
        file_headers = maec_static_features.get("file_headers")

        if obfuscation_methods:
            for obfuscation_method in obfuscation_methods:
                if obfuscation_method["method"] != "packing":
                    additional_labels.add(obfuscation_method["method"])

                if "encryption_algorithm" in obfuscation_method:
                    additional_labels.add(
                        obfuscation_method["encryption_algorithm"]
                    )

        if certificates:
            tlo_ids, stix_ids = \
                sco_mapping.get_stix_object_closure_for_maec_ids(
                    certificates, ["x509-certificate"]
                )
            all_tlo_ids |= tlo_ids
            all_stix_ids |= stix_ids

        if file_headers:
            tlo_ids, stix_ids = \
                sco_mapping.get_stix_object_closure_for_maec_ids(
                    file_headers, ["file"]
                )
            all_tlo_ids |= tlo_ids
            all_stix_ids |= stix_ids

    return all_tlo_ids, all_stix_ids, additional_labels


def _translate_dynamic_features(
    maec_dynamic_features, maec_package, sco_mapping
):
    """
    Translate MAEC dynamic features to STIX 2.1 SCOs.

    :param maec_dynamic_features: MAEC dynamic features
    :param maec_package: The containing MAEC package
    :param sco_mapping: The STIX 2.0->2.1 SCO mapping object
    :return: A 2-tuple: (1) The STIX 2.1 IDs of SCOs to be directly referenced
        from a malware-analysis SDO, (2) All IDs of SCOs to be included in the
        eventual bundle
    """
    all_tlo_ids = set()
    all_stix_ids = set()

    if "action_refs" in maec_dynamic_features:
        for action_ref in maec_dynamic_features["action_refs"]:

            # Find the ref in the maec objects.  Should I get fancy and create a
            # mapping from ID to object, for fast lookup?
            for maec_obj in maec_package["maec_objects"]:
                if maec_obj["id"] == action_ref:
                    break
            else:
                # reference error: action doesn't exist!
                continue

            if maec_obj["type"] != "malware-action":
                # type error: reference must be to an action!
                continue

            # Make sure the action has what we need.
            if "output_object_refs" not in maec_obj:
                continue

            tlo_ids, stix_ids = \
                sco_mapping.get_stix_object_closure_for_maec_ids(
                    maec_obj["output_object_refs"]
                )

            all_tlo_ids |= tlo_ids
            all_stix_ids |= stix_ids

    if "network_traffic_refs" in maec_dynamic_features:
        tlo_ids, stix_ids = sco_mapping.get_stix_object_closure_for_maec_ids(
            maec_dynamic_features["network_traffic_refs"]
        )

        all_tlo_ids |= tlo_ids
        all_stix_ids |= stix_ids

    return all_tlo_ids, all_stix_ids


def _translate_static_analyses(maec_static_analyses, maec_static_features,
                               timestamp, sco_mapping):
    """
    Translates MAEC static analyses/features to a STIX static analysis.

    :param maec_static_analyses: List of MAEC static analyses
    :param maec_static_features: MAEC static_features dict
    :param timestamp: The timestamp to use for versioning properties of newly
        created SDOs, etc
    :param sco_mapping: The STIX 2.0->2.1 SCO mapping object
    :return: A 3-tuple: (1) A malware-analysis SDO, (2) a set of labels for
        the malware object (representing the malware being analyzed), (3)
        set of STIX 2.1 IDs of SCOs to be included in the eventual bundle
    """
    all_stix_ids = set()
    additional_labels = set()

    if len(maec_static_analyses) == 1:
        maec_static_analysis = maec_static_analyses[0]
    else:
        maec_static_analysis = None

    stix_static_analysis, stix_ids = \
        _start_stix_malware_analysis_from_maec_analysis(
            timestamp, sco_mapping, maec_static_analysis
        )
    all_stix_ids |= stix_ids

    if maec_static_features:
        tlo_ids, stix_ids, additional_labels = _translate_static_features(
            maec_static_features, sco_mapping
        )

        if tlo_ids:
            all_stix_ids |= stix_ids
            stix_static_analysis["analysis_sco_refs"] = list(tlo_ids)

    # STIX spec says analyses must have at least one of the below two
    # properties.  If we didn't get either one, gotta toss our analysis out.
    # (But keep the additional labels.)
    if all(
        prop not in stix_static_analysis
        for prop in ("result", "analysis_sco_refs")
    ):
        stix_static_analysis = None
        all_stix_ids.clear()

    return stix_static_analysis, additional_labels, all_stix_ids


def _translate_dynamic_analyses(maec_dynamic_analyses, maec_dynamic_features,
                                maec_package, timestamp, sco_mapping):
    """
    Translates MAEC dynamic analyses/features to a STIX dynamic analysis.

    :param maec_dynamic_analyses: List of MAEC dynamic analyses
    :param maec_dynamic_features: MAEC dynamic_features dict
    :param maec_package: The containing MAEC package
    :param timestamp: The timestamp to use for created/modified properties of
        newly created malware-analysis SDOs, SROs, etc.
    :param sco_mapping: The STIX 2.0->2.1 SCO mapping object
    :return: A 2-tuple: (1) A malware-analysis SDO, (2) set of STIX 2.1 IDs of
        SCOs to be included in the eventual bundle
    """
    all_stix_ids = set()

    if len(maec_dynamic_analyses) == 1:
        maec_dynamic_analysis = maec_dynamic_analyses[0]
    else:
        maec_dynamic_analysis = None

    stix_dynamic_analysis, stix_ids = \
        _start_stix_malware_analysis_from_maec_analysis(
            timestamp, sco_mapping, maec_dynamic_analysis
        )
    all_stix_ids |= stix_ids

    if maec_dynamic_features:
        tlo_ids, stix_ids = _translate_dynamic_features(
            maec_dynamic_features, maec_package, sco_mapping
        )

        if tlo_ids:
            all_stix_ids |= stix_ids
            stix_dynamic_analysis["analysis_sco_refs"] = list(tlo_ids)

    # STIX spec says analyses must have at least one of the below two
    # properties.  If we didn't get either one, gotta toss our analysis out.
    if all(
        prop not in stix_dynamic_analysis
        for prop in ("result", "analysis_sco_refs")
    ):
        stix_dynamic_analysis = None
        all_stix_ids.clear()

    return stix_dynamic_analysis, all_stix_ids


def _translate_analyses(
    maec_malware_instance, maec_package, timestamp, sco_mapping
):
    """
    Translate analyses and features from the given MAEC malware instance to
    STIX analyses.

    :param maec_malware_instance: A MAEC malware instance
    :param maec_package: The containing MAEC package
    :param timestamp: The timestamp to use for created/modified properties of
        newly created STIX objects
    :param sco_mapping: The STIX 2.0->2.1 SCO mapping object
    :return: A 4-tuple: (1) a STIX static analysis, (2) STIX dynamic analysis,
        (3) a set of additional labels to be appended to a STIX malware object,
        (4) set of STIX 2.1 IDs of SCOs to be included in the eventual bundle
    """
    all_stix_ids = set()

    maec_static_analyses = []
    maec_dynamic_analyses = []
    maec_static_features = None
    maec_dynamic_features = None

    if "analysis_metadata" in maec_malware_instance:
        for analysis in maec_malware_instance["analysis_metadata"]:
            if analysis["analysis_type"] == "static":
                maec_static_analyses.append(analysis)
            else:
                maec_dynamic_analyses.append(analysis)

    if "static_features" in maec_malware_instance:
        maec_static_features = maec_malware_instance["static_features"]

    if "dynamic_features" in maec_malware_instance:
        maec_dynamic_features = maec_malware_instance["dynamic_features"]

    stix_static_analysis, additional_labels, stix_ids = \
        _translate_static_analyses(
            maec_static_analyses, maec_static_features, timestamp, sco_mapping
        )

    all_stix_ids |= stix_ids

    stix_dynamic_analysis, stix_ids = _translate_dynamic_analyses(
        maec_dynamic_analyses, maec_dynamic_features, maec_package, timestamp,
        sco_mapping
    )

    all_stix_ids |= stix_ids

    return stix_static_analysis, stix_dynamic_analysis, additional_labels, \
        all_stix_ids


def _translate_observable_extensions(
    maec_malware_instance, maec_package, timestamp
):
    """
    Translate x-maec-avclass extensions of cyber observables referenced by
    the given MAEC malware instance, to STIX malware-analysis SDOs.

    :param maec_malware_instance: A MAEC malware instance
    :param maec_package: The containing MAEC package
    :param timestamp: The timestamp to use for versioning properties of
        newly created STIX objects
    :return: A list of malware-analysis SDO dicts
    """
    stix_analyses = []

    maec_av_classification_extensions = itertools.chain.from_iterable(
        maec_package["observable_objects"][obj_id]
        ["extensions"]["x-maec-avclass"]
        for obj_id in maec_malware_instance["instance_object_refs"]
        if "extensions" in
           maec_package["observable_objects"][obj_id]
        and "x-maec-avclass" in
           maec_package["observable_objects"][obj_id]["extensions"]
    )

    for extension in maec_av_classification_extensions:

        stix_analysis = _start_stix_malware_analysis_from_sco_extension(
            extension, timestamp
        )

        # I guess nothing else to add to the SDO.  No analysis_sco_refs
        # here: the SCO extension doesn't identify anything the analysis
        # discovered, other than a general benign/malicious/etc
        # classification (and maybe a name).  It seems to me
        # analysis_sco_refs is not intended to include the thing being
        # analyzed.  That is represented via an SRO relationship to a
        # malware SDO.

        stix_analyses.append(stix_analysis)

    return stix_analyses


def _translate_capabilities(maec_capabilities, stix_capabilities=None):
    """
    Translates the given MAEC capabilities into STIX malware capabilities.

    :param maec_capabilities: An iterable of MAEC capabilities as dicts (see
        the MAEC "capability" type).
    :param stix_capabilities: A set of STIX capabilities as strings.  This is
        shared across the recursive calls and built up incrementally.  It's a
        set to ensure we don't get capability duplicates.  If None, a new set
        is created (and returned).
    :return: Returns stix_capabilities, i.e. the translated capability set.
    """
    if stix_capabilities is None:
        stix_capabilities = set()

    for maec_capability in maec_capabilities:
        maec_cap_name = maec_capability["name"]
        if maec_cap_name in _MAEC_STIX_CAPABILITY_MAP:
            stix_capabilities.add(_MAEC_STIX_CAPABILITY_MAP[maec_cap_name])
        if "refined_capabilities" in maec_capability:
            _translate_capabilities(maec_capability["refined_capabilities"],
                                    stix_capabilities)

    return stix_capabilities


def _translate_first_last_seen(maec_field_data, stix_malware):
    """
    Translate from MAEC field data to first/last seen properties on the
    given STIX malware object.

    :param maec_field_data: MAEC field data
    :param stix_malware: The STIX malware object to update
    """
    if "first_seen" in maec_field_data:
        stix_malware["first_seen"] = maec_field_data["first_seen"]
    if "last_seen" in maec_field_data:
        stix_malware["last_seen"] = maec_field_data["last_seen"]


def _translate_malware_instance(
    maec_malware_instance, maec_package, timestamp, sco_mapping
):
    """
    Translate a MAEC malware instance to a STIX malware SDO.

    :param maec_malware_instance: The MAEC malware instance
    :param maec_package: The containing MAEC package
    :param timestamp: The timestamp to use for versioning properties of
        newly created STIX objects
    :param sco_mapping: The STIX 2.0->2.1 SCO mapping object
    :return: A 5-tuple: (1) a STIX 2.1 malware SDO dict, (2) a STIX
        malware-analysis SDO dict for a static analysis of the malware, or None,
        (3) same as (2) for a dynamic analysis, (4) a list of malware-analysis
        SDOs for all the SCO extension based av scan analyses, (5) set of STIX
        2.1 IDs of SCOs to be included in the eventual bundle
    """

    stix_malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--" + _uuid_from_id(maec_malware_instance["id"]),
        "created": timestamp,
        "modified": timestamp,
        "is_family": False
    }

    all_stix_ids = set()

    name = _name_from_malware_instance(maec_malware_instance, maec_package)
    if name:
        stix_malware["name"] = name
    if "aliases" in maec_malware_instance:
        stix_malware["aliases"] = [
            alias["value"] for alias in maec_malware_instance["aliases"]
        ]

    if "labels" in maec_malware_instance:
        maec_labels = maec_malware_instance["labels"][:]
    else:
        maec_labels = ["unknown"]
    stix_malware["malware_types"] = maec_labels

    if "description" in maec_malware_instance:
        stix_malware["description"] = maec_malware_instance["description"]

    if "field_data" in maec_malware_instance:
        _translate_first_last_seen(maec_malware_instance["field_data"],
                                   stix_malware)

    if "architecture_execution_envs" in maec_malware_instance:
        stix_malware["architecture_execution_envs"] = \
            maec_malware_instance["architecture_execution_envs"][:]

    stix_static_analysis, stix_dynamic_analysis, additional_labels, stix_ids = \
        _translate_analyses(
            maec_malware_instance, maec_package, timestamp, sco_mapping
        )
    all_stix_ids |= stix_ids

    if additional_labels:
        stix_malware["labels"] = additional_labels

    stix_avscan_analyses = _translate_observable_extensions(
        maec_malware_instance, maec_package, timestamp
    )

    if "capabilities" in maec_malware_instance:
        stix_capabilities = _translate_capabilities(
            maec_malware_instance["capabilities"]
        )

        if stix_capabilities:
            stix_malware["capabilities"] = list(stix_capabilities)

    tlo_ids, stix_ids = sco_mapping.get_stix_object_closure_for_maec_ids(
        maec_malware_instance["instance_object_refs"],
        ["file", "artifact"]
    )
    if tlo_ids:
        stix_malware["sample_refs"] = list(tlo_ids)
        all_stix_ids |= stix_ids

    return stix_malware, stix_static_analysis, stix_dynamic_analysis, \
        stix_avscan_analyses, all_stix_ids


def _translate_malware_family(maec_malware_family, timestamp, sco_mapping):
    """
    Translate a MAEC malware family to a STIX malware SDO.

    :param maec_malware_family: A MAEC malware family
    :param timestamp: The timestamp to use for versioning properties of
        newly created STIX objects
    :param sco_mapping: The STIX 2.0->2.1 SCO mapping object
    :return: A 2-tuple: (1) The STIX malware SDO, and (2) set of STIX 2.1 IDs
        of SCOs to be included in the eventual bundle
    """
    stix_malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--" + _uuid_from_id(maec_malware_family["id"]),
        "created": timestamp,
        "modified": timestamp,
        "is_family": True,
        "name": maec_malware_family["name"]
    }

    all_stix_ids = set()

    if "description" in maec_malware_family:
        stix_malware["description"] = maec_malware_family["description"]

    if "aliases" in maec_malware_family:
        stix_malware["aliases"] = [
            alias["value"] for alias in maec_malware_family["aliases"]
        ]

    if "labels" in maec_malware_family:
        maec_labels = maec_malware_family["labels"][:]
    else:
        maec_labels = ["unknown"]
    stix_malware["malware_types"] = maec_labels

    if "references" in maec_malware_family:
        stix_malware["external_references"] = [
            copy.deepcopy(maec_ref)
            for maec_ref in maec_malware_family["references"]
        ]

    if "field_data" in maec_malware_family:
        _translate_first_last_seen(maec_malware_family["field_data"],
                                   stix_malware)

    if "common_capabilities" in maec_malware_family:
        stix_capabilities = _translate_capabilities(
            maec_malware_family["common_capabilities"]
        )

        if stix_capabilities:
            stix_malware["capabilities"] = list(stix_capabilities)

    if "common_code_refs" in maec_malware_family:
        tlo_ids, stix_ids = sco_mapping.get_stix_object_closure_for_maec_ids(
            maec_malware_family["common_code_refs"],
            ["file", "artifact"]
        )

        if tlo_ids:
            stix_malware["sample_refs"] = list(tlo_ids)
            all_stix_ids |= stix_ids

    return stix_malware, all_stix_ids


def _translate_relationships(maec_package, timestamp):
    """
    Translate MAEC relationships to STIX SROs.

    :param maec_package: The MAEC package containing the relationships
    :param timestamp: The timestamp to use for the SROs (created/modified), if
        the MAEC relationship doesn't have a "timestamp" property.
    :return: A list of SROs (as a list of dicts)
    """

    # Make looking up a MAEC object by ID fast
    ref_map = {
        maec_obj["id"]: maec_obj
        for maec_obj in maec_package["maec_objects"]
    }

    stix_relationships = []
    for maec_relationship in maec_package["relationships"]:

        src_maec_obj = ref_map[maec_relationship["source_ref"]]
        dst_maec_obj = ref_map[maec_relationship["target_ref"]]

        # Guidance doesn't define translations for relationships with
        # other source/target types.
        if src_maec_obj["type"] != "malware-instance":
            continue

        if dst_maec_obj["type"] not in ("malware-instance", "malware-family"):
            continue

        stix_source_ref = "malware--" + _uuid_from_id(
            maec_relationship["source_ref"]
        )
        stix_target_ref = "malware--" + _uuid_from_id(
            maec_relationship["target_ref"]
        )
        stix_ts = maec_relationship.get("timestamp", timestamp)
        stix_rel_id = "relationship--" + _uuid_from_id(maec_relationship["id"])

        # Relationship type mapping is simple enough that a simple if-then
        # seems good enough; don't need a formal mapping dict yet.
        maec_rel_type = maec_relationship["relationship_type"]
        if maec_rel_type in ("variant-of", "derived-from", "related-to"):
            stix_rel_type = maec_rel_type

        elif maec_rel_type == "dropped-by":
            # Reverse the directionality of the relationship for this type
            stix_source_ref, stix_target_ref = stix_target_ref, stix_source_ref
            stix_rel_type = "drops"

        elif maec_rel_type == "downloaded-by":
            # Reverse the directionality of the relationship for this type
            stix_source_ref, stix_target_ref = stix_target_ref, stix_source_ref
            stix_rel_type = "downloads"

        else:
            stix_rel_type = "related-to"

        stix_relationship = _make_sro(
            stix_source_ref,
            stix_target_ref,
            stix_rel_type,
            stix_ts,
            stix_rel_id
        )

        stix_relationships.append(stix_relationship)

    return stix_relationships


def translate_package(maec_package):
    """
    Translate a MAEC package to a STIX bundle.

    The resulting bundle should be independent of the MAEC package (i.e. not
    share any mutable data), even if some things could be directly reused.
    (Barring bugs, of course.)

    :param maec_package: The MAEC package (a dict)
    :return: The STIX bundle (a dict)
    """

    # Use this whenever we need to set created/modified timestamps on things,
    # so they're consistent across the whole bundle.
    current_timestamp = _get_timestamp()

    package_uuid = _uuid_from_id(maec_package["id"])

    stix_note = {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--" + package_uuid,
        "content": "translated from MAEC 5.0",
        "created": current_timestamp,
        "modified": current_timestamp
    }

    stix_bundle = {
        "type": "bundle",
        "id": "bundle--" + package_uuid,
        "objects": [stix_note]
    }
    stix_objects = stix_bundle["objects"] = [stix_note]

    maec_observable_objects = maec_package.get("observable_objects", {})
    sco_mapping = SCOMapping(maec_observable_objects, current_timestamp)
    all_sco_ids = set()

    for maec_obj in maec_package["maec_objects"]:
        obj_type = maec_obj["type"]

        if obj_type == "malware-instance":
            stix_obj, static_analysis, dynamic_analysis, avscan_analyses, \
                sco_ids = _translate_malware_instance(
                    maec_obj, maec_package, current_timestamp, sco_mapping
                )

            stix_objects.append(stix_obj)
            all_sco_ids |= sco_ids

            if static_analysis:
                stix_objects.append(static_analysis)
                stix_objects.append(
                    _make_sro(
                        static_analysis["id"], stix_obj["id"],
                        "static-analysis-of", current_timestamp
                    )
                )

            if dynamic_analysis:
                stix_objects.append(dynamic_analysis)
                stix_objects.append(
                    _make_sro(
                        dynamic_analysis["id"], stix_obj["id"],
                        "dynamic-analysis-of", current_timestamp
                    )
                )

            if avscan_analyses:
                stix_objects.extend(avscan_analyses)
                stix_objects.extend(
                    _make_sro(
                        analysis["id"], stix_obj["id"], "av-analysis-of",
                        current_timestamp
                    )
                    for analysis in avscan_analyses
                )

        elif obj_type == "malware-family":
            stix_obj, sco_ids = _translate_malware_family(
                maec_obj, current_timestamp, sco_mapping
            )

            stix_objects.append(stix_obj)
            all_sco_ids |= sco_ids

        # Other top-level MAEC objects ignored for now

    stix_objects.extend(sco_mapping.get_stix_objects(all_sco_ids))

    if "relationships" in maec_package:
        stix_relationships = _translate_relationships(maec_package,
                                                      current_timestamp)

        if stix_relationships:
            stix_objects.extend(stix_relationships)

    stix_note["object_refs"] = [
        obj["id"] for obj in stix_objects
        if obj is not stix_note  # except the note itself!
    ]

    return stix_bundle


def translate_package_to_object(maec_package):
    """
    Translate a MAEC package to a STIX bundle.  This will return a stix2
    Bundle object, instead of a plain dict.

    Note that this function may produce errors where translate_package() does
    not.  The stix2 parsing process performs a lot more validation of content
    than the translator does.  For example, invalid MAEC content might be
    copied to the bundle by the translator without error, whereas the stix2
    parsing process detects the problem and triggers an error.

    :param maec_package: The MAEC package (a dict)
    :return: The STIX bundle (as a stix2 object)
    """
    if not stix2:
        raise TranslationError("Can't create a stix2 object: "
                               "please install stix2 first!")

    stix_bundle_dict = translate_package(maec_package)
    return stix2.parse(stix_bundle_dict)
