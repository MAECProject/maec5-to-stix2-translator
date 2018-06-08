from __future__ import unicode_literals

import collections
import copy
import datetime
import itertools


class TranslationError(Exception):
    """
    Represents a translation error.  In particular, an error condition which
    was specifically checked for by the translator.  The translator doesn't
    try to be an exhaustive MAEC "validator", so many types of problems will
    be incidental and cause other types of exceptions.  This can be used where
    a more MAEC-specific exception makes sense.
    """
    pass


# Describes how a MAEC action name maps to STIX.
_ActionMapping = collections.namedtuple("ActionMapping",
                                        "stix_name observable_type")


# Maps MAEC malware-action name to corresponding STIX dynamic malware analysis
# name and corresponding cyber-observable type(s).  If a list of types is
# given, any observables of any of the given types are copied to STIX.
_MAEC_STIX_ACTION_MAP = {
    "create-process": _ActionMapping("created-processes", "process"),
    "read-from-process-memory": _ActionMapping("read-processes", "process"),
    "write-to-process-memory": _ActionMapping("written-processes", "process"),
    "kill-process": _ActionMapping("terminated-processes", "process"),
    "create-service": _ActionMapping("loaded-services", "process"),
    "load-library": _ActionMapping("loaded-dlls", "file"),
    "create-mutex": _ActionMapping("created-mutexes", "mutex"),
    "create-file": _ActionMapping("created-files", "file"),
    "open-file": _ActionMapping("opened-files", "file"),
    "delete-file": _ActionMapping("deleted-files", "file"),
    "read-from-file": _ActionMapping("read-files", "file"),
    "write-to-file": _ActionMapping("written-files", "file"),
    "create-directory": _ActionMapping("created-directories", "directory"),
    "open-directory": _ActionMapping("written-directories", "directory"),
    "create-registry-key": _ActionMapping("created-registry-keys",
                                          "windows-registry-key"),
    "delete-registry-key": _ActionMapping("deleted-registry-keys",
                                          "windows-registry-key"),
    "open-registry-key": _ActionMapping("opened-registry-keys",
                                        "windows-registry-key"),
    "create-registry-key-value": _ActionMapping("written-registry-key-values",
                                                "windows-registry-key"),
    "read-registry-key-value": _ActionMapping("read-registry-keys",
                                              "windows-registry-key"),
    "connect-to-url": _ActionMapping("contacted-urls", "url"),
    "connect-to-ip-address": _ActionMapping("contacted-ips",
                                            ["ipv4-addr", "ipv6-addr"])
}


# shortcut for these since they all map to the same STIX
for maec_action_name in ("send-http-connect-request",
                         "send-http-delete-request", "send-http-get-request",
                         "send-http-head-request", "send-http-options-request",
                         "send-http-patch-request", "send-http-post-request",
                         "send-http-put-request", "send-http-trace-request"):
    _MAEC_STIX_ACTION_MAP[maec_action_name] = _ActionMapping("http-requests",
                                                             "network-traffic")


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
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _name_from_malware_instance(maec_malware_instance, maec_package):
    """
    Derive a STIX malware object name from a MAEC malware instance.

    :param maec_malware_instance: A MAEC malware instance
    :param maec_package: The containing MAEC package
    :return:
    """
    if "name" in maec_malware_instance:
        return maec_malware_instance["name"]["value"]

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

    else:
        raise TranslationError("Unable to compute a STIX malware name from " +
                               maec_malware_instance["id"])

    return name


def _find_observable_refs(val, refs=None, visited_ids=None):
    """
    Traverse a single observable and find all its ref/refs property values.

    :param val: The observable, or some sub-object of it.
    :param refs: A set shared among the recursive calls, which builds up the
        set of discovered references.  If None, a new set will be created (and
        returned).
    :param visited_ids: Collects id()'s of visited sub-objects, to prevent
        infinite loops in the case of cyclic structures, and keep from
        re-traversing shared sub-objects.  If None, a new set is created.
    :return: The refs parameter is returned, for convenience.  It will contain
        all discovered references.
    """

    if visited_ids is None:
        visited_ids = set()

    if refs is None:
        refs = set()

    visited_ids.add(id(val))

    if isinstance(val, dict):
        for k, v in val.items():
            if k.endswith("_ref"):
                refs.add(v)
            elif k.endswith("_refs"):
                refs.update(v)
            elif id(v) not in visited_ids:
                _find_observable_refs(v, refs, visited_ids)

    elif isinstance(val, list):
        for v in val:
            if id(v) not in visited_ids:
                _find_observable_refs(v, refs, visited_ids)

    return refs


def _find_observable_closures(observable_ids, obs_map, visited_obs=None):
    """
    Given some observable IDs, figure out what they're connected to, both
    directly and indirectly.  I.e. find their closures.

    :param observable_ids: Iterable of the observable ID's of interest
    :param obs_map: A map of all observables (ID -> observable)
    :param visited_obs: Set of observable IDs shared among the recursive calls,
        used for collection, to prevent infinite loops in case there are
         cycles, and to keep from re-traversing shared substructure.  If None,
         a new set will be created (and returned).
    :return: The visited_obs parameter is returned, for convenience.  This
        will be the closure set.
    """

    if visited_obs is None:
        visited_obs = set()

    for obs_id in observable_ids:
        if obs_id not in visited_obs:
            visited_obs.add(obs_id)
            refs = _find_observable_refs(obs_map[obs_id])
            _find_observable_closures(refs, obs_map, visited_obs)

    return visited_obs


def _copy_extract_observables(observable_ids, maec_package):
    """
    Given some observable IDs from maec_package, return a new dict which
    contains copies of just those observables, along with any other indirectly
    referenced observables (so that there are no dangling references).

    Guidance is that the "x-maec-avclass" extension in observables embedded
    in a MAEC package should always be stripped in the translation to STIX.
    So this method also does that stripping.

    :param observable_ids: Iterable of IDs of observables to copy
    :param maec_package: The source of the copy, a MAEC package (observables
        are taken from its "observable_objects" property).
    :return: A dict with copies of all necessary observables from maec_package.
    """
    obs_map = maec_package["observable_objects"]
    extracted_obs = {
        object_ref: copy.deepcopy(obs_map[object_ref])
        for object_ref in _find_observable_closures(observable_ids, obs_map)
    }

    for obs in extracted_obs.values():
        if obs["type"] == "file" and "extensions" in obs:
            extensions = obs["extensions"]
            if "x-maec-avclass" in extensions:
                del extensions["x-maec-avclass"]
            if not extensions:
                del obs["extensions"]

    return extracted_obs


def _translate_static_features(maec_static_features, maec_package):
    """
    Translate MAEC static features to STIX static analysis results.

    :param maec_static_features: The MAEC static features
    :param maec_package: The containing MAEC package
    :return: A 2-tuple: A STIX static analysis results dict and a set of
        additional labels to be added to a STIX malware object
    """
    stix_results = {}
    additional_labels = set()

    if "certificates" in maec_static_features:
        stix_results["certificates"] = _copy_extract_observables(
            maec_static_features["certificates"], maec_package
        )

    if "obfuscation_methods" in maec_static_features:
        stix_packer_obfuscators = []
        for obfuscation_method in maec_static_features["obfuscation_methods"]:
            if obfuscation_method["method"] == "packing":
                stix_packer_obfuscators.append({
                    "type": "software",
                    "name": obfuscation_method["packer_name"],
                    "version": obfuscation_method["packer_version"]
                })
            else:
                additional_labels.add(obfuscation_method["method"])

            if "encryption_algorithm" in obfuscation_method:
                additional_labels.add(
                    obfuscation_method["encryption_algorithm"]
                )

        if stix_packer_obfuscators:
            stix_results["packers"] = {
                str(n): packer
                for n, packer in enumerate(stix_packer_obfuscators)
            }

    if "strings" in maec_static_features:
        stix_results["strings"] = maec_static_features["strings"][:]

    if "file_headers" in maec_static_features:
        stix_results["file-headers"] = _copy_extract_observables(
            maec_static_features["file_headers"], maec_package
        )

    return stix_results, additional_labels


def _translate_dynamic_features(maec_dynamic_features, maec_package):
    """
    Translate MAEC dynamic features to STIX dynamic analysis results.  This
    currently just looks at MAEC action_refs and ignores everything else.

    :param maec_dynamic_features: MAEC dynamic features
    :param maec_package: The containing MAEC package
    :return: A STIX dynamic analysis results dict
    """
    stix_results = {}

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

            # Make sure the action has what we need, and is one we can translate
            # (The "name" property is required.  Shouldn't need to check that.)
            if "output_object_refs" not in maec_obj or \
                    maec_obj["name"] not in _MAEC_STIX_ACTION_MAP:
                continue

            stix_mapping = _MAEC_STIX_ACTION_MAP[maec_obj["name"]]

            # Handle list-of-types by normalizing singles to a list as well.
            observable_types = stix_mapping.observable_type if isinstance(
                stix_mapping.observable_type, list
            ) else [
                stix_mapping.observable_type
            ]

            # Don't trust that the observables referenced from the action
            # satisfy STIX requirements.  Specifically look for observables
            # of the correct type.
            correct_type_observables = (
                obs_id for obs_id in maec_obj["output_object_refs"]
                if maec_package["observable_objects"][obs_id]["type"]
                in observable_types
            )

            observables = _copy_extract_observables(
                correct_type_observables,
                maec_package
            )

            # Yeah, sometimes an action refers only to observables of the
            # "wrong" type.  Then we have no observables to include in the
            # STIX.
            if observables:
                stix_results.setdefault(stix_mapping.stix_name, {}).update(
                    observables
                )

    return stix_results


def _start_stix_analysis(maec_analysis, maec_package):
    """
    Both MAEC and STIX can represent both static and dynamic analyses, and in
    both specs, both types of analyses are represented with a common type
    (analysis-metadata in MAEC and analysis-type in STIX).  So there is some
    common metadata for all analyses, in both specs.  This translates some
    commonalities from MAEC to STIX.

    :param maec_analysis: The MAEC analysis (static or dynamic)
    :param maec_package: The MAEC package containing the analysis
    :return: The beginnings of a new STIX analysis (a dict)
    """
    stix_analysis = {}
    if "start_time" in maec_analysis:
        stix_analysis["start_time"] = maec_analysis["start_time"]

    if "end_time" in maec_analysis:
        stix_analysis["end_time"] = maec_analysis["end_time"]

    if "tool_refs" in maec_analysis:
        stix_analysis["analysis_tools"] = _copy_extract_observables(
            maec_analysis["tool_refs"], maec_package
        )

    return stix_analysis


def _translate_static_analyses(maec_static_analyses, maec_static_features,
                               maec_package):
    """
    Translates MAEC static analyses/features to a STIX static analysis.

    :param maec_static_analyses: List of MAEC static analyses
    :param maec_static_features: MAEC static_features dict
    :param maec_package: The containing MAEC package
    :return: A 2-tuple: A STIX static analysis and a list of additional
        labels to be added to a STIX malware object.
    """

    # Guidance is to copy over some analysis metadata if there is exactly one
    # analysis.  Otherwise, either we have no metadata, or it's ambiguous
    # which analysis (if any) produced the static features.  So we don't copy
    # anything.  In all cases, we never produce more than one STIX analysis.
    if len(maec_static_analyses) == 1:
        stix_static_analysis = _start_stix_analysis(maec_static_analyses[0],
                                                    maec_package)
    else:
        stix_static_analysis = {}

    stix_static_results = None
    additional_labels = []
    if maec_static_features:
        stix_static_results, additional_labels = _translate_static_features(
            maec_static_features, maec_package
        )

    # "results" is actually required in STIX.  But nothing in MAEC's
    # static-features type is required.  But I don't think it can be empty
    # either.  Requirements are more complex.  But I can't add an empty
    # "results" property either, so I'll check.  Should an exception be raised
    # instead of omitting empty results?
    if stix_static_results:
        stix_static_analysis["results"] = stix_static_results

    return stix_static_analysis, additional_labels


def _translate_dynamic_analyses(maec_dynamic_analyses, maec_dynamic_features,
                                maec_package):
    """
    Translates MAEC dynamic analyses/features to a STIX dynamic analysis.

    :param maec_dynamic_analyses: List of MAEC dynamic analyses
    :param maec_dynamic_features: MAEC dynamic_features dict
    :param maec_package: The containing MAEC package
    :return: A STIX dynamic analysis
    """

    # similar issues for dynamic results as for static results
    if len(maec_dynamic_analyses) == 1:
        maec_dynamic_analysis = maec_dynamic_analyses[0]
        stix_dynamic_analysis = _start_stix_analysis(maec_dynamic_analysis,
                                                     maec_package)

        if "analysis_environment" in maec_dynamic_analysis:
            stix_dynamic_analysis["analysis_environment"] = \
                copy.deepcopy(maec_dynamic_analysis["analysis_environment"])
    else:
        stix_dynamic_analysis = {}

    stix_dynamic_results = None
    if maec_dynamic_features:
        stix_dynamic_results = _translate_dynamic_features(
            maec_dynamic_features, maec_package
        )

    if stix_dynamic_results:
        stix_dynamic_analysis["results"] = stix_dynamic_results

    return stix_dynamic_analysis


def _translate_analyses(maec_malware_instance, maec_package):
    """
    Translate analyses and features from the given MAEC malware instance to
    STIX analyses.

    :param maec_malware_instance: A MAEC malware instance
    :param maec_package: The containing MAEC package
    :return: A 3-tuple: list of STIX static analyses, list of STIX dynamic
        analyses, and a list of additional labels to be appended to a STIX
        malware object.  (Some MAEC malware features just result in some extra
        labels.)
    """
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

    stix_static_analysis, additional_labels = _translate_static_analyses(
        maec_static_analyses, maec_static_features, maec_package
    )

    stix_dynamic_analysis = _translate_dynamic_analyses(
        maec_dynamic_analyses, maec_dynamic_features, maec_package
    )

    return stix_static_analysis, stix_dynamic_analysis, additional_labels


def _translate_observable_extensions(maec_malware_instance, maec_package):
    """
    Translate x-maec-avclass extensions of cyber observables referenced by
    the given MAEC malware instance, to STIX malware av_results.

    :param maec_malware_instance: A MAEC malware instance
    :param maec_package: The containing MAEC package
    :return: An av_results value, which is a list of dicts (see the STIX
        "av-results-type" type).
    """

    maec_av_classification_extensions = itertools.chain.from_iterable(
        maec_package["observable_objects"][obj_id]
        ["extensions"]["x-maec-avclass"]
        for obj_id in maec_malware_instance["instance_object_refs"]
        if "extensions" in
           maec_package["observable_objects"][obj_id]
        and "x-maec-avclass" in
           maec_package["observable_objects"][obj_id]["extensions"]
    )

    results = []
    for extension in maec_av_classification_extensions:
        result = {
            "scanned": extension["scan_date"]
        }

        if "av_vendor" in extension:
            result["product"] = extension["av_vendor"]
        if "av_engine_version" in extension:
            result["engine_version"] = extension["av_engine_version"]
        if "av_definition_version" in extension:
            result["definition_version"] = extension["av_definition_version"]
        if "submission_date" in extension:
            result["submitted"] = extension["submission_date"]
        if extension["is_detected"] and "classification_name" in extension:
            result["result"] = extension["classification_name"]

        results.append(result)

    return results


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


def _translate_labels(maec_labels):
    """
    Translate MAEC labels to STIX malware labels.

    :param maec_labels: An iterable of MAEC labels
    :return: A list of STIX labels
    """

    # The labels are mostly the same; just one is different.  So we don't
    # need a full-fledged mapping at this point.
    return [
        "resource_exploitation" if maec_label == "resource_exploiter"
        else maec_label
        for maec_label in maec_labels
    ]


def _translate_aliases(maec_aliases):
    """
    Translate MAEC aliases to STIX external references.

    :param maec_aliases: An iterable of MAEC aliases
    :return: A list of STIX external references
    """
    return [
        {
            "source_name": "n/a",
            "description": "alias",
            "external_id": alias["value"]
        }
        for alias in maec_aliases
    ]


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


def _translate_malware_instance(maec_malware_instance, maec_package, timestamp):
    """
    Translate a MAEC malware instance to a STIX malware SDO.

    :param maec_malware_instance: The MAEC malware instance
    :param maec_package: The containing MAEC package
    :param timestamp: The timestamp to use for the SDO (created/modified)
    :return: The STIX malware SDO
    """
    stix_malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--" + _uuid_from_id(maec_malware_instance["id"]),
        "created": timestamp,
        "modified": timestamp,
        "is_family": False,
        "name": _name_from_malware_instance(maec_malware_instance,
                                            maec_package),
        "samples": _copy_extract_observables(
            maec_malware_instance["instance_object_refs"], maec_package
        )
    }

    # Optional properties
    if "labels" in maec_malware_instance:
        stix_malware["labels"] = _translate_labels(
            maec_malware_instance["labels"]
        )

    if "aliases" in maec_malware_instance:
        stix_malware["external_references"] = _translate_aliases(
            maec_malware_instance["aliases"]
        )

    if "description" in maec_malware_instance:
        stix_malware["description"] = maec_malware_instance["description"]

    if "field_data" in maec_malware_instance:
        _translate_first_last_seen(maec_malware_instance["field_data"],
                                   stix_malware)

    if "architecture_execution_envs" in maec_malware_instance:
        stix_malware["architecture_execution_envs"] = \
            maec_malware_instance["architecture_execution_envs"][:]

    stix_static_analysis, stix_dynamic_analysis, additional_labels = \
        _translate_analyses(maec_malware_instance, maec_package)
    if stix_static_analysis:
        stix_malware["static_analysis_results"] = [stix_static_analysis]
    if stix_dynamic_analysis:
        stix_malware["dynamic_analysis_results"] = [stix_dynamic_analysis]
    if additional_labels:
        stix_malware.setdefault("labels", []).extend(additional_labels)

    av_results = _translate_observable_extensions(maec_malware_instance,
                                                  maec_package)
    if av_results:
        stix_malware["av_results"] = av_results

    if "capabilities" in maec_malware_instance:
        stix_capabilities = _translate_capabilities(
            maec_malware_instance["capabilities"]
        )

        if stix_capabilities:
            stix_malware["capabilities"] = list(stix_capabilities)

    return stix_malware


def _translate_malware_family(maec_malware_family, timestamp):
    """
    Translate a MAEC malware family to a STIX malware SDO.

    :param maec_malware_family: A MAEC malware family
    :param timestamp: The timestamp to use for the SDO (created/modified)
    :return: The STIX malware SDO
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

    if "description" in maec_malware_family:
        stix_malware = maec_malware_family["description"]

    if "aliases" in maec_malware_family:
        stix_malware["external_references"] = _translate_aliases(
            maec_malware_family["aliases"]
        )

    if "references" in maec_malware_family:
        stix_malware.setdefault("external_references", []).extend(
            copy.deepcopy(maec_ref)
            for maec_ref in maec_malware_family["references"]
        )

    if "field_data" in maec_malware_family:
        _translate_first_last_seen(maec_malware_family["field_data"],
                                   stix_malware)

    if "common_capabilities" in maec_malware_family:
        stix_capabilities = _translate_capabilities(
            maec_malware_family["common_capabilities"]
        )

        if stix_capabilities:
            stix_malware["capabilities"] = list(stix_capabilities)

    if "common_strings" in maec_malware_family:
        # MAEC malware families can't have analyses, so translating this
        # to a STIX analysis may not really make sense...
        stix_malware["static_analysis_results"] = {
            "results": {
                "strings": maec_malware_family["common_strings"][:]
            }
        }

    return stix_malware


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

        stix_relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--" + _uuid_from_id(maec_relationship["id"]),
            "source_ref": "malware--" + _uuid_from_id(
                maec_relationship["source_ref"]
            ),
            "target_ref": "malware--" + _uuid_from_id(
                maec_relationship["target_ref"]
            )
        }

        if "timestamp" in maec_relationship:
            ts = maec_relationship["timestamp"]
        else:
            ts = timestamp
        stix_relationship["created"] = stix_relationship["modified"] = ts

        # Relationship type mapping is simple enough that a simple if-then
        # seems good enough; don't need a formal mapping dict yet.
        maec_rel_type = maec_relationship["relationship_type"]
        if maec_rel_type in ("variant-of", "derived-from", "related-to"):
            stix_relationship["relationship_type"] = maec_rel_type

        elif maec_rel_type == "dropped-by":
            # Reverse the directionality of the relationship for this type
            stix_relationship["source_ref"], stix_relationship["target_ref"] =\
                stix_relationship["target_ref"], stix_relationship["source_ref"]
            stix_relationship["relationship_type"] = "drops"

        else:
            stix_relationship["relationship_type"] = "related-to"

        stix_relationships.append(stix_relationship)

    return stix_relationships


def translate_package(maec_package):
    """
    Translate a MAEC package to a STIX bundle.

    The resulting bundle should be independent of the MAEC package (i.e. not
    share any mutable data), even if some things could be directly reused.
    (Barring bugs, of course.)

    :param maec_package: The MAEC package
    :return: The STIX bundle
    """

    # Use this whenever we need to set created/modified timestamps on things,
    # so they're consistent across the whole bundle.
    current_timestamp = _get_timestamp()

    package_uuid = _uuid_from_id(maec_package["id"])

    stix_note = {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--" + package_uuid,
        "description": "translated from MAEC 5.0",
        "created": current_timestamp,
        "modified": current_timestamp
    }

    stix_bundle = {
        "type": "bundle",
        "id": "bundle--" + package_uuid,
        "objects": [stix_note]
    }

    stix_obj_refs = []
    for maec_obj in maec_package["maec_objects"]:
        obj_type = maec_obj["type"]

        stix_obj = None
        if obj_type == "malware-instance":
            stix_obj = _translate_malware_instance(
                maec_obj, maec_package, current_timestamp
            )
        elif obj_type == "malware-family":
            stix_obj = _translate_malware_family(maec_obj, current_timestamp)
        # Other top-level MAEC objects ignored for now

        if stix_obj:
            stix_bundle["objects"].append(stix_obj)
            stix_obj_refs.append(stix_obj["id"])

    if "relationships" in maec_package:
        stix_relationships = _translate_relationships(maec_package,
                                                      current_timestamp)

        if stix_relationships:
            stix_bundle["objects"].extend(stix_relationships)
            stix_obj_refs.extend(rel["id"] for rel in stix_relationships)

    stix_note["object_refs"] = stix_obj_refs

    return stix_bundle
