"""Classify provision-scoped legislation.gov.uk unapplied effects.

Do not auto-approve a source merely because it is official. Commencement is
not inferred from the existence of an amendment. Only the first four classes
may clear source admission.
"""

from __future__ import annotations

from typing import Any, Literal
from xml.etree import ElementTree as ET

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_source_hold_review import (
    local_xml_tag,
    unapplied_effect_is_material_to_source,
)

PROVISION_EFFECT_SCHEMA = "legalbot.provision-effect-resolution.v2"
EffectClass = Literal[
    "EFFECT_ALREADY_APPLIED_IN_CURRENT_TEXT",
    "PROSPECTIVE_EFFECT_NOT_YET_IN_FORCE",
    "EFFECT_NOT_MATERIAL_TO_CURRENT_PROPOSITION",
    "MATERIAL_CURRENT_EFFECT_RESOLVED",
    "MATERIAL_CURRENT_EFFECT_UNRESOLVED",
]
CLEARING_CLASSES: frozenset[EffectClass] = frozenset(
    {
        "EFFECT_ALREADY_APPLIED_IN_CURRENT_TEXT",
        "PROSPECTIVE_EFFECT_NOT_YET_IN_FORCE",
        "EFFECT_NOT_MATERIAL_TO_CURRENT_PROPOSITION",
        "MATERIAL_CURRENT_EFFECT_RESOLVED",
    }
)


def _attr(element: ET.Element, name: str) -> str:
    for key, value in element.attrib.items():
        if local_xml_tag(key) == name:
            return str(value or "").strip()
    return ""


def classify_unapplied_effect(
    element: ET.Element,
    *,
    official_source_url: str,
    as_of_date: str,
) -> dict[str, Any]:
    required = _attr(element, "RequiresApplied").casefold() == "true"
    commenced = _attr(element, "Commenced").casefold()
    prospective = _attr(element, "Prospective").casefold() == "true"
    applied = _attr(element, "Applied").casefold() == "true"
    effect_type = _attr(element, "Type") or _attr(element, "Effect")
    affecting = _attr(element, "AffectingURI") or _attr(element, "AffectingProvisions")
    material = unapplied_effect_is_material_to_source(
        element, official_source_url=official_source_url
    )
    classification: EffectClass
    if not required or not material:
        classification = "EFFECT_NOT_MATERIAL_TO_CURRENT_PROPOSITION"
    elif applied and not required:
        classification = "EFFECT_ALREADY_APPLIED_IN_CURRENT_TEXT"
    elif prospective or commenced in {"false", "no", "0"}:
        classification = "PROSPECTIVE_EFFECT_NOT_YET_IN_FORCE"
    elif commenced in {"true", "yes", "1"}:
        classification = "MATERIAL_CURRENT_EFFECT_UNRESOLVED"
    else:
        # RequiresApplied on this provision, commencement not attested.
        classification = "MATERIAL_CURRENT_EFFECT_UNRESOLVED"
    payload = {
        "schema": PROVISION_EFFECT_SCHEMA,
        "official_source_url": official_source_url,
        "as_of_date": as_of_date,
        "requires_applied": required,
        "material_to_provision": material,
        "prospective": prospective,
        "commenced_attribute": commenced or None,
        "applied_attribute": applied,
        "effect_type": effect_type or None,
        "affecting": affecting or None,
        "classification": classification,
        "may_clear_source_admission": classification in CLEARING_CLASSES,
        "commencement_inferred_from_amendment_existence": False,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(payload)
    return payload


def classify_source_effects(
    official_xml: bytes,
    *,
    official_source_url: str,
    as_of_date: str,
) -> dict[str, Any]:
    effects: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(official_xml)
    except ET.ParseError:
        return {
            "schema": PROVISION_EFFECT_SCHEMA,
            "official_source_url": official_source_url,
            "as_of_date": as_of_date,
            "effect_count": 0,
            "unresolved_count": 0,
            "may_clear_source_admission": False,
            "classification": "MATERIAL_CURRENT_EFFECT_UNRESOLVED",
            "parse_failed": True,
            "effects": [],
            "writes_active": False,
            "writes_o04": False,
        }
    for element in root.iter():
        if local_xml_tag(element.tag) != "UnappliedEffect":
            continue
        if _attr(element, "RequiresApplied").casefold() != "true":
            continue
        effects.append(
            classify_unapplied_effect(
                element,
                official_source_url=official_source_url,
                as_of_date=as_of_date,
            )
        )
    unresolved = [item for item in effects if item["classification"] not in CLEARING_CLASSES]
    if unresolved:
        overall: EffectClass = "MATERIAL_CURRENT_EFFECT_UNRESOLVED"
    elif any(item["classification"] == "PROSPECTIVE_EFFECT_NOT_YET_IN_FORCE" for item in effects):
        overall = "PROSPECTIVE_EFFECT_NOT_YET_IN_FORCE"
    elif any(
        item["classification"] == "EFFECT_ALREADY_APPLIED_IN_CURRENT_TEXT" for item in effects
    ):
        overall = "EFFECT_ALREADY_APPLIED_IN_CURRENT_TEXT"
    elif effects:
        overall = "EFFECT_NOT_MATERIAL_TO_CURRENT_PROPOSITION"
    else:
        overall = "EFFECT_NOT_MATERIAL_TO_CURRENT_PROPOSITION"
    payload = {
        "schema": PROVISION_EFFECT_SCHEMA,
        "official_source_url": official_source_url,
        "as_of_date": as_of_date,
        "effect_count": len(effects),
        "unresolved_count": len(unresolved),
        "may_clear_source_admission": overall in CLEARING_CLASSES and not unresolved,
        "classification": overall,
        "parse_failed": False,
        "effects": effects,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "effects"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "effects"}
    )
    return payload
