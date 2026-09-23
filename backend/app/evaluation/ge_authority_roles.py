"""Authority dependency roles. A rejected redundant route is not a case blocker."""

from __future__ import annotations

from .ge_hold_reason_router import CASE_174

DEPENDENCY_ROLES = (
    "CONTROLLING",
    "REQUIRED",
    "REQUIRED_IF_CONTRACT_INCORPORATES_THAT_EDITION",
    "SUPPLEMENTARY",
    "SUPPLEMENTARY_CASE_MANAGEMENT_AUTHORITY",
    "ALTERNATIVE_ROUTE",
    "REDUNDANT",
    "REJECTED_ROUTE",
)

NAMED_ROLES: dict[str, dict[str, str | bool]] = {
    "cable & wireless plc v ibm united kingdom ltd": {
        "authority_dependency_role": "REJECTED_ROUTE",
        "case_174_global_blocker": False,
        "mandatory_evidence_route": False,
    },
    "icc mediation rules (contractually incorporated edition)": {
        "authority_dependency_role": "REQUIRED_IF_CONTRACT_INCORPORATES_THAT_EDITION",
        "case_174_global_blocker": False,
        "mandatory_evidence_route": True,
    },
    "churchill v merthyr tydfil county borough council": {
        "authority_dependency_role": "SUPPLEMENTARY_CASE_MANAGEMENT_AUTHORITY",
        "case_174_global_blocker": False,
        "mandatory_evidence_route": True,
    },
    "ohpen operations uk ltd v invesco fund managers ltd": {
        "authority_dependency_role": "REQUIRED",
        "case_174_global_blocker": False,
        "mandatory_evidence_route": True,
    },
    "kajima construction europe (uk) ltd v children's ark partnership ltd": {
        "authority_dependency_role": "REQUIRED",
        "case_174_global_blocker": False,
        "mandatory_evidence_route": True,
    },
    "the civil procedure rules 1998": {
        "authority_dependency_role": "SUPPLEMENTARY",
        "case_174_global_blocker": False,
        "mandatory_evidence_route": True,
    },
}


def authority_dependency(title: str, *, case_id: str = "") -> dict[str, str | bool]:
    key = str(title or "").casefold().replace("’", "'")
    role = NAMED_ROLES.get(key)
    if role is None:
        return {
            "authority_dependency_role": "SUPPLEMENTARY",
            "case_174_global_blocker": False,
            "mandatory_evidence_route": False,
        }
    value = dict(role)
    if case_id == CASE_174 and value["authority_dependency_role"] == "REJECTED_ROUTE":
        value["case_174_global_blocker"] = False
    return value


def rejected_route_must_not_stop_case(title: str, *, alternative_official_route_present: bool) -> bool:
    role = authority_dependency(title)
    return role["authority_dependency_role"] == "REJECTED_ROUTE" and alternative_official_route_present
