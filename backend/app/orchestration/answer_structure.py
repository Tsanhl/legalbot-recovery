"""Host-owned section roles shared by prompting, rendering and quality checks."""

from ..types import TaskType


SECTION_CONTRACTS = {
    TaskType.GENERAL: (
        ("direct-answer", "Direct answer"),
        ("applicable-law", "Applicable law"),
        ("application", "Application to your facts"),
        ("qualifications", "Qualifications and uncertainty"),
        ("next-steps", "Practical next steps"),
        ("conclusion", "Conclusion"),
    ),
    TaskType.ESSAY: (
        ("thesis", "Introduction and thesis"),
        ("legal-framework", "Legal framework"),
        ("analysis", "Critical analysis"),
        ("counterargument", "Counterargument and evaluation"),
        ("conclusion", "Conclusion"),
    ),
    TaskType.PROBLEM: (
        ("issues", "Parties and issues"),
        ("rules", "Applicable rules"),
        ("application", "Application to the facts"),
        ("alternatives", "Counterarguments and uncertainty"),
        ("remedies", "Remedies and ranked outcomes"),
        ("conclusion", "Conclusion"),
    ),
}


def section_contract(task_type: TaskType | str) -> list[dict[str, str]]:
    task = TaskType(task_type)
    return [
        {"id": key, "heading": heading}
        for key, heading in SECTION_CONTRACTS.get(task, SECTION_CONTRACTS[TaskType.GENERAL])
    ]


def canonical_heading(task_type: TaskType | str, section_id: str, position: int) -> str:
    # An unrecognised model heading still cannot smuggle unchecked legal prose
    # into the answer. Known section roles retain their meaning for the scorer.
    headings = {item["id"]: item["heading"] for item in section_contract(task_type)}
    return headings.get(section_id, f"Analysis {position}")
