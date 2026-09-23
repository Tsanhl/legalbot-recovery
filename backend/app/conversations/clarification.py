"""Small observable-fact intake rules, separate from legal classification."""

from __future__ import annotations

import re


def user_fact_text(question: str) -> str:
    if not question.startswith("Saved conversation ("):
        return question
    pieces = re.split(
        r"(?:^|\n)(USER MESSAGE \d+:|ASSISTANT MESSAGE \d+:|CURRENT USER MESSAGE:)\n", question
    )
    return "\n\n".join(
        pieces[i + 1] for i in range(1, len(pieces) - 1, 2) if not pieces[i].startswith("ASSISTANT")
    )


def necessary_questions(question: str) -> tuple[str, ...]:
    text = user_fact_text(question).casefold()
    questions = []
    if any(cue in text for cue in ("landlord", "rent a flat", "rent a house")) and re.search(
        r"\b(uk|united kingdom|britain)\b", text
    ):
        if not any(
            nation in text for nation in ("england", "wales", "scotland", "northern ireland")
        ):
            questions.append("Is the property in England, Wales, Scotland or Northern Ireland?")
        if not any(
            cue in text
            for cue in ("entire flat", "whole flat", "entire house", "whole house", "rent a room")
        ):
            questions.append("Do you rent the whole property or a room, and is it your main home?")
        if not any(
            cue in text
            for cue in (
                "landlord does not live",
                "landlord lives",
                "landlord does not share",
                "does not live there",
                "never shared",
                "live with my landlord",
            )
        ):
            questions.append("Does the landlord live there or share accommodation with you?")
        if not re.search(
            r"(?:agreement|tenancy|contract|term|moved in|renting).{0,100}(?:\d{4}|began|started)",
            text,
        ):
            questions.append(
                "When did you move in, and what start/end dates does the agreement give?"
            )
        if not any(
            cue in text
            for cue in (
                "only notice",
                "no other notice",
                "only document",
                "no other document",
                "only email",
            )
        ):
            questions.append(
                "Apart from that email, have you received any notice, prescribed form or attachment?"
            )
    if "scotland" in text and any(
        cue in text for cue in ("inherit", "died", "estate", "succession")
    ):
        if not any(
            cue in text
            for cue in (
                "no will",
                "left a will",
                "there is a will",
                "valid will",
                "signed will",
                "will leaves",
                "will says",
                "intestate",
            )
        ):
            questions.append("Did the person leave a will, and what does it say if there is one?")
        if not any(
            cue in text
            for cue in ("married", "civil partner", "spouse", "widow", "widower", "unmarried")
        ):
            questions.append("Was the person married or in a civil partnership when they died?")
        if not any(cue in text for cue in ("children", "child", "descendant")):
            questions.append("Did they have children or descendants of a deceased child?")
        if not re.search(r"(?:died|death).{0,55}\d{4}", text):
            questions.append("On what date did they die?")
    if "florida" in text and any(
        cue in text for cue in ("relocat", "move with", "moving with", "move my child")
    ):
        if not any(
            cue in text
            for cue in ("court order", "parenting plan", "no order", "no existing order")
        ):
            questions.append(
                "Is there a court order or parenting plan, and what does it say about residence and relocation?"
            )
        if not re.search(r"\b\d+\s*(?:miles|days|months)\b", text):
            questions.append(
                "Where would you move, how far from the current home, and for how long?"
            )
        if not any(cue in text for cue in ("agrees", "objects", "consent", "disagrees", "opposes")):
            questions.append("Has the other parent agreed in writing or objected?")
    return tuple(questions)


def resolved_jurisdiction(selected: str, question: str) -> str:
    """Narrow an explicitly broad UK selection using a single stated nation.

    No timezone inference, US-state guessing or silent replacement of a
    conflicting specific selection is permitted.
    """
    if selected.casefold() not in {"uk", "united kingdom", "great britain"}:
        return selected
    facts = user_fact_text(question)
    nations = [n for n in ("England", "Wales", "Scotland", "Northern Ireland")
               if re.search(r"\b" + re.escape(n) + r"\b", facts, re.I)]
    return nations[0] if len(nations) == 1 else selected
