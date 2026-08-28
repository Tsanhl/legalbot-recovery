# Isolated Promptfoo workspace

Promptfoo is not a LegalBot runtime dependency. If used at all, it must write
only to the ignored evaluation tools directory:

`data/evaluations/tools/promptfoo/`

Do not point Promptfoo at Live30/Live60 questions, answers, vault paths or
ACTIVE pointers. Evaluation artefacts remain ineligible for training.
