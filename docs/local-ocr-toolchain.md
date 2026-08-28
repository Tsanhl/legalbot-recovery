# Local OCR toolchain

LegalBot uses an isolated OCR environment at `tools/ocr`; it does not install
OCR packages with Homebrew or write into system Python. The environment and
micromamba cache are ignored by Git. The pinned, reviewable input manifest is
`config/ocr-toolchain.json` and a successful installation writes its resolved
package URLs and tool versions to the ignored
`tools/ocr/legalbot-provenance.json`.

Preview the exact plan (the default does not download or create anything):

```sh
python3 scripts/setup_ocr_toolchain.py
```

Download the exact `resolver.asset_url` recorded in the manifest, then create
the environment explicitly:

```sh
python3 scripts/setup_ocr_toolchain.py \
  --execute \
  --micromamba /absolute/path/to/verified/micromamba
```

The installer verifies the selected executable against the manifest's pinned
SHA-256 and version before it can resolve packages. It accepts only the project-local prefixes in the manifest, disables
micromamba rc files, uses only conda-forge with strict channel priority, and
installs the pinned OCRmyPDF Python package from PyPI because conda-forge's
macOS-arm64 build currently has an unavailable `pngquant` dependency. The
runtime does not request OCRmyPDF's optional `--clean`/`unpaper` path. The
installer refuses symlinked environment roots and never deletes or replaces an existing
system toolchain. Review the dry-run, package licences and available disk space
before using `--execute`.

At runtime `OcrMyPdfProcessor` first uses an explicitly supplied tool directory,
then `LEGALBOT_OCR_TOOL_DIR`, and otherwise `tools/ocr`. The variable names an
environment prefix (or its `bin` directory), for example:

```sh
LEGALBOT_OCR_TOOL_DIR=/approved/private/ocr-env uv run legalbot-api
```

There is no ambient `PATH` fallback. OCR runs with a controlled `PATH`, isolated
temporary/cache/config directories, no stdin, a bounded timeout and generic
failure messages. Source paths, filenames and subprocess output are not logged.
