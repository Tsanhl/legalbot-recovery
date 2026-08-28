"""Run with: python -m app.model_runtime (with backend on PYTHONPATH)."""

from .config import ModelRuntimeConfig
from .service import serve


def main() -> None:
    serve(ModelRuntimeConfig.from_env())


if __name__ == "__main__":
    main()
