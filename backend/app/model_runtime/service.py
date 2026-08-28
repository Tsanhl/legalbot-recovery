"""Minimal loopback-only HTTP service exposing the model-runtime v1 contract."""

from __future__ import annotations

import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .adapters import (
    ModelBackend,
    RequestLimitError,
    RuntimeNotReadyError,
    build_backend,
)
from .config import ModelRuntimeConfig
from .contracts import ContractError, ErrorResponse, GenerateRequest

_LOGGER = logging.getLogger("legalbot.model_runtime")
_CLIENT_DISCONNECT = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class ModelRuntimeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        backend: ModelBackend,
        config: ModelRuntimeConfig,
    ):
        self.backend = backend
        self.runtime_config = config
        super().__init__(address, ModelRuntimeRequestHandler)


class ModelRuntimeRequestHandler(BaseHTTPRequestHandler):
    server: ModelRuntimeHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _record_client_disconnect(self, *, after_generation: bool, request_id: str | None) -> None:
        event = (
            "client_disconnected_after_generation" if after_generation else "client_disconnected"
        )
        _LOGGER.info(
            json.dumps(
                {
                    "event": event,
                    "request_id": request_id,
                    "treat_as_verified": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        after_generation: bool = False,
        request_id: str | None = None,
    ) -> bool:
        body = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return True
        except _CLIENT_DISCONNECT:
            self._record_client_disconnect(after_generation=after_generation, request_id=request_id)
            return False

    def _error(
        self,
        status: int,
        code: str,
        message: str,
        request_id: str | None = None,
    ) -> None:
        self._send_json(
            status,
            ErrorResponse(code=code, message=message, request_id=request_id).to_dict(),
        )

    def do_GET(self) -> None:
        if self.path != "/api/v1/health":
            self._error(HTTPStatus.NOT_FOUND, "not_found", "unknown endpoint")
            return
        health = self.server.backend.health()
        status = HTTPStatus.OK if health.status == "ok" else HTTPStatus.SERVICE_UNAVAILABLE
        self._send_json(status, health.to_dict())

    def do_POST(self) -> None:
        if self.path != "/api/v1/generate":
            self._error(HTTPStatus.NOT_FOUND, "not_found", "unknown endpoint")
            return
        media_type = self.headers.get_content_type()
        if media_type != "application/json":
            self._error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Content-Type must be application/json",
            )
            return
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "0")
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", "invalid Content-Length")
            return
        if length < 1 or length > self.server.runtime_config.max_body_bytes:
            self._error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request_too_large",
                "request body is empty or exceeds the configured limit",
            )
            return

        request_id: str | None = None
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("request_id"), str):
                request_id = payload["request_id"]
            request = GenerateRequest.from_dict(payload)
            response = self.server.backend.generate(request)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", str(exc), request_id)
            return
        except ContractError as exc:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", str(exc), request_id)
            return
        except RequestLimitError as exc:
            self._error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "safe_limit_exceeded",
                str(exc),
                request_id,
            )
            return
        except RuntimeNotReadyError as exc:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "model_unavailable",
                str(exc),
                request_id,
            )
            return
        except Exception:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "generation_failed",
                "model generation failed; inspect local runtime logs",
                request_id,
            )
            return
        self._send_json(
            HTTPStatus.OK,
            response.to_dict(),
            after_generation=True,
            request_id=request_id or request.request_id,
        )


def create_server(
    config: ModelRuntimeConfig | None = None,
    backend: ModelBackend | None = None,
) -> ModelRuntimeHTTPServer:
    config = config or ModelRuntimeConfig.from_env()
    backend = backend or build_backend(config)
    return ModelRuntimeHTTPServer((config.host, config.port), backend, config)


def serve(config: ModelRuntimeConfig | None = None) -> None:
    server = create_server(config)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
