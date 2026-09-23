"""Deterministic worker wait budgets; no subprocess, model or filesystem IO."""
import subprocess

import pytest
from scripts.ge_auto_role_runtime import RoleWaitTimeout, transport_prompt, wait_for_role


class Clock:
    elapsed = 0.0

    def __call__(self):
        return self.elapsed


class Process:
    def __init__(self, clock, finish=None, returncode=0):
        self.clock, self.finish, self.returncode = clock, finish, returncode
        self.inputs = []

    def communicate(self, data, *, timeout):
        self.inputs.append(data)
        if self.finish is not None and self.clock.elapsed + timeout >= self.finish:
            self.clock.elapsed = self.finish
            return b"", b""
        self.clock.elapsed += timeout
        raise subprocess.TimeoutExpired("synthetic-role", timeout)


def test_silent_role_stops_at_idle_bound_without_resubmitting_prompt():
    clock = Clock()
    process = Process(clock)
    with pytest.raises(RoleWaitTimeout, match="ROLE_NO_OBSERVABLE_PROGRESS_TIMEOUT"):
        wait_for_role(process, b"one request", lambda: (0,), clock=clock,
                      total_seconds=10, idle_seconds=3, poll_seconds=1)
    assert clock.elapsed == 3
    assert process.inputs == [b"one request", None, None]


def test_observable_progress_resets_idle_budget_but_not_total_budget():
    clock = Clock()
    process = Process(clock)
    with pytest.raises(RoleWaitTimeout, match="ROLE_TOTAL_RUNTIME_TIMEOUT"):
        wait_for_role(process, b"one request", lambda: (clock.elapsed,), clock=clock,
                      total_seconds=5, idle_seconds=2, poll_seconds=1)
    assert clock.elapsed == 5
    assert process.inputs[0] == b"one request"
    assert all(x is None for x in process.inputs[1:])


@pytest.mark.parametrize("returncode", [0, 7])
def test_completed_process_retains_its_actual_exit_code(returncode):
    clock = Clock()
    process = Process(clock, finish=4, returncode=returncode)
    assert wait_for_role(process, b"one request", lambda: (clock.elapsed,), clock=clock,
                         total_seconds=10, idle_seconds=2, poll_seconds=1) == returncode


def test_effective_prompt_requires_a_durable_schema_checked_role_result():
    prompt = transport_prompt("role instructions\n", schema_name="transport-schema.json")
    assert "validate the\ncomplete response against transport-schema.json" in prompt
    assert "write exactly that JSON to\nrole-result.json" in prompt
    assert "final assistant\nmessage" in prompt
