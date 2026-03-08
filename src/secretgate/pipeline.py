"""Minimal pluggable pipeline for request/response processing.

CodeGate had ~500 lines for this. We need ~60.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PipelineContext:
    """Carries state across pipeline steps for a single request."""

    secrets_found: int = 0
    alerts: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class PipelineStep(ABC):
    """Base class for a processing step."""

    @abstractmethod
    async def process_request(self, body: dict, ctx: PipelineContext) -> dict | None:
        """Process an outbound request body. Return modified body, or None to block."""
        ...

    async def process_response(self, body: dict, ctx: PipelineContext) -> dict:
        """Process an inbound response body. Default: pass through."""
        return body

    async def process_response_chunk(self, chunk: bytes, ctx: PipelineContext) -> bytes:
        """Process a single SSE chunk in a streaming response. Default: pass through."""
        return chunk


class Pipeline:
    """Runs a list of steps sequentially."""

    def __init__(self, steps: list[PipelineStep] | None = None):
        self.steps = steps or []

    async def run_request(self, body: dict, ctx: PipelineContext) -> dict | None:
        """Run all steps on an outbound request. Returns None if any step blocks."""
        for step in self.steps:
            result = await step.process_request(body, ctx)
            if result is None:
                return None
            body = result
        return body

    async def run_response(self, body: dict, ctx: PipelineContext) -> dict:
        for step in reversed(self.steps):
            body = await step.process_response(body, ctx)
        return body

    async def run_response_chunk(self, chunk: bytes, ctx: PipelineContext) -> bytes:
        for step in reversed(self.steps):
            chunk = await step.process_response_chunk(chunk, ctx)
        return chunk
