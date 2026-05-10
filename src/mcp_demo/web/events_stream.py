"""Live telemetry SSE stream for /demo.

The /demo page lists experiments and their last result; the events
table at /demo/events lists historical events. Neither tells a viewer
"something just happened" without a manual reload. This module adds a
single ``GET /demo/events/stream`` endpoint that pushes
``ImpactEvent`` rows in real time over Server-Sent Events.

Each ImpactLedger keeps an in-memory subscriber list (see
``mcp_demo.shared.impact.ImpactLedger.subscribe``). The SSE handler
creates an asyncio.Queue per client, registers it on every ledger,
streams events out as they arrive, and unsubscribes cleanly on
disconnect.
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from mcp_demo.shared.impact import ImpactEvent, ImpactLedger


_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",  # disable nginx buffering when proxied
}


def _format_sse(event: ImpactEvent) -> str:
    payload = event.model_dump(mode="json")
    return f"event: impact\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def build_events_stream_router(*, ledgers: list[ImpactLedger]) -> APIRouter:
    router = APIRouter(prefix="/demo")

    @router.get("/events/stream")
    async def events_stream(request: Request) -> StreamingResponse:
        queue: asyncio.Queue[ImpactEvent] = asyncio.Queue(maxsize=256)
        for ledger in ledgers:
            ledger.subscribe(queue)

        async def _stream() -> AsyncIterator[bytes]:
            # Send a ready frame so clients can confirm the connection
            # before the first event arrives.
            yield b"event: ready\ndata: {}\n\n"
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    except asyncio.TimeoutError:
                        # Periodic heartbeat keeps proxies from closing the
                        # connection; clients ignore comment lines.
                        yield b": heartbeat\n\n"
                        continue
                    yield _format_sse(event).encode("utf-8")
            finally:
                for ledger in ledgers:
                    ledger.unsubscribe(queue)

        return StreamingResponse(
            _stream(),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )

    return router
