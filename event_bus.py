"""
AgentAudit Event Bus
====================
In-process async fan-out pub/sub for streaming audit decisions to
connected SSE clients.
 
Design:
  - Each SSE client gets its own bounded asyncio.Queue.
  - publish() fan-outs to every subscriber's queue without blocking.
  - If a subscriber's queue is full (slow client), the oldest event is
    dropped for that subscriber only. The publisher never blocks.
  - subscribe() returns (queue, unsubscribe_fn). The caller consumes the
    queue with whatever timeout/keepalive pattern it wants, then calls
    unsubscribe() in a finally block.
 
Bounded memory guarantee:
  max_subscribers * max_queue_size events in flight.
  Default: 100 clients * 100 events = 10k events max buffered.
"""
 
import asyncio
from typing import Callable, Tuple
 
_MAX_QUEUE_SIZE = 100
_MAX_SUBSCRIBERS = 100
 
_subscribers: set = set()
_lock = asyncio.Lock()
 
 
async def publish(event: dict) -> None:
    """
    Fan-out an event to all current subscribers.
    Non-blocking: drops oldest on a full client queue rather than stalling
    the audit pipeline.
    """
    async with _lock:
        targets = list(_subscribers)
 
    for q in targets:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            # Slow consumer — drop oldest, push newest
            try:
                q.get_nowait()
                q.put_nowait(event)
            except Exception:
                pass
 
 
async def subscribe() -> Tuple[asyncio.Queue, Callable]:
    """
    Register a new subscriber. Returns (queue, unsubscribe).
    Caller is responsible for calling await unsubscribe() when done,
    typically in a finally block.
 
    Raises RuntimeError if the subscriber limit is reached.
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
 
    async with _lock:
        if len(_subscribers) >= _MAX_SUBSCRIBERS:
            raise RuntimeError("SUBSCRIBER_LIMIT_EXCEEDED")
        _subscribers.add(q)
 
    async def unsubscribe():
        async with _lock:
            _subscribers.discard(q)
 
    return q, unsubscribe
 
 
def get_subscriber_count() -> int:
    """Expose current subscriber count for /health."""
    return len(_subscribers)