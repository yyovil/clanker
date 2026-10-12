"""Trusted gateway turn context for native plugins, never selected by tool arguments.

The runner binds this after routing/authorization, inside the owning profile.
Context-local storage prevents a concurrent profile's tools borrowing the source.
Outside a gateway turn (CLI, cron, subprocess), the context is absent.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional


@dataclass(frozen=True)
class IsolatedGatewayTask:
    """Process-local capability for an isolated worker with durable reply ownership.

    Only trusted gateway code constructs this object. Ingress metadata and saved
    SessionSource dictionaries cannot create it; its owner restores it from its
    own validated durable task record after a restart.
    """
    task_id: str
    respond: Callable[[object, str, object], Awaitable[None]]


def isolated_gateway_task(source):
    task = getattr(source, 'isolated_task', None)
    return task if isinstance(task, IsolatedGatewayTask) else None


@dataclass(frozen=True)
class GatewayTurn:
    runner: object
    source: object
    task_id: str
    message: str
    home: str
    message_id: Optional[str] = None
    conversation: tuple[tuple[str, str], ...] = ()
    # Copied tool contexts share this turn's backend-owned handoff evidence.
    handoff_context: dict = field(default_factory=dict, compare=False, repr=False)
    # Authenticated current request, kept separate from model-only sender/history context.
    request_message: Optional[str] = None


_turn = ContextVar('hermes_gateway_turn', default=None)


def current_gateway_turn():
    return _turn.get()


@contextmanager
def gateway_turn_scope(runner, source, task_id, message, message_id=None, *, conversation_history=(), request_message=None):
    from hermes_constants import get_hermes_home
    # Handoffs need the request and clarification exchange, never tool results,
    # credentials, reasoning or a worker's unrelated private session history.
    conversation = []
    for entry in conversation_history:
        role = entry.get('role')
        if role not in ('user', 'assistant') or entry.get('tool_calls'):
            continue
        content = entry.get('content')
        if isinstance(content, list):
            content = '\n'.join(part['text'] for part in content
                                if isinstance(part, dict) and part.get('type') == 'text'
                                and isinstance(part.get('text'), str))
        if isinstance(content, str) and content.strip():
            conversation.append((role, content))
    token = _turn.set(GatewayTurn(runner, source, str(task_id), str(message), str(get_hermes_home()),
                                  str(message_id) if message_id is not None else None, tuple(conversation),
                                  request_message=str(message) if request_message is None else request_message))
    try:
        yield
    finally:
        _turn.reset(token)
