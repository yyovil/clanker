"""Backend-confirmed private access cards own their current Slack turn's reply."""
from dataclasses import dataclass
import logging

from gateway.config import Platform

logger = logging.getLogger("gateway.run")


def _source_key(source):
    return tuple(getattr(source, key, None) for key in
                 ('platform', 'scope_id', 'user_id', 'chat_id', 'thread_id', 'profile'))


@dataclass(frozen=True)
class _PrivateAccessResponse:
    event_id: str
    source_key: tuple
    pending: bool = True


def mark_private_access_response(source, event_id):
    """Latch only after the backend confirms its committed current-turn card.

    The typed receipt stays process-local; source serialization cannot create it.
    Delta callbacks can check it without querying storage for each token.
    """
    source._private_access_response = _PrivateAccessResponse(event_id, _source_key(source))


def _current_receipt(source, event_id):
    receipt = getattr(source, '_private_access_response', None)
    if (isinstance(event_id, str) and event_id and isinstance(receipt, _PrivateAccessResponse)
            and receipt.event_id == event_id and receipt.source_key == _source_key(source)):
        return receipt
    return None


def private_access_response_pending(source, event_id):
    receipt = _current_receipt(source, event_id)
    return receipt is not None and receipt.pending


def release_private_access_response(source, event_id):
    """An explicit authenticated result lets this exact turn continue normally."""
    source._private_access_response = _PrivateAccessResponse(event_id, _source_key(source), False)


def private_access_response_successful(agent_result):
    return (not any(agent_result.get(key) for key in ('failed', 'error', 'interrupted', 'partial'))
            and agent_result.get('completed') is not False)


def private_access_response_owned(runner, event, source, agent_result):
    """Suppress ordinary delivery only when the configured backend owns this reply."""
    if (source.platform != Platform.SLACK or source.chat_type not in {'dm', 'private'}
            or source.is_bot or not private_access_response_successful(agent_result)):
        return False
    event_id = getattr(event, 'ledger_message_id', None) or event.message_id
    receipt = _current_receipt(source, event_id)
    if receipt is not None and not receipt.pending:
        return False
    from gateway.slack_workspace import workspace_policy

    policy = workspace_policy(runner, source)
    service = getattr(policy, 'vault_service', None)
    owns_reply = getattr(service, 'private_link_response_owned', None)
    if not callable(owns_reply):
        return False
    try:
        return owns_reply(source, event_id) is True
    except Exception:
        # Storage or routing uncertainty cannot justify hiding an ordinary reply.
        logger.warning("Private access response ownership could not be confirmed")
        return False
