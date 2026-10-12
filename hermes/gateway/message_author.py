"""Persist the admitted message's author, without treating backfill as their words."""

from agent.gateway_context import isolated_gateway_task


def message_author_metadata(event, source):
    if (event is None or source is None or getattr(event, 'internal', False) or
            getattr(source, 'is_bot', False) or isolated_gateway_task(source) is not None or
            not getattr(event, 'message_id', None)):
        return {}
    text = getattr(event, 'text', None)
    if not isinstance(text, str):
        return {}
    platform = getattr(source.platform, 'value', source.platform)
    return {'gateway_sender': {
        'platform': platform, 'scope_id': source.scope_id,
        'chat_id': source.chat_id, 'chat_type': source.chat_type,
        'user_id': source.user_id, 'thread_id': source.thread_id,
        'message_id': str(event.message_id), 'text': text,
    }}
