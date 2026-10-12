"""Persisted authorship follows the event envelope, not backfill or a shared thread owner."""
from types import SimpleNamespace

from gateway.config import Platform
from gateway.message_author import message_author_metadata
from gateway.platforms.event import MessageEvent
from gateway.run import GatewayRunner
from gateway.session import SessionSource


def test_message_author_is_per_event_and_preserved_in_failure_transcript():
    prepared = SimpleNamespace(persist_user_message=None, message_text='BACKFILL_CANARY',
        persist_user_timestamp=None, persist_user_display_kind=None, persistence_owner='input-owner')
    for user in ('UA', 'UB', 'UA'):
        source = SessionSource(Platform.SLACK, 'CSHARED', chat_type='group', scope_id='TT', user_id=user,
                               thread_id='100.1')
        event = MessageEvent('I want to fly to Mumbai', source=source, message_id='100.2',
            channel_context='OTHER_PERSON_CANARY', metadata={'gateway_sender': {'user_id': 'FORGED'}})
        metadata = message_author_metadata(event, source)
        author = metadata['gateway_sender']
        assert author['user_id'] == user and author['text'] == event.text
        assert 'CANARY' not in repr(metadata) and 'FORGED' not in repr(metadata)
        row = GatewayRunner._hmwa_user_transcript_entry(event, prepared, 1)
        assert row['display_metadata']['gateway_sender'] == author
        assert row['display_metadata']['gateway_input_owner'] == prepared.persistence_owner


def test_internal_and_bot_events_cannot_become_a_users_past_statement():
    source = SessionSource(Platform.SLACK, 'CSHARED', scope_id='TT', user_id='UA')
    event = MessageEvent('Synthetic continuation', source=source, message_id='100.2', internal=True)
    assert message_author_metadata(event, source) == {}
    event.internal = False
    source.is_bot = True
    assert message_author_metadata(event, source) == {}
    assert message_author_metadata(None, source) == {}
