"""Bounded recall evidence shared by tools in one authenticated gateway turn.

Only the recall handler records its authorized result. Arbitrary tool output,
private account state and model-supplied handoff text never enter this buffer.
"""
import json
from threading import Lock

_MAX_MESSAGES = 64
_MAX_CHARS = 48000
_FIELDS = ('text', 'message_id', 'thread_id', 'author_id', 'role', 'timestamp', 'url')


class _RecallEvidence:
    def __init__(self):
        self.lock = Lock()
        self.messages = {}
        self.truncated = False

    def add(self, channel, result):
        with self.lock:
            self.truncated |= bool(result.get('truncated'))
            for message in result['messages']:
                entry = {key: message[key] for key in _FIELDS if key in message}
                entry.update(channel_id=channel, scope=result['scope'])
                encoded = json.dumps(entry, ensure_ascii=False)
                key = (channel, message['message_id'])
                self.messages.pop(key, None)
                if len(encoded) > _MAX_CHARS:
                    self.truncated = True
                    continue
                self.messages[key] = encoded
                while (len(self.messages) > _MAX_MESSAGES or
                       sum(map(len, self.messages.values())) > _MAX_CHARS):
                    self.messages.pop(next(iter(self.messages)))
                    self.truncated = True

    def snapshot(self):
        with self.lock:
            return {'messages': [json.loads(value) for value in self.messages.values()],
                    'truncated': self.truncated}


def capture_recall(turn, result):
    if not result.get('success') or not result.get('messages'):
        return
    evidence = turn.handoff_context.setdefault('clanker.recall', _RecallEvidence())
    evidence.add(result.get('channel_id', turn.source.chat_id), result)


def recalled_context(turn):
    evidence = turn.handoff_context.get('clanker.recall')
    return evidence.snapshot() if evidence is not None else {'messages': [], 'truncated': False}


def context_receipt(recalled):
    return {'recalled_message_ids': [message['channel_id'] + ':' + message['message_id']
                                    for message in recalled['messages']],
            'recalled_context_truncated': recalled['truncated']}
