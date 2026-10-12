"""Ordinary retry language for an already authenticated verification turn.

This recognizes intent, not a required approval sentence. Identity, task,
credential scope and single-use state are checked by KernelVaultService.
History can clarify a short affirmative; it cannot supply the user's approval.
"""
import re
import unicodedata


def _text(value):
    if not isinstance(value, str) or len(value) > 500:
        return ''
    text = unicodedata.normalize('NFKC', value).casefold().replace('’', "'")
    text = text.replace('‘', "'")
    if any(mark in text for mark in ('"', '“', '”', '`', '\n', '>')):
        return ''
    text = ' '.join(text.split()).strip(' *_')
    return '' if text.startswith("'") or text.rstrip(' .!?').endswith("'") else text


def _command(value):
    text = _text(value)
    words = re.findall(r"[a-z0-9]+(?:'[a-z]+)?", text)
    if not words or set(words) & {
        'no', 'not', "don't", 'dont', 'never', 'stop', 'cancel', 'wait',
        'if', 'unless', 'whether', 'maybe', 'might', 'perhaps', 'when',
        'until', 'without', 'said', 'says', 'told', 'quote', 'quoted',
    }:
        return []
    while words and words[0] in {'please', 'plz', 'pls', 'hey', 'ok', 'okay', 'yes', 'yeah', 'yep', 'yup', 'sure'}:
        words.pop(0)
    if words and words[0] in {"let's", 'lets'}:
        words.pop(0)
    elif words[:2] == ['let', 'us']:
        words = words[2:]
    if words[:2] in (['can', 'you'], ['could', 'you'], ['would', 'you'], ['will', 'you']):
        words = words[2:]
    while words and words[0] in {'please', 'plz', 'pls'}:
        words.pop(0)
    return words


def retry_request(value):
    words = _command(value)
    if not words:
        return False
    action, rest = words[0], set(words[1:])
    auth = {'signin', 'login', 'verification', 'verify', 'otp', 'code', 'sms', 'form'}
    sign_in = bool(rest & {'sign', 'signing', 'log', 'logging'}) and 'in' in rest
    if action == 'retry':
        return rest <= {'now', 'please', 'plz', 'pls', 'it', 'that'} or bool(rest & auth) or sign_in
    if action == 'try':
        return 'again' in rest and (rest <= {'again', 'now', 'please', 'plz', 'pls', 'it', 'that'} or
                                    bool(rest & auth) or sign_in)
    if action in {'sign', 'log'}:
        return 'in' in rest and 'again' in rest
    if action == 'resend':
        return bool(rest & {'code', 'otp', 'sms'})
    if action in {'request', 'send', 'use', 'enter'}:
        return bool(rest & {'new', 'fresh'}) and bool(rest & {'code', 'otp', 'sms'})
    return action in {'new', 'fresh'} and bool(rest & {'code', 'otp', 'sms'})


def affirmative(value):
    text = _text(value).strip(' .,!?:')
    return bool(re.fullmatch(
        r'(?:yes|yep|yeah|yup|sure|ok|okay|approved|approve|go ahead|do it|let\'?s do that)'
        r'(?:[,! ]+(?:please|plz|pls|now|go ahead|do it))*', text))


def answering_retry_prompt(conversation):
    # Only the immediately preceding assistant prompt can supply context.
    # An older user request, tool result or intervening dialogue cannot.
    if not conversation or conversation[-1][0] != 'assistant':
        return False
    previous = conversation[-1][1]
    if not isinstance(previous, str) or len(previous) > 4000:
        return False
    if previous.lstrip().startswith(('"', '“', "'", '‘', '>', '`')):
        return False
    for sentence in re.split(r'(?<=[.!?])\s+|\n+', previous.casefold()):
        if re.search(r"\b(?:do not|don't|don’t|dont|never|not|no|stop|cancel|avoid)\b", sentence):
            continue
        if re.search(r'\b(?:page|website|site|bot|message|text) (?:says|said|displays|reads|asks|told)\b', sentence):
            continue
        auth = re.search(r'\b(?:otp|code|verification|sign[ -]?in|login|logging in|signing in)\b', sentence)
        retry = re.search(r'\b(?:retry|reopen(?:ing)?|resend|fresh|new)\b', sentence)
        asking = re.search(
            r'\b(?:(?:can|could|would|may|shall|should) i|'
            r'(?:do|would) you (?:want|like)(?: me)? to|'
            r'(?:please|plz|pls) (?:reply|send|confirm|approve|let me|allow|tell me|retry)|'
            r'(?:requires?|needs?) (?:your |explicit )*(?:approval|permission))\b', sentence)
        if auth and retry and asking:
            return True
    return False
