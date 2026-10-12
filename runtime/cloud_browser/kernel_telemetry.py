"""Kernel browser telemetry, restricted to session health events.

Page, input, screenshots, network, console and submitted control code stay off.
Every owner-verified task browser gets the operational categories by default; a
benchmark manifest row only names its campaign. Existing browsers additionally
require their claimed session ID. Managed Auth uses a separate create path with
no telemetry.
"""
import json
import math
import os
import re
import stat
import time

from vault.store import AccessError


CATEGORIES = ('captcha', 'connection', 'console', 'control', 'interaction',
              'network', 'page', 'platform', 'screenshot', 'system')
OPERATIONAL = frozenset(('connection', 'system', 'captcha'))
DEFAULT_CAMPAIGN = 'operational-default'
# A missing, disabled or non-matching benchmark manifest falls back to the
# default; ownership and session failures never do.
DEFAULT_FALLBACK_REASONS = frozenset(('disabled', 'expired', 'not_allowlisted', 'invalid_manifest'))


def operational_telemetry():
    # enabled:true replaces any previous category selection on PATCH. Listing
    # every category avoids the API's implicit default, which includes control.
    return {'enabled': True, 'browser': {
        category: {'enabled': category in OPERATIONAL} for category in CATEGORIES}}


def validate_telemetry(value):
    if value == {'enabled': False} and type(value.get('enabled')) is bool:
        return {'enabled': False}
    expected = operational_telemetry()
    if (not isinstance(value, dict) or set(value) != set(expected) or
            value.get('enabled') is not True or
            not isinstance(value.get('browser'), dict) or
            set(value['browser']) != set(CATEGORIES) or
            any(not isinstance(value['browser'][category], dict) or
                set(value['browser'][category]) != {'enabled'} or
                value['browser'][category]['enabled'] is not (category in OPERATIONAL)
                for category in CATEGORIES)):
        raise AccessError('Only the reviewed benchmark operational telemetry is supported.', 503)
    return expected


def telemetry_matches(remote, expected):
    """Verify the active selection without returning provider-owned metadata."""
    if expected == {'enabled': False}:
        return remote is None or (isinstance(remote, dict) and remote.get('enabled') is False)
    if not isinstance(remote, dict) or remote.get('enabled') is False:
        return False
    browser = remote.get('browser')
    if not isinstance(browser, dict) or set(browser) - set(CATEGORIES):
        return False
    for category in CATEGORIES:
        setting = browser.get(category, {'enabled': False})
        if (not isinstance(setting, dict) or
                setting.get('enabled') is not (category in OPERATIONAL)):
            return False
    export = remote.get('export') or {}
    if not isinstance(export, dict):
        return False
    otlp = export.get('otlp') or {}
    return isinstance(otlp, dict) and otlp.get('enabled') is not True


class TelemetryPlan:
    def __init__(self, cloud, *, clock=time.time):
        self.cloud = cloud
        self.clock = clock

    @staticmethod
    def denied(reason):
        return {'telemetry_allowed': False, 'reason': reason}

    def inspect(self, turn, *, creating=False):
        result = self.campaign(turn, creating=creating)
        if result['telemetry_allowed'] or result['reason'] not in DEFAULT_FALLBACK_REASONS:
            return result
        return self._default(turn, creating=creating)

    def _default(self, turn, *, creating):
        """Operational categories stay on for every owner-verified task browser."""
        try:
            _, state = self.cloud.state(turn)
            selected = state.get('threads', {}).get(self.cloud.thread(turn))
            entry = state.get('sessions', {}).get(selected, {})
            self.cloud.check_access(turn, entry)
            session_id = entry.get('session_id')
            if creating:
                if session_id:
                    return self.denied('existing_session')
            else:
                if (not isinstance(session_id, str) or
                        re.fullmatch(r'[A-Za-z0-9_-]{1,200}', session_id) is None):
                    return self.denied('session_unavailable')
                self.cloud.check_claim(turn, session_id)
        except (ValueError, OSError, KeyError, TypeError):
            return self.denied('invalid_state')
        except AccessError:
            return self.denied('ownership_unverified')
        return {'telemetry_allowed': True, 'reason': 'default', 'campaign': DEFAULT_CAMPAIGN,
                'telemetry': operational_telemetry()}

    def campaign(self, turn, *, creating=False):
        path = self.cloud.directory / 'benchmark-replays.json'
        try:
            # Open without following symlinks, then check the same inode read.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return self.denied('disabled')
        except OSError:
            return self.denied('invalid_manifest')
        try:
            with os.fdopen(fd, 'r') as stream:
                metadata = os.fstat(stream.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or
                        metadata.st_mode & 0o077 or metadata.st_size > 65536):
                    return self.denied('invalid_manifest')
                raw = stream.read(65537)
            if len(raw) > 65536:
                return self.denied('invalid_manifest')
            plan = json.loads(raw)
            if not isinstance(plan, dict):
                return self.denied('invalid_manifest')
            if plan.get('enabled') is not True:
                return self.denied('disabled')
            campaign = plan.get('campaign')
            if not isinstance(campaign, str) or re.fullmatch(r'[A-Za-z0-9_-]{1,200}', campaign) is None:
                return self.denied('invalid_manifest')
            expiry, now = plan.get('expires_at'), self.clock()
            if (type(expiry) not in (int, float) or not math.isfinite(expiry) or
                    not now < expiry <= now + 86400):
                return self.denied('expired')
            tasks = plan.get('tasks')
            if not isinstance(tasks, list) or not 1 <= len(tasks) <= 64:
                return self.denied('invalid_manifest')
            scope = {'team': turn.source.scope_id, 'requester': turn.source.user_id,
                'channel': turn.source.chat_id, 'thread': turn.source.thread_id,
                'context': self.cloud.context_key(turn)}
            _, state = self.cloud.state(turn)
            selected = state.get('threads', {}).get(self.cloud.thread(turn))
            entry = state.get('sessions', {}).get(selected, {})
            self.cloud.check_access(turn, entry)
            if creating:
                if entry.get('session_id'):
                    return self.denied('existing_session')
                allowed = any(isinstance(row, dict) and row.get('telemetry_create') is True and
                    all(key in row and row[key] == value for key, value in scope.items()) for row in tasks)
            else:
                session_id = entry.get('session_id')
                if (not isinstance(session_id, str) or
                        re.fullmatch(r'[A-Za-z0-9_-]{1,200}', session_id) is None):
                    return self.denied('session_unavailable')
                scope['session_id'] = session_id
                allowed = any(isinstance(row, dict) and
                    (all(key in row and row[key] == value for key, value in scope.items()) or
                     row.get('telemetry_create') is True and row.get('bind_created_session') is True and
                     row.get('session_id') is None and
                     all(key in row and row[key] == value for key, value in scope.items() if key != 'session_id'))
                    for row in tasks)
                if allowed:
                    self.cloud.check_claim(turn, session_id)
            if not allowed:
                return self.denied('not_allowlisted')
            return {'telemetry_allowed': True, 'reason': 'allowed', 'campaign': campaign,
                'scope': scope, 'telemetry': operational_telemetry()}
        except (ValueError, OSError, KeyError, TypeError, OverflowError):
            return self.denied('invalid_manifest')
        except AccessError:
            return self.denied('ownership_unverified')
