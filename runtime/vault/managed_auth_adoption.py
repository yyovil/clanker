"""Checked local adoption of an explicitly reviewed legacy owner login.

The migration coordinator validates provider profile identity and writer
quiescence. This module validates the authentication half, using provider GET
only, then joins the coordinator's single SQLite transaction.
"""
from dataclasses import dataclass
import hashlib
from types import MappingProxyType

from .delegation import credential_binding
from .store import AccessError


@dataclass(frozen=True, repr=False)
class LegacyAuthEvidence:
    context: tuple
    candidate: object
    flow: object
    account: object
    request: object
    checked_at: float


def _local(auth, db, turn, candidate):
    context = auth._context(turn)
    profiles = auth.service.cloud_browser.profiles
    if (candidate['team'], candidate['owner']) != context[:2] or candidate['principal_key'] != profiles._key(
            'personal', context[0], context[1]):
        raise AccessError('Legacy adoption requires the exact current account owner.', 403)
    flow = db.execute('SELECT * FROM kernel_auth_flows WHERE key=?', (candidate['flow_key'],)).fetchone()
    if not flow:
        raise AccessError('The reviewed legacy authentication is unavailable.', 409)
    row = dict(flow)
    expected = dict(team=context[0], requester=context[1], account_owner=context[1],
        account_handle=candidate['account_handle'], handle=candidate['account_handle'],
        origin=candidate['origin'], profile_name=candidate['profile_name'],
        connection_id=candidate['connection_id'], proxy_id=candidate['proxy_id'], state='authenticated',
        principal_key=None, auth_lease=None,
        home=str(auth.service.private_home(*context[:2])))
    policy = getattr(auth.service.cloud_browser.client, 'proxy_policy', None)
    if (any(row.get(k) != value for k, value in expected.items()) or
            row['proxy_id'] != (policy['id'] if policy else None) or
            hashlib.sha256(row['binding'].encode()).hexdigest() != candidate['binding_sha256']):
        raise AccessError('The reviewed legacy authentication identity changed.', 409)
    access = auth.service.delegations.resolve(turn, candidate['account_handle'])
    if (access.grant_id or access.owner != context[1] or access.meta.kind != 'login' or
            access.meta.origin != row['origin'] or credential_binding(access.meta) != row['binding']):
        raise AccessError('This legacy login is not the current requester\'s owned account.', 403)
    account = db.execute('SELECT * FROM kernel_auth_accounts WHERE team=? AND owner=? AND handle=?',
        (row['team'], row['account_owner'], row['account_handle'])).fetchone()
    request = db.execute('SELECT * FROM requests WHERE id=?', (row['request_id'],)).fetchone()
    if (not account or account['origin'] != row['origin'] or not account['credential_name'] or not request or
            request['status'] not in {'saved', 'resumed'} or request['grant_id'] is not None or
            (request['team'], request['owner'], request['home'], request['handle'], request['origin']) !=
            (row['team'], row['requester'], row['home'], row['account_handle'], row['origin'])):
        raise AccessError('The reviewed login request or credential binding is unavailable.', 409)
    if (db.execute('SELECT 1 FROM credential_grants WHERE team=? AND owner=? AND handle=? AND revoked IS NULL',
            (row['team'], row['account_owner'], row['account_handle'])).fetchone() or
            db.execute("SELECT 1 FROM browser_profile_principals WHERE kind='shared' AND team=? AND owner=? AND account_handle=?",
                (row['team'], row['account_owner'], row['account_handle'])).fetchone()):
        raise AccessError('A shared credential cannot adopt a personal cookie profile.', 403)
    if (db.execute('SELECT 1 FROM kernel_auth_flows WHERE profile_name=? AND key!=? AND state!=?',
            (row['profile_name'], row['key'], 'deleted')).fetchone() or
            db.execute('SELECT 1 FROM browser_profile_leases WHERE principal_key=?',
                (candidate['principal_key'],)).fetchone()):
        raise AccessError('The reviewed profile has another authentication generation or writer.', 409)
    return context, row, dict(account), dict(request)


def evidence(auth, turn, candidate):
    fields = {'team', 'owner', 'principal_key', 'profile_id', 'profile_name', 'flow_key',
        'connection_id', 'account_handle', 'origin', 'binding_sha256', 'proxy_id', 'allowed_domains'}
    if (not isinstance(candidate, dict) or set(candidate) != fields or
            any(not isinstance(candidate[k], str) or not candidate[k] for k in fields - {'proxy_id', 'allowed_domains'}) or
            candidate['proxy_id'] is not None and not isinstance(candidate['proxy_id'], str) or
            not isinstance(candidate['allowed_domains'], (list, tuple)) or not candidate['allowed_domains'] or
            any(not isinstance(value, str) or not value for value in candidate['allowed_domains'])):
        raise AccessError('Use one exact reviewed legacy authentication candidate.', 400)
    candidate = dict(candidate, allowed_domains=tuple(candidate['allowed_domains']))
    with auth.store.connection() as db:
        context, row, account, request = _local(auth, db, turn, candidate)
    remote = auth._remote(row)
    if (remote['status'] != 'AUTHENTICATED' or remote.get('flow_status') != 'SUCCESS' or
            tuple(remote.get('allowed_domains') or ()) != candidate['allowed_domains']):
        raise AccessError('The reviewed legacy login is not an exact successful provider generation.', 409)
    # No provider payload or hosted capability survives this check.
    with auth.store.connection() as db:
        current = _local(auth, db, turn, candidate)
    if current != (context, row, account, request):
        raise AccessError('The legacy authentication changed during provider validation.', 409)
    return LegacyAuthEvidence(context, MappingProxyType(candidate), MappingProxyType(row),
        MappingProxyType(account), MappingProxyType(request), auth.store.clock())


def commit(auth, db, turn, checked, principal):
    if (not db.in_transaction or not isinstance(checked, LegacyAuthEvidence) or
            not 0 <= auth.store.clock() - checked.checked_at <= 60):
        raise AccessError('Legacy adoption needs a current check inside the migration transaction.', 409)
    candidate = checked.candidate
    context, row, account, request = _local(auth, db, turn, candidate)
    if (context != checked.context or row != dict(checked.flow) or account != dict(checked.account) or
            request != dict(checked.request)):
        raise AccessError('The reviewed legacy authentication changed before adoption.', 409)
    expected = dict(key=candidate['principal_key'], profile_name=candidate['profile_name'], kind='personal',
        team=candidate['team'], owner=candidate['owner'], account_handle='', origin='', binding='', generation=1)
    registered = db.execute('SELECT * FROM browser_profile_principals WHERE key=?', (expected['key'],)).fetchone()
    if (principal != expected or not registered or any(registered[k] != v for k, v in expected.items()) or
            registered['state'] != 'ready' or registered['profile_id'] != candidate['profile_id'] or
            db.execute('SELECT 1 FROM browser_profile_accounts WHERE principal_key=?', (expected['key'],)).fetchone()):
        raise AccessError('The migration did not reserve the exact empty personal principal.', 409)
    db.execute('UPDATE kernel_auth_flows SET principal_key=? WHERE key=? AND principal_key IS NULL',
        (expected['key'], row['key']))
    db.execute('INSERT INTO browser_profile_accounts VALUES (?,?,?,?,?)',
        (expected['key'], row['origin'], row['account_owner'], row['account_handle'], row['binding']))
