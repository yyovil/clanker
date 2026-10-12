"""Owner personal details stored and filled by Kernel; local state is metadata.

Ordinary fields are explicitly non-sensitive provider fields. Model reads still
require explicit owner consent in value-free metadata. Gender remains opaque.
Only the trusted migration path supplies values to ``save``; owner edits use
Kernel's authenticated collection action instead of a custom value form.
"""
from contextlib import ExitStack
import json
import re

from agent.vault_store import ADDRESS_FIELDS
from agent.vault_login_classifier import LoginControl
from .identity import _targets
from .personal import (
    KINDS, LABELS, MODEL_READABLE_KINDS, PersonalInfo,
    exact_origin, personal_fills, validate,
)
from .store import AccessError


ORIGIN = 'https://vault.kernel.sh'
_FIELDS = {
    'email': ('email',), 'phone': ('phone_number', 'country_code'),
    'address': tuple(ADDRESS_FIELDS), 'name': ('given_name', 'middle_name', 'family_name'),
    'dob': ('date_of_birth',), 'gender': ('gender',),
}
_REQUIRED = {
    'email': {'email'}, 'phone': {'phone_number'},
    'address': {'address_line1', 'city', 'postal_code', 'country'},
    'name': {'given_name'}, 'dob': {'date_of_birth'}, 'gender': {'gender'},
}
_TOKENS = {'email': ('email', 'email'), 'tel': ('phone', 'phone_number'),
    'given-name': ('name', 'given_name'), 'additional-name': ('name', 'middle_name'),
    'family-name': ('name', 'family_name'), 'bday': ('dob', 'date_of_birth'),
    **{token: ('address', key) for key, token in ADDRESS_FIELDS.items()}}


def _kind(kind):
    if kind not in KINDS:
        raise AccessError('Choose a supported personal detail.')
    return kind


def _definitions(kind, values=None):
    _kind(kind)
    return [{'name': name, 'type': 'email' if kind == 'email' else 'text',
             'required': name in _REQUIRED[kind], 'sensitive': kind == 'gender',
             **({'value': values[name]} if values and name in values else {})}
            for name in _FIELDS[kind]]


class KernelPersonalStore:
    def __init__(self, kernel, team, owner):
        self.kernel = kernel
        self.team, self.owner, self.home = kernel.scope(team, owner)
        self.kernel.metadata.vault(self.team, self.owner, self.home)
        with self.kernel.metadata.requests.connection() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS kernel_personal_consent (
                team TEXT NOT NULL, owner TEXT NOT NULL, home TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL, revision INTEGER NOT NULL,
                PRIMARY KEY(team,owner))''')

    def _record(self, kind):
        _kind(kind)
        vault = self.kernel.metadata.vault(self.team, self.owner, self.home)
        if vault is None:
            return None
        return self.kernel.metadata.item(self.team, self.owner, self.home,
                                         'personal_' + kind, include_deleted=True)

    def _verify(self, kind, record, item):
        if (record.get('kind') != 'personal' or record.get('origin') != ORIGIN or
                record.get('handle') != 'personal_' + kind or record.get('key') != 'personal_' + kind or
                record.get('fields') != list(_FIELDS[kind]) or item.get('id') != record.get('remote_id') or
                item.get('key') != record.get('key') or item.get('type') != 'credential'):
            raise AccessError('The saved personal detail has no verified owner identity.', 403)
        expected = _definitions(kind)
        spec = item.get('spec', {})
        fields = spec.get('fields')
        if (spec.get('provider') != 'kernel' or not isinstance(fields, list) or
                [{key: field.get(key) for key in ('name', 'type', 'required', 'sensitive')}
                 for field in fields if isinstance(field, dict)] != expected or
                len(fields) != len(expected)):
            raise AccessError('A saved personal detail has changed its field privacy definition.', 403)
        if (type(item.get('version')) is not int or item['version'] < int(record['version']) or
                not isinstance(item.get('state'), dict) or
                item['state'].get('status') not in ('ready', 'pending_collection')):
            raise AccessError('A saved personal detail needs review in your private vault.', 409)

    def _sync(self, kind, record, item):
        self._verify(kind, record, item)
        return self.kernel.metadata.update_item_status(self.team, self.owner, self.home,
            record['handle'], 'ready' if item['state']['status'] == 'ready' else 'pending',
            version=item['version'])

    def _get(self, kind, *, public=False):
        record = self._record(kind)
        if record is None:
            return None, None
        if record['status'] in ('revoked', 'deleted', 'cancelled', 'failed'):
            return None, None
        item = self.kernel.client.get_credential(record['vault_id'], record['key'],
                                                 include_public_values=public)
        if item is None:
            return record, None
        return self._sync(kind, record, item), item

    def ready_record(self, kind):
        record, item = self._get(kind)
        return record if item is not None and record['status'] == 'ready' else None

    def values(self, kind):
        _kind(kind)
        # No sensitive expansion, including for a trusted backend caller.
        if kind == 'gender':
            return None
        record, item = self._get(kind, public=True)
        if item is None or record['status'] != 'ready':
            return None
        state = item['state'].get('fields', {})
        values = {name: field['value'] for name, field in state.items()
                  if name in _FIELDS[kind] and isinstance(field, dict) and field.get('has_value') is True
                  and isinstance(field.get('value'), str)}
        try:
            return validate(kind, values)
        except (AccessError, KeyError, TypeError):
            raise AccessError('A saved personal detail needs review in your private vault.', 409) from None

    def _consent(self):
        with self.kernel.metadata.requests.connection() as db:
            rows = db.execute('SELECT * FROM kernel_personal_consent WHERE '
                '(team=? AND owner=?) OR home=?', (self.team, self.owner, str(self.home))).fetchall()
        if any((row['team'], row['owner'], row['home']) !=
               (self.team, self.owner, str(self.home)) for row in rows):
            raise AccessError('The personal model consent does not belong to this owner.', 403)
        return (dict(rows[0]) if len(rows) == 1 and rows[0]['enabled'] == 1 and
                type(rows[0]['revision']) is int and rows[0]['revision'] >= 1 else None)

    def model_access(self):
        return self._consent() is not None

    def set_model_access(self, enabled):
        """Trusted operator/migration entry point; never registered as a tool."""
        if type(enabled) is not bool:
            raise AccessError('Choose whether the model may read your personal details.')
        with self.kernel.metadata.requests.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute('SELECT * FROM kernel_personal_consent WHERE '
                '(team=? AND owner=?) OR home=?', (self.team, self.owner, str(self.home))).fetchall()
            if any((row['team'], row['owner'], row['home']) !=
                   (self.team, self.owner, str(self.home)) for row in rows):
                raise AccessError('The personal model consent does not belong to this owner.', 403)
            db.execute('INSERT INTO kernel_personal_consent VALUES (?,?,?,?,1) '
                'ON CONFLICT(team,owner) DO UPDATE SET enabled=excluded.enabled, '
                'revision=kernel_personal_consent.revision+1',
                (self.team, self.owner, str(self.home), int(enabled)))

    def model_values(self, fields):
        if (not isinstance(fields, list) or not fields or
                any(not isinstance(field, str) or field not in MODEL_READABLE_KINDS for field in fields) or
                len(fields) != len(set(fields))):
            raise AccessError('Request only the required saved name, address, phone, email or dob.')
        consent = self._consent()
        if consent is None:
            raise AccessError('Personal details are hidden from the model for this owner.', 403)
        result = {field: value for field in fields if (value := self.values(field)) is not None}
        if self._consent() != consent:
            raise AccessError('Personal model consent changed during this read. Review your private vault consent.', 403)
        return result

    def summary(self):
        """List owner metadata without making inventory depend on provider I/O.

        This status is informational. Reads, collection and fills still verify
        the current remote identity, privacy definition and readiness.
        """
        result = {}
        for kind in KINDS:
            record = self._record(kind)
            status = record['status'] if record else None
            saved, pending = status == 'ready', status == 'pending'
            result[kind] = {'saved': saved, 'label': LABELS[kind],
                'display': 'Saved in Kernel' if saved else 'Pending in Kernel' if pending else '',
                'inventory_status': 'saved_metadata' if saved else 'pending_metadata' if pending else 'not_saved'}
        return result

    def _create(self, kind, *, values=None):
        vault = self.kernel.ensure_vault(self.team, self.owner)
        key = 'personal_' + _kind(kind)
        item = self.kernel.client.create_credential(vault['id'], key, _definitions(kind, values),
                                                     description=LABELS[kind])
        record = self.kernel.metadata.put_item(self.team, self.owner, self.home, key, key,
            item['id'], 'personal', LABELS[kind], ORIGIN, fields=list(_FIELDS[kind]),
            status='ready' if item['state']['status'] == 'ready' else 'pending', version=item['version'])
        self._verify(kind, record, item)
        return record, item

    def collection(self, kind):
        """Return a bearer URL only to the authenticated backend redirect."""
        _kind(kind)
        record = self._record(kind)
        if record is None:
            record, _ = self._create(kind)
        elif record['status'] in ('revoked', 'deleted', 'cancelled', 'failed'):
            raise AccessError('This saved personal detail is unavailable. Review its private vault mapping.', 409)
        current = self.kernel.client.get_credential(record['vault_id'], record['key'])
        if current is None:
            raise AccessError('This saved personal detail is unavailable. Review its private vault mapping.', 409)
        self._sync(kind, record, current)
        result = self.kernel.client.collect(record['vault_id'], record['key'])
        self._sync(kind, record, result)
        action = result.get('action', {})
        if action.get('name') != 'collect' or not isinstance(action.get('url'), str):
            raise AccessError('Kernel did not confirm a private collection page.', 502)
        return action['url']

    def save(self, kind, fields):
        """Trusted migration entry point; never registered as a model tool."""
        values = validate(kind, fields)
        record = self._record(kind)
        if record is None:
            return self._create(kind, values=values)[0]
        record, item = self._get(kind)
        if item is None:
            raise AccessError('This saved personal detail is unavailable. Review its private vault mapping.', 409)
        updated = self.kernel.client.update_credential(record['vault_id'], record['key'],
            version=item['version'], expected_item_id=item['id'],
            fields={name: {'value': values.get(name)} for name in _FIELDS[kind]})
        return self._sync(kind, record, updated)

    def remove(self, kind):
        """Clear values without silently replacing immutable provider identity."""
        _kind(kind)
        record, item = self._get(kind)
        if item is None:
            return
        updated = self.kernel.client.update_credential(record['vault_id'], record['key'],
            version=item['version'], expected_item_id=item['id'],
            fields={name: {'value': None} for name in _FIELDS[kind]})
        self._sync(kind, record, updated)


class KernelPersonalInfo(PersonalInfo):
    def __init__(self, service, kernel):
        super().__init__(service)
        self.kernel = kernel

    def store(self, team, owner):
        return KernelPersonalStore(self.kernel, team, owner)

    def fill(self, turn, *, origin, fields):
        home = self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        self.kernel.assert_personal_browser(turn)
        origin = exact_origin(origin)
        if (not isinstance(fields, list) or not fields or
                any(not isinstance(field, str) or field not in KINDS for field in fields) or
                len(fields) != len(set(fields))):
            raise AccessError('Choose only saved personal details to fill: phone, email, address, name, dob or gender.')
        owner_home = self.service.private_home(turn.source.scope_id, turn.source.user_id)
        with ExitStack() as locks:
            locks.enter_context(self.service.lock_for(home))
            if home != owner_home:
                locks.enter_context(self.service.lock_for(owner_home))
            store = self.store(turn.source.scope_id, turn.source.user_id)
            values = {kind: store.values(kind) for kind in fields if kind != 'gender'}
            records = {kind: store.ready_record(kind) if kind == 'gender' else store._record(kind)
                       for kind in fields}
            missing = [kind for kind in fields if records[kind] is None or kind != 'gender' and values[kind] is None]
            if missing:
                return {'status': 'personal_info_needed', 'missing': missing,
                    'available_fields': [kind for kind in fields if kind not in missing],
                    'vault_url': self.service.config['public_url'].rstrip('/') + '/vault',
                    'next': 'Collect only missing required details through private Personal info in Kernel, then resume. Never collect private values in chat.'}
            plan = self.kernel.inspect(turn, origin)
            if not isinstance(plan.nonce, str) or not re.fullmatch(r'[0-9a-f]{16,64}', plan.nonce):
                raise AccessError('The personal form inspection has no verified target binding.', 409)
            controls = [LoginControl.from_dict(control) if isinstance(control, dict) else control
                        for control in plan.controls]
            if not controls:
                raise AccessError('The active private browser page has no visible editable form controls.', 409)
            ordinary = [kind for kind in fields if kind != 'gender']
            fills = personal_fills(controls, values, ordinary,
                phone_context=getattr(plan, 'phone_context', None)) if ordinary else []
            def selector(index):
                return '[data-hermes-vault-slot=' + json.dumps(plan.nonce + ':' + str(index)) + ']'
            groups = {}
            transformed = []
            for fill in fills:
                source = _TOKENS.get(fill['token'])
                # Kernel collection may retain a national phone number while
                # validation returns its combined international form. Always
                # fill the formatted phone value, rather than the raw field.
                if source and source[0] in ordinary and source[0] != 'phone' and values[source[0]].get(source[1]) == fill['value']:
                    groups.setdefault(source[0], []).append({'field': source[1], 'selector': selector(fill['index'])})
                else:
                    transformed.append(fill)
            if 'gender' in fields:
                targets = _targets(controls, 'gender')
                if set(targets) != {'gender'}:
                    raise AccessError('The gender field is ambiguous. Open only the intended form.', 409)
                groups['gender'] = [{'field': 'gender', 'selector': selector(targets['gender'].index)}]
            indexes = [fill['index'] for fill in fills] + ([targets['gender'].index] if 'gender' in fields else [])
            if len(set(indexes)) != len(indexes):
                raise AccessError('The personal form fields overlap. Inspect the intended form before continuing.', 409)
            self.register_redactions(turn)
            # Converted ordinary values use one temporary Kernel item. Avoid
            # splitting one kind across remote operations after formatting.
            if transformed:
                groups = {kind: bindings for kind, bindings in groups.items() if kind == 'gender'}
                transformed = fills
            confirmed = 0
            expected = len(fills) + (1 if 'gender' in fields else 0)
            try:
                if transformed:
                    result = self.kernel.fill_values(turn, origin, transformed, plan.nonce, plan=plan)
                    if result.get('success') is not True:
                        raise AccessError('Kernel did not confirm the personal details fill.', 409)
                    confirmed += len(transformed)
                for kind, bindings in groups.items():
                    result = self.kernel.fill_item(turn, records[kind], bindings, origin, plan=plan)
                    if result.get('success') is not True:
                        raise AccessError('Kernel did not confirm the personal details fill.', 409)
                    confirmed += len(bindings)
            except AccessError:
                if confirmed:
                    raise AccessError('The personal details fill was only partly confirmed. '
                        f'filled={confirmed}/{expected}. Review the form before continuing; do not automatically retry.', 409) from None
                raise
            return {'success': True, 'filled_fields': confirmed, 'origin': origin,
                'next': 'Kernel filled the requested personal details. Review the form and continue the task; no form has been submitted.'}
