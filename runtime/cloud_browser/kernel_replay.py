"""Operator-scoped, partial public-page benchmark replay segments.

Capture is opt-in for exact authenticated tasks and approved public routes.
Private tools and uncertain inputs create explicit coverage gaps; authentication
browsers are never selected. No replay URL or page contents enter the ledger.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import urlsplit

from vault.store import AccessError

API = 'https://api.onkernel.com'
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]{1,200}')
AUTH_PATH = re.compile(r'(^|[/_.-])(login|log-in|signin|sign-in|signup|sign-up|auth|oauth|password|verify|verification|otp|payment|pay|billing)([/_.-]|$)', re.I)
CAPTURE_TOOLS = frozenset({'browser_navigate', 'browser_click', 'browser_press',
    'browser_snapshot', 'browser_scroll', 'browser_vision', 'browser_get_images'})


def public_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        url = urlsplit(value)
        return (url.scheme == 'https' and bool(url.hostname) and not url.username
            and not url.password and not url.fragment and not url.query
            and not AUTH_PATH.search(url.path) and url.port in (None, 443)
            and not re.search(r'(^|[.-])(accounts?|login|signin|auth)([.-]|$)', url.hostname, re.I))
    except ValueError:
        return False


def approved_url(value, pages):
    if not public_url(value):
        return False
    url = urlsplit(value)
    for prefix in pages:
        if not public_url(prefix):
            continue
        allowed = urlsplit(prefix)
        if (url.scheme, url.netloc) == (allowed.scheme, allowed.netloc):
            path = allowed.path.rstrip('/') or '/'
            if url.path == path or url.path.startswith(path if path == '/' else path + '/'):
                return True
    return False


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise AccessError('Invalid replay resource identifier.', 400)
    return value


class ReplayPlan:
    """Read only an operator-owned manifest, never model arguments or process env."""
    def __init__(self, cloud, *, clock=time.time):
        self.cloud = cloud
        self.clock = clock

    @staticmethod
    def denied(reason, **metadata):
        return {'capture_allowed': False, 'reason': reason, **metadata}

    def inspect(self, turn):
        path = self.cloud.directory / 'benchmark-replays.json'
        if not path.exists():
            return self.denied('disabled')
        try:
            stat = path.lstat()
            if path.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077 or stat.st_size > 65536:
                return self.denied('invalid_manifest')
            plan = json.loads(path.read_text())
            if not isinstance(plan, dict):
                return self.denied('invalid_manifest')
            if plan.get('enabled') is not True:
                return self.denied('disabled')
            campaign = identifier(plan.get('campaign'))
            expiry = plan.get('expires_at')
            if type(expiry) not in (int, float) or not self.clock() < expiry <= self.clock() + 86400:
                return self.denied('expired')
            if not isinstance(plan.get('tasks'), list) or not 1 <= len(plan['tasks']) <= 64:
                return self.denied('invalid_manifest')
            _, state = self.cloud.state(turn)
            _, entry = self.cloud.selected(turn, state)
            scope = {'team': turn.source.scope_id, 'requester': turn.source.user_id,
                'channel': turn.source.chat_id, 'thread': turn.source.thread_id,
                'context': self.cloud.context_key(turn), 'session_id': entry['session_id']}
            row = next((row for row in plan['tasks'] if isinstance(row, dict)
                and all(row.get(k) == v for k, v in scope.items() if k != 'session_id')
                and (row.get('session_id') == scope['session_id'] or
                     row.get('session_id') is None and row.get('bind_created_session') is True)), None)
            if row is None:
                return self.denied('not_allowlisted')
            self.cloud.check_access(turn, entry)
            self.cloud.check_claim(turn, entry['session_id'])
        except (ValueError, OSError, KeyError, TypeError):
            return self.denied('invalid_manifest')
        except AccessError:
            return self.denied('ownership_unverified')
        # Old preparation manifests do not silently become capture authority.
        if not row.get('checkpoint') or not row.get('public_pages'):
            return self.denied('auth_exclusion_unavailable', campaign=campaign, scope=scope)
        try:
            checkpoint = identifier(row['checkpoint'])
            pages = row['public_pages']
            if (not isinstance(pages, list) or not 1 <= len(pages) <= 24
                    or any(not public_url(value) for value in pages)):
                return self.denied('invalid_public_pages')
            tools = row.get('capture_tools', sorted(CAPTURE_TOOLS))
            if not isinstance(tools, list) or not tools or set(tools) - CAPTURE_TOOLS:
                return self.denied('invalid_capture_tools')
            if row.get('review_url') is not None and not approved_url(row['review_url'], pages):
                return self.denied('invalid_review_url')
        except (KeyError, AccessError, TypeError):
            return self.denied('invalid_checkpoint')
        return {'capture_allowed': True, 'campaign': campaign, 'scope': scope,
            'checkpoint': checkpoint, 'public_pages': pages, 'capture_tools': tools,
            'review_url': row.get('review_url'),
            'resume_public_after_private': row.get('resume_public_after_private') is True}


class ReplayAPI:
    """Kernel's real replay wire contract. No retry of ambiguous mutations.

    This transport alone grants no capture authority.
    Responses never expose replay-view URLs, auth URLs, headers or raw errors.
    """
    def __init__(self, client):
        self.client = client

    def request(self, method, session_id, suffix='', **kwargs):
        route = API + '/browsers/' + identifier(session_id) + '/replays' + suffix
        try:
            result = self.client._request(method, route,
                headers={'Authorization': 'Bearer ' + self.client.key(),
                         'Accept': 'video/mp4' if kwargs.get('stream') else 'application/json'},
                timeout=30, allow_redirects=False, **kwargs)
        except Exception:
            raise AccessError('Kernel replay request was not confirmed.', 503) from None
        if result.status_code not in (200, 201, 204):
            result.close()
            raise AccessError('Kernel replay request was not confirmed.', 503)
        return result

    def start(self, session_id, *, max_duration=60):
        if type(max_duration) is not int or not 1 <= max_duration <= 600:
            raise AccessError('Replay duration must be between 1 and 600 seconds.', 400)
        response = self.request('POST', session_id, json={'framerate': 10,
            'max_duration_in_seconds': max_duration, 'record_audio': False})
        try:
            value = response.json()
            replay_id = identifier(value.get('replay_id'))
        except (ValueError, AttributeError, AccessError):
            raise AccessError('Kernel replay start returned an invalid record; outcome is unknown.', 502) from None
        finally:
            response.close()
        return {'replay_id': replay_id}

    def stop(self, session_id, replay_id):
        response = self.request('POST', session_id, '/' + identifier(replay_id) + '/stop')
        response.close()

    def list_ids(self, session_id):
        response = self.request('GET', session_id)
        try:
            value = response.json()
            rows = value.get('replays') if isinstance(value, dict) else value
            if not isinstance(rows, list):
                raise ValueError
            return [identifier(row['replay_id']) for row in rows]
        except (ValueError, KeyError, TypeError, AccessError):
            raise AccessError('Kernel replay listing was not confirmed.', 502) from None
        finally:
            response.close()

    def export(self, session_id, replay_id, destination, *, max_bytes=128 * 1024 * 1024):
        destination = Path(destination)
        if destination.suffix != '.mp4' or destination.exists() or destination.is_symlink():
            raise AccessError('Replay export requires a new MP4 artifact path.', 400)
        if type(max_bytes) is not int or max_bytes < 12:
            raise AccessError('Replay export size limit is invalid.', 400)
        response = self.request('GET', session_id, '/' + identifier(replay_id), stream=True)
        temporary = None
        try:
            if response.headers.get('Content-Type', '').split(';')[0].strip() != 'video/mp4':
                raise AccessError('Kernel replay export was not an MP4 video.', 502)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, temporary = tempfile.mkstemp(prefix='.replay-', dir=destination.parent)
            count, first, digest = 0, b'', hashlib.sha256()
            with os.fdopen(fd, 'wb') as stream:
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    count += len(chunk)
                    if count > max_bytes:
                        raise AccessError('Kernel replay export exceeded its size limit.', 502)
                    first = (first + chunk)[:12]
                    stream.write(chunk); digest.update(chunk)
                if len(first) < 12 or first[4:8] != b'ftyp':
                    raise AccessError('Kernel replay export was not an MP4 video.', 502)
                stream.flush(); os.fsync(stream.fileno())
            # An export is immutable. Refuse collisions rather than replacing a
            # previously reviewed artifact, including during concurrent export.
            os.link(temporary, destination)
            return {'path': str(destination.resolve()), 'bytes': count, 'sha256': digest.hexdigest()}
        except AccessError:
            raise
        except Exception:
            raise AccessError('Kernel replay export did not complete.', 503) from None
        finally:
            response.close()
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)


class ReplayCapture:
    """Bounded segments around reviewed public-page commands, never auth flows.

    The operator ledger survives gateway interruption. Unknown start/stop
    outcomes block subsequent capture and private operations until reconciled;
    starts and stops are never blindly repeated. Suspect segments stay at the
    provider and are labelled quarantined rather than published as safe video.
    """
    max_duration = 30

    def __init__(self, cloud, *, clock=time.time, api=None, probe=None):
        self.cloud, self.clock = cloud, clock
        self.api = api or ReplayAPI(cloud.client)
        self.probe = probe or self.page_probe

    def ledger_path(self, session_id):
        directory = self.cloud.directory / 'benchmark-capture'
        if directory.is_symlink():
            raise AccessError('Replay ledger directory is unsafe.', 403)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
            raise AccessError('Replay ledger must remain private to the operator.', 403)
        return directory / (identifier(session_id) + '.json')

    def read(self, session_id):
        path = self.ledger_path(session_id)
        if not path.exists():
            return {'session_id': session_id, 'segments': [], 'gaps': [], 'suspended_checkpoints': []}
        if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
            raise AccessError('Replay ledger is unsafe.', 403)
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            raise AccessError('Replay ledger is unreadable; recording status is unknown.', 503) from None
        if not isinstance(data, dict) or data.get('session_id') != session_id:
            raise AccessError('Replay ledger identity is invalid.', 403)
        return data

    def write(self, data):
        path = self.ledger_path(data['session_id'])
        fd, temporary = tempfile.mkstemp(prefix='.capture-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(data, stream, indent=2)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def selected(self, turn):
        _, state = self.cloud.state(turn)
        _, entry = self.cloud.selected(turn, state)
        self.cloud.check_access(turn, entry)
        self.cloud.check_claim(turn, entry['session_id'])
        return entry

    def page_probe(self, turn):
        # Return booleans only. Values are inspected inside direct CDP, never
        # copied into tool results, argv, ledger, telemetry or errors.
        from tools.browser_supervisor import SUPERVISOR_REGISTRY
        kernel = getattr(self.cloud.vault, 'kernel_vault', None)
        values = [value for value in kernel.observation_values(turn)
            if isinstance(value, str) and len(value) >= 4] if kernel else []
        expression = r'''(() => {
          const credential = /password|passwd|passcode|one.?time|otp|totp|verification|security.?code|card.?number|credit.?card|cvv|cvc|expiry|api.?key|access.?token/i;
          const controls = Array.from(document.querySelectorAll('input,textarea,select'));
          const splitCode = controls.filter(el => el.maxLength === 1 && el.getClientRects().length).length >= 4;
          const unsafeControl = controls.some(el => {
            const description = [el.type,el.name,el.id,el.autocomplete,el.getAttribute('aria-label'),el.placeholder].join(' ');
            if (credential.test(description)) return true;
            if (!el.getClientRects().length || ['checkbox','radio','button','submit','hidden'].includes(el.type)) return false;
            const search = el.type === 'search' || el.getAttribute('role') === 'searchbox';
            return !!String(el.value || '') && !search;
          });
          const text = [document.body ? document.body.innerText : '', ...controls.map(el => String(el.value || ''))].join('\n');
          const leaked = __VALUES__.some(value => value && text.includes(value));
          return {url:location.href, unsafe:unsafeControl || splitCode || leaked};
        })()'''.replace('__VALUES__', json.dumps(values))
        supervisor = SUPERVISOR_REGISTRY.get(self.cloud.native_task_id(turn))
        try:
            self.cloud.assert_supervisor(turn, supervisor)
            result = supervisor.evaluate_runtime(expression)
            self.cloud.assert_supervisor(turn, supervisor)
        except Exception:
            return None
        data = result.get('result') if result.get('ok') else None
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                return None
        if not isinstance(data, dict) or not isinstance(data.get('url'), str) or type(data.get('unsafe')) is not bool:
            return None
        return data

    def gap(self, data, reason, *, tool=None, checkpoint=None):
        item = {'at': self.clock(), 'reason': reason}
        if tool:
            item['tool'] = tool
        data.setdefault('gaps', []).append(item)
        if checkpoint and checkpoint not in data.setdefault('suspended_checkpoints', []):
            data['suspended_checkpoints'].append(checkpoint)
        self.write(data)

    def reconcile_start(self, data, segment):
        current = self.api.list_ids(data['session_id'])
        added = set(current) - set(segment.get('baseline_replay_ids', []))
        if len(added) != 1:
            raise AccessError('Replay start outcome is unknown; reconcile the exact recording before private access.', 503)
        segment['replay_id'] = added.pop()
        segment['status'] = 'recording'
        self.write(data)

    def settle(self, data, *, publish=True):
        segment = data.get('active')
        if not segment:
            return
        status = segment.get('status')
        if status in {'start_pending', 'start_unknown'}:
            self.reconcile_start(data, segment)
            status = segment['status']
            # An interrupted start was never observed by the public-page guard.
            publish = False
        if status in {'stop_pending', 'stop_unknown'}:
            raise AccessError('Replay stop outcome is unknown; reconcile it before private access.', 503)
        if status == 'recording':
            segment['status'] = 'stop_pending'; self.write(data)
            try:
                self.api.stop(data['session_id'], segment['replay_id'])
            except Exception:
                segment['status'] = 'stop_unknown'; self.write(data)
                raise AccessError('Replay stop was not confirmed; private access is paused.', 503) from None
            segment['stopped_at'] = self.clock()
            segment['status'] = 'export_pending' if publish else 'quarantined'
            self.write(data)
        if segment['status'] == 'export_pending':
            destination = self.artifact_path(data, segment)
            segment['artifact_destination'] = str(destination.resolve())
            try:
                artifact = self.api.export(data['session_id'], segment['replay_id'], destination)
            except Exception:
                # A confirmed stop makes private operations safe. Provider
                # processing or a failed download must not turn a successful
                # browser action into an error that could invite replaying it.
                segment['download_error'] = 'pending'
            else:
                segment.update(artifact); segment['status'] = 'downloaded'
        data.setdefault('segments', []).append(segment)
        data.pop('active', None); self.write(data)

    def artifact_path(self, data, segment):
        return (self.ledger_path(data['session_id']).parent / 'artifacts'
            / identifier(segment.get('campaign') or data['campaign']) / data['session_id']
            / (identifier(segment['replay_id']) + '.mp4'))

    def retry_exports(self, session_id):
        """Operator-side GET-only recovery of confirmed-stopped safe segments."""
        data = self.read(identifier(session_id))
        for segment in data.get('segments', []):
            if segment.get('status') != 'export_pending':
                continue
            try:
                artifact = self.api.export(session_id, segment['replay_id'], self.artifact_path(data, segment))
            except Exception:
                continue
            segment.update(artifact); segment['status'] = 'downloaded'
            segment.pop('download_error', None)
            self.write(data)
        return {'session_id': session_id,
            'downloaded': sum(item.get('status') == 'downloaded' for item in data.get('segments', [])),
            'pending': sum(item.get('status') == 'export_pending' for item in data.get('segments', []))}

    def suspend(self, turn, reason='private_tool', *, tool=None):
        try:
            entry = self.selected(turn)
        except AccessError as error:
            if error.status == 409:
                return
            raise
        # A disabled campaign should introduce no new runtime filesystem work.
        path = self.cloud.directory / 'benchmark-capture' / (entry['session_id'] + '.json')
        if not path.exists():
            return
        with self.cloud.vault.lock_for(turn.home):
            data = self.read(entry['session_id'])
            self.settle(data, publish=False)
            self.gap(data, reason, tool=tool, checkpoint=data.get('checkpoint'))

    def around(self, turn, tool, args, next_call):
        plan = ReplayPlan(self.cloud, clock=self.clock).inspect(turn)
        if not plan['capture_allowed']:
            self.suspend(turn, plan['reason'], tool=tool)
            return next_call(args)
        session_id = plan['scope']['session_id']
        with self.cloud.vault.lock_for(turn.home):
            data = self.read(session_id)
            self.settle(data, publish=False)
            data.update(campaign=plan['campaign'], scope=plan['scope'], checkpoint=plan['checkpoint'])
            suspended = plan['checkpoint'] in data.get('suspended_checkpoints', [])
            if suspended and not plan['resume_public_after_private']:
                self.gap(data, 'operator_rearm_required', tool=tool)
                return next_call(args)
            if (tool not in plan['capture_tools'] or tool == 'browser_press'
                    and args.get('key') not in {'Enter', 'Escape', 'Tab', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Space'}):
                self.gap(data, 'uncertain_input_or_action', tool=tool, checkpoint=plan['checkpoint'])
                return next_call(args)
            before = self.probe(turn)
            safe = (before and not before['unsafe'] and approved_url(before['url'], plan['public_pages'])
                and (plan['review_url'] is None or before['url'] == plan['review_url']))
            if (tool == 'browser_navigate' and before and not before['unsafe']
                    and before['url'] == 'about:blank' and plan['review_url'] is None
                    and approved_url(args.get('url'), plan['public_pages'])):
                safe = True
            if tool == 'browser_navigate' and not approved_url(args.get('url'), plan['public_pages']):
                safe = False
            if not safe:
                self.gap(data, 'unreviewed_or_private_page', tool=tool, checkpoint=plan['checkpoint'])
                return next_call(args)
            # Snapshot the provider's existing IDs before dispatch so an
            # ambiguous start can be reconciled by reads without a second POST.
            try:
                baseline = self.api.list_ids(session_id)
            except Exception:
                self.gap(data, 'replay_listing_unavailable', tool=tool)
                return next_call(args)
            segment = {'tool': tool, 'campaign': plan['campaign'], 'scope': plan['scope'],
                'checkpoint': plan['checkpoint'], 'started_at': self.clock(),
                'max_duration': self.max_duration, 'status': 'start_pending', 'baseline_replay_ids': baseline}
            data['active'] = segment; self.write(data)
            try:
                started = self.api.start(session_id, max_duration=self.max_duration)
            except Exception:
                segment['status'] = 'start_unknown'; self.write(data)
                raise AccessError('Replay start was not confirmed; browser action was withheld.', 503) from None
            segment.update(started); segment['status'] = 'recording'; self.write(data)
            try:
                return next_call(args)
            finally:
                after = self.probe(turn)
                publish = bool(after and not after['unsafe'] and approved_url(after['url'], plan['public_pages']))
                if not publish:
                    self.gap(data, 'segment_quarantined_after_page_change', tool=tool, checkpoint=plan['checkpoint'])
                self.settle(data, publish=publish)

    def close_entry(self, entry):
        session_id = entry.get('session_id')
        if not session_id:
            return
        path = self.cloud.directory / 'benchmark-capture' / (session_id + '.json')
        if path.exists():
            self.settle(self.read(session_id), publish=False)
