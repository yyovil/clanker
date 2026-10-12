"""Privileged cleanup of persisted account tasks without reviving execution access."""
import asyncio
import json
from pathlib import Path
import weakref

from .store import AccessError


class ChannelControl:
    def __init__(self, service):
        self.service = service

    def private_source(self, team, owner):
        from gateway.config import Platform
        from gateway.session import SessionSource
        member = self.service.validate_member(team, owner)
        source = SessionSource(Platform.SLACK, member['dm_id'], user_id=owner,
                               scope_id=team, profile=member['profile'])
        if not self.service.policy.authorize_source(source):
            raise AccessError('This account cleanup is no longer authorized.', 403)
        return source

    def task_context(self, row):
        """Validate database ownership and profile identity, including cancelled tasks."""
        from gateway.session import SessionSource
        from .service import Binding
        with self.service.store.connection() as db:
            saved = db.execute("SELECT * FROM transfers WHERE id=? AND reply_mode='channel'",
                               (row['id'],)).fetchone()
        if not saved or saved['team'] != row['team'] or saved['owner'] != row['owner']:
            raise AccessError('The account task cleanup does not match its requester.', 403)
        saved = dict(saved)
        owner_source = self.private_source(saved['team'], saved['owner'])
        original = json.loads(saved['original_source'])
        owner_home = self.service.private_home(saved['team'], saved['owner'])
        if (original.get('platform') != 'slack' or original.get('scope_id') != saved['team'] or
                original.get('user_id') != saved['owner'] or not original.get('thread_id') or
                Path(saved['home']).resolve(strict=True) != owner_home):
            raise AccessError('The account task cleanup has no verified owner binding.', 403)
        home = self.service.channel_tasks.home(saved)
        expected = self.service.policy.home.resolve() / 'profiles' / ('task-' + saved['id'])
        # A transfer may be cancelled before its fresh profile was created.
        if not home.exists():
            if saved['source']:
                raise AccessError('The account task profile is unavailable for cleanup.', 409)
            return None, None
        home = home.resolve(strict=True)
        marker = {'workspace_id': saved['team'], 'user_id': saved['owner'],
                  'kind': 'isolated_task', 'task_id': saved['id']}
        if home != expected or json.loads((home / 'slack_identity.json').read_text()) != marker:
            raise AccessError('The account task profile has no verified cleanup identity.', 403)
        source = None
        if saved['source']:
            data = json.loads(saved['source'])
            source = SessionSource.from_dict(data)
            # channel_task checks all serialized runtime/source identity slots.
            bound = self.service.store.channel_task(data)
            if (bound is None or bound['id'] != saved['id'] or source.platform.value != 'slack' or
                    source.scope_id != saved['team'] or source.user_id != saved['owner'] or
                    source.chat_id != owner_source.chat_id or not source.thread_id or
                    source.profile != 'task-' + saved['id']):
                raise AccessError('The private worker cleanup has no verified requester.', 403)
        # Cloud cleanup keys depend on owner + execution home. An ordinary,
        # authorized DM source proves the owner without re-granting a cancelled
        # worker's execution capability.
        return source, Binding(self.service, owner_source, 'cleanup', '', home)

    def usage_context(self, usage):
        from gateway.session import SessionSource
        from .service import Binding
        source = SessionSource.from_dict(json.loads(usage['source']))
        if source.scope_id != usage['team'] or source.user_id != usage['recipient']:
            raise AccessError('The invited browser cleanup belongs to another requester.', 403)
        home = Path(usage['home']).resolve(strict=True)
        row = self.service.store.channel_task(source.to_dict())
        if row is not None:
            worker, turn = self.task_context(row)
            if turn is None or turn.home != home:
                raise AccessError('The invited task browser does not match its saved context.', 403)
            return worker, turn
        owner_source = self.private_source(usage['team'], usage['recipient'])
        if (source.platform.value != 'slack' or source.chat_id != owner_source.chat_id or
                source.profile != owner_source.profile or
                home != self.service.private_home(usage['team'], usage['recipient'])):
            raise AccessError('The invited browser has no verified private context.', 403)
        return source, Binding(self.service, owner_source, 'cleanup', '', home)

    def validate_cleanup(self, turn):
        """Only known private or signed isolated homes may have cookies removed."""
        team, owner = turn.source.scope_id, turn.source.user_id
        owner_source = self.private_source(team, owner)
        home = turn.home.resolve(strict=True)
        if turn.source.chat_id != owner_source.chat_id:
            raise AccessError('The browser cleanup does not match its requester DM.', 403)
        if home == self.service.private_home(team, owner):
            return home
        for row in self.service.store.channel_tasks_for_control(team, owner):
            if self.service.channel_tasks.home(row).resolve() == home:
                _, saved_turn = self.task_context(row)
                if saved_turn is not None and saved_turn.home == home:
                    return home
        raise AccessError('This browser home is not assigned to the cleanup requester.', 403)

    def pin_cleanup_source(self, source, home, runner):
        from gateway.session_identity import RoutingIdentity
        adapter = self.service.policy.adapter
        transport_profile = getattr(runner, '_primary_profile_name', None) or 'default'
        owning = getattr(runner, '_owning_profile', None)
        if callable(owning):
            _, profile = owning(adapter, source.platform)
            transport_profile = profile or transport_profile
        try:
            transport = weakref.ref(adapter)
        except TypeError:
            transport = None
        # The persisted binding above fixes both paths. Never ask the ingress
        # route to authorize (or silently rehome) a cancelled worker.
        source._identity = RoutingIdentity(
            transport_profile=transport_profile, runtime_profile=source.profile,
            authorization_home=self.service.policy.home.resolve(), runtime_home=home,
            multiplexed=bool(getattr(runner.config, 'multiplex_profiles', False)),
            transport=transport)

    async def interrupt(self, source, home, *, whole_private_home=False):
        if source is None:
            return
        runner = getattr(self.service.policy.adapter, 'gateway_runner', None)
        if runner is None:
            return
        self.pin_cleanup_source(source, home, runner)
        # Use the same key/config and hard interruption as native /stop. Calling
        # the slash handler here would invoke this control hook recursively.
        key = runner._session_key_for_source(source)
        from gateway.run import _INTERRUPT_REASON_STOP
        keys = [key]
        if whole_private_home:
            source.thread_id = None
            key = runner._session_key_for_source(source)
            keys = [key] + runner._chat_scoped_run_keys(source, runner._same_chat_runs(source, key))
        adapter = self.service.policy.adapter
        cancelled = []
        errors = []
        for key in dict.fromkeys(keys):
            owns_cleanup = getattr(runner, '_busy_stop_cleanup_owns', None)
            if callable(owns_cleanup) and owns_cleanup(key) is True:
                # Plain-text stop already hard-interrupted this exact session;
                # cancelling its carrier would race its own awaited cleanup.
                continue
            try:
                await runner._interrupt_and_clear_session(
                    key, source, interrupt_reason=_INTERRUPT_REASON_STOP,
                    invalidation_reason='clanker_account_cleanup')
            except Exception as error:
                errors.append(error)
            active = getattr(adapter, '_active_sessions', {}).get(key)
            if active is not None:
                active.set()
            task = getattr(adapter, '_session_tasks', {}).get(key)
            if task is not None and task is not asyncio.current_task() and not task.done():
                task.cancel()
                cancelled.append(task)
        if cancelled:
            done, pending = await asyncio.wait(cancelled, timeout=5)
            if done:
                await asyncio.gather(*done, return_exceptions=True)
            if pending:
                errors.append(AccessError('The account worker has not finished interruption.', 409))
        if errors:
            raise AccessError('Account worker interruption is still pending.', 409)

    def clear_with_retention(self, turn, *, retain_usage):
        # A native interruption failure must not prevent browser shutdown, or
        # allow cleanup to acknowledge revoked access while a worker may live.
        # Snapshot/reinstate under the same lock as fills and cookie removal.
        with self.service.lock_for(turn.home):
            with self.service.store.connection() as db:
                usages = list(db.execute('SELECT * FROM credential_grant_usage '
                    'WHERE team=? AND recipient=? AND home=?',
                    (turn.source.scope_id, turn.source.user_id, str(turn.home)))) if retain_usage else []
            try:
                self.service.clear_invited_browsers(turn)
            finally:
                if usages:
                    with self.service.store.connection() as db:
                        db.executemany('INSERT OR REPLACE INTO credential_grant_usage '
                            '(grant_id,team,recipient,home,source) VALUES (?,?,?,?,?)',
                            [tuple(row) for row in usages])

    async def stop_context(self, source, turn, *, whole_private_home=False):
        errors = []
        try:
            await self.interrupt(source, turn.home, whole_private_home=whole_private_home)
        except Exception as error:
            errors.append(error)
        try:
            await asyncio.to_thread(self.clear_with_retention, turn, retain_usage=bool(errors))
        except Exception as error:
            errors.append(error)
        if errors:
            raise AccessError('Account worker or browser cleanup is still pending.', 409)

    async def stop_sources(self, rows):
        pending = False
        for row in rows:
            try:
                source, turn = self.task_context(row)
                if turn is None:
                    continue
                if source is not None:
                    self.service.store.cancel(team=row['team'], owner=row['owner'], source=source.to_dict())
                await self.stop_context(source, turn)
            except Exception:
                # Cancellation remains durable; uncertain cookie state is kept
                # for another cleanup attempt and never becomes execution access.
                pending = True
        return pending

    async def stop_message(self, source, message_id):
        """An edit revokes only the work and access forms linked to that inbound message."""
        service = self.service
        if not service.policy.authorize_source(source):
            raise AccessError('The edited task is no longer authorized.', 403)
        rows = [row for row in service.store.channel_tasks_for_control(
            source.scope_id, source.user_id, source.to_dict(), message_id=message_id)
            if row['task_state'] in ('active', 'result_pending')]
        service.store.cancel(team=source.scope_id, owner=source.user_id,
                             source=source.to_dict(), message_id=message_id)
        if await self.stop_sources(rows):
            raise AccessError('The previous task is still stopping. Retry the edit shortly.', 409)

    async def stop_owner(self, team, owner):
        rows = self.service.store.channel_tasks_for_control(team, owner)
        return await self.stop_sources(rows)

    async def stop_usage(self, usage):
        source, turn = self.usage_context(usage)
        task = self.service.store.channel_task(source.to_dict())
        if task is not None:
            self.service.store.cancel(team=usage['team'], owner=usage['recipient'], source=source.to_dict())
        await self.stop_context(source, turn, whole_private_home=task is None)
