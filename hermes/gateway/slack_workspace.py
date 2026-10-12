"""Join-driven Slack membership and private/shared profile routing.

The transport owns this controller. Member tools receive neither its registry
nor Slack credentials; message admission uses Slack's current membership APIs.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import tempfile
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)
WELCOME_TEXT = "I'm ready to chat. Tell me what you need."
WELCOME_BROWSER_TEXT = "I'm clanker. Tell me what you'd like me to do."
CLANKER_STYLE_SETTINGS = {
    "display.personality": "",
    "agent.personalities.concise": None,
    "display.tool_progress": "off",
    "display.tool_progress_command": False,
    "display.platforms.slack.busy_ack_detail": False,
    "display.platforms.slack.live_status": "off",
    "gateway.platforms.slack.mention_reply_user": True,
    "onboarding.enabled": False,
    "onboarding.profile_build": "off",
    "clanker.public_web.enabled": True,
}


def apply_clanker_style(config):
    """Apply product defaults without inheriting another profile's private state."""
    for dotted, value in CLANKER_STYLE_SETTINGS.items():
        keys = dotted.split(".")
        section = config
        for key in keys[:-1]:
            section = section.setdefault(key, {})
        if value is None:
            section.pop(keys[-1], None)
        else:
            section[keys[-1]] = value


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def workspace_policy(runner, source):
    from gateway.config import Platform

    if source.platform != Platform.SLACK:
        return None
    adapter = (getattr(runner, "adapters", None) or {}).get(Platform.SLACK)
    policy = getattr(adapter, "_workspace_membership", None)
    return policy if isinstance(policy, SlackWorkspaceMembership) else None


class SlackWorkspaceMembership:
    def __init__(self, adapter, home: Path, settings: dict):
        self.adapter = adapter
        self.home = Path(home)
        self.team = str(settings["workspace_id"])
        self.existing_profiles = dict(settings.get("existing_profiles", {}))
        self.path = self.home / "slack_membership.json"
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {
            "version": 1, "workspace_id": self.team, "members": {}, "conversations": {}
        }
        if self.state.get("workspace_id") != self.team:
            raise ValueError("Slack membership registry belongs to another workspace")
        self.lock = asyncio.Lock()

    def save(self):
        atomic_json(self.path, self.state)

    def eligible(self, user):
        return bool(user.get("id")) and user.get("id") != "USLACKBOT" and not any(
            user.get(key) for key in ("deleted", "is_bot", "is_app_user", "is_invited_user", "is_stranger")
        ) and user.get("team_id", self.team) == self.team

    def client(self):
        return self.adapter._team_clients[self.team]

    def refresh_execution(self, profile):
        fleet = self.home / '.clanker-execution'
        manifest = fleet / 'fleet.json'
        if not manifest.exists() or not json.loads(manifest.read_text()).get('activated'):
            return False
        target = self.home if profile == 'default' else self.home / 'profiles' / profile
        try:
            from seatbelt.install import activate_context
            from gateway.run import _profile_runtime_scope
            from hermes_cli.plugins import discover_plugins
            activate_context(target, fleet)
            with _profile_runtime_scope(target):
                discover_plugins()
                from model_tools import get_tool_definitions
                definitions = get_tool_definitions(enabled_toolsets=['clanker_browser'], quiet_mode=True)
                from vault.tools import TOOLS as vault_tools
                from seatbelt.plugin import browser_tools, discovery_tools, recall_tools
                if {item['function']['name'] for item in definitions} != {*browser_tools(),*discovery_tools(),*recall_tools(),'terminal',*vault_tools}:
                    raise RuntimeError('Native browser tool surface is not ready')
            return True
        except Exception:
            logger.exception('[Slack onboarding] browser execution unavailable for profile=%s', profile)
            return False

    def ensure_profile(self, profile, identity):
        import yaml
        from gateway.run import _profile_runtime_scope
        from hermes_cli.profiles import get_profile_dir, _bootstrap_profile_dir, _finish_profile_layout
        from hermes_state import SessionDB

        with _profile_runtime_scope(self.home):
            target = get_profile_dir(profile)
            marker = target / "slack_identity.json"
            if target.exists():
                if not marker.exists() or json.loads(marker.read_text()) != identity:
                    raise ValueError(f"Refusing to adopt an unrelated profile: {profile}")
                self.refresh_execution(profile)
                return
            final = target
        # Reuse the native fresh-profile builders in a hidden staging tree.
        # Publish only after identity, configuration and inference are ready.
        staging_root = self.home / ".slack-provisioning"
        staging_root.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=staging_root) as staged_home:
            target = Path(staged_home) / profile
            with _profile_runtime_scope(self.home):
                _bootstrap_profile_dir(target, None)
                _finish_profile_layout(target, no_skills=True, clone_all=False, description=None)
            marker = target / "slack_identity.json"
            root = yaml.safe_load((self.home / "config.yaml").read_text()) or {}
            config_path = target / "config.yaml"
            config = (yaml.safe_load(config_path.read_text()) or {}) if config_path.exists() else {}
            config.update({
                "model": copy.deepcopy(root["model"]),
                "auth": {"adopt_external_logins": False},
                "model_catalog": {"enabled": False},
                "platform_toolsets": {"cli": [], "slack": []},
                "gateway": {"platforms": {"slack": {"skip_context_files": True}}},
                # A fresh profile must never briefly select a local provider.
                # Slack browser tools remain disabled until accepted execution
                # installs the authenticated Kernel adapter for this identity.
                "browser": {"cloud_provider": "kernel", "backend": "agent-browser",
                    "use_real_profile": False, "headed": False,
                    "auto_local_for_private_urls": False, "allow_private_urls": False,
                    "allow_local_fallback": False, "record_sessions": False,
                    "restrict_evaluate": True, "allow_unsafe_evaluate": False,
                    "extension_control": {"enabled": False}, "inactivity_timeout": 600},
            })
            apply_clanker_style(config)
            (target / "config.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
            # Only inference authentication is shared. Never clone platform tokens,
            # memories, site credentials, cookies, skills or the owner's workspace.
            auth_path = self.home / "auth.json"
            if auth_path.exists():
                original = json.loads(auth_path.read_text())
                provider = root["model"].get("provider")
                auth = {k: original[k] for k in ("version", "updated_at") if k in original}
                auth["providers"] = {provider: original.get("providers", {})[provider]} if provider in original.get("providers", {}) else {}
                auth["credential_pool"] = {provider: original.get("credential_pool", {})[provider]} if provider in original.get("credential_pool", {}) else {}
                auth["active_provider"] = provider
                atomic_json(target / "auth.json", auth)
            for name in ("memories", "workspace", "browser", "artifacts"):
                (target / name).mkdir(exist_ok=True)
            database = SessionDB(db_path=target / "state.db")
            database.close()
            atomic_json(marker, identity)
            final.parent.mkdir(parents=True, exist_ok=True)
            os.rename(target, final)
        self.refresh_execution(profile)

    async def serve_profile(self, profile):
        runner = self.adapter.gateway_runner
        if runner is None or not runner._multiplex_on():
            raise RuntimeError("Workspace onboarding requires a multiplexed gateway")
        for _ in range(100):
            result = await runner.reconcile_served_profiles(reason="slack-workspace-onboarding")
            if not result.get("pending"):
                if profile not in result.get("served_profiles", []):
                    raise RuntimeError(f"Profile was not activated: {profile}")
                return
            await asyncio.sleep(0.1)
        raise RuntimeError("Gateway did not become ready to serve new profiles")

    async def onboard(self, user, *, source, event_id=None, welcome=False):
        if not self.eligible(user):
            return
        uid = user["id"]
        async with self.lock:
            member = self.state["members"].get(uid)
            if member is None:
                profile = self.existing_profiles.get(uid, f"slack-{self.team.lower()}-{uid.lower()}")
                member = {"profile": profile, "status": "provisioning", "created_at": time.time(),
                          "source": source, "event_id": event_id, "name": user.get("real_name", user.get("name", uid))}
                self.state["members"][uid] = member
                self.save()
            if member.get("status") != "ready" and uid not in self.existing_profiles:
                await asyncio.to_thread(self.ensure_profile, member["profile"],
                                        {"workspace_id": self.team, "user_id": uid, "kind": "private"})
            response = await self.client().conversations_open(users=uid)
            dm = response["channel"]["id"]
            self.state["conversations"][dm] = {"profile": member["profile"], "members": [uid], "kind": "dm", "enabled": True}
            await self.serve_profile(member["profile"])
            browser_ready = await asyncio.to_thread(self.refresh_execution, member['profile'])
            member.update(status="ready", dm_id=dm, capabilities=["chat", "browser"] if browser_ready else ["chat"],
                          onboarding_status="ready" if browser_ready else "pending_browser",
                          browser_status="ready" if browser_ready else "pending_execution_boundary")
            member.setdefault("ready_at", time.time())
            if source == "team_join":
                member.setdefault("team_join_event_id", event_id)
                member.setdefault("team_join_received_at", time.time())
            elif source == "user_change":
                member.setdefault("activation_event_id", event_id)
                member.setdefault("activation_received_at", time.time())
            if welcome and not member.get("welcome_ts"):
                member["welcome_pending"] = True
            self.save()
            if welcome and not member.get("welcome_ts"):
                message_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"slack-onboarding:{self.team}:{uid}"))
                welcome_text = WELCOME_BROWSER_TEXT if browser_ready else WELCOME_TEXT
                # Recover a successful POST whose response/registry write was lost.
                history = await self.client().conversations_history(channel=dm, limit=100)
                delivered = next((item for item in history.get("messages", [])
                                  if (item.get("client_msg_id") == message_id or item.get("text") in {WELCOME_TEXT, WELCOME_BROWSER_TEXT}) and
                                  item.get("user") == self.adapter._team_bot_user_ids[self.team]), None)
                if delivered is None:
                    delivered = await self.client().chat_postMessage(
                        channel=dm,
                        text=welcome_text,
                        client_msg_id=message_id,
                    )
                member["welcome_ts"] = delivered["ts"]
                member["welcome_pending"] = False
                self.save()
            logger.info("[Slack onboarding] member=%s profile=%s source=%s ready", uid, member["profile"], source)

    async def startup(self):
        try:
            cursor = None
            while True:
                response = await self.client().users_list(limit=200, cursor=cursor)
                for user in response.get("members", []):
                    try:
                        if not self.eligible(user):
                            await self.handle_event({"type": "user_change", "user": user}, {"team_id": self.team})
                        else:
                            member = self.state["members"].get(user["id"], {})
                            if member.get("status") != "ready" or member.get("welcome_pending"):
                                await self.onboard(user, source="reconcile", welcome=bool(self.state.get("initialized_at")) or bool(member.get("welcome_pending")))
                            elif (self.home / '.clanker-execution' / 'fleet.json').exists():
                                ready = await asyncio.to_thread(self.refresh_execution, member['profile'])
                                member.update(capabilities=['chat','browser'] if ready else ['chat'],
                                              onboarding_status='ready' if ready else 'pending_browser',
                                              browser_status='ready' if ready else 'pending_execution_boundary')
                    except Exception:
                        logger.exception("[Slack onboarding] reconciliation failed for member=%s", user.get("id"))
                cursor = response.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break
            logger.info("[Slack onboarding] workspace reconciliation complete")
            self.state.setdefault("initialized_at", time.time())
            self.save()
        except Exception:
            logger.exception("[Slack onboarding] workspace reconciliation failed")

    async def run(self):
        from vault.service import configured_service
        self.vault_service = None
        try:
            # Slack connects before the gateway publishes its served profiles.
            # Preserve the normal private-route checks during Vault bootstrap.
            for profile in sorted({member['profile'] for member in self.state['members'].values()
                                   if member.get('status') == 'ready'}):
                await self.serve_profile(profile)
            # Bootstrap can validate retained provider profiles with bounded
            # HTTP reads. Keep Slack's loop responsive and preserve its context.
            construction = asyncio.create_task(asyncio.to_thread(configured_service, self))
            try:
                service = await asyncio.shield(construction)
            except asyncio.CancelledError:
                # A cancelled await cannot stop a synchronous migration. Drain
                # its worker before releasing this gateway's lifetime/lock;
                # never publish a service from the cancelled startup.
                while not construction.done():
                    try:
                        await asyncio.shield(construction)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                if not construction.cancelled():
                    construction.exception()
                raise
            if service:
                await service.start()
                self.vault_service = service
        except Exception:
            logger.error('[Clanker access] Hosted vault is unavailable; ordinary chat and browser remain available')
        try:
            while True:
                await self.startup()
                # Poll saved requests separately from slower membership refreshes.
                for _ in range(15):
                    if self.vault_service:
                        await self.vault_service.drain()
                    await asyncio.sleep(2)
        finally:
            if self.vault_service:
                await self.vault_service.close()

    async def handle_event(self, event, body):
        if self.adapter._event_team_id(event, body) != self.team:
            return
        kind = event.get("type")
        if kind in {"team_join", "user_change"}:
            user = event.get("user", {})
            if not self.eligible(user):
                member = self.state["members"].get(user.get("id"))
                if member:
                    member["status"] = "disabled"
                    self.save()
                return
            # Slack may expose a pending invite before acceptance. Its authenticated
            # activation update is also a join signal; no message is needed to provision.
            if kind == "team_join" or self.state["members"].get(user["id"], {}).get("status") != "ready":
                await self.onboard(user, source=kind, event_id=body.get("event_id"), welcome=True)
            return
        channel = self.state["conversations"].get(event.get("channel"))
        if channel and kind == "member_left_channel":
            uid = event.get("user")
            channel["members"] = [member for member in channel["members"] if member != uid]
            if uid == self.adapter._team_bot_user_ids[self.team]:
                channel["enabled"] = False
            self.save()
        elif channel and kind == "member_joined_channel":
            uid = event.get("user")
            if uid not in channel["members"]:
                channel["members"].append(uid)
            if uid == self.adapter._team_bot_user_ids[self.team]:
                channel["enabled"] = True
            self.save()

    async def prepare_message(self, user_id, channel_id, team_id):
        member = self.state["members"].get(user_id)
        if team_id != self.team or not member or member.get("status") != "ready":
            return False
        info = (await self.client().conversations_info(channel=channel_id))["channel"]
        if info.get("is_im"):
            allowed = info.get("user") == user_id and channel_id == member.get("dm_id")
            if allowed:
                member.setdefault("first_contact_at", time.time())
                self.save()
            return allowed
        if info.get("is_mpim") or not info.get("is_member") or info.get("is_archived") or info.get("is_ext_shared"):
            return False
        members, cursor = [], None
        while True:
            response = await self.client().conversations_members(channel=channel_id, limit=200, cursor=cursor)
            members.extend(response["members"])
            cursor = response.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
        bot = self.adapter._team_bot_user_ids[self.team]
        if user_id not in members or bot not in members:
            return False
        async with self.lock:
            conversation = self.state["conversations"].get(channel_id)
            if not conversation:
                profile = f"slack-{self.team.lower()}-{channel_id.lower()}"
                await asyncio.to_thread(self.ensure_profile, profile,
                                        {"workspace_id": self.team, "channel_id": channel_id, "kind": "shared"})
                await self.serve_profile(profile)
            else:
                profile = conversation["profile"]
            self.state["conversations"][channel_id] = {
                "profile": profile, "members": members, "kind": "shared", "enabled": True
            }
            member.setdefault("first_contact_at", time.time())
            self.save()
        return True

    def authorize_sender(self, user_id, channel_id):
        member = self.state["members"].get(user_id, {})
        conversation = self.state["conversations"].get(channel_id, {})
        return member.get("status") == "ready" and conversation.get("enabled") is True and user_id in conversation.get("members", [])

    async def prepare_event(self, event):
        source = event.source
        transport = getattr(source, '_transport_adapter_ref', None)
        if (not callable(transport) or transport() is not self.adapter or source.is_bot or
                source.platform.value!='slack' or source.scope_id!=self.team or
                not self.authorize_sender(source.user_id,source.chat_id)):
            return False
        if self.vault_service is not None:
            return await self.vault_service.channel_tasks.admit_event(event)
        return True

    def route(self, source):
        from gateway.profile_routing import ProfileRouteRejected

        if source.scope_id != self.team or source.is_bot or not self.authorize_sender(source.user_id, source.chat_id):
            raise ProfileRouteRejected("slack-workspace-membership")
        if getattr(source, 'isolated_task', None) is not None:
            service = getattr(self, 'vault_service', None)
            if service is None:
                raise ProfileRouteRejected('slack-workspace-task-unavailable')
            try:
                profile = service.channel_tasks.execution_route(source)
            except Exception as error:
                raise ProfileRouteRejected('slack-workspace-task-unauthorized') from error
        else:
            profile = self.state["conversations"][source.chat_id]["profile"]
        home = (self.adapter.gateway_runner._served_profile_homes or {}).get(profile)
        expected = self.home if profile == "default" else self.home / "profiles" / profile
        if home is None or Path(home).resolve() != expected.resolve() or not expected.is_dir():
            raise ProfileRouteRejected("slack-workspace-profile-unavailable")
        return profile

    def authorize_source(self, source):
        from gateway.profile_routing import ProfileRouteRejected

        try:
            return source.profile == self.route(source)
        except ProfileRouteRejected:
            return False
