"""Workspace admission invariants with real profiles, Bolt and runner routing.

Slack transport replies are fixture data. No model, Slack network or credentials.
"""
import json
import queue
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from gateway.config import Platform, PlatformConfig
from gateway.run import GatewayRunner
from gateway.session import SessionSource
from gateway.profile_routing import ProfileRouteRejected
from gateway.slack_workspace import SlackWorkspaceMembership
from gateway.slack_workspace import apply_clanker_style
from hermes_cli.default_soul import DEFAULT_SOUL_MD
from agent.prompt_builder import load_soul_md
from plugins.platforms.slack.adapter import SlackAdapter
from slack_bolt.async_app import AsyncApp
from slack_bolt.authorization import AuthorizeResult
from slack_bolt.request.async_request import AsyncBoltRequest


@pytest.mark.asyncio
async def test_private_and_shared_profiles_get_concise_natural_language_defaults(workspace):
    home, adapter, runner, policy, client = workspace
    for uid in ('UALICE', 'UBOB'):
        await policy.onboard({'id': uid, 'team_id': 'TTEST'}, source='team_join', welcome=True)
    client.conversations_info.return_value = {'channel': {'is_member': True}}
    client.conversations_members.return_value = {'members': ['UALICE', 'UBOB', 'UBOT']}
    assert await policy.prepare_message('UALICE', 'CSHARED', 'TTEST')
    profiles = [policy.state['members'][uid]['profile'] for uid in ('UALICE', 'UBOB')]
    profiles.append(policy.state['conversations']['CSHARED']['profile'])
    from gateway.run import _profile_runtime_scope, _load_gateway_config
    from hermes_cli.personality import active_personality_name
    for name in [*profiles, profiles[0]]:
        with _profile_runtime_scope(home / 'profiles' / name):
            config = _load_gateway_config()
            assert active_personality_name(config) == ''
            assert runner._load_ephemeral_system_prompt() == ''
            assert load_soul_md(home_override=home / 'profiles' / name) == DEFAULT_SOUL_MD
            assert config['onboarding']['enabled'] is False
            assert config['display']['tool_progress'] == 'off'
            assert not config['display']['platforms']['slack']['busy_ack_detail']
            assert config['browser']['cloud_provider'] == 'kernel'
            assert config['browser']['allow_local_fallback'] is False
            assert config['browser']['auto_local_for_private_urls'] is False
    for call in client.chat_postMessage.call_args_list:
        text = call.kwargs['text']
        assert len(text.split()) < 20
        assert not any(word in text.lower() for word in ('browser', 'workspace', '!stop', '/help'))
    config = {'model': {'default': 'original'}, 'display': {'skin': 'original'}}
    apply_clanker_style(config)
    assert config['model']['default'] == 'original' and config['display']['skin'] == 'original'


@pytest.mark.asyncio
@pytest.mark.parametrize('enabled', [False, True])
async def test_gateway_onboarding_switch_controls_intro_home_and_first_time_tips(tmp_path, monkeypatch, enabled):
    from gateway import run as module
    from gateway.config import GatewayConfig
    from gateway.platforms.event import MessageEvent
    from gateway.run_turn_runner import TurnRunner
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    config = {'onboarding': {'enabled': enabled, 'profile_build': 'off'},
              'display': {'tool_progress_command': True, 'busy_ack_detail': False}}
    (tmp_path / 'config.yaml').write_text(yaml.safe_dump(config))
    monkeypatch.setattr(module, '_hermes_home', tmp_path)
    monkeypatch.setattr(module, '_load_gateway_config', lambda: config)
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    runner.session_store = None
    runner._async_session_store = SimpleNamespace(_store=None, has_any_sessions=AsyncMock(return_value=False))
    runner._deliver_platform_notice = AsyncMock()
    notes = []
    request = source('UNEW', 'DNEW')
    await runner._hmwa_first_contact_notes(request, [], notes)
    assert bool(notes) is enabled
    assert bool(runner._deliver_platform_notice.await_count) is enabled
    if enabled:
        runner.async_session_store.has_any_sessions.assert_awaited_once()
    else:
        runner.async_session_store.has_any_sessions.assert_not_awaited()
    ack = runner._compose_busy_ack_message(
        MessageEvent(source=request, text='another task'), time.time(), None, None,
        is_steer_mode=False, is_queue_mode=True, is_redirect_mode=False,
        demoted_for_subagents=False, demoted_for_compression=False,
    )
    assert ('First-time tip' in ack) is enabled
    ctx = SimpleNamespace(_LONG_TOOL_THRESHOLD_S=1, progress_mode='all',
                          long_tool_hint_fired=[False], progress_queue=queue.Queue())
    TurnRunner(runner, ctx)._progress_onboarding_hint({'duration': 2})
    assert (not ctx.progress_queue.empty()) is enabled
    assert ctx.long_tool_hint_fired[0] is enabled


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    (tmp_path / 'config.yaml').write_text(yaml.safe_dump({'model': {'provider': 'fixture', 'default': 'fixture'}}))
    (tmp_path / 'memories').mkdir()
    (tmp_path / 'memories' / 'owner.txt').write_text('private-owner-sentinel')
    client = SimpleNamespace(
        conversations_open=AsyncMock(side_effect=lambda users: {'channel': {'id': 'D' + users}}),
        chat_postMessage=AsyncMock(return_value={'ts': '1.1'}),
        conversations_info=AsyncMock(), conversations_members=AsyncMock(),
        conversations_history=AsyncMock(return_value={'messages': []}),
    )
    adapter = SlackAdapter(PlatformConfig(enabled=True, token='xoxb-FIXTURE'))
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = SimpleNamespace(multiplex_profiles=True, profile_routes=[])
    runner.adapters = {Platform.SLACK: adapter}
    runner._served_profile_homes = {'default': tmp_path}
    async def reconcile(**kwargs):
        runner._served_profile_homes.update({p.name: p for p in (tmp_path / 'profiles').iterdir() if p.is_dir()})
        return {'served_profiles': sorted(runner._served_profile_homes)}
    runner.reconcile_served_profiles = AsyncMock(side_effect=reconcile)
    adapter.gateway_runner = runner
    adapter._team_clients = {'TTEST': client}
    adapter._team_bot_user_ids = {'TTEST': 'UBOT'}
    policy = SlackWorkspaceMembership(adapter, tmp_path, {'workspace_id': 'TTEST'})
    adapter._workspace_membership = policy
    return tmp_path, adapter, runner, policy, client


def source(uid, channel):
    return SessionSource(platform=Platform.SLACK, chat_id=channel, user_id=uid, chat_type='group' if channel.startswith('C') else 'dm', scope_id='TTEST')


@pytest.mark.asyncio
async def test_join_provisions_before_contact_and_replay_reuses_profile(workspace):
    home, adapter, runner, policy, client = workspace
    driver = home / 'bin' / 'browser-use'
    driver.parent.mkdir()
    driver.write_text('#!/bin/sh\nexit 0\n')
    driver.chmod(0o700)
    for name in ('agent-browser', 'node'):
        legacy = home / 'node' / 'bin' / name
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text('retired executable fixture')
    (home / 'browser').mkdir()
    (home / 'browser' / 'owner-cookie.txt').write_text('private-browser-sentinel')
    async def authorize(enterprise_id, team_id, user_id):
        return AuthorizeResult(enterprise_id=enterprise_id, team_id=team_id, user_id=user_id, bot_user_id='UBOT', bot_token='xoxb-FIXTURE')
    adapter._app = AsyncApp(signing_secret='FIXTURE', authorize=authorize, process_before_response=True, request_verification_enabled=False, ignoring_self_events_enabled=False)
    manager = SimpleNamespace(get_slack_action_handlers=lambda: [], get_platform_handler_factories=lambda platform: [])
    with patch('hermes_cli.plugins.get_plugin_manager', return_value=manager):
        adapter._register_bolt_handlers()
    body = {'type': 'event_callback', 'team_id': 'TTEST', 'api_app_id': 'ATEST', 'event_id': 'EvJOIN', 'event_time': 1,
            'event': {'type': 'team_join', 'user': {'id': 'UNEW', 'team_id': 'TTEST'}},
            'authorizations': [{'team_id': 'TTEST', 'user_id': 'UBOT', 'is_bot': True, 'is_enterprise_install': False}]}
    result = await adapter._app.async_dispatch(AsyncBoltRequest(body=body, mode='socket_mode'))
    assert result.status == 200
    member = policy.state['members']['UNEW']
    assert member['status'] == 'ready' and member['team_join_event_id'] == 'EvJOIN'
    assert 'first_contact_at' not in member
    profile = home / 'profiles' / member['profile']
    assert (profile / 'state.db').is_file()
    assert (profile / 'workspace').is_dir() and (profile / 'browser').is_dir()
    assert not (profile / 'bin' / 'browser-use').exists()
    assert not (profile / 'node' / 'bin' / 'agent-browser').exists()
    assert not (profile / 'node' / 'bin' / 'node').exists()
    assert not (profile / 'browser' / 'owner-cookie.txt').exists()
    assert not (profile / 'memories' / 'owner.txt').exists()
    assert yaml.safe_load((profile / 'config.yaml').read_text())['platform_toolsets']['slack'] == []
    assert not (profile / 'auth.json').exists()
    assert not list((home / '.slack-provisioning').iterdir())
    mtime = (profile / 'config.yaml').stat().st_mtime_ns
    await policy.handle_event(body['event'], body)
    restored = SlackWorkspaceMembership(adapter, home, {'workspace_id': 'TTEST'})
    await restored.handle_event(body['event'], body)
    assert client.chat_postMessage.await_count == 1
    assert (profile / 'config.yaml').stat().st_mtime_ns == mtime
    await restored.onboard({'id': 'UPENDING', 'is_invited_user': True}, source='reconcile')
    assert 'UPENDING' not in restored.state['members']
    await restored.handle_event({'type': 'user_change', 'user': {'id': 'UPENDING', 'team_id': 'TTEST', 'is_invited_user': False}}, {'team_id': 'TTEST', 'event_id': 'EvACTIVATE'})
    assert restored.state['members']['UPENDING']['activation_event_id'] == 'EvACTIVATE'
    assert restored.state['members']['UPENDING']['status'] == 'ready'
    assert 'first_contact_at' not in restored.state['members']['UPENDING']
    await restored.handle_event({'type': 'team_join', 'user': {'id': 'UOTHER'}}, {'team_id': 'TOTHER'})
    assert 'UOTHER' not in restored.state['members']


@pytest.mark.asyncio
@pytest.mark.parametrize('browser_ready', [False, True])
async def test_fresh_profile_declares_only_kernel_before_execution_refresh(workspace, monkeypatch, browser_ready):
    home, adapter, runner, policy, client = workspace
    observed = []
    def refresh(profile):
        target = home / 'profiles' / profile
        config = yaml.safe_load((target / 'config.yaml').read_text())
        assert config['browser']['cloud_provider'] == 'kernel'
        assert config['browser']['backend'] == 'agent-browser'
        assert config['browser']['allow_local_fallback'] is False
        assert config['browser']['allow_private_urls'] is False
        assert config['browser']['auto_local_for_private_urls'] is False
        assert config['platform_toolsets']['slack'] == []
        assert not (target / 'bin' / 'browser-use').exists()
        assert not (target / 'node' / 'bin' / 'agent-browser').exists()
        observed.append(profile)
        return browser_ready
    monkeypatch.setattr(policy, 'refresh_execution', refresh)
    await policy.onboard({'id': 'UNEW', 'team_id': 'TTEST'}, source='team_join')
    member = policy.state['members']['UNEW']
    assert observed and set(observed) == {member['profile']}
    assert member['capabilities'] == (['chat', 'browser'] if browser_ready else ['chat'])


@pytest.mark.asyncio
async def test_all_members_share_channel_context_but_private_profiles_and_denial(workspace):
    home, adapter, runner, policy, client = workspace
    for uid in ('UALICE', 'UBOB', 'UTHIRD'):
        await policy.onboard({'id': uid, 'team_id': 'TTEST'}, source='team_join')
    client.conversations_info.return_value = {'channel': {'id': 'CSHARED', 'is_member': True}}
    client.conversations_members.return_value = {'members': ['UALICE', 'UBOB', 'UTHIRD', 'UBOT']}
    for uid in ('UALICE', 'UBOB', 'UTHIRD', 'UALICE'):
        assert await policy.prepare_message(uid, 'CSHARED', 'TTEST')
        request = source(uid, 'CSHARED')
        request.profile = runner._profile_name_for_source(request)
        assert request.profile == 'slack-ttest-cshared'
        assert runner._is_user_authorized_for_source(request)
        assert adapter._is_sender_authorized(uid, 'group', 'CSHARED') is True
    private = []
    for uid in ('UALICE', 'UBOB', 'UTHIRD'):
        client.conversations_info.return_value = {'channel': {'is_im': True, 'user': uid}}
        assert await policy.prepare_message(uid, 'D' + uid, 'TTEST')
        request = source(uid, 'D' + uid)
        request.profile = runner._profile_name_for_source(request)
        assert runner._is_user_authorized_for_source(request)
        private.append(request.profile)
    assert len(set(private)) == 3
    assert not await policy.prepare_message('UTHIRD', 'DUALICE', 'TTEST')
    bad = source('UNKNOWN', 'CSHARED')
    with pytest.raises(ProfileRouteRejected):
        runner._profile_name_for_source(bad)
    assert not runner._is_user_authorized_for_source(bad)
    wrong = source('UALICE', 'CSHARED')
    wrong.profile = private[0]
    assert not runner._is_user_authorized_for_source(wrong)
    runner._served_profile_homes.pop('slack-ttest-cshared')
    with pytest.raises(ProfileRouteRejected):
        runner._profile_name_for_source(source('UALICE', 'CSHARED'))
    await runner.reconcile_served_profiles()
    wrong.scope_id = 'TOTHER'
    with pytest.raises(ProfileRouteRejected):
        runner._profile_name_for_source(wrong)
    client.conversations_info.return_value = {'channel': {'is_member': False}}
    assert not await policy.prepare_message('UTHIRD', 'CABSENT', 'TTEST')
    client.conversations_info.return_value = {'channel': {'is_member': True}}
    client.conversations_members.return_value = {'members': ['UALICE', 'UBOT']}
    assert not await policy.prepare_message('UTHIRD', 'CABSENT', 'TTEST')
    await policy.handle_event({'type': 'member_left_channel', 'channel': 'CSHARED', 'user': 'UBOT'}, {'team_id': 'TTEST'})
    assert adapter._is_sender_authorized('UALICE', 'group', 'CSHARED') is False
    await policy.handle_event({'type': 'user_change', 'user': {'id': 'UALICE', 'deleted': True}}, {'team_id': 'TTEST'})
    assert adapter._is_sender_authorized('UALICE', 'dm', 'DUALICE') is False


@pytest.mark.asyncio
async def test_interrupted_provisioning_and_lost_welcome_response_recover(workspace, monkeypatch):
    home, adapter, runner, policy, client = workspace
    import gateway.slack_workspace as module
    original = module.atomic_json
    def fail_identity_once(path, value):
        if path.name == 'slack_identity.json':
            raise OSError('fixture interrupted profile provisioning')
        return original(path, value)
    with monkeypatch.context() as scoped:
        scoped.setattr(module, 'atomic_json', fail_identity_once)
        with pytest.raises(OSError):
            await policy.onboard({'id': 'UNEW'}, source='team_join', event_id='EvRETRY', welcome=True)
    assert policy.state['members']['UNEW']['status'] == 'provisioning'
    assert not (home / 'profiles' / 'slack-ttest-unew').exists()
    assert not list((home / '.slack-provisioning').iterdir())
    delivered = []
    async def accepted_then_response_lost(**kwargs):
        delivered.append({'user': 'UBOT', 'ts': '2.2', 'text': kwargs['text']})
        raise OSError('fixture response lost after server accepted')
    client.chat_postMessage.side_effect = accepted_then_response_lost
    with pytest.raises(OSError):
        await policy.onboard({'id': 'UNEW'}, source='team_join', event_id='EvRETRY', welcome=True)
    assert policy.state['members']['UNEW']['welcome_pending']
    client.conversations_history.return_value = {'messages': delivered}
    client.users_list = AsyncMock(return_value={'members': [{'id': 'UNEW'}]})
    restored = SlackWorkspaceMembership(adapter, home, {'workspace_id': 'TTEST'})
    await restored.startup()
    assert restored.state['members']['UNEW']['welcome_ts'] == '2.2'
    assert not restored.state['members']['UNEW']['welcome_pending']
    assert client.chat_postMessage.await_count == 1
