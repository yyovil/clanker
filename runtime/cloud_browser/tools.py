"""Close only the authenticated task's Kernel browser."""
import json

from vault.service import binding
from vault.store import AccessError

TOOLS = ['clanker_browser_stop']


def execute(name, args, **kwargs):
    try:
        if name != 'clanker_browser_stop' or not isinstance(args, dict) or args:
            raise AccessError('Only authenticated Kernel browser cleanup is available here.', 403)
        turn = binding(kwargs.get('task_id'))
        cloud = turn.service.cloud_browser
        if cloud is None or not getattr(cloud, 'uses_native_tools', False):
            raise AccessError('The Kernel browser connection has not been configured.', 503)
        cloud.stop(turn)
        return json.dumps({'status': 'stopped', 'profile_retained': cloud.profile_retained_on_stop})
    except AccessError as error:
        return json.dumps({'success': False, 'error': str(error), 'status': error.status})
    except Exception:
        return json.dumps({'success': False, 'error': 'Kernel browser cleanup could not be verified.'})


def register_tools(ctx):
    name = 'clanker_browser_stop'
    description = (
        "Close this authenticated thread's Kernel browser. The backend selects the owned session "
        "and verifies remote deletion before confirming cleanup. Keep it open while waiting for "
        "the owner's private credential form.")
    schema = {'name': name, 'description': description, 'parameters': {'type': 'object',
        'properties': {}, 'required': [], 'additionalProperties': False}}
    ctx.register_tool(name, 'clanker_browser', schema,
        lambda args, **kwargs: execute(name, args, **kwargs), description=description, emoji='🌐')
