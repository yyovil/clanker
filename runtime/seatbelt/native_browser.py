"""Scope native browser dispatch to the authenticated requester's Kernel key."""
import copy
import hashlib
import json
import os
from pathlib import Path


def kernel_ready():
    """Discover the accepted remote driver without exposing a local CLI wrapper."""
    try:
        from dotenv import dotenv_values
        from hermes_constants import get_hermes_home
        from cloud_browser.kernel_client import COMMIT, PROVIDER_SHA256, validate_kernel_settings
        from .context import Context

        context = Context(get_hermes_home())
        if context.settings.get('activated') is not True:
            return False
        backend = Path(context.settings['transport_home']).resolve(strict=True)
        settings = validate_kernel_settings(json.loads(
            (backend / '.clanker-cloud/config.json').read_text()))
        source = Path(settings['plugin_path']).resolve(strict=True)
        if (settings['plugin_commit'] != COMMIT or
                not source.is_relative_to(backend / '.clanker-cloud') or
                hashlib.sha256((source / 'provider.py').read_bytes()).hexdigest() != PROVIDER_SHA256):
            return False
        driver = Path(context.settings['agent_browser_executable']).resolve(strict=True)
        return bool(driver.is_file() and os.access(driver, os.X_OK) and
                    dotenv_values(backend / '.env', interpolate=False).get('KERNEL_API_KEY'))
    except Exception:
        return False


def kernel_vision_ready():
    from tools.vision_tools import check_vision_requirements
    return kernel_ready() and check_vision_requirements()


def _owned_handler(stock_handler):
    def execute(args, **kwargs):
        from hermes_constants import get_hermes_home
        from vault.service import binding
        from vault.store import AccessError
        from .context import Context

        try:
            turn = binding(kwargs.get('task_id'))
            context = Context(get_hermes_home())
            if kwargs.get('task_id') != turn.task_id or turn.home.resolve() != context.home:
                raise AccessError('This browser call is not bound to the authenticated task.', 403)
            if context.settings.get('activated') is not True:
                raise AccessError('Kernel browser execution has not been activated.', 503)
            from .plugin import kernel_enabled
            if not kernel_enabled():
                raise AccessError('The Kernel browser connection is unavailable.', 503)
            cloud = turn.service.cloud_browser
            if cloud is None or cloud.settings.get('provider') != 'kernel' or not cloud.uses_native_tools:
                raise AccessError('The Kernel browser connection is unavailable.', 503)
            # Gateway and vault bindings keep their logical conversation task ID.
            # Only Hermes's process-global browser/session maps see this owner key.
            native_kwargs = dict(kwargs)
            native_kwargs['task_id'] = cloud.native_task_id(turn)
            return stock_handler(args, **native_kwargs)
        except AccessError as error:
            return json.dumps({'success': False, 'error': str(error), 'status': error.status})
        except Exception:
            return json.dumps({'success': False, 'error': 'The Kernel browser call could not complete in this authorized task.', 'status': 503})

    return execute


def register_tools(ctx):
    from tools import browser_tool  # Import the stock registration table first.
    from tools.registry import registry
    from .plugin import NATIVE_BROWSER_TOOLS

    for name in NATIVE_BROWSER_TOOLS:
        # The global slot always contains the stock handler. Looking up the
        # current scoped entry would wrap a previous generation on rediscovery.
        stock = registry.snapshot_registration(name)
        if stock is None:
            raise RuntimeError('The native browser tool is unavailable: ' + name)
        ctx.register_tool(name, stock.toolset, copy.deepcopy(stock.schema),
                          _owned_handler(stock.handler),
                          check_fn=kernel_vision_ready if name == 'browser_vision' else kernel_ready,
                          requires_env=list(stock.requires_env), is_async=stock.is_async,
                          description=stock.description, emoji=stock.emoji, override=True)
