"""Profile-scoped native plugin notification for authenticated control commands."""
async def notify_gateway_control(runner, source, command):
    from hermes_cli.plugins import has_hook, ainvoke_hook
    from gateway.run import _profile_runtime_scope
    with _profile_runtime_scope(runner._resolve_profile_home_for_source(source)):
        if not has_hook('on_gateway_control'):return []
        return await ainvoke_hook('on_gateway_control', command=command, source=source, runner=runner)
