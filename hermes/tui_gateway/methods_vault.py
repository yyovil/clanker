"""External manager RPCs; retired local credential routes refuse without I/O."""

from .method_ctx import HandlerRegistry

_registry = HandlerRegistry()
method = _registry.method
# server.py's ``@_profile_scoped`` (applied at install): the one scoping path every RPC uses, so the
# launch profile (no ``params.profile``) keeps its secret scope bound once the process multiplexes
# instead of its manager-token reads raising ``UnscopedSecretError``.
_profile_scoped = _registry.profile_scoped

# JSON-RPC error code 5095 = vault failure (validation + store errors).
# Kept as a literal inside handler bodies: handlers are rebound onto
# server.py's globals, so module-level constants are not reachable there.


@method("vault.list")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Metadata-only listing across enabled external password managers.
    Each item carries ``backend``; locked managers contribute nothing (see vault.sources)."""
    try:
        from agent.vault_backends import enabled_backends

        items = []
        for backend in enabled_backends():
            if backend.needs_unlock and not backend.is_unlocked():
                continue
            items.extend({**meta.to_dict(), "backend": backend.name} for meta in backend.list_items())
        return _ok(rid, {"items": items})
    except Exception as e:
        return _err(rid, 5095, str(e))


@method("vault.sources")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Status of every login source: {name, display_name, enabled, needs_unlock, unlocked, installed}."""
    from agent.vault_backends import enabled_backends
    from agent.vault_backends.base import external_backend_classes, is_installed

    enabled = {b.name: b for b in enabled_backends()}
    rows = []
    for cls in external_backend_classes():
        live = enabled.get(cls.name)
        rows.append({"name": cls.name, "display_name": cls.display_name, "enabled": live is not None,
                     "needs_unlock": True, "unlocked": bool(live and live.is_unlocked()),
                     "installed": is_installed(cls.name)})
    return _ok(rid, {"sources": rows})


@method("vault.source.set")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Enable/disable an external manager: writes ``vault.<name>.enabled`` and locks it when disabling."""
    from agent.vault_backends.base import external_backend_classes
    from agent.vault_backends.unlock import lock
    from hermes_cli.config import _ensure_dict, load_config, save_config

    name = str(params.get("name") or "")
    if name not in {cls.name for cls in external_backend_classes()}:
        return _err(rid, 5095, f"unknown vault source: {name}")
    enabled = bool(params.get("enabled"))
    cfg = load_config()
    section = _ensure_dict(_ensure_dict(cfg, "vault"), name)
    if enabled:
        section.pop("enabled", None)  # detected managers are on by default; this removes the opt-out
    else:
        section["enabled"] = False
    if not enabled:
        lock(name)
    save_config(cfg)
    return _ok(rid, {"name": name, "enabled": enabled})


@method("vault.unlock")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Unlock a manager with the master password typed in the Settings dialog (consumed by the CLI on stdin)."""
    from agent.vault_backends import enabled_backends

    name = str(params.get("name") or "")
    password = str(params.get("password") or "")
    backend = next((b for b in enabled_backends() if b.name == name and b.needs_unlock), None)
    if backend is None:
        return _err(rid, 5095, f"{name} is not an enabled password manager")
    if not password:
        return _err(rid, 5095, "master password is required")
    try:
        backend.unlock(password)  # type: ignore[attr-defined]
    except Exception as e:
        return _err(rid, 5095, str(e).replace(password, "[REDACTED]"))
    finally:
        del password
    return _ok(rid, {"name": name, "unlocked": True})


@method("vault.lock")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Forget a manager's session token (or every one when ``name`` is omitted)."""
    from agent.vault_backends.unlock import lock

    name = params.get("name")
    lock(str(name) if name else None)
    return _ok(rid, {"locked": True})


@method("vault.add")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Refuse removed local collection without inspecting submitted secrets."""
    return _err(rid, 5095, "Local credential storage has been removed. Request a private Kernel Vault form through Clanker.")


@method("vault.remove")
@_profile_scoped
def _(rid, params: dict) -> dict:
    """Refuse stale local-store deletion without opening old credential files."""
    return _err(rid, 5095, "Local credential storage has been removed. Manage connected accounts through Clanker.")


def register(server) -> None:
    """Bind this module's handlers onto ``server``'s globals and registry."""
    _registry.install(server)
