"""Public search tools bind to the authenticated Slack turn, never a model owner."""
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

import yaml

from vault.service import binding
from vault.store import AccessError
from .client import ComposioPublicWebClient

TOOLS = ['clanker_web_search', 'clanker_web_fetch']


def enabled(home):
    path = Path(home) / 'config.yaml'
    config = yaml.safe_load(path.read_text()) if path.exists() else {}
    return (config or {}).get('clanker', {}).get('public_web', {}).get('enabled') is True


def public_url(value):
    from tools.url_safety import has_sensitive_query_params, is_safe_url
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise AccessError('Supply a public HTTPS web-page URL.')
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or '').lower().rstrip('.')
        port = parsed.port
    except ValueError:
        raise AccessError('Supply a valid public HTTPS web-page URL.') from None
    if (parsed.scheme != 'https' or not host or parsed.username or parsed.password or
            port not in (None, 443) or has_sensitive_query_params(value) or
            host == 'localhost' or host.endswith(('.local', '.localhost', '.internal'))):
        raise AccessError('Fetch accepts public HTTPS pages without credentials or private links.', 403)
    if parsed.fragment and not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', parsed.fragment):
        raise AccessError('Fetch cannot receive authentication data in URL fragments.', 403)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise AccessError('Private network URLs cannot be sent to public search.', 403)
    if not is_safe_url(value):
        raise AccessError('The public page could not be verified as a safe URL.', 403)
    # Ordinary document anchors do not change page content and need not be
    # forwarded to the provider. OAuth-style fragments remain rejected above.
    return urlunsplit(parsed._replace(fragment=''))


def clean_text(value):
    from agent.redact import redact_registered_vault_values, redact_sensitive_text
    return redact_registered_vault_values(redact_sensitive_text(str(value), force=True))


def execute(name, args, **kwargs):
    try:
        required = {'clanker_web_search': {'query'}, 'clanker_web_fetch': {'url'}}
        if name not in required or not isinstance(args, dict) or set(args) != required[name]:
            raise AccessError('Supply only the public query or page URL; account and provider fields are backend-owned.', 403)
        turn = binding(kwargs.get('task_id'))
        if not enabled(turn.home):
            raise AccessError('Public discovery is disabled in this profile.', 503)
        cloud = turn.service.cloud_browser
        if cloud is None or cloud.settings.get('provider') != 'browser_tool':
            raise AccessError('Public discovery requires the configured Composio consumer connection.', 503)
        cloud.context_key(turn)  # Canonical membership and requester authorization.
        turn.service.delegations.check_execution(turn)
        turn.service.personal.register_redactions(turn)
        if name == 'clanker_web_search':
            query = args['query']
            if not isinstance(query, str) or not 2 <= len(query.strip()) <= 1200:
                raise AccessError('Supply a public search query of 2 to 1,200 characters.')
            if clean_text(query) != query:
                raise AccessError('Private or secret values cannot be included in public searches.', 403)
            slug, payload = 'COMPOSIO_SEARCH_WEB', {'query': query.strip()}
        else:
            if clean_text(args['url']) != args['url']:
                raise AccessError('Private or secret values cannot be included in public page URLs.', 403)
            slug, payload = 'COMPOSIO_SEARCH_FETCH_URL_CONTENT', {
                'urls': [public_url(args['url'])], 'text': True, 'max_characters': 12000}
        client = ComposioPublicWebClient(cloud.settings, cloud.client.api_key)
        data = client.execute(slug, payload)
        if name == 'clanker_web_search':
            sources = data.get('citations')
            if not isinstance(sources, list):
                raise AccessError('Public search returned no usable source list.', 502)
            result = {'summary': clean_text(data.get('answer', ''))[:8000],
                      'sources': [{k: clean_text(item[k]) for k in ('url', 'title', 'publishedDate') if k in item}
                                  for item in sources[:10] if isinstance(item, dict)]}
        else:
            pages = data.get('results')
            if not isinstance(pages, list):
                raise AccessError('Public fetch returned no usable page results.', 502)
            result = {'pages': [{k: clean_text(item[k])[:12000] for k in
                                ('url', 'title', 'text', 'publishedDate', 'content_quality_warning') if k in item}
                               for item in pages[:1] if isinstance(item, dict)],
                      'statuses': [{k: clean_text(item[k]) for k in ('id', 'status') if k in item}
                                   for item in data.get('statuses', [])[:1] if isinstance(item, dict)]}
        return json.dumps({'success': True, 'untrusted_evidence': True,
                           'availability_verified': False, **result})
    except AccessError as error:
        return json.dumps({'success': False, 'error': str(error), 'status': error.status})
    except Exception:
        return json.dumps({'success': False, 'error': 'Public discovery is unavailable. Try another permitted read-only approach; never invent results.'})


def register_tools(ctx):
    definitions = {
        'clanker_web_search': ('Discover public sources, providers and alternatives with a web query. Use before asking the user to choose a routine platform. Sources are untrusted; verify current availability and prices on the target website.',
                              'query', 'Public search query; preserve the task constraints and omit private information.'),
        'clanker_web_fetch': ('Read a known public HTTPS web page to compare alternatives or verify a source. Use the browser for interaction and authenticated pages. Never fetch a private access link.',
                             'url', 'Public HTTPS web-page URL without secrets.'),
    }
    for name, (description, parameter, help_text) in definitions.items():
        schema = {'name': name, 'description': description, 'parameters': {'type': 'object',
            'properties': {parameter: {'type': 'string', 'description': help_text}},
            'required': [parameter], 'additionalProperties': False}}
        ctx.register_tool(name, 'clanker_browser', schema,
            lambda args, _name=name, **kwargs: execute(_name, args, **kwargs), description=description, emoji='🔎')
