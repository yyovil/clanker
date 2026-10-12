"""Separate search-only consumer session with no browser-tool dependency."""
import json
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

from vault.store import AccessError

VERSION = '20260903_00'
SLUGS = frozenset({'COMPOSIO_SEARCH_WEB', 'COMPOSIO_SEARCH_FETCH_URL_CONTENT'})


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ComposioPublicWebClient:
    def __init__(self, settings, api_key):
        self.settings = settings
        self.api_key = api_key
        self.router_session_id = None

    def post(self, route, payload):
        request = Request('https://backend.composio.dev/api/v3.1/' + route,
            data=json.dumps(payload).encode(), method='POST', headers={
                'x-user-api-key': self.api_key,
                'x-org-id': self.settings['organization_id'],
                'x-project-id': self.settings['project_id'],
                'Content-Type': 'application/json',
            })
        try:
            with build_opener(NoRedirects()).open(request, timeout=45) as response:
                return json.load(response)
        except Exception:
            raise AccessError('The public-search request was not acknowledged.', 502) from None

    def schema(self, slug):
        request = Request('https://backend.composio.dev/api/v3.1/tools/' + slug,
            headers={'x-user-api-key': self.api_key,
                     'x-org-id': self.settings['organization_id'],
                     'x-project-id': self.settings['project_id']})
        try:
            with build_opener(NoRedirects()).open(request, timeout=20) as response:
                return json.load(response)
        except Exception:
            raise AccessError('Could not verify the public-search tool version. Operator connection review is required.', 503) from None

    def execute(self, slug, arguments):
        if slug not in SLUGS:
            raise AccessError('Only the two public-search actions are available.', 403)
        expected = {'query'} if slug == 'COMPOSIO_SEARCH_WEB' else {'urls', 'text', 'max_characters'}
        if not isinstance(arguments, dict) or set(arguments) != expected:
            raise AccessError('Unsupported public-search arguments.', 403)
        # Router execution follows the catalog version. Reject drift instead of
        # silently relying on a new schema; this is not a provider execution pin.
        metadata = self.schema(slug)
        if metadata.get('version') != VERSION:
            raise AccessError('The public-search tool changed version. Operator schema review is required.', 503)
        if self.router_session_id is None:
            session = self.post('tool_router/session', {
                'user_id': self.settings['connection_user_id'],
                'toolkits': {'enable': ['composio_search']},
                'tools': {'composio_search': {'enable': sorted(SLUGS)}},
                'instant': False,
                'manage_connections': {'enable': False},
                'workbench': {'enable': False},
                'proxy_execute': {'enable': False},
                'search': {'enable': False},
                'execute': {'enable_multi_execute': False},
            })
            config = session.get('config', {})
            if (not isinstance(session.get('session_id'), str) or not session['session_id'] or
                    config.get('instant') is not False or
                    config.get('toolkits', {}).get('enabled') != ['composio_search'] or
                    set(config.get('tools', {}).get('composio_search', {}).get('enabled', [])) != SLUGS or
                    config.get('workbench', {}).get('enable') is not False):
                raise AccessError('Composio did not confirm search-only access with instant billing disabled.', 503)
            self.router_session_id = quote(session['session_id'], safe='')
        result = self.post('tool_router/session/' + self.router_session_id + '/execute',
                           {'tool_slug': slug, 'arguments': arguments})
        if (result.get('error') or result.get('successful') is False or
                result.get('result_type', 'completed') != 'completed' or not isinstance(result.get('data'), dict)):
            raise AccessError('Public discovery failed. Try another public source or report the blocker; no result was verified.', 502)
        data = result['data']
        # Some providers retain their action-level envelope inside router data.
        if 'successful' in data:
            if data.get('successful') is not True or not isinstance(data.get('data'), dict):
                raise AccessError('The search provider did not confirm a result.', 502)
            data = data['data']
        return data
