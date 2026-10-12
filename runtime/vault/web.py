"""Hosted form and Slack OIDC. No credential bodies or access URLs are logged."""
import asyncio
import hmac
import json
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from aiohttp import web, ClientSession, ClientTimeout
import jwt

from .store import AccessError, SESSION_TTL_SECONDS

SECURITY_HEADERS = {
    'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer',
    'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY',
    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
}


def verify_slack_token(token, key, audience, nonce):
    try:
        claims = jwt.decode(token,key,algorithms=['RS256'],audience=audience,
                            issuer='https://slack.com',options={'require':['exp','iat','iss','aud','nonce','sub']})
        if not hmac.compare_digest(str(claims['nonce']),nonce):
            raise ValueError('nonce')
        identity={'team':claims['https://slack.com/team_id'],'owner':claims['https://slack.com/user_id']}
        if not all(isinstance(value,str) and value for value in identity.values()):
            raise ValueError('identity')
        return identity
    except (jwt.PyJWTError,ValueError,KeyError):
        raise AccessError('Slack sign-in could not be verified.',403) from None


class VaultWeb:
    def __init__(self, service, config, *, verify_identity=None):
        self.service, self.store, self.config = service, service.store, config
        self.origin = config['public_url'].rstrip('/')
        parts = urlsplit(self.origin)
        if parts.scheme != 'https' and not config.get('local_test'):
            raise ValueError('The hosted credential form requires HTTPS')
        if parts.path not in ('','/') or parts.query or parts.fragment or parts.username or not parts.hostname:
            raise ValueError('public_url must be a website origin')
        self.verify_identity = verify_identity or self.slack_identity
        self.app = web.Application(client_max_size=16384, middlewares=[self.errors])
        self.app.router.add_get('/vault/fill',self.page)
        self.app.router.add_get('/vault',self.page)
        self.app.router.add_get('/assets/vault.js',self.asset)
        self.app.router.add_get('/assets/vault.css',self.asset)
        self.app.router.add_get('/auth/callback',self.callback)
        self.app.router.add_get('/health',self.health)
        self.app.router.add_post('/auth/start',self.auth_start)
        self.app.router.add_post('/api/request',self.request)
        self.app.router.add_post('/api/payment/approve',self.payment_approve)
        self.app.router.add_post('/api/items',self.items)
        self.app.router.add_post('/api/authenticator/status',self.authenticator_status)
        self.app.router.add_post('/api/authenticator/save',self.authenticator_save)
        self.app.router.add_post('/api/personal/details',self.personal_details)
        self.app.router.add_post('/api/personal/remove',self.personal_remove)
        self.app.router.add_post('/api/disconnect',self.disconnect)
        self.app.router.add_post('/api/invitations',self.invitations)
        self.app.router.add_post('/api/invite',self.invite)
        self.app.router.add_post('/api/invite/revoke',self.revoke_invitation)

    @web.middleware
    async def errors(self, request, handler):
        try:
            if request.method=='POST' and request.headers.get('Origin')!=self.origin:
                raise AccessError('This request did not come from the credential form.', 403)
            response = await handler(request)
        except AccessError as exc:
            response = web.json_response({'error':str(exc)},status=exc.status)
        except (ValueError,KeyError,TypeError,json.JSONDecodeError):
            response = web.json_response({'error':'The request is invalid.'},status=400)
        except web.HTTPException as exc:
            response = web.Response(body=exc.body,status=exc.status,headers=exc.headers)
        except Exception:
            # Never echo exception bodies: a vault/provider exception may contain input.
            response = web.json_response({'error':'Could not complete this operation. Your task is still saved.'},status=503)
        response.headers.update(SECURITY_HEADERS)
        if not self.config.get('local_test'):
            response.headers['Strict-Transport-Security']='max-age=31536000'
        return response

    async def health(self, request):
        return web.json_response({'ready':True})

    async def page(self, request):
        return web.Response(text=Path(__file__).with_name('page.html').read_text(),content_type='text/html')

    async def asset(self, request):
        name = request.path.rsplit('/',1)[-1]
        return web.Response(text=Path(__file__).with_name(name).read_text(),content_type='text/javascript' if name.endswith('.js') else 'text/css')

    def identity(self, request, *, csrf=False):
        identity = self.store.session(request.cookies.get('__Host-clanker',''))
        self.service.validate_member(identity['team'],identity['owner'])
        if csrf and not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),identity['csrf']):
            raise AccessError('The form session could not be verified. Reload the page.',403)
        return identity

    async def auth_start(self, request):
        data = await request.json()
        row = self.store.get(data['id'],data['token']) if data else None
        if row:self.service.validate_member(row['team'],row['owner'])
        state,browser,nonce = self.store.start_auth(row['id'] if row else '')
        query = urlencode({'response_type':'code','scope':'openid profile','client_id':self.config['client_id'],
                           'state':state,'nonce':nonce,'team':row['team'] if row else self.service.policy.team,
                           'redirect_uri':self.origin+'/auth/callback'})
        response = web.json_response({'url':'https://slack.com/openid/connect/authorize?'+query})
        response.set_cookie('__Host-clanker-auth',browser,secure=True,httponly=True,samesite='Lax',max_age=600,path='/')
        return response

    async def slack_identity(self, code, nonce):
        from agent.secret_scope import build_profile_secret_scope
        secret = build_profile_secret_scope(self.service.policy.home).get('CLANKER_SLACK_CLIENT_SECRET')
        if not secret:
            raise AccessError('Slack sign-in has not been configured.',503)
        async with ClientSession(timeout=ClientTimeout(total=15)) as client:
            async with client.post('https://slack.com/api/openid.connect.token',data={
                'client_id':self.config['client_id'],'client_secret':secret,'code':code,
                'redirect_uri':self.origin+'/auth/callback'}) as response:
                result = await response.json()
        if not result.get('ok') or not result.get('id_token'):
            raise AccessError('Slack could not verify this sign-in. Open your access link again.',403)
        def decode():
            key = jwt.PyJWKClient('https://slack.com/openid/connect/keys',timeout=10).get_signing_key_from_jwt(result['id_token'])
            return verify_slack_token(result['id_token'],key.key,self.config['client_id'],nonce)
        return await asyncio.to_thread(decode)

    async def callback(self, request):
        auth = self.store.consume_auth(request.query.get('state',''),request.cookies.get('__Host-clanker-auth',''))
        identity = await self.verify_identity(request.query.get('code',''),auth['nonce'])
        if auth['request_id']:self.store.get(auth['request_id'],self.store.token(auth['request_id']),identity=identity)
        self.service.validate_member(identity['team'],identity['owner'])
        sid = self.store.new_session(identity['team'],identity['owner'])
        response = web.Response(status=302,headers={'Location':'/vault/fill' if auth['request_id'] else '/vault'})
        response.set_cookie('__Host-clanker',sid,secure=True,httponly=True,samesite='Lax',max_age=SESSION_TTL_SECONDS,path='/')
        response.del_cookie('__Host-clanker-auth',path='/')
        return response

    async def request(self, request):
        data = await request.json()
        row = self.store.get(data['id'],data['token'],identity=self.identity(request),waiting=False)
        if row['kind'] == 'payment':
            result = await asyncio.to_thread(self.service.payments.view, data['id'], data['token'], self.identity(request))
            result['csrf'] = self.identity(request)['csrf']
            return web.json_response(result)
        self.service.delegations.request_access(row)
        kernel = getattr(self.service, 'kernel_vault', None)
        if kernel is None:
            raise AccessError('Kernel Vault is not activated. No local collection form is available.', 503)
        managed = getattr(self.service, 'kernel_auth', None)
        is_auth = bool(managed and managed.flow_for_request(row['id'], include_ended=True))
        if is_auth:
            result = await asyncio.to_thread(managed.hosted_view, row)
            result['csrf'] = self.identity(request)['csrf']
            return web.json_response(result)
        url = await asyncio.to_thread(kernel.collection_link, row)
        return web.json_response({'provider': 'kernel', 'collection_url': url,
                                  'csrf': self.identity(request)['csrf']})

    async def payment_approve(self, request):
        identity = self.identity(request, csrf=True)
        data = await request.json()
        if set(data) != {'id', 'token', 'remember', 'approve'}:
            raise AccessError('Only purchase approval and a remember-card choice are accepted.', 400)
        result = await asyncio.to_thread(self.service.approve_payment, data['id'], data['token'], identity,
                                        {'remember': data['remember'], 'approve': data['approve']})
        return web.json_response(result)

    def return_slack_url(self, identity):
        member = self.service.validate_member(identity['team'],identity['owner'])
        return 'https://slack.com/app_redirect?'+urlencode({'team':identity['team'],'channel':member['dm_id']})

    async def items(self, request):
        identity = self.identity(request)
        items = await asyncio.to_thread(self.service.delegations.items,identity['team'],identity['owner'])
        managed = getattr(self.service, 'kernel_auth', None)
        if managed:
            for item in items:
                account = managed.account(identity['team'], identity['owner'], item['id'])
                item['authenticator_setup'] = bool(item.get('access') != 'invited' and account and account['credential_name'])
        personal=await asyncio.to_thread(self.service.personal.store(identity['team'],identity['owner']).summary)
        return web.json_response({'provider':'kernel','items':items,'personal_info':personal,'csrf':identity['csrf']})

    async def authenticator_status(self, request):
        identity = self.identity(request, csrf=True)
        data = await request.json()
        if not isinstance(data, dict) or set(data) != {'handle'} or not isinstance(data['handle'], str):
            raise AccessError('Choose one of your saved logins.', 400)
        managed = getattr(self.service, 'kernel_auth', None)
        if managed is None:
            raise AccessError('Authenticator setup is unavailable.', 503)
        _, status = await asyncio.to_thread(managed.authenticator_status, identity, data['handle'])
        return web.json_response({'has_totp': status['has_totp_secret']})

    async def authenticator_save(self, request):
        identity = self.identity(request, csrf=True)
        data = await request.json()
        if (not isinstance(data, dict) or set(data) != {'handle', 'setup_key', 'consent'} or
                not isinstance(data['handle'], str) or data['consent'] is not True):
            raise AccessError('Confirm permission to generate sign-in codes for this account.', 400)
        managed = getattr(self.service, 'kernel_auth', None)
        if managed is None:
            raise AccessError('Authenticator setup is unavailable.', 503)
        # Neither request bodies nor provider error bodies are logged. Kernel
        # remains the only durable store, and no agent tool exposes this route.
        value = data.pop('setup_key')
        try:
            result = await asyncio.to_thread(managed.configure_totp, identity, data['handle'], value)
        finally:
            value = None
        return web.json_response(result)

    async def personal_details(self, request):
        identity=self.identity(request,csrf=True);data=await request.json()
        if not isinstance(data,dict) or set(data)!={'kind'}:raise AccessError('Choose the personal detail to edit.')
        store=self.service.personal.store(identity['team'],identity['owner'])
        if getattr(self.service, 'kernel_vault', None) is None:
            raise AccessError('Kernel Vault is not activated.', 503)
        url=await asyncio.to_thread(store.collection,data['kind'])
        return web.json_response({'provider':'kernel','collection_url':url})

    async def personal_remove(self, request):
        identity=self.identity(request,csrf=True);data=await request.json()
        if not isinstance(data,dict) or set(data)!={'kind'}:raise AccessError('Choose the personal detail to remove.')
        home=self.service.private_home(identity['team'],identity['owner'])
        def remove():
            with self.service.lock_for(home):
                store=self.service.personal.store(identity['team'],identity['owner'])
                store.remove(data['kind'])
                return store.summary()
        return web.json_response({'removed':True,'personal_info':await asyncio.to_thread(remove)})

    async def invitations(self, request):
        identity = self.identity(request)
        data = await request.json()
        if not isinstance(data,dict) or set(data)!={'handle'}:
            raise AccessError('Choose one of your saved credentials.')
        invitations = await asyncio.to_thread(self.service.delegations.invitations,identity,data['handle'])
        members = await self.service.invitation_members(identity)
        items = await asyncio.to_thread(self.service.delegations.items,identity['team'],identity['owner'])
        credentials = [item for item in items if item.get('access') != 'invited' and item['kind'] in ('login','api_key','payment')]
        return web.json_response({'invitations':invitations,'members':members,'credentials':credentials,'csrf':identity['csrf']})

    async def invite(self, request):
        identity = self.identity(request,csrf=True)
        data = await request.json()
        if not isinstance(data,dict) or set(data)!={'handles','recipient'}:
            raise AccessError('Choose a Slack member and the credentials to share.')
        return web.json_response(await self.service.set_invitation_access(identity,data['recipient'],data['handles']))

    async def revoke_invitation(self, request):
        identity = self.identity(request,csrf=True)
        data = await request.json()
        if not isinstance(data,dict) or set(data)!={'id'}:
            raise AccessError('Choose an invitation to revoke.')
        return web.json_response(await self.service.revoke_invitation(identity,data['id']))

    async def disconnect(self, request):
        identity = self.identity(request,csrf=True)
        data = await request.json()
        await self.service.disconnect(identity['team'],identity['owner'],data['handle'])
        return web.json_response({'removed':True})

    async def start(self):
        self.runner = web.AppRunner(self.app,access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner,'127.0.0.1',int(self.config.get('port',8767))).start()

    async def close(self):
        await self.runner.cleanup()
