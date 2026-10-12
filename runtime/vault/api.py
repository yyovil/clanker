"""Authenticated HTTPS requests; Kernel values remain backend-only.

The model supplies an opaque owned/invited handle and a relative JSON request.
There is no local-vault fallback, redirect following, or automatic retry.
"""
import http.client
import ipaddress
import json
from decimal import Decimal, InvalidOperation
import re
import socket
import ssl
from urllib.parse import urlsplit

from .kernel_store import _origin
from .store import AccessError

MAX_RESPONSE = 1024 * 1024
MAX_BODY = 65536


class _TransportRefusal(AccessError):
    """Only fixed messages created by this transport may cross its boundary."""


def _public_ip(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        elif address in ipaddress.ip_network('64:ff9b::/96') or address in ipaddress.ip_network('::ffff:0:0:0/96'):
            address = ipaddress.IPv4Address(int(address) & 0xffffffff)
        elif address.sixtofour and not _public_ip(str(address.sixtofour)):
            return False
        elif address.teredo and any(not _public_ip(str(item)) for item in address.teredo):
            return False
    return address.is_global and not address.is_multicast and not address.is_reserved


def send(host, path, method, headers, body):
    # Pin one public destination; verify TLS against the saved origin hostname.
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = {item[4][0] for item in addresses}
    if not ips or any(not _public_ip(ip) for ip in ips):
        raise _TransportRefusal('API access requires a public HTTPS service.', 403)
    address = sorted(ips)[0]

    class PinnedConnection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((address, 443), timeout=self.timeout)
            try:
                self.sock = tls.wrap_socket(raw, server_hostname=host)
            except Exception:
                raw.close()
                raise

    tls = ssl.create_default_context()
    connection = PinnedConnection(host, 443, timeout=25, context=tls)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if type(response.status) is not int or not 100 <= response.status <= 599:
            raise _TransportRefusal('The API returned an invalid HTTP status.', 502)
        if 300 <= response.status < 400:
            raise _TransportRefusal('The API redirected. The credential was not forwarded to another origin.', 403)
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise _TransportRefusal('The API response exceeds the supported size.', 413)
        return response.status, data.decode('utf-8', errors='replace')
    finally:
        connection.close()


def _json_value(value, depth=0):
    if depth > 30:
        return False
    if value is None or type(value) in (str, bool, int, float):
        return True
    if type(value) is list:
        return all(_json_value(item,depth+1) for item in value)
    if type(value) is dict:
        return all(type(key) is str and _json_value(item,depth+1) for key, item in value.items())
    return False


def _request(path, method, body, auth_header, auth_scheme, headers):
    try:
        target = urlsplit(path) if type(path) is str else None
        if (target is None or not path.startswith('/') or path.startswith('//') or
                target.scheme or target.netloc or target.fragment or len(path) > 4096 or
                any(ord(c) <= 32 or ord(c) >= 127 for c in path)):
            raise ValueError
    except (TypeError, ValueError):
        raise AccessError('Specify an ASCII relative API path beginning with one slash, without fragments or whitespace.') from None
    if type(method) is not str or method not in ('GET','POST','PUT','PATCH','DELETE','HEAD'):
        raise AccessError('This HTTP method is unsupported.')
    if (type(auth_header) is not str or auth_header not in ('Authorization','x-api-key','X-API-Key','api-key') or
            type(auth_scheme) is not str or auth_scheme not in ('Bearer','')):
        raise AccessError('Select a supported API authentication header.')
    if headers is None:
        headers = {}
    if type(headers) is not dict or len(headers) > 20:
        raise AccessError('The API headers are invalid.')
    permitted, seen = {}, set()
    forbidden = {'authorization','proxy-authorization','host','cookie','connection','content-length',
                 'transfer-encoding','x-api-key','api-key','upgrade','te','trailer'}
    for key, value in headers.items():
        if (type(key) is not str or not re.fullmatch(r'[A-Za-z0-9-]{1,80}',key) or
                key.lower() in forbidden or key.lower() in seen or type(value) is not str or len(value) > 2048 or
                any(ord(char) < 32 or ord(char) >= 127 for char in value)):
            raise AccessError('The API headers contain an unsupported field.')
        permitted[key] = value
        seen.add(key.lower())
    if body is not None and (type(body) is not dict or not _json_value(body)):
        raise AccessError('The API body must be a JSON object.')
    try:
        payload = json.dumps(body,allow_nan=False).encode() if body is not None else None
    except (ValueError,TypeError,RecursionError):
        raise AccessError('The API body must contain finite JSON values.') from None
    if payload is not None and len(payload) > MAX_BODY:
        raise AccessError('The API request body is too large.',413)
    if payload is not None:
        permitted = {key:value for key,value in permitted.items() if key.lower() != 'content-type'}
        permitted['Content-Type'] = 'application/json'
    if 'accept' not in seen:
        permitted['Accept'] = 'application/json'
    return permitted,payload


def _access(turn, handle):
    try:
        access = turn.service.delegations.resolve(turn,handle)
        if access.meta.kind != 'api_key':
            raise ValueError
        origin = _origin(access.meta.origin)
        from .delegation import credential_binding
        binding = (access.owner,str(access.home.resolve()),access.handle,access.grant_id,
                   credential_binding(access.meta))
        return access,origin,binding
    except Exception:
        raise AccessError('Select an owned or invited API-key handle with one exact HTTPS origin.',403) from None


def _redact(result,key):
    from agent.redact import redact_registered_vault_values, redact_sensitive_text
    numeric_key = None
    if re.fullmatch(r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?',key):
        try:
            numeric_key = Decimal(key)
        except InvalidOperation:
            pass
    def scrub(value):
        if isinstance(value,str):
            return redact_registered_vault_values(redact_sensitive_text(value.replace(key,'[REDACTED]'),force=True))
        if isinstance(value,dict):
            return {scrub(name):scrub(item) for name,item in value.items()}
        if isinstance(value,list):
            return [scrub(item) for item in value]
        if type(value) in (int,float) and numeric_key is not None:
            try:
                if Decimal(str(value)) == numeric_key:
                    return '[REDACTED]'
            except (InvalidOperation,ValueError):
                pass
        return value
    try:
        parsed = json.loads(result)
    except (ValueError,TypeError):
        parsed = result
    return scrub(parsed)


def execute(turn, *, handle, path, method='GET', body=None, auth_header='Authorization', auth_scheme='Bearer', headers=None):
    service = turn.service
    service.assert_private(turn)
    permitted,payload = _request(path,method,body,auth_header,auth_scheme,headers)
    access,origin,binding = _access(turn,handle)
    kernel = getattr(service,'kernel_vault',None)
    if kernel is None:
        raise AccessError('Kernel Vault is required for API requests. No local credential fallback is permitted.',503)
    with service.lock_for(access.home):
        service.delegations.check_execution(turn)
        current,current_origin,current_binding = _access(turn,handle)
        if current_binding != binding or current_origin != origin:
            raise AccessError('The API credential permission or origin changed before this request.',403)
        try:
            key = kernel.api_key(turn,handle)
        except Exception as error:
            if isinstance(error,AccessError) and getattr(error,'kernel_api_key_reason',None) == 'write_only':
                raise AccessError('Recollect this API key through a new private Kernel form with backend API access enabled, then retry the request.',409) from None
            raise AccessError('The Kernel API key could not be authorized for this request.',403) from None
        if (type(key) is not str or not key or len(key) > 4096 or
                any(ord(char) < 32 or ord(char) >= 127 for char in key)):
            raise AccessError('This API key cannot be used in an HTTP header.')
        try:
            from agent.redact import register_vault_redaction_value
            register_vault_redaction_value(key)
            kernel.remember_values(turn,[key])
        except Exception:
            raise AccessError('The API credential could not be protected for this request.',503) from None
        _,latest_origin,latest_binding = _access(turn,handle)
        service.delegations.check_execution(turn)
        if latest_binding != binding or latest_origin != origin:
            raise AccessError('The API credential permission or origin changed before this request.',403)
        permitted[auth_header] = (auth_scheme+' ' if auth_scheme else '')+key
        try:
            status,result = send(urlsplit(origin).hostname,path,method,permitted,payload)
            if type(status) is not int or not 100 <= status <= 599 or type(result) is not str:
                raise ValueError
        except _TransportRefusal:
            raise
        except Exception:
            raise AccessError('The API request was not confirmed. Check its outcome before repeating an operation with side effects.',502) from None
        _,after_origin,after_binding = _access(turn,handle)
        if after_binding != binding or after_origin != origin:
            raise AccessError('The API credential permission changed. Its response was withheld.',403)
        return {'status_code':status,'success':200 <= status < 300,'result':_redact(result,key)}
