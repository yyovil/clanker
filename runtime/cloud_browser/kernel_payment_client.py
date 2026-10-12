"""Native Kernel wallet/card transport. Never returns payment credential values."""
from urllib.parse import urlsplit
from .kernel_vault_client import KernelVaultClient, _argument, _response, _reference, _timestamp, _fill_result

CURRENCIES = frozenset('aud brl cad chf czk dkk eur gbp hkd inr jpy krw mxn nok nzd pln sek sgd usd zar'.split())
CARD_FIELDS = frozenset({'number', 'expiration', 'exp_month', 'exp_year', 'cvc', 'billing_name'})


def https_url(value):
    try:
        parsed = urlsplit(value)
        _argument(isinstance(value, str) and len(value) <= 8192 and parsed.scheme == 'https'
                  and bool(parsed.hostname) and not parsed.username and not parsed.password
                  and parsed.port in (None, 443) and not any(ord(c) < 32 for c in value))
        return 'https://' + parsed.netloc.lower()
    except (ValueError, TypeError):
        _argument(False)


def payment_item(body, key, kind):
    _response(isinstance(body, dict) and body.get('type') == kind and body.get('key') == key)
    _response(body.get('spec', {}).get('provider') == 'kernel' and body.get('state', {}).get('provider') == 'kernel')
    states = ({'pending_authorization', 'connected', 'reconnect_required', 'degraded'} if kind == 'wallet'
              else {'requested', 'pending_authorization', 'ready', 'consumed', 'expired', 'declined', 'recovery_required'})
    _response(body['state'].get('status') in states)
    _response(isinstance(body.get('id'), str) and bool(body['id']))
    operations = body.get('available_operations')
    _response(isinstance(operations, list) and all(isinstance(op, dict) for op in operations))
    clean = {'id': body['id'], 'key': key, 'type': kind,
             'state': {'provider': 'kernel', 'status': body['state']['status']},
             'available_operations': [{'type': op['type']} for op in operations if op.get('type') in {'authorize', 'fill'}]}
    expansions = body.get('available_expansions', [])
    _response(isinstance(expansions, list) and all(isinstance(entry, dict) for entry in expansions))
    clean['available_expansions'] = [entry['type'] for entry in expansions if entry.get('type') == 'payment_methods']
    if body.get('expires_at'):
        clean['expires_at'] = _timestamp(body['expires_at'])
    action = body.get('action')
    if action:
        expected = 'card_enrollment' if kind == 'wallet' else 'spend_approval'
        _response(isinstance(action, dict) and action.get('name') == expected)
        try:
            _response(isinstance(action.get('url'), str) and not any(ord(c) < 32 for c in action['url']))
            parsed = urlsplit(action.get('url', ''))
            _response(parsed.scheme == 'https' and parsed.hostname == 'vault.kernel.sh' and
                      not parsed.username and not parsed.password and parsed.port in (None, 443))
        except ValueError:
            _response(False)
        clean['action'] = {'name': expected, 'url': action['url']}
    # Strictly extract eligibility and a fixed activation code; IDs, card values, and provider text stay private.
    methods = body.get('expanded', {}).get('payment_methods', []) if isinstance(body.get('expanded'), dict) else []
    _response(isinstance(methods,list))
    def single_use(method):
        capabilities = method.get('capabilities') if isinstance(method,dict) else None
        single = capabilities.get('single_use_card') if isinstance(capabilities,dict) else None
        return single if isinstance(single,dict) else {}
    singles = [single_use(method) for method in methods]
    clean['eligible'] = any(single.get('eligible') is True for single in singles)
    # A missing capability is unknown; only eligible=false is Kernel's explicit refusal.
    refused = [single for single in singles if single.get('eligible') is False]
    clean['activation'] = ('eligible' if clean['eligible'] else 'network_token_pending'
        if any(isinstance(s.get('reasons'), list) and 'network_token_pending' in s['reasons'] for s in refused)
        else 'ineligible' if refused else 'unknown')
    return clean


class KernelPaymentClient(KernelVaultClient):
    def get_payment(self, vault, key, kind):
        _argument(kind in {'wallet', 'card'})
        item = self._request('GET', self._path(vault, key), '/vaults/{vault}/items/{key}', absent=True,
            parser=lambda body: payment_item(body, key, kind))
        # Pending wallets expose their enrollment action through the plain GET.
        # Expanding payment methods before connection returns 409 and hides it.
        if (item is not None and kind == 'wallet' and item['state']['status'] == 'connected'
                and 'payment_methods' in item['available_expansions']):
            return self._request('GET', self._path(vault, key), '/vaults/{vault}/items/{key}',
                params={'expand': 'payment_methods'}, absent=True,
                parser=lambda body: payment_item(body, key, kind))
        return item

    def create_wallet(self, vault, key):
        return self._request('PUT', self._path(vault, key), '/vaults/{vault}/items/{key}',
            body={'type': 'wallet', 'spec': {'provider': 'kernel'}}, expected=(200, 201),
            parser=lambda body: payment_item(body, key, 'wallet'))

    def create_card(self, vault, key, *, wallet, merchant_name, merchant_url, amount, currency, merchant_country):
        _reference(wallet)
        https_url(merchant_url)
        _argument(type(amount) is int and 0 < amount <= 50000 and currency in CURRENCIES)
        _argument(isinstance(merchant_name, str) and 0 < len(merchant_name) <= 120)
        _argument(isinstance(merchant_country, str) and len(merchant_country) == 2 and merchant_country.isalpha())
        spec = dict(provider='kernel', wallet=wallet, merchant_name=merchant_name, merchant_url=merchant_url,
                    amount=amount, currency=currency, merchant_country=merchant_country.upper())
        return self._request('PUT', self._path(vault, key), '/vaults/{vault}/items/{key}',
            body={'type': 'card', 'spec': spec}, expected=(200, 201), parser=lambda body: payment_item(body, key, 'card'))

    def authorize_card(self, vault, key):
        item = self.get_payment(vault, key, 'card')
        _argument(item is not None and {'type': 'authorize'} in item['available_operations'])
        return self._request('POST', self._path(vault, key) + '/operations', '/vaults/{vault}/items/{key}/operations',
            body={'type': 'authorize'}, parser=lambda body: payment_item(body, key, 'card'))

    def fill_card(self, vault, key, *, browser_id, page_url, fields):
        _reference(browser_id); https_url(page_url)
        _argument(isinstance(fields, list) and 1 <= len(fields) <= 6)
        for field in fields:
            _argument(isinstance(field, dict) and set(field) <= {'field', 'selector', 'format'} and
                field.get('field') in CARD_FIELDS and isinstance(field.get('selector'), str) and 0 < len(field['selector']) <= 4096)
            _argument(field.get('format') in {'MM/YY', 'MM/YYYY'} if field['field'] == 'expiration' else 'format' not in field)
        _argument(len({f['field'] for f in fields}) == len(fields) and len({f['selector'] for f in fields}) == len(fields))
        item = self.get_payment(vault, key, 'card')
        _argument(item is not None and item['state']['status'] == 'ready' and {'type': 'fill'} in item['available_operations'])
        return self._request('POST', self._path(vault, key) + '/operations', '/vaults/{vault}/items/{key}/operations',
            body=dict(type='fill', browser_id=browser_id, page_url=page_url, fields=fields, timeout_ms=10000),
            parser=lambda body: _fill_result(body, len(fields)))
