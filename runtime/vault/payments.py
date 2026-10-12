"""Owner-approved native Kernel purchases. Local state contains metadata only.

Each provider mutation and merchant submission is claimed durably before dispatch.
An uncertain attempt is reconciled by reads, never replayed automatically.
"""
import asyncio
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import re
import secrets
from urllib.parse import urlsplit

from .store import AccessError


def require_offline_fixture(service):
    raise AccessError('Legacy card-value payment entry points are retired. Use native Kernel payments.', 410)


def displayed_amount(text):
    """INR only: require a single unambiguous decimal amount in a total element."""
    if not isinstance(text, str):
        raise AccessError('The checkout total could not be verified.', 409)
    if re.search(r'-\s*\d', text):
        raise AccessError('A positive checkout total is required.',409)
    numbers = re.findall(r'\d[\d,]*(?:\.\d{1,2})?', text)
    if len(numbers) != 1:
        raise AccessError('Select a checkout total containing exactly one amount.', 409)
    try:
        value = Decimal(numbers[0].replace(',', '')) * 100
        if value != value.to_integral_value():
            raise ValueError
        return int(value)
    except (InvalidOperation, ValueError):
        raise AccessError('The checkout total could not be verified.', 409) from None


class Payments:
    def __init__(self, service):
        self.service = service
        with service.store.connection() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS kernel_payment_wallets (
                team TEXT NOT NULL, owner TEXT NOT NULL, vault TEXT NOT NULL,
                item_key TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
                PRIMARY KEY(team,owner));
              CREATE TABLE IF NOT EXISTS kernel_payment_verifications (
                request_id TEXT PRIMARY KEY, item_key TEXT NOT NULL UNIQUE,
                origin TEXT NOT NULL, page_url TEXT NOT NULL, browser_id TEXT NOT NULL,
                fields TEXT NOT NULL, button_selector TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS kernel_purchases (
                request_id TEXT PRIMARY KEY, vault TEXT NOT NULL, wallet_key TEXT NOT NULL,
                card_key TEXT NOT NULL UNIQUE, state TEXT NOT NULL, remember INTEGER,
                approved REAL, submitted REAL, receipt TEXT);
            ''')

    @property
    def client(self):
        from cloud_browser.kernel_payment_client import KernelPaymentClient
        if self.service.kernel_vault is None:
            raise AccessError('Kernel Vault is unavailable.', 503)
        if not hasattr(self, '_client'):
            self._client = KernelPaymentClient(self.service.cloud_browser.client)
        return self._client

    def require_offline_fixture(self, *args, **kwargs):
        require_offline_fixture(self.service)

    card_access = execute = require_offline_fixture

    def _row(self, request_id, *, identity=None, turn=None):
        if turn:
            self.service.assert_private(turn)
            self.service.delegations.check_execution(turn)
            identity = dict(team=turn.source.scope_id, owner=turn.source.user_id)
        if not identity:
            raise AccessError('Payment access requires an authenticated owner.', 403)
        try:
            row = self.service.store.get(request_id, self.service.store.token(request_id), identity=identity, waiting=False)
        except AccessError as error:
            # Expiry cannot erase owner access for cancellation/reconciliation.
            # Approval, fill and submit still require a live review deadline.
            with self.service.store.connection() as db:
                candidate = db.execute('SELECT r.* FROM requests r JOIN kernel_purchases p ON p.request_id=r.id WHERE r.id=? AND r.team=? AND r.owner=?',
                    (request_id,identity['team'],identity['owner'])).fetchone()
            if error.status != 410 or not candidate:
                raise
            row = dict(candidate)
        if row['kind'] != 'payment' or row.get('grant_id') or row['status'] == 'cancelled':
            raise AccessError('This purchase is unavailable.', 403)
        if turn:
            source = json.loads(row['source'])
            current = turn.source.to_dict()
            if any(source.get(key) != current.get(key) for key in ('chat_id', 'thread_id', 'profile', 'isolated_task')):
                raise AccessError('This purchase belongs to a different private task.', 403)
        with self.service.store.connection() as db:
            purchase = db.execute('SELECT * FROM kernel_purchases WHERE request_id=?', (request_id,)).fetchone()
        if not purchase:
            raise AccessError('This purchase is unavailable.', 404)
        return row, dict(purchase), json.loads(row['checkout'])

    def _state(self, request_id, state):
        with self.service.store.connection() as db:
            db.execute('UPDATE kernel_purchases SET state=? WHERE request_id=?', (state, request_id))

    def _claim(self, request_id, before, after):
        with self.service.store.connection() as db:
            changed = db.execute('UPDATE kernel_purchases SET state=? WHERE request_id=? AND state=?',
                                 (after, request_id, before)).rowcount
        if not changed:
            raise AccessError('This payment step has already been attempted. Reconcile its outcome.', 409)

    def _observe(self, turn, checkout=None, *, total_selector=None, summary_selector=None):
        from tools import browser_vault_tool as native
        plan = self.service.kernel_vault.inspect(turn, checkout['origin'] if checkout else None)
        total_selector = checkout['total_selector'] if checkout else total_selector
        summary_selector = checkout['summary_selector'] if checkout else summary_selector
        expression = '''(() => { const read = selector => {const e=document.querySelectorAll(selector);
          if(e.length!==1 || !e[0].getClientRects().length) return null;
          return e[0].innerText;}; return JSON.stringify({total:read(__TOTAL__),summary:read(__SUMMARY__)}); })()'''
        values={'__TOTAL__':total_selector,'__SUMMARY__':summary_selector}
        expression=re.sub(r'__[A-Z_]+__',lambda match:json.dumps(values[match.group()]),expression)
        response = native._eval_js(plan.task_id, expression)
        data = native._parse_json_result(response.get('result')) if response.get('success') else None
        if isinstance(data, str):
            data = native._parse_json_result(data)
        if not isinstance(data, dict) or not isinstance(data.get('summary'), str) or not data['summary'].strip():
            raise AccessError('The visible checkout items could not be verified.', 409)
        amount = displayed_amount(data.get('total'))
        summary = data['summary'].strip()
        if checkout and (amount != checkout['amount'] or summary != checkout['summary'] or plan.page_url != checkout['page_url']):
            raise AccessError('Checkout changed since approval. Request a new payment review.', 409)
        return plan, amount, summary

    def inventory(self, turn):
        self.service.assert_private(turn)
        with self.service.store.connection() as db:
            row = db.execute('SELECT state FROM kernel_payment_wallets WHERE team=? AND owner=?',
                             (turn.source.scope_id, turn.source.user_id)).fetchone()
        return {'provider': 'kernel', 'saved': bool(row and row['state'] == 'active')}

    def protect_browser(self, turn, tool_name):
        # Token credentials can be inside cross-origin frames. Main-frame value
        # redaction alone is insufficient, so ordinary tools fail closed until
        # the payment workflow removes the filled controls or resolves its receipt.
        with self.service.store.connection() as db:
            rows = db.execute("SELECT r.source FROM requests r JOIN kernel_purchases p ON r.id=p.request_id "
                              "WHERE r.team=? AND r.owner=? AND p.state IN ('cancelling','filling','filled','fill_failed','fill_unknown','submitting','submitted_unknown','submit_blocked','otp','otp_ready','otp_filling','otp_filled','otp_submitting','otp_submitted_unknown','creating_otp')",
                              (turn.source.scope_id, turn.source.user_id)).fetchall()
        current = turn.source.to_dict()
        for row in rows:
            source = json.loads(row['source'])
            if all(source.get(key) == current.get(key) for key in ('chat_id','thread_id','profile','isolated_task')):
                raise AccessError('Use the payment status, submit, verification or receipt tools while private payment fields are present.', 409)

    def _button(self, turn, plan, selector):
        from tools import browser_vault_tool as native
        expression='''(() => {const e=document.querySelectorAll(__SELECTOR__);if(e.length!==1||!e[0].getClientRects().length)return null;
          const b=e[0];if(b.tagName!=='BUTTON'&&!(b.tagName==='INPUT'&&b.type==='submit'))return null;
          return b.tagName==='BUTTON'?b.innerText:b.value;})()'''.replace('__SELECTOR__',json.dumps(selector))
        response=native._eval_js(plan.task_id,expression)
        label=response.get('result') if response.get('success') else None
        if not isinstance(label,str) or not re.search(r'\b(?:pay|place order|confirm purchase|complete purchase)\b',label,re.I):
            raise AccessError('Select the visible final payment button before approval.',409)
        return label.strip()

    async def request(self, turn, *, merchant_name, total_selector, summary_selector, pay_button_selector, merchant_country='IN'):
        self.service.assert_private(turn)
        if not isinstance(merchant_name, str) or not merchant_name.strip() or len(merchant_name) > 120:
            raise AccessError('Specify the merchant name.', 400)
        if merchant_country != 'IN':
            raise AccessError('This first payment flow supports INR purchases in India.', 400)
        for selector in (total_selector, summary_selector, pay_button_selector):
            if not isinstance(selector, str) or not 0 < len(selector) <= 4096:
                raise AccessError('Provide selectors for the visible checkout total and items.', 400)
        with self.service.lock_for(turn.home):
            plan, amount, summary = self._observe(turn, total_selector=total_selector, summary_selector=summary_selector)
            with self.service.store.connection() as db:
                unresolved = db.execute("SELECT r.id FROM requests r JOIN kernel_purchases p ON r.id=p.request_id WHERE r.team=? AND r.owner=? AND p.state NOT IN ('completed','cancelled','review') LIMIT 1",
                    (turn.source.scope_id, turn.source.user_id)).fetchone()
            if unresolved:
                raise AccessError('Reconcile the existing purchase before creating another payment request.', 409)
            if not 0 < amount <= 50000 or len(summary) > 4000:
                raise AccessError('Kernel native purchases currently support up to ₹500. Checkout summary must fit the review.', 400)
            pay_label = self._button(turn, plan, pay_button_selector)
            checkout = dict(pay_button_selector=pay_button_selector, pay_label=pay_label, merchant_name=merchant_name.strip(), amount=amount, currency='inr', merchant_country='IN',
                origin=plan.origin, page_url=plan.page_url, total_selector=total_selector,
                summary_selector=summary_selector, summary=summary, browser_id=plan.browser_id)
            home = self.service.private_home(turn.source.scope_id, turn.source.user_id)
            row = self.service.store.create(team=turn.source.scope_id, owner=turn.source.user_id, home=home,
                task_id=turn.task_id, source=turn.source.to_dict(), task=turn.message, kind='payment',
                label=f'{merchant_name.strip()} · Pay ₹{amount / 100:.2f}', origin=plan.origin,
                checkout=checkout, gateway_event_id=turn.message_id)
            vault = self.service.kernel_vault.ensure_vault(row['team'], row['owner'])['id']
            with self.service.store.connection() as db:
                # Reuse a saved native wallet; otherwise provision only after owner approval.
                wallet = db.execute('SELECT * FROM kernel_payment_wallets WHERE team=? AND owner=?', (row['team'], row['owner'])).fetchone()
                if wallet and wallet['state'] != 'active':
                    raise AccessError('Previous card enrollment/removal needs reconciliation before another payment.', 409)
                wallet_key = wallet['item_key'] if wallet else 'wallet-' + secrets.token_hex(16)
                db.execute('INSERT OR IGNORE INTO kernel_purchases VALUES (?,?,?,?,?,NULL,NULL,NULL,NULL)',
                           (row['id'], vault, wallet_key, 'purchase-' + row['id'], 'review'))
        receipt = await self.service.deliver_link(row)
        return dict(receipt, status='waiting_for_owner', payment_id=row['id'], link_delivery=receipt.get('status',receipt.get('link_delivery','unconfirmed')))

    def view(self, request_id, token, identity):
        import hmac
        if not isinstance(token,str) or not hmac.compare_digest(token,self.service.store.token(request_id)):
            raise AccessError('This payment link is invalid.',404)
        row, purchase, checkout = self._row(request_id, identity=identity)
        result = dict(provider='kernel_payment', payment_id=request_id, state=purchase['state'],
                      merchant=checkout['merchant_name'], amount=checkout['amount'], currency=checkout['currency'],
                      summary=checkout['summary'])
        if purchase['state'] in {'creating_otp', 'otp', 'otp_ready'}:
            with self.service.store.connection() as db:
                verification = db.execute('SELECT * FROM kernel_payment_verifications WHERE request_id=?',(request_id,)).fetchone()
            if verification:
                result['summary'] = 'Enter your bank verification code privately for this purchase on ' + verification['origin']
                item = self.service.kernel_vault.client.get_credential(purchase['vault'],verification['item_key'])
                if item and item['state']['status'] == 'pending_collection':
                    item = self.service.kernel_vault.client.collect(purchase['vault'], verification['item_key'])
                if item and item.get('action'):
                    result['collection_url'] = item['action']['url']
            return result
        kind = 'wallet' if purchase['state'] == 'enrollment' else 'card'
        if purchase['state'] in {'enrollment', 'approval'}:
            key = purchase['wallet_key'] if kind == 'wallet' else purchase['card_key']
            item = self.client.get_payment(purchase['vault'], key, kind)
            if item and item.get('action'):
                result['collection_url'] = item['action']['url']
        return result

    def approve(self, request_id, token, identity, fields):
        self.service.store.get(request_id, token, identity=identity)
        row, purchase, checkout = self._row(request_id, identity=identity)
        if not isinstance(fields, dict) or set(fields) != {'remember', 'approve'} or type(fields['remember']) is not bool or fields['approve'] is not True:
            raise AccessError('Approve this exact purchase and choose whether to remember the card.', 400)
        with self.service.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            other = db.execute("SELECT r.id FROM requests r JOIN kernel_purchases p ON p.request_id=r.id WHERE r.team=? AND r.owner=? AND r.id<>? AND p.state NOT IN ('review','completed','cancelled') LIMIT 1",
                (row['team'],row['owner'],request_id)).fetchone()
            if other:
                raise AccessError('Another purchase needs reconciliation before this approval.',409)
            changed = db.execute("UPDATE kernel_purchases SET state='approved',remember=?,approved=? WHERE request_id=? AND state='review'",
                (int(fields['remember']), self.service.store.clock(), request_id)).rowcount
            if not changed:
                raise AccessError('This purchase has already been approved.', 409)
        return {'approved': True, 'payment_id': request_id}

    def _drive(self, row, purchase):
        """Mutation claims survive crashes. Polling reconciles only known item keys."""
        pid, vault, wallet_key, card_key = row['id'], purchase['vault'], purchase['wallet_key'], purchase['card_key']
        state = purchase['state']
        if state in {'creating_otp', 'otp'}:
            with self.service.store.connection() as db:
                verification = db.execute('SELECT * FROM kernel_payment_verifications WHERE request_id=?',(pid,)).fetchone()
            if verification:
                item = self.service.kernel_vault.client.get_credential(vault,verification['item_key'])
                if item:
                    self._state(pid,'otp_ready' if item['state']['status']=='ready' else 'otp')
                    if item['state']['status']=='ready':
                        with self.service.store.connection() as db:
                            db.execute("UPDATE requests SET status='saved' WHERE id=? AND status='waiting'",(pid,))
            return
        checkout = json.loads(row['checkout'])
        if state == 'approved':
            wallet = self.client.get_payment(vault, wallet_key, 'wallet')
            if wallet is None:
                self._claim(pid, 'approved', 'creating_wallet')
                with self.service.store.connection() as db:
                    db.execute('INSERT INTO kernel_payment_wallets VALUES (?,?,?,?,?)',
                        (row['team'], row['owner'], vault, wallet_key, 'active'))
                wallet = self.client.create_wallet(vault, wallet_key)
            self._state(pid, 'enrollment')
            state = 'enrollment'
        if state == 'enrollment':
            wallet = self.client.get_payment(vault, wallet_key, 'wallet')
            if not wallet or wallet['state']['status'] != 'connected' or not wallet['eligible']:
                return
            self._claim(pid, 'enrollment', 'creating_card')
            self.client.create_card(vault, card_key, wallet=wallet_key,
                **{k: checkout[k] for k in ('merchant_name', 'amount', 'currency', 'merchant_country')}, merchant_url=checkout['page_url'])
            self._state(pid, 'card_created')
            state = 'card_created'
        # Recover acknowledged creation only by reading the deterministic key.
        if state in {'creating_wallet', 'creating_card'}:
            kind = 'wallet' if state == 'creating_wallet' else 'card'
            item = self.client.get_payment(vault, wallet_key if kind == 'wallet' else card_key, kind)
            if item:
                self._state(pid, 'enrollment' if kind == 'wallet' else 'card_created')
            return
        if state == 'card_created':
            self._claim(pid, 'card_created', 'authorizing')
            item = self.client.authorize_card(vault, card_key)
        elif state in {'authorizing', 'approval'}:
            item = self.client.get_payment(vault, card_key, 'card')
        else:
            return
        if not item:
            return
        remote = item['state']['status']
        if remote == 'ready':
            self._state(pid, 'ready')
            with self.service.store.connection() as db:
                db.execute("UPDATE requests SET status='saved' WHERE id=? AND status='waiting'", (pid,))
        elif remote == 'pending_authorization':
            self._state(pid, 'approval')
        elif remote in {'declined', 'expired', 'recovery_required'}:
            self._state(pid, remote)

    def poll(self):
        self.cleanup()
        with self.service.store.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT r.* FROM requests r JOIN kernel_purchases p ON r.id=p.request_id WHERE r.status='waiting' AND r.expires>? AND p.state NOT IN ('review','ready')", (self.service.store.clock(),))]
        for row in rows:
            try:
                self.service.validate_member(row['team'], row['owner'])
                with self.service.lock_for(self.service.private_home(row['team'], row['owner'])):
                    _, purchase, _ = self._row(row['id'], identity=dict(team=row['team'], owner=row['owner']))
                    self._drive(row, purchase)
            except AccessError as error:
                if getattr(error,'kernel_vault_code',None) in {'invalid_request','forbidden','authentication_failed'}:
                    self._state(row['id'],'provider_rejected')
                    with self.service.store.connection() as db:
                        db.execute("UPDATE requests SET status='saved' WHERE id=? AND status='waiting'",(row['id'],))
                continue
            except Exception:
                # Unknown mutations stay claimed. No provider errors/URLs enter logs.
                continue

    async def deliver_actions(self):
        with self.service.store.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT r.* FROM requests r JOIN kernel_purchases p ON r.id=p.request_id WHERE r.status='waiting' AND r.expires>? AND p.state='approval'", (self.service.store.clock(),))]
        for row in rows:
            try:
                await self.service.deliver_link(row, delivery_event_id='native-spend-approval-' + row['id'])
            except Exception:
                continue

    def status(self, turn, *, payment_id):
        from tools import browser_vault_tool as native
        row, purchase, checkout = self._row(payment_id, turn=turn)
        result = dict(payment_id=payment_id, state=purchase['state'], provider='kernel',
            next='Fill only when ready. After submission reconcile the merchant; never resubmit. If bank verification is shown, use clanker_payment_request_code.')
        if purchase['state'] in {'submitting','submitted_unknown','otp_submitting','otp_submitted_unknown'}:
            plan = self.service.kernel_vault.inspect(turn)
            if plan.browser_id != checkout['browser_id']:
                raise AccessError('Payment browser changed.',403)
            # No input values, screenshots or frame contents are read. This
            # restricted observation helps identify a bank challenge safely.
            response = native._eval_js(plan.task_id, "JSON.stringify({text:document.body.innerText.slice(0,6000),controls:Array.from(document.querySelectorAll('input,button')).filter(e=>e.getClientRects().length).map(e=>({tag:e.tagName,type:e.type,id:e.id,name:e.name,label:e.tagName==='BUTTON'?e.innerText:e.getAttribute('aria-label')}))})")
            data = native._parse_json_result(response.get('result')) if response.get('success') else None
            if isinstance(data,str):
                data=native._parse_json_result(data)
            if isinstance(data,dict):
                # Network token digits must not enter model context if a site
                # displays them as ordinary text outside an input.
                serialized=re.sub(r'(?<!\d)(?:\d[ -]?){12,19}(?!\d)','[private card]',json.dumps(data))
                result['checkout_observation']=json.loads(serialized)
        return result

    async def request_code(self, turn, *, payment_id, code_selector, button_selector):
        row,purchase,checkout=self._row(payment_id,turn=turn)
        with self.service.lock_for(turn.home):
            plan=self.service.kernel_vault.inspect(turn)
            if plan.browser_id!=checkout['browser_id']:
                raise AccessError('Bank verification belongs to another browser.',403)
            for selector in (code_selector,button_selector):
                if not isinstance(selector,str) or not 0<len(selector)<=4096:
                    raise AccessError('Select the visible bank code field and verification button.',400)
            if purchase['state'] not in {'submitted_unknown','submitting'}:
                raise AccessError('A bank-code request requires the submitted purchase. No automatic code retries.',409)
            key='verification-'+payment_id
            with self.service.store.connection() as db:
                db.execute('INSERT INTO kernel_payment_verifications VALUES (?,?,?,?,?,?,?)',
                    (payment_id,key,plan.origin,plan.page_url,plan.browser_id,json.dumps([{'field':'code','selector':code_selector}]),button_selector))
            self._claim(payment_id,purchase['state'],'creating_otp')
            item=self.service.kernel_vault.client.create_credential(purchase['vault'],key,
                [{'name':'code','type':'password','required':True,'sensitive':True,'label':'Bank verification code'}],
                description='Verification for the approved purchase on '+plan.origin)
            self._state(payment_id,'otp')
            with self.service.store.connection() as db:
                db.execute("UPDATE requests SET status='waiting',expires=? WHERE id=?",(self.service.store.clock()+300,payment_id))
                row=dict(db.execute('SELECT * FROM requests WHERE id=?',(payment_id,)).fetchone())
        delivery=await self.service.deliver_link(row,delivery_event_id='native-bank-code-'+payment_id)
        return dict(delivery,status='waiting_for_owner',payment_id=payment_id,link_delivery=delivery.get('status',delivery.get('link_delivery','unconfirmed')))

    def verify_code(self, turn, *, payment_id):
        from tools import browser_vault_tool as native
        with self.service.lock_for(turn.home):
            row,purchase,checkout=self._row(payment_id,turn=turn)
            with self.service.store.connection() as db:
                verification=db.execute('SELECT * FROM kernel_payment_verifications WHERE request_id=?',(payment_id,)).fetchone()
            if not verification:
                raise AccessError('No bank verification was requested.',409)
            plan=self.service.kernel_vault.inspect(turn,verification['origin'])
            if plan.browser_id!=verification['browser_id'] or plan.page_url!=verification['page_url']:
                raise AccessError('The bank verification page changed. Do not reuse the code.',409)
            fields=json.loads(verification['fields'])
            self._claim(payment_id,'otp_ready','otp_filling')
            self.service.kernel_vault._arm_privacy(turn,plan,fields,sensitive=True)
            result=self.service.kernel_vault.client.fill(purchase['vault'],verification['item_key'],
                browser_id=plan.browser_id,page_url=plan.page_url,fields=fields)
            self.service.kernel_vault.refresh_privacy(turn)
            if result['status']!='completed':
                self._state(payment_id,'otp_fill_'+result['status'])
                raise AccessError('Bank-code fill was not confirmed. Do not submit or replay it.',409)
            self._state(payment_id,'otp_filled')
            self.service.kernel_vault.client.delete_credential(purchase['vault'],verification['item_key'])
            self._claim(payment_id,'otp_filled','otp_submitting')
            # Button selection is bound to the observed bank page before private
            # collection. Unique visible target; no value is returned.
            expression='''(() => {const e=document.querySelectorAll(__SELECTOR__); if(e.length!==1||!e[0].getClientRects().length||e[0].disabled)return false; e[0].click();return true;})()'''.replace('__SELECTOR__',json.dumps(verification['button_selector']))
            native._eval_js(plan.task_id,expression)
            self._state(payment_id,'otp_submitted_unknown')
            return dict(payment_id=payment_id,state='otp_submitted_unknown',next='Reconcile the merchant paid-order receipt; never submit the purchase again.')

    def fill(self, turn, *, payment_id, fields):
        with self.service.lock_for(turn.home):
            row, purchase, checkout = self._row(payment_id, turn=turn)
            if row['expires'] <= self.service.store.clock():
                raise AccessError('Purchase approval expired. Do not dispatch this payment.', 410)
            plan, _, _ = self._observe(turn, checkout)
            if plan.browser_id != checkout['browser_id']:
                raise AccessError('Payment browser changed; request a new purchase review.', 409)
            self._claim(payment_id, 'ready', 'filling')
            # Install observation guards before the provider writes any values.
            self.service.kernel_vault._arm_privacy(turn, plan, fields, sensitive=True)
            result = self.client.fill_card(purchase['vault'], purchase['card_key'], browser_id=plan.browser_id,
                                           page_url=plan.page_url, fields=fields)
            self.service.kernel_vault.refresh_privacy(turn)
            self._state(payment_id, 'filled' if result['status'] == 'completed' else 'fill_' + result['status'])
            return dict(payment_id=payment_id, state='filled' if result['status'] == 'completed' else 'fill_' + result['status'])

    def submit(self, turn, *, payment_id):
        from tools import browser_vault_tool as native
        with self.service.lock_for(turn.home):
            row, purchase, checkout = self._row(payment_id, turn=turn)
            if row['expires'] <= self.service.store.clock():
                raise AccessError('Purchase approval expired. Do not dispatch this payment.', 410)
            plan, _, _ = self._observe(turn, checkout)
            if plan.browser_id != checkout['browser_id']:
                raise AccessError('Payment browser changed.', 409)
            card = self.client.get_payment(purchase['vault'], purchase['card_key'], 'card')
            if not card or card['state']['status'] != 'ready' or not card.get('expires_at') or datetime.fromisoformat(card['expires_at'].replace('Z', '+00:00')) <= datetime.now(timezone.utc):
                raise AccessError('Payment credentials expired. Do not submit this checkout.', 409)
            if self._button(turn, plan, checkout['pay_button_selector']) != checkout['pay_label']:
                raise AccessError('The payment button changed since review.', 409)
            self._claim(payment_id, 'filled', 'submitting')
            with self.service.store.connection() as db:
                db.execute('UPDATE kernel_purchases SET submitted=? WHERE request_id=?', (self.service.store.clock(), payment_id))
            # Revalidate page, item summary and button atomically with the click.
            expression=r'''(() => {if(location.href!==__URL__||window.__hermesNativePageBinding!==__MARKER__)return false;
              const items=document.querySelectorAll(__ITEMS__),buttons=document.querySelectorAll(__BUTTON__),totals=document.querySelectorAll(__TOTAL__);
              if(totals.length!==1||!totals[0].getClientRects().length)return false;
              const numbers=totals[0].innerText.match(/\d[\d,]*(?:\.\d{1,2})?/g)||[];
              if(numbers.length!==1||Math.round(Number(numbers[0].replace(/,/g,''))*100)!==__AMOUNT__)return false;
              if(items.length!==1||items[0].innerText.trim()!==__SUMMARY__||buttons.length!==1)return false;
              const b=buttons[0];if(!b.getClientRects().length||b.disabled)return false;
              const label=b.tagName==='BUTTON'?b.innerText:b.value;if(label.trim()!==__LABEL__)return false;
              b.click();return true;})()'''
            values={'__URL__':plan.page_url,'__MARKER__':plan.marker,'__ITEMS__':checkout['summary_selector'],
                '__BUTTON__':checkout['pay_button_selector'],'__TOTAL__':checkout['total_selector'],'__AMOUNT__':checkout['amount'],
                '__SUMMARY__':checkout['summary'],'__LABEL__':checkout['pay_label']}
            expression=re.sub(r'__[A-Z_]+__',lambda match:json.dumps(values[match.group()]),expression)
            native._eval_js(plan.task_id,expression)
            self._state(payment_id, 'submitted_unknown')
            # Never equate a successful click with a charge or paid order.
            return dict(payment_id=payment_id, state='submitted_unknown',
                        next='Inspect the merchant for bank authentication or a matching paid-order receipt. Never click Pay again for this purchase.')

    def receipt(self, turn, *, payment_id, receipt_selector, paid_selector, amount_selector, order_selector):
        """Resolve only visible paid status + matching amount + merchant order ID."""
        from tools import browser_vault_tool as native
        with self.service.lock_for(turn.home):
            row, purchase, checkout = self._row(payment_id, turn=turn)
            if purchase['state'] not in {'submitting', 'submitted_unknown', 'otp_submitting', 'otp_submitted_unknown'}:
                raise AccessError('Reconcile the submitted purchase first.', 409)
            plan = self.service.kernel_vault.inspect(turn, checkout['origin'])
            if plan.browser_id != checkout['browser_id']:
                raise AccessError('The merchant receipt belongs to a different browser.', 403)
            selectors = [receipt_selector, paid_selector, amount_selector, order_selector]
            if any(not isinstance(selector, str) or not 0 < len(selector) <= 4096 for selector in selectors):
                raise AccessError('Select the visible merchant receipt, paid status, total and order ID.', 400)
            expression = "JSON.stringify(" + json.dumps(selectors) + ".map(s=>{const e=document.querySelectorAll(s); return e.length===1&&e[0].getClientRects().length?e[0].innerText:null;}))"
            response = native._eval_js(plan.task_id, expression)
            values = native._parse_json_result(response.get('result')) if response.get('success') else None
            if isinstance(values, str):
                values = native._parse_json_result(values)
            if not isinstance(values, list) or len(values) != 4 or any(not isinstance(v,str) or not v.strip() for v in values):
                raise AccessError('A visible merchant paid-order receipt is required.', 409)
            receipt, paid, amount, order = [v.strip() for v in values]
            if (len(receipt) > 8000 or not re.fullmatch(r'(?:payment\s+(?:successful|completed)|paid|paid\s+successfully)', paid, re.I)
                    or displayed_amount(amount) != checkout['amount'] or len(order) > 120 or not re.search(r'\d', order)):
                raise AccessError('Receipt must show a matching total, explicit paid status and order ID.', 409)
            # Retain only bounded order metadata, not full private receipt text.
            with self.service.store.connection() as db:
                db.execute("UPDATE kernel_purchases SET state='completed',receipt=? WHERE request_id=?", (order, payment_id))
            cleanup_pending = False
            if not purchase['remember']:
                try:
                    self._remove_wallet(row, purchase)
                except Exception:
                    cleanup_pending = True
            return dict(payment_id=payment_id, state='completed', order_id=order,
                        paid_amount=checkout['amount'], currency='inr', card_removal_pending=cleanup_pending)

    def cancel(self, turn, *, payment_id):
        """Retire an unsubmitted approval before changing/rebuilding checkout."""
        with self.service.lock_for(turn.home):
            row,purchase,_=self._row(payment_id,turn=turn)
            if purchase['submitted'] is not None or purchase['state'] in {'recovery_required','submitting','submitted_unknown','creating_otp','otp','otp_ready','otp_filling','otp_submitting','otp_submitted_unknown'}:
                raise AccessError('This purchase may have been submitted. Reconcile it; cancellation is not a refund.',409)
            if purchase['state']=='cancelled':
                return dict(payment_id=payment_id,state='cancelled')
            if purchase['state']!='cancelling':
                self._claim(payment_id,purchase['state'],'cancelling')
            # Closing the owned browser removes filled token fields, including
            # cross-origin frames, before ordinary browser access is permitted.
            self.service.cloud_browser.stop(turn)
            self.client.delete_credential(purchase['vault'],purchase['card_key'])
            self._state(payment_id,'cancelled')
            cleanup_pending=False
            if purchase['remember'] is False or purchase['remember']==0:
                try:self._remove_wallet(row,purchase)
                except Exception:cleanup_pending=True
            with self.service.store.connection() as db:
                db.execute("UPDATE requests SET status='cancelled' WHERE id=?",(payment_id,))
            return dict(payment_id=payment_id,state='cancelled',card_removal_pending=cleanup_pending,
                        next='The approval is retired. Reopen the merchant and request a fresh review for changed items or total.')

    def _remove_wallet(self, row, purchase):
        # Block new purchases first. Provider DELETE failure must not make a
        # temporary card look saved or successfully removed.
        with self.service.store.connection() as db:
            db.execute("UPDATE kernel_payment_wallets SET state='removal_pending' WHERE team=? AND owner=? AND item_key=?",
                       (row['team'], row['owner'], purchase['wallet_key']))
        self.client.delete_credential(purchase['vault'], purchase['card_key'])
        self.client.delete_credential(purchase['vault'], purchase['wallet_key'])
        with self.service.store.connection() as db:
            db.execute("DELETE FROM kernel_payment_wallets WHERE team=? AND owner=? AND item_key=? AND state='removal_pending'",
                       (row['team'], row['owner'], purchase['wallet_key']))

    def cleanup(self):
        with self.service.store.connection() as db:
            rows = [dict(row) for row in db.execute("SELECT r.* FROM requests r JOIN kernel_purchases p ON p.request_id=r.id JOIN kernel_payment_wallets w ON w.item_key=p.wallet_key WHERE w.state='removal_pending' AND p.state IN ('completed','cancelled') AND p.remember=0")]
        for row in rows:
            try:
                with self.service.lock_for(self.service.private_home(row['team'],row['owner'])):
                    with self.service.store.connection() as db:
                        purchase = dict(db.execute('SELECT * FROM kernel_purchases WHERE request_id=?',(row['id'],)).fetchone())
                    self._remove_wallet(row,purchase)
            except Exception:
                continue
