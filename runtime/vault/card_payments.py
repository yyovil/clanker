"""Private card collection and owner-scoped reuse, without checkout text parsing.

Legacy native purchases remain readable/reconcilable through the existing code.
New purchases use native Kernel card handles, never card readback.
"""
from datetime import datetime, timezone
import hmac
import json
import secrets
from string import Template

from .payments import Payments as LegacyPayments
from .store import AccessError

CARD_PROGRESS_NEXT = {
    'not_added': 'The owner has not added a card in Kernel yet. Wait for the private card step; never collect card details in chat.',
    'activating': ('The owner already added the card. Kernel is still activating it with the card network, so no purchase card '
                   'exists and nothing was charged. This task resumes automatically when the card is ready or this payment window closes. '
                   'Do not ask for the card again or start another purchase.'),
    'ineligible': ('The owner added the card, but Kernel currently reports it ineligible for agent purchases. Nothing was charged. '
                   'Tell the owner; checks continue until this payment window closes. Do not start another purchase.'),
    'preparing': 'The owner added the card and Kernel is preparing this purchase. Nothing was charged. This task resumes automatically when it is ready.',
    'unknown': 'Kernel could not confirm the card step. Nothing was charged. Do not start another purchase; check status again later.',
}


def card_progress(wallet):
    """Enrollment progress as a fixed code; provider reasons never reach the model or page."""
    status = wallet['state']['status'] if wallet else None
    if status in {'pending_authorization', 'reconnect_required'}:
        return 'not_added'
    if status != 'connected':
        return 'unknown'
    return {'network_token_pending': 'activating', 'ineligible': 'ineligible'}.get(wallet['activation'], 'preparing')


class Payments(LegacyPayments):
    def inventory(self, turn):
        self.service.assert_private(turn)
        with self.service.store.connection() as db:
            saved = db.execute("SELECT 1 FROM kernel_payment_wallets w JOIN kernel_purchases p ON p.wallet_key=w.item_key JOIN requests r ON r.id=p.request_id WHERE w.team=? AND w.owner=? AND r.team=w.team AND r.owner=w.owner AND w.state='active' AND p.remember=1 AND p.approved IS NOT NULL AND p.state NOT IN ('review','approved','creating_wallet','enrollment') LIMIT 1",
                (turn.source.scope_id, turn.source.user_id)).fetchone()
        return {'provider': 'kernel', 'saved': bool(saved)}

    def status(self, turn, *, payment_id):
        result = super().status(turn, payment_id=payment_id)
        row, purchase, checkout = self._row(payment_id, turn=turn)
        if checkout.get('flow') != 'private_card':
            return result
        result['next'] = ('Fill only when ready, then submit once. Observe the merchant result or bank verification; '
                          'use clanker_payment_complete only for an explicit success or definite failure. Never repeat uncertain payment.')
        if purchase['state'] == 'enrollment':
            try:
                wallet = self.client.get_payment(purchase['vault'], purchase['wallet_key'], 'wallet')
            except Exception:
                wallet = None
            result['card'] = card_progress(wallet)
            result['next'] = CARD_PROGRESS_NEXT[result['card']]
        if purchase['state'] in {'enrollment', 'approval'} and row['expires'] <= self.service.store.clock():
            result['expired'] = True
            result['next'] = ('The payment window closed before this card step finished. No card was filled or submitted and nothing was charged. '
                              'Tell the owner plainly, then use clanker_payment_cancel to retire this purchase. Start a new payment only when the owner asks again.')
        return result

    def poll(self):
        super().poll()
        with self.service.store.connection() as db:
            rows = db.execute("SELECT r.id, r.checkout FROM requests r JOIN kernel_purchases p ON p.request_id=r.id "
                              "WHERE r.status='waiting' AND r.expires<=? AND p.state IN ('enrollment','approval')",
                              (self.service.store.clock(),)).fetchall()
            for row in rows:
                # An expired card step can no longer fill. Resume once so the owner hears the outcome.
                if json.loads(row['checkout']).get('flow') == 'private_card':
                    db.execute("UPDATE requests SET status='saved' WHERE id=? AND status='waiting'", (row['id'],))

    def _button(self, turn, plan, selector):
        from tools import browser_vault_tool as native
        # Empty card forms disable Pay until private fill. Bind the visible
        # control now; submit still requires it to be enabled before clicking.
        expression = """(() => {const elements=document.querySelectorAll(SELECTOR);
          if(elements.length!==1)return null;const b=elements[0];
          if(!b.getClientRects().length)return null;
          if(b.tagName==='BUTTON')return b.innerText.trim();
          if(b.tagName==='INPUT'&&b.type==='submit')return b.value.trim();return null;})()""".replace('SELECTOR', json.dumps(selector))
        response = native._eval_js(plan.task_id, expression)
        label = response.get('result') if response.get('success') else None
        if not isinstance(label, str) or not label:
            raise AccessError('Select the visible final payment button.', 409)
        return label

    def receipt(self, turn, **kwargs):
        _, _, checkout = self._row(kwargs['payment_id'], turn=turn)
        if checkout.get('flow') == 'private_card':
            raise AccessError('Use clanker_payment_complete after observing the merchant result.', 409)
        return super().receipt(turn, **kwargs)

    async def request(self, turn, *, merchant_name, amount, pay_button_selector, merchant_country='IN'):
        """Call only for the owner's current instruction to proceed with payment."""
        self.service.assert_private(turn)
        self.service.delegations.check_execution(turn)
        if (not isinstance(merchant_name, str) or not merchant_name.strip() or len(merchant_name) > 120
                or type(amount) is not int or not 0 < amount <= 50000 or merchant_country != 'IN'):
            raise AccessError('Provide the merchant and INR amount in paise (Kernel maximum ₹500).', 400)
        if not isinstance(pay_button_selector, str) or not 0 < len(pay_button_selector) <= 4096:
            raise AccessError('Select the final payment button.', 400)
        with self.service.lock_for(turn.home):
            plan = self.service.kernel_vault.inspect(turn)
            with self.service.store.connection() as db:
                unresolved = db.execute("SELECT r.id FROM requests r JOIN kernel_purchases p ON r.id=p.request_id WHERE r.team=? AND r.owner=? AND p.state NOT IN ('completed','cancelled','review') LIMIT 1",
                    (turn.source.scope_id, turn.source.user_id)).fetchone()
                wallet = db.execute('SELECT * FROM kernel_payment_wallets WHERE team=? AND owner=?',
                    (turn.source.scope_id, turn.source.user_id)).fetchone()
                remembered = bool(wallet and db.execute('SELECT 1 FROM kernel_purchases p JOIN requests r ON r.id=p.request_id WHERE r.team=? AND r.owner=? AND p.wallet_key=? AND p.remember=1 AND p.approved IS NOT NULL LIMIT 1',
                    (turn.source.scope_id, turn.source.user_id, wallet['item_key'])).fetchone())
            if unresolved:
                raise AccessError('Reconcile the existing payment before starting another.', 409)
            if wallet and wallet['state'] != 'active':
                raise AccessError('Previous card enrollment/removal needs reconciliation.', 409)
            vault = self.service.kernel_vault.ensure_vault(turn.source.scope_id, turn.source.user_id)['id']
            checkout = dict(flow='private_card', merchant_name=merchant_name.strip(), amount=amount,
                currency='inr', merchant_country='IN', origin=plan.origin, page_url=plan.page_url,
                browser_id=plan.browser_id, pay_button_selector=pay_button_selector,
                pay_label=self._button(turn, plan, pay_button_selector))
            row = self.service.store.create(team=turn.source.scope_id, owner=turn.source.user_id,
                home=self.service.private_home(turn.source.scope_id, turn.source.user_id), task_id=turn.task_id,
                source=turn.source.to_dict(), task=turn.message, kind='payment',
                label=f'{merchant_name.strip()} · Pay ₹{amount / 100:.2f}', origin=plan.origin,
                checkout=checkout, gateway_event_id=turn.message_id)
            key = wallet['item_key'] if wallet else 'wallet-' + secrets.token_hex(16)
            with self.service.store.connection() as db:
                db.execute('INSERT OR IGNORE INTO kernel_purchases VALUES (?,?,?,?,?,?,?,?,NULL)',
                    (row['id'], wallet['vault'] if wallet else vault, key, 'purchase-' + row['id'],
                     'approved' if remembered else 'review', 1 if remembered else None,
                     self.service.store.clock() if remembered else None, None))
            if remembered:
                _, purchase, _ = self._row(row['id'], turn=turn)
                try:
                    self._drive(row, purchase)
                except AccessError as error:
                    if getattr(error, 'kernel_vault_code', None) in {'invalid_request', 'forbidden', 'authentication_failed'}:
                        self._state(row['id'], 'provider_rejected')
                        with self.service.store.connection() as db:
                            db.execute("UPDATE requests SET status='resumed',resume_delivered=? WHERE id=?",
                                       (self.service.store.clock(), row['id']))
                        return dict(payment_id=row['id'], status='blocked', state='provider_rejected')
                    # Retain uncertain mutation claims for read-only reconciliation.
                except Exception:
                    pass
                state = self._row(row['id'], turn=turn)[1]['state']
                if state == 'ready':
                    self.service.store.mark_resumed(row['id'])
                    return dict(payment_id=row['id'], status='ready', state='ready', remembered=True)
        state = self._row(row['id'], turn=turn)[1]['state']
        delivery = await self.service.deliver_link(row, **({'delivery_event_id': 'native-spend-approval-' + row['id']} if state == 'approval' else {}))
        return dict(delivery, status='waiting_for_owner', payment_id=row['id'],
                    link_delivery=delivery.get('status', 'unconfirmed'))

    def _observe(self, turn, checkout=None, **kwargs):
        if not checkout or checkout.get('flow') != 'private_card':
            return super()._observe(turn, checkout, **kwargs)
        plan = self.service.kernel_vault.inspect(turn, checkout['origin'])
        if plan.page_url != checkout['page_url'] or plan.browser_id != checkout['browser_id']:
            raise AccessError('The payment page or browser changed.', 409)
        return plan, checkout['amount'], ''

    def view(self, request_id, token, identity):
        if not isinstance(token, str) or not hmac.compare_digest(token, self.service.store.token(request_id)):
            raise AccessError('This payment link is invalid.', 404)
        row, purchase, checkout = self._row(request_id, identity=identity)
        if checkout.get('flow') != 'private_card':
            return super().view(request_id, token, identity)
        result = dict(provider='kernel_payment', payment_id=request_id, state=purchase['state'],
                      merchant=checkout['merchant_name'], amount=checkout['amount'], currency='inr')
        if purchase['state'] in {'creating_otp', 'otp', 'otp_ready'}:
            with self.service.store.connection() as db:
                verification = db.execute('SELECT * FROM kernel_payment_verifications WHERE request_id=?', (request_id,)).fetchone()
            if verification:
                item = self.service.kernel_vault.client.get_credential(purchase['vault'], verification['item_key'])
                if item and item['state']['status'] == 'pending_collection':
                    item = self.service.kernel_vault.client.collect(purchase['vault'], verification['item_key'])
                if item and item.get('action'):
                    result['collection_url'] = item['action']['url']
        elif purchase['state'] in {'enrollment', 'approval'}:
            kind = 'wallet' if purchase['state'] == 'enrollment' else 'card'
            key = purchase['wallet_key'] if kind == 'wallet' else purchase['card_key']
            item = self.client.get_payment(purchase['vault'], key, kind)
            if item and item.get('action'):
                result['collection_url'] = item['action']['url']
            if kind == 'wallet':
                result['card'] = card_progress(item)
        return result

    def submit(self, turn, *, payment_id):
        from tools import browser_vault_tool as native
        row, purchase, checkout = self._row(payment_id, turn=turn)
        if checkout.get('flow') != 'private_card':
            return super().submit(turn, payment_id=payment_id)
        with self.service.lock_for(turn.home):
            if row['expires'] <= self.service.store.clock():
                raise AccessError('Payment request expired.', 410)
            plan, _, _ = self._observe(turn, checkout)
            card = self.client.get_payment(purchase['vault'], purchase['card_key'], 'card')
            if (not card or card['state']['status'] != 'ready' or not card.get('expires_at')
                    or datetime.fromisoformat(card['expires_at'].replace('Z', '+00:00')) <= datetime.now(timezone.utc)):
                raise AccessError('Payment credentials expired.', 409)
            self._claim(payment_id, 'filled', 'submitting')
            with self.service.store.connection() as db:
                db.execute('UPDATE kernel_purchases SET submitted=? WHERE request_id=?', (self.service.store.clock(), payment_id))
            expression = '''(() => {if(location.href!==$url||window.__hermesNativePageBinding!==$marker)return false;
              const buttons=document.querySelectorAll($selector);if(buttons.length!==1)return false;
              const b=buttons[0];if(!b.getClientRects().length||b.disabled)return false;
              if(b.tagName!=='BUTTON'&&!(b.tagName==='INPUT'&&b.type==='submit'))return false;
              const label=b.tagName==='BUTTON'?b.innerText:b.value;if(label.trim()!==$label)return false;
              b.click();return true;})()'''
            expression = Template(expression).substitute(url=json.dumps(plan.page_url), marker=json.dumps(plan.marker),
                selector=json.dumps(checkout['pay_button_selector']), label=json.dumps(checkout['pay_label']))
            response = native._eval_js(plan.task_id, expression)
            if response.get('success') and response.get('result') is False:
                self._state(payment_id, 'submit_blocked')
                with self.service.store.connection() as db:
                    db.execute('UPDATE kernel_purchases SET submitted=NULL WHERE request_id=?', (payment_id,))
            else:
                self._state(payment_id, 'submitted_unknown')
            return dict(payment_id=payment_id, state=self._row(payment_id, turn=turn)[1]['state'],
                        next='Check the merchant outcome or bank verification. Never repeat an uncertain payment.')

    def complete(self, turn, *, payment_id, outcome):
        """Agent reports the merchant outcome after observing the browser."""
        with self.service.lock_for(turn.home):
            row, purchase, checkout = self._row(payment_id, turn=turn)
            if checkout.get('flow') != 'private_card':
                raise AccessError('Use the legacy reconciliation path for this existing purchase.', 409)
            if outcome not in {'paid', 'failed'} or purchase['state'] not in {'submitted_unknown', 'otp_submitted_unknown'}:
                raise AccessError('Confirm the merchant outcome of the submitted payment first.', 409)
            plan = self.service.kernel_vault.inspect(turn, checkout['origin'])
            if plan.browser_id != checkout['browser_id']:
                raise AccessError('Payment browser changed.', 403)
            # Remove filled controls, including frames, before lifting privacy guards.
            self.service.cloud_browser.stop(turn)
            self._state(payment_id, 'completed')
            pending = False
            if not purchase['remember']:
                try:
                    self._remove_wallet(row, purchase)
                except Exception:
                    pending = True
            return dict(payment_id=payment_id, state='completed', outcome=outcome, card_removal_pending=pending)

