"""Durable task and access-request metadata for Kernel credential collection.

Legacy credential write/consume methods fail closed; Kernel owns secret values.
Existing encrypted control-plane fields remain readable for task continuation.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time


# Keep a verified browser signed in across vault visits. This absolute lifetime
# is shared with the host-only cookie; current membership and request ownership
# are still checked separately on every operation.
SESSION_TTL_SECONDS = 30 * 24 * 60 * 60


class AccessError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class RequestStore:
    def __init__(self, directory, *, clock=time.time):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.clock = clock
        key = self.directory / 'request.key'
        if not key.exists():
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
        self.key = key.read_bytes()
        self.path = self.directory / 'requests.sqlite'
        with self.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS requests (
                  id TEXT PRIMARY KEY, team TEXT NOT NULL, owner TEXT NOT NULL,
                  home TEXT NOT NULL, task_id TEXT NOT NULL, source TEXT NOT NULL,
                  task TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL,
                  origin TEXT NOT NULL, identifier TEXT NOT NULL,
                  created REAL NOT NULL, expires REAL NOT NULL,
                  status TEXT NOT NULL DEFAULT 'waiting', handle TEXT,
                  message_ts TEXT, resume_attempt REAL, resume_delivered REAL);
                CREATE TABLE IF NOT EXISTS auth_states (
                  state TEXT PRIMARY KEY, browser TEXT NOT NULL, nonce TEXT NOT NULL,
                  request_id TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                  id TEXT PRIMARY KEY, team TEXT NOT NULL, owner TEXT NOT NULL,
                  csrf TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS transfers (
                  id TEXT PRIMARY KEY, team TEXT NOT NULL, owner TEXT NOT NULL,
                  home TEXT NOT NULL, task_id TEXT NOT NULL, original_source TEXT NOT NULL,
                  task TEXT NOT NULL, source TEXT, created REAL NOT NULL,
                  status TEXT NOT NULL DEFAULT 'waiting');
                CREATE TABLE IF NOT EXISTS private_link_deliveries (
                  request_id TEXT NOT NULL, event_id TEXT NOT NULL,
                  message_ts TEXT NOT NULL,
                  PRIMARY KEY(request_id,event_id));
            ''')
            # Hermes reuses a session id across turns. Older development stores
            # made that id unique, dropping every later handoff in the thread.
            transfer_schema = db.execute("SELECT sql FROM sqlite_master WHERE name='transfers'").fetchone()[0]
            if 'UNIQUE(team,owner,task_id)' in transfer_schema.replace(' ', ''):
                db.executescript('''
                    BEGIN IMMEDIATE;
                    ALTER TABLE transfers RENAME TO transfers_legacy;
                    CREATE TABLE transfers (
                      id TEXT PRIMARY KEY, team TEXT NOT NULL, owner TEXT NOT NULL,
                      home TEXT NOT NULL, task_id TEXT NOT NULL, original_source TEXT NOT NULL,
                      task TEXT NOT NULL, source TEXT, created REAL NOT NULL,
                      status TEXT NOT NULL DEFAULT 'waiting');
                    INSERT INTO transfers SELECT * FROM transfers_legacy;
                    DROP TABLE transfers_legacy;
                    COMMIT;
                ''')
            if 'code_payload' not in {row[1] for row in db.execute('PRAGMA table_info(requests)')}:
                db.execute('ALTER TABLE requests ADD COLUMN code_payload BLOB')
            columns = {row[1] for row in db.execute('PRAGMA table_info(requests)')}
            for name, kind in [('checkout','TEXT'),('payment_payload','BLOB'),('payment_expires','REAL'),
                               ('grant_id','TEXT'),('approver','TEXT'),('gateway_event_id','TEXT'),
                               ('login_method', "TEXT NOT NULL DEFAULT 'password'")]:
                if name not in columns:db.execute(f'ALTER TABLE requests ADD COLUMN {name} {kind}')
            columns = {row[1] for row in db.execute('PRAGMA table_info(transfers)')}
            for name, kind in [('reply_mode', "TEXT NOT NULL DEFAULT 'private'"),
                               ('task_state', 'TEXT'), ('result_payload', 'BLOB'),
                               ('result_message_ts', 'TEXT'), ('result_event_id', 'TEXT'),
                               ('last_inbound_id', 'TEXT'), ('result_private', 'INTEGER NOT NULL DEFAULT 0'),
                               ('result_return_state', "TEXT NOT NULL DEFAULT 'completed'"),
                               ('recovery_event_id', 'TEXT'), ('recovery_state', 'TEXT'),
                               ('recovery_profile', 'TEXT'), ('recovery_form_id', 'TEXT'),
                               ('context_receipt', 'TEXT')]:
                if name not in columns:db.execute(f'ALTER TABLE transfers ADD COLUMN {name} {kind}')
            db.execute('''CREATE TABLE IF NOT EXISTS public_task_updates (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL, event_id TEXT NOT NULL,
                kind TEXT NOT NULL, stage TEXT NOT NULL, payload BLOB NOT NULL,
                fingerprint TEXT NOT NULL, original_digest TEXT NOT NULL,
                private_source TEXT NOT NULL, private_version TEXT, private_digest TEXT,
                created REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', message_ts TEXT,
                UNIQUE(task_id,event_id,fingerprint))''')
        os.chmod(self.path, 0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.execute('PRAGMA secure_delete=ON')
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def token(self, request_id):
        return hmac.new(self.key, request_id.encode(), hashlib.sha256).hexdigest()

    def create(self, *, team, owner, home, task_id, source, task, kind, label, origin, identifier='', handle=None, checkout=None, grant_id=None, approver=None, gateway_event_id=None, login_method='password'):
        if kind not in ('login','code','api_key','payment'):
            raise AccessError('This access form supports logins, cards, API keys and verification codes.')
        if login_method not in ('password', 'sms') or (login_method == 'sms' and kind not in ('login', 'code')):
            raise AccessError('Unsupported login method for this request.')
        if login_method == 'sms' and identifier:
            raise AccessError('Phone numbers must be supplied through the private form.')
        if (kind=='payment') != isinstance(checkout,dict):
            raise AccessError('Card requests require a bound checkout.')
        checkout_json = json.dumps(checkout,sort_keys=True) if checkout is not None else None
        if kind=='api_key':
            from agent.vault_store import VaultError, normalize_origin
            from urllib.parse import urlsplit
            if not isinstance(origin,str):
                raise AccessError('API keys require an exact HTTPS API origin.')
            parts=urlsplit(origin)
            if parts.scheme!='https' or not parts.hostname or parts.path not in ('','/') or parts.query or parts.fragment or parts.username or parts.password:
                raise AccessError('API keys require an exact HTTPS API origin.')
            try:origin=normalize_origin(origin)
            except (VaultError,ValueError):
                raise AccessError('API keys require an exact HTTPS API origin.') from None
            if not isinstance(label,str) or not label.strip() or len(label)>120 or identifier or handle:
                raise AccessError('API key requests require a title and no login fields.')
            label=label.strip()
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT * FROM requests WHERE team=? AND owner=? AND task_id=? AND task=? AND origin=? AND kind=? AND identifier=? AND handle IS ? AND checkout IS ? AND grant_id IS ? AND approver IS ? AND gateway_event_id IS ? AND login_method=? AND status='waiting' AND expires>?",
                             (team, owner, task_id, task, origin, kind, identifier, handle, checkout_json, grant_id, approver, gateway_event_id, login_method, self.clock())).fetchone()
            if row:
                return dict(row)
            request_id = secrets.token_hex(16)
            now = self.clock()
            db.execute('INSERT INTO requests (id,team,owner,home,task_id,source,task,kind,label,origin,identifier,created,expires,handle,checkout,grant_id,approver,gateway_event_id,login_method) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       (request_id,team,owner,str(home),task_id,json.dumps(source),task,kind,label,origin,identifier,now,now+({'code':300,'payment':900}.get(kind,1800)),handle,checkout_json,grant_id,approver,gateway_event_id,login_method))
            return dict(db.execute('SELECT * FROM requests WHERE id=?', (request_id,)).fetchone())

    def get(self, request_id, token, *, identity=None, waiting=True):
        if not isinstance(token, str) or not hmac.compare_digest(self.token(request_id), token):
            raise AccessError('This access link is invalid.', 404)
        with self.connection() as db:
            row = db.execute('SELECT * FROM requests WHERE id=?', (request_id,)).fetchone()
        if not row:
            raise AccessError('This access link is invalid.', 404)
        row = dict(row)
        if identity and (row['team'],row.get('approver') or row['owner']) != (identity['team'],identity['owner']):
            raise AccessError('Sign in with the Slack account that requested this task.', 403)
        if row['expires'] <= self.clock():
            raise AccessError('This access link has expired. Ask Clanker for a new link.', 410)
        if waiting and row['status'] != 'waiting':
            raise AccessError('This access link has already been used or cancelled.', 410)
        return row

    def start_auth(self, request_id):
        state, browser, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        with self.connection() as db:
            db.execute('DELETE FROM auth_states WHERE expires<=?', (self.clock(),))
            db.execute('INSERT INTO auth_states VALUES (?,?,?,?,?)',
                       (digest(state),digest(browser),nonce,request_id,self.clock()+600))
        return state, browser, nonce

    def consume_auth(self, state, browser):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM auth_states WHERE state=?', (digest(state),)).fetchone()
            if not row or row['expires'] <= self.clock() or not hmac.compare_digest(row['browser'],digest(browser)):
                raise AccessError('Sign-in expired or could not be verified. Open your access link again.', 403)
            db.execute('DELETE FROM auth_states WHERE state=?', (digest(state),))
            return dict(row)

    def new_session(self, team, owner):
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute('DELETE FROM sessions WHERE expires<=?', (self.clock(),))
            db.execute('INSERT INTO sessions VALUES (?,?,?,?,?)', (digest(sid),team,owner,csrf,self.clock()+SESSION_TTL_SECONDS))
        return sid

    def session(self, sid):
        with self.connection() as db:
            row = db.execute('SELECT * FROM sessions WHERE id=? AND expires>?', (digest(sid),self.clock())).fetchone()
        if not row:
            raise AccessError('Sign in with Slack to continue.', 401)
        return dict(row)

    def save_login(self, request_id, token, identity, fields):
        raise AccessError('Local credential storage is retired. Use Kernel vault collection.', 410)

    def save_api_key(self, request_id, token, identity, fields):
        raise AccessError('Local credential storage is retired. Use Kernel vault collection.', 410)

    def _save_item(self, row, secret):
        raise AccessError('Local credential storage is retired. Use Kernel vault collection.', 410)

    def pending_resumes(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM requests WHERE status='saved' ORDER BY created")]

    def pending_links(self):
        with self.connection() as db:
            db.execute('UPDATE requests SET code_payload=NULL WHERE kind=\'code\' AND expires<=?',(self.clock(),))
            db.execute('UPDATE requests SET payment_payload=NULL WHERE payment_expires<=?',(self.clock(),))
            return [dict(row) for row in db.execute("SELECT * FROM requests WHERE status='waiting' AND message_ts IS NULL AND expires>?",(self.clock(),))]

    def recover_saves(self):
        """Legacy credential saves are never adopted after Kernel migration."""
        return None

    def code_crypto(self):
        """Encrypt task continuation and delivery state, never credential values."""
        import base64
        from cryptography.fernet import Fernet
        return Fernet(base64.urlsafe_b64encode(hmac.new(self.key,b'one-time-code',hashlib.sha256).digest()))

    def save_code(self, request_id, token, identity, fields):
        raise AccessError('Local credential storage is retired. Use Kernel vault collection.', 410)

    def consume_code(self, *, team, owner, home, handle, origin, task_id, validate=None):
        raise AccessError('Local credential storage is retired. Use Kernel vault collection.', 410)

    def mark_resumed(self, request_id):
        with self.connection() as db:
            db.execute("UPDATE requests SET status='resumed',resume_delivered=? WHERE id=? AND status='saved'", (self.clock(),request_id))

    def transfer(self, *, team, owner, home, task_id, source, task, reply_mode='private', context_receipt=None):
        if reply_mode not in ('private', 'channel'):
            raise AccessError('Invalid task reply destination.')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            candidates = db.execute("SELECT * FROM transfers WHERE team=? AND owner=? AND task_id=? AND task=? "
                "AND (status IN ('waiting','saved') OR (reply_mode='channel' AND "
                "(task_state IN ('active','result_pending') OR ?)))",
                (team,owner,task_id,task,bool(source.get('message_id')))).fetchall()
            for row in candidates:
                if json.loads(row['original_source'])==source and row['reply_mode']==reply_mode:
                    return dict(row)
            transfer_id = secrets.token_hex(16)
            db.execute('INSERT INTO transfers (id,team,owner,home,task_id,original_source,task,created,reply_mode,task_state,context_receipt) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                       (transfer_id,team,owner,str(home),task_id,json.dumps(source),task,self.clock(),reply_mode,
                        'active' if reply_mode=='channel' else None,
                        json.dumps(context_receipt) if context_receipt is not None else None))
            return dict(db.execute('SELECT * FROM transfers WHERE id=?',(transfer_id,)).fetchone())

    def pending_transfers(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM transfers WHERE status IN ('waiting','saved') ORDER BY created")]

    def set_transfer_source(self, request_id, source):
        with self.connection() as db:
            db.execute("UPDATE transfers SET source=?,status='saved' WHERE id=? AND status='waiting'",(json.dumps(source),request_id))

    def mark_transfer_resumed(self, request_id):
        with self.connection() as db:
            db.execute("UPDATE transfers SET status='resumed' WHERE id=? AND status='saved'",(request_id,))

    def is_pending(self, request_id, *, transfer=False):
        table='transfers' if transfer else 'requests'
        with self.connection() as db:
            row=db.execute(f'SELECT status FROM {table} WHERE id=?',(request_id,)).fetchone()
        return bool(row and row['status'] in ('waiting','saved'))

    def channel_task(self, source):
        profile = source.get('profile', '')
        if not profile.startswith('task-'):
            return None
        with self.connection() as db:
            row = db.execute("SELECT * FROM transfers WHERE id=? AND reply_mode='channel'",
                             (profile[5:],)).fetchone()
        if not row or not row['source']:
            return None
        expected = json.loads(row['source'])
        fields = ('platform', 'scope_id', 'user_id', 'chat_id', 'thread_id', 'profile')
        if any(source.get(key)!=expected.get(key) for key in fields):
            raise AccessError('This account task belongs to another requester or conversation.', 403)
        return dict(row)

    def pending_channel_results(self):
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM transfers WHERE reply_mode='channel' AND task_state='result_pending'")]

    def linked_channel_task(self, source, *, private=False, active_only=False):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM transfers WHERE team=? AND owner=? AND reply_mode='channel' "
                              "ORDER BY created DESC,rowid DESC", (source['scope_id'],source['user_id'])).fetchall()
        for row in rows:
            if active_only and row['task_state'] not in ('active','result_pending'):
                continue
            saved = row['source'] if private else row['original_source']
            if not saved:continue
            expected = json.loads(saved)
            if all(source.get(key)==expected.get(key) for key in ('platform','scope_id','user_id','chat_id','thread_id')):
                return dict(row)

    def begin_channel_reply(self, task_id, event_id, *, recovery=False):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM transfers WHERE id=?', (task_id,)).fetchone()
            if (not row or row['task_state'] not in ('active','completed') or
                    row['result_event_id']==event_id):
                return False
            if recovery and (row['task_state']!='active' or row['recovery_state']!='pending' or
                    row['recovery_event_id']!=event_id or row['last_inbound_id'] not in (None,event_id)):
                return False
            db.execute("UPDATE transfers SET task_state='active',last_inbound_id=? WHERE id=?",
                       (event_id,task_id))
            return True

    def pending_task_recoveries(self):
        """Persist one continuation for the evidenced pre-fix DM profile split."""
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            tasks = db.execute("SELECT * FROM transfers WHERE reply_mode='channel' "
                               "AND task_state='active' AND status='resumed'").fetchall()
            for task in tasks:
                if (task['recovery_event_id'] or task['last_inbound_id'] or
                        task['result_event_id'] or not task['source']):
                    continue
                expected = json.loads(task['source'])
                requests = db.execute('SELECT id,source,kind,status,origin,handle,created,grant_id,approver,'
                    'gateway_event_id,code_payload IS NULL AS consumed FROM requests '
                    'WHERE team=? AND owner=? AND home=? AND kind=\'code\' ORDER BY created DESC,rowid DESC',
                    (task['team'],task['owner'],task['home'])).fetchall()
                waiting = next((row for row in requests if row['status']=='waiting' and
                    self.same_task_source(json.loads(row['source']),expected)),None)
                if waiting is None:continue
                for request in requests:
                    source = json.loads(request['source'])
                    if (request['status']!='resumed' or not request['consumed'] or
                            request['created']<waiting['created'] or not request['gateway_event_id'] or
                            source.get('message_id')!=request['gateway_event_id'] or
                            source.get('profile')==expected.get('profile') or
                            any(request[key]!=waiting[key] for key in ('origin','handle','grant_id','approver')) or
                            not self.same_task_source(source | {'profile':expected.get('profile')},expected)):
                        continue
                    event_id='clanker-task-recovery-v1:'+task['id']+':'+request['id']
                    db.execute("UPDATE transfers SET recovery_event_id=?,recovery_state='pending',"
                               "recovery_profile=?,recovery_form_id=? WHERE id=?",
                               (event_id,source.get('profile'),waiting['id'],task['id']))
                    break
            return [dict(row) for row in db.execute("SELECT * FROM transfers WHERE reply_mode='channel' "
                "AND task_state='active' AND recovery_state='pending'")]

    def is_pending_recovery(self, task_id, event_id):
        with self.connection() as db:
            row=db.execute("SELECT last_inbound_id FROM transfers WHERE id=? AND task_state='active' "
                           "AND recovery_state='pending' AND recovery_event_id=?",(task_id,event_id)).fetchone()
        return bool(row and row['last_inbound_id'] in (None,event_id))

    def mark_task_recovered(self, task_id, event_id):
        with self.connection() as db:
            db.execute("UPDATE transfers SET recovery_state='done' WHERE id=? AND recovery_event_id=?",
                       (task_id,event_id))

    def expire_recovery_form(self, task_id, event_id):
        """Supersede only the old form after live destination authorization."""
        with self.connection() as db:
            db.execute("UPDATE requests SET expires=min(expires,?) WHERE status='waiting' AND id IN "
                       "(SELECT recovery_form_id FROM transfers WHERE id=? AND recovery_event_id=? "
                       "AND recovery_state='pending' AND task_state='active')",
                       (self.clock(),task_id,event_id))

    def channel_form_status(self, source):
        with self.connection() as db:
            rows = db.execute('SELECT source,kind,status,expires FROM requests WHERE team=? AND owner=? '
                              'ORDER BY created DESC,rowid DESC', (source['scope_id'],source['user_id'])).fetchall()
        for row in rows:
            if self.same_task_source(source,json.loads(row['source'])):
                status = 'expired' if row['expires']<=self.clock() and row['status']=='waiting' else row['status']
                return row['kind'],status

    def pending_channel_access(self, task):
        """Only the latest live form can own an existing handoff's continuation."""
        if not task['source']:
            return False
        source = json.loads(task['source'])
        with self.connection() as db:
            rows = db.execute('SELECT id,source,status,expires,resume_delivered FROM requests '
                'WHERE team=? AND owner=? ORDER BY created DESC,rowid DESC',
                (task['team'],task['owner'])).fetchall()
        for row in rows:
            if not self.same_task_source(source,json.loads(row['source'])):
                continue
            if row['status'] in ('kernel_creating','kernel_create_unknown'):
                return True  # An uncertain create must not be replayed after expiry.
            if row['status']=='waiting':
                return row['expires']>self.clock()
            return (row['status']=='saved' and not row['resume_delivered'] and
                    task['result_event_id']!='clanker-access-resume-'+row['id'])
        return False

    @staticmethod
    def same_task_source(left, right):
        return all(left.get(key)==right.get(key) for key in
                   ('platform','scope_id','user_id','chat_id','thread_id','profile'))

    def channel_tasks_for_control(self, team, owner, source=None, message_id=None):
        with self.connection() as db:
            rows = [dict(row) for row in db.execute(
                "SELECT * FROM transfers WHERE team=? AND owner=? AND reply_mode='channel'",(team,owner))]
        if source is None:return rows
        def matches(row):
            if message_id and json.loads(row['original_source']).get('message_id') != message_id:
                return False
            candidates = [json.loads(row['original_source'])]
            if row['source']:candidates.append(json.loads(row['source']))
            return any(item['chat_id']==source['chat_id'] and (not source.get('thread_id') or
                       item.get('thread_id')==source['thread_id']) for item in candidates)
        return [row for row in rows if matches(row)]

    def save_channel_result(self, task_id, text, *, event_id=None, private=False, continuing=False):
        payload = self.code_crypto().encrypt(text.encode())
        with self.connection() as db:
            db.execute("UPDATE transfers SET result_payload=?,task_state='result_pending',result_event_id=?,"
                       "result_private=?,result_return_state=? WHERE id=? AND reply_mode='channel' AND task_state='active'",
                       (payload,event_id,int(private),'active' if continuing else 'completed',task_id))

    def mark_channel_result(self, task_id, message_ts):
        # Delivery now completes one DM reply, not the linked task. This also
        # migrates an old pending channel result to private continuation when
        # it is recovered after an upgrade.
        with self.connection() as db:
            db.execute("UPDATE transfers SET task_state='active',result_private=1,result_return_state='active',"
                       "result_message_ts=?,status='resumed' "
                       "WHERE id=? AND task_state='result_pending'", (message_ts,task_id))

    def queue_public_update(self, row, *, event_id, kind, stage, text, source, revision=None):
        parts = [kind,stage,' '.join(text.split())]
        if source.get('public_thread_id') is not None:
            parts.append(source['public_thread_id'])
        fingerprint = digest(json.dumps(parts))
        payload = self.code_crypto().encrypt(text.encode())
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            task = db.execute('SELECT task_state,original_source FROM transfers WHERE id=?',(row['id'],)).fetchone()
            if not task or task['task_state'] not in ('active','result_pending') or task['original_source']!=row['original_source']:
                raise AccessError('The originating task is no longer available.',403)
            duplicate = db.execute('SELECT * FROM public_task_updates WHERE task_id=? AND event_id=? AND fingerprint=?',
                (row['id'],str(event_id),fingerprint)).fetchone()
            latest = db.execute("SELECT * FROM public_task_updates WHERE task_id=? AND status IN ('pending','delivered') ORDER BY rowid DESC LIMIT 1",(row['id'],)).fetchone()
            if duplicate or latest and latest['fingerprint']==fingerprint:
                return dict(duplicate or latest),True
            if latest and latest['kind']=='final' and kind=='progress' and latest['event_id']==str(event_id):
                return dict(latest),True
            update_id = secrets.token_hex(16)
            db.execute('INSERT INTO public_task_updates (id,task_id,event_id,kind,stage,payload,fingerprint,original_digest,private_source,private_version,private_digest,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                (update_id,row['id'],str(event_id),kind,stage,payload,fingerprint,digest(row['original_source']),
                 json.dumps(source),str(revision.version) if revision else None,revision.digest if revision else None,self.clock()))
            if kind=='final':
                db.execute("UPDATE public_task_updates SET status='superseded' WHERE task_id=? AND status='pending' "
                           "AND (kind='progress' OR event_id=?) AND id<>?",(row['id'],str(event_id),update_id))
            return dict(db.execute('SELECT * FROM public_task_updates WHERE id=?',(update_id,)).fetchone()),False

    def public_updates(self, *, task_id=None, pending=False):
        clauses,args = [],[]
        if task_id:
            clauses.append('task_id=?');args.append(task_id)
        if pending:
            clauses.append("status='pending'")
        query = 'SELECT * FROM public_task_updates' + (' WHERE '+' AND '.join(clauses) if clauses else '') + ' ORDER BY rowid'
        with self.connection() as db:
            return [dict(row) for row in db.execute(query,args)]

    def public_update_task(self, update):
        with self.connection() as db:
            row = db.execute('SELECT * FROM transfers WHERE id=?',(update['task_id'],)).fetchone()
        return dict(row) if row else None

    def public_thread_updates(self, source):
        with self.connection() as db:
            return [dict(row) for row in db.execute('''SELECT p.* FROM public_task_updates p
                JOIN transfers t ON t.id=p.task_id WHERE p.status='delivered' AND t.team=?
                AND json_extract(t.original_source,'$.chat_id')=?
                AND COALESCE(json_extract(p.private_source,'$.public_thread_id'),json_extract(t.original_source,'$.thread_id'))=?
                AND NOT EXISTS (SELECT 1 FROM transfers newer WHERE newer.team=t.team AND newer.owner=t.owner
                    AND newer.reply_mode='channel' AND newer.rowid>t.rowid
                    AND json_extract(newer.original_source,'$.chat_id')=json_extract(t.original_source,'$.chat_id')
                    AND json_extract(newer.original_source,'$.thread_id')=json_extract(t.original_source,'$.thread_id'))
                ORDER BY p.rowid DESC''',(source.scope_id,source.chat_id,source.thread_id))]

    def mark_public_update(self, update_id, *, message_ts=None, status='delivered'):
        if status not in ('delivered','superseded','cancelled'):
            raise ValueError('Unsupported public update disposition.')
        with self.connection() as db:
            db.execute('UPDATE public_task_updates SET status=?,message_ts=? WHERE id=? AND status=\'pending\'',
                       (status,message_ts,update_id))

    def channel_task_waiting(self, source):
        with self.connection() as db:
            rows = db.execute("SELECT source FROM requests WHERE team=? AND owner=? AND status='waiting' AND expires>?",
                              (source['scope_id'],source['user_id'],self.clock())).fetchall()
        return any(self.same_task_source(json.loads(row['source']),source) for row in rows)

    def channel_task_requested_access(self, source, event_id):
        """A turn that created a form cannot become a final result after save."""
        if not event_id:return False
        with self.connection() as db:
            rows = db.execute('SELECT source FROM requests WHERE team=? AND owner=? AND gateway_event_id=?',
                              (source['scope_id'],source['user_id'],str(event_id))).fetchall()
        return any(self.same_task_source(json.loads(row['source']),source) for row in rows)

    def cancel_owner(self, team, owner):
        """Disconnect cancels outstanding account work before removing its credentials."""
        with self.connection() as db:
            for table in ('requests','transfers'):
                pending="status IN ('waiting','saved')"+(" OR (kind='payment' AND status='resumed' AND payment_payload IS NOT NULL)" if table=='requests' else '')
                db.execute(f"UPDATE {table} SET status='cancelled' WHERE team=? AND owner=? AND ({pending})",(team,owner))
            db.execute('UPDATE requests SET code_payload=NULL WHERE team=? AND owner=?',(team,owner))
            db.execute('UPDATE requests SET payment_payload=NULL WHERE team=? AND owner=?',(team,owner))
            db.execute("UPDATE transfers SET task_state='cancelled',result_payload=NULL WHERE team=? AND owner=? AND task_state IN ('active','result_pending')",(team,owner))

    def cancel(self, *, team, owner, source, message_id=None):
        count=0
        with self.connection() as db:
            for table in ('requests','transfers'):
                pending="status IN ('waiting','saved')"+(" OR (kind='payment' AND status='resumed' AND payment_payload IS NOT NULL)" if table=='requests' else " OR task_state IN ('active','result_pending')")
                rows=db.execute(f"SELECT * FROM {table} WHERE team=? AND owner=? AND ({pending})",(team,owner)).fetchall()
                for row in rows:
                    candidates=[json.loads(row['source'])] if row['source'] else []
                    if table=='transfers':candidates.append(json.loads(row['original_source']))
                    elif candidates and (task := self.channel_task(candidates[0])) is not None:
                        candidates.append(json.loads(task['original_source']))
                    if any(item.get('chat_id')==source['chat_id'] and
                           (not source.get('thread_id') or item.get('thread_id')==source['thread_id']) and
                           (not message_id or item.get('message_id')==message_id or
                            (table=='requests' and row['gateway_event_id']==message_id)) for item in candidates):
                        db.execute(f"UPDATE {table} SET status='cancelled' WHERE id=?",(row['id'],));count+=1
                        if table=='requests':db.execute('UPDATE requests SET code_payload=NULL,payment_payload=NULL WHERE id=?',(row['id'],))
                        else:db.execute("UPDATE transfers SET task_state='cancelled',result_payload=NULL WHERE id=?",(row['id'],))
        return count
