"""Payload-silent, bounded metadata and exact DELETE transport for cleanup."""
from urllib.parse import quote
import time
import requests
from .profile_cleanup import digest, identity, credential_reference, require, Refused


class CleanupProvider:
    def __init__(self,key,project,owners,vaults,*,transport=None,budget_seconds=1800):
        self.key,self.project,self.owners,self.vaults=key,project,owners,vaults
        self.transport=transport or requests.Session()
        if transport is None:self.transport.trust_env=False
        self.deadline=time.monotonic()+budget_seconds
        self.vault_fingerprint=None

    def close(self): self.transport.close()

    def _request(self,method,path,params=None):
        require(method in {'GET','DELETE'} and path.startswith('/'),'unsupported_request')
        require(time.monotonic()<self.deadline,'deadline_reached')
        try:
            response=self.transport.request(method,'https://api.onkernel.com'+path,params=params,
                headers={'Authorization':'Bearer '+self.key(),'X-Kernel-Project':self.project},
                timeout=min(15,max(.1,self.deadline-time.monotonic())),allow_redirects=False)
            if response.status_code==404:return None,{}
            require(response.status_code in ({200} if method=='GET' else {200,204}),'provider_refused')
            return (response.json() if method=='GET' else None),response.headers
        except Exception:raise Refused('provider_metadata_unavailable') from None

    def _get(self,path):return self._request('GET',path)[0]

    def _list(self,path,params=None):
        rows=[];offset=0;seen=set()
        for _ in range(10):
            raw,headers=self._request('GET',path,dict(params or {},limit=100,offset=offset))
            require(isinstance(raw,list) and len(raw)<=100,'incomplete_inventory')
            for row in raw:
                require(isinstance(row,dict) and row.get('id') not in seen,'incomplete_inventory')
                identity(row.get('id'));seen.add(row['id'])
            rows.extend(raw)
            more,next_=headers.get('X-Has-More'),headers.get('X-Next-Offset')
            require(more in {'true','false'} and isinstance(next_,str) and next_.isdigit(),'incomplete_inventory')
            if more=='false':require(next_=='0','incomplete_inventory');return rows
            following=int(next_);require(following>offset,'incomplete_inventory');offset=following
        raise Refused('incomplete_inventory')

    def _profile(self,raw):
        if raw is None:return None
        identity(raw.get('id'));identity(raw.get('name'))
        owner=self.owners.get((raw['id'],raw['name']))
        # Unknown inventory members remain visible and prevent a four-total claim.
        return dict(id=raw['id'],name=raw['name'],owner=owner or 'unattributed')

    def profile(self,identity_):
        identity(identity_);return self._profile(self._get('/profiles/'+quote(identity_,safe='')))

    def inventory(self):return [self._profile(r) for r in self._list('/profiles')]

    def _connection(self,raw):
        if raw is None:return None
        from .kernel_auth_client import _connection
        browser=raw.get('browser')
        # This field is browser configuration, not a browser-session resource.
        # Unknown session/capability-shaped fields remain a refusal.
        require(browser is None or isinstance(browser,dict) and
                not set(browser)-{'proxy','region','stealth','telemetry'},'unknown_auth_browser')
        try:parsed=_connection(raw)
        except Exception:raise Refused('connection_metadata_invalid') from None
        credential=parsed.get('credential')
        require(not parsed.get('external_credential'),'credential_unknown')
        ids=[]
        if credential is not None:
            credential_reference(credential.get('name'));ids=[credential['name']]
        require(parsed.get('health_checks') is False and parsed.get('auto_reauth') is False,'background_auth_writer')
        safe={k:parsed.get(k) for k in ('id','profile_name','domain','allowed_domains','proxy_id','browser','status',
            'flow_status','flow_step','flow_type','flow_expires_at','last_auth_at','last_auth_check_at','health_checks','auto_reauth','record_session','save_credentials')}
        safe['credential_ids']=ids
        require(parsed.get('flow_status') in {'SUCCESS','FAILED','EXPIRED','CANCELED'},'connection_not_terminal')
        return dict(id=parsed['id'],profile_name=parsed['profile_name'],generation=digest(safe),terminal=True,
                    active_writer=False,credential_ids=ids,backing_references=0)

    def connection(self,identity_):
        identity(identity_);return self._connection(self._get('/auth/connections/'+quote(identity_,safe='')))

    def connections(self,name):
        identity(name);rows=self._list('/auth/connections',{'profile_name':name})
        require(all(r.get('profile_name')==name for r in rows),'connection_set_changed')
        return [self._connection(r) for r in rows]

    def credential(self,identity_):
        from .kernel_auth_client import KernelAuthClient
        credential_reference(identity_);raw=self._get('/credentials/'+quote(identity_,safe=''))
        require(raw is not None,'credential_changed')
        meta=KernelAuthClient._credential_metadata(raw)
        # Connections select credentials by name. Bind that exact lookup to
        # the returned immutable ID as well; alias reassignment changes SHA.
        require(identity_ in {meta['id'],meta['name']},'credential_changed')
        return dict(id=identity_,fingerprint=digest(meta))

    def verify_vaults(self):
        meta=[]
        for vault in self.vaults:
            identity(vault)
            rows=self._get('/vaults/'+quote(vault,safe='')+'/items')
            require(isinstance(rows,list),'vault_inventory_incomplete')
            for row in rows:
                # A provider-backed item requires a separate reviewed rebind.
                # Native Kernel items are independent of auth connections.
                require(row.get('type')=='credential' and (row.get('spec') or {}).get('provider')=='kernel'
                        and (row.get('state') or {}).get('provider')=='kernel','saved_vault_reference')
                identity(row.get('id'))
                meta.append(dict(vault=vault,id=row['id'],key=row.get('key'),version=row.get('version'),
                                 spec=row['spec'],status=row['state'].get('status')))
        fingerprint=digest(meta)
        if self.vault_fingerprint is None:self.vault_fingerprint=fingerprint
        require(fingerprint==self.vault_fingerprint,'vault_metadata_changed')
        return fingerprint

    def active_browsers(self):
        self.verify_vaults()
        raw,_=self._request('GET','/browsers',{'status':'active','limit':1,'offset':0})
        require(raw==[],'active_browser');return []

    def browser_absent(self,identity_):
        identity(identity_);return self._get('/browsers/'+quote(identity_,safe='')) is None

    def delete_connection(self,identity_):
        identity(identity_);self._request('DELETE','/auth/connections/'+quote(identity_,safe=''))

    def delete_profile(self,identity_):
        identity(identity_);self._request('DELETE','/profiles/'+quote(identity_,safe=''))
