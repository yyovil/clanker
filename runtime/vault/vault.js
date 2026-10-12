'use strict';
const el = id => document.getElementById(id);
let csrf = '';
let invitationState = {members:[],credentials:[],invitations:[]};
let vaultItems = [];
let vaultView = 'owned';
let vaultFilter = 'all';
let vaultQuery = '';
let credentialDetail = null;
let loading = false;
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('r') && fragment.has('token')) {
  sessionStorage.setItem('clanker-request',JSON.stringify({id:fragment.get('r'),token:fragment.get('token')}));
  history.replaceState(null,'',location.pathname);
}
let access=null;
try{access=JSON.parse(sessionStorage.getItem('clanker-request') || 'null');}catch{sessionStorage.removeItem('clanker-request');}
async function api(path,data) {
  const controller=['/api/items','/api/invitations'].includes(path)?new AbortController():null;
  const timer=controller?setTimeout(()=>controller.abort(),20000):null;
  try{
    const response = await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(data),...(controller?{signal:controller.signal}:{})});
    const result = await response.json();
    if (!response.ok) { const error = new Error(result.error || 'Please try again.');error.status=response.status;throw error; }
    return result;
  }catch(error){
    if(error.name==='AbortError')throw new Error('The connection timed out. Try again to load your accounts.');
    throw error;
  }finally{if(timer!==null)clearTimeout(timer);}
}
function fail(error) {el('error').textContent=error.message;el('error').hidden=false;}
const requestReturn=document.createElement('p');
requestReturn.id='request-return';requestReturn.hidden=true;
const slackReturn=document.createElement('a');
slackReturn.textContent='Return to Slack';slackReturn.setAttribute('href','slack://open');slackReturn.className='dashboard-secondary';
requestReturn.append(slackReturn);document.querySelector('main').append(requestReturn);
function kernelCollection(result, replace=false) {
  if(!result||!['kernel','kernel_managed_auth'].includes(result.provider)||typeof result.collection_url!=='string')throw new Error('The secure form is unavailable. Please reopen your access link.');
  let url;
  try{url=new URL(result.collection_url);}catch{throw new Error('The secure form is unavailable. Please reopen your access link.');}
  const authHosts=['auth.kernel.com','auth.kernel.sh','auth.onkernel.com','managed-auth.onkernel.com'];
  const allowed=result.provider==='kernel_managed_auth'
    ?authHosts.includes(url.hostname)&&url.pathname.startsWith('/login/')&&url.pathname.length>7&&!url.hash
    :url.hostname==='vault.kernel.sh';
  if(url.protocol!=='https:'||!allowed||url.port||url.username||url.password)
    throw new Error('The secure form could not be verified. Please reopen your access link.');
  if(replace)location.replace(url.href);else location.assign(url.href);
}
el('signin').onclick=async()=>{
  try{
    el('signin').disabled=true;
    const result=await api('/auth/start',location.pathname==='/vault'?{}:access);
    location.assign(result.url);
  }catch(error){fail(error);el('signin').disabled=false;}
};
el('close-invite').onclick=()=>el('invite-dialog').close();
el('invite-vault').onclick=()=>openInvitations();
el('invite-member').onchange=()=>{el('invite-consent').checked=false;renderCredentialSelection();};
function selectedCredentials(){return [...el('credential-selection').querySelectorAll('input:checked')].map(input=>input.value);}
function updateInviteSelection(){
  const selected=selectedCredentials();
  el('send-invite').disabled=!el('invite-member').value||!selected.length;
}
function renderCredentialSelection(){
  const recipient=el('invite-member').value;
  const active=invitationState.invitations.filter(invitation=>invitation.recipient===recipient&&invitation.revoked==null);
  const handles=new Set(active.map(invitation=>invitation.handle));
  el('invite-title').textContent=active.length?'Manage access':'Share access';
  el('send-invite').textContent=active.length?'Save access':'Invite';
  el('credential-selection').replaceChildren();
  for(const item of invitationState.credentials){
    const label=document.createElement('label');label.className='credential-option';
    const input=document.createElement('input');input.type='checkbox';input.value=item.id;input.checked=handles.has(item.id);input.disabled=!recipient;
    input.onchange=()=>{el('invite-consent').checked=false;updateInviteSelection();};
    const text=document.createElement('span'),title=document.createElement('strong'),detail=document.createElement('small');
    title.textContent=item.label;
    const kind=item.kind==='api_key'?'API key':'Login';
    detail.textContent=[kind,item.origin,item.identifier].filter(Boolean).join(' · ');
    text.append(title,detail);label.append(input,text);el('credential-selection').append(label);
  }
  if(!invitationState.credentials.length){const empty=document.createElement('p');empty.className='hint';empty.textContent='Connect an account through Clanker before sharing access.';el('credential-selection').append(empty);}
  updateInviteSelection();
}
async function removeMemberAccess(recipient,name){
  if(!confirm('Remove '+name+'’s access to these accounts? Any affected private browser sessions will be closed.'))return;
  try{const result=await api('/api/invite',{recipient,handles:[]});await refreshInvitations();
    el('vault-message').textContent=result.cleanup_pending?'Access removed. Browser cleanup is pending; further browser tasks for this member are blocked.':'Access removed.';el('vault-message').hidden=false;
  }catch(error){fail(error);}
}
async function refreshInvitations(){
  const result=await api('/api/invitations',{handle:null});csrf=result.csrf;invitationState=result;
  const selectedMember=el('invite-member').value;
  el('invite-member').replaceChildren(new Option('Choose a member',''));
  const names=new Map(result.members.map(member=>[member.id,member.name]));
  for(const member of result.members){
    const duplicate=result.members.filter(other=>other.name===member.name).length>1;
    const option=new Option(member.name+(duplicate?' · '+member.id.slice(-6):''),member.id);
    el('invite-member').append(option);
  }
  el('invite-member').value=selectedMember;
  el('invite-vault').disabled=!result.credentials.length||!result.members.length;
  renderCredentialSelection();
  renderInvitationList();
  renderDashboard();
}
function renderInvitationList(){
  const result=invitationState;
  const names=new Map(result.members.map(member=>[member.id,member.name]));
  el('invitation-list').replaceChildren();
  if(!result.invitations.length){const empty=document.createElement('p');empty.className='hint';empty.textContent='No accounts are shared with other members.';el('invitation-list').append(empty);}
  const groups=new Map();
  for(const invitation of result.invitations){if(!groups.has(invitation.recipient))groups.set(invitation.recipient,[]);groups.get(invitation.recipient).push(invitation);}
  for(const [recipient,invitations] of groups){
    const row=document.createElement('div');row.className='invitation-row';
    const name=names.get(recipient)||'Slack member '+recipient;
    const active=invitations.filter(invitation=>invitation.revoked==null),pending=invitations.find(invitation=>invitation.cleanup_pending);
    if(!active.length&&!pending)continue;
    const label=document.createElement('span'),title=document.createElement('strong'),detail=document.createElement('small');
    title.textContent=name;detail.textContent=active.length?active.length+' '+(active.length===1?'credential':'credentials')+' · '+active.map(invitation=>invitation.credential).join(', '):'Access removed';
    label.append(title,detail);
    if(pending){const warning=document.createElement('small');warning.textContent='Browser cleanup pending';label.append(warning);}
    const actions=document.createElement('div');actions.className='sharing-actions';
    if(active.length&&names.has(recipient)){const edit=document.createElement('button');edit.type='button';edit.textContent='Edit access';edit.onclick=()=>openInvitations(recipient);actions.append(edit);}
    if(active.length){const remove=document.createElement('button');remove.type='button';remove.textContent='Remove';remove.onclick=()=>removeMemberAccess(recipient,name);actions.append(remove);}
    if(pending){const retry=document.createElement('button');retry.type='button';retry.textContent='Retry cleanup';retry.onclick=async()=>{
      retry.disabled=true;try{const status=await api('/api/invite/revoke',{id:pending.id});await refreshInvitations();el('vault-message').textContent=status.cleanup_pending?'Browser cleanup is still pending. Further browser tasks for this member remain blocked.':'Browser cleanup complete.';el('vault-message').hidden=false;}catch(error){fail(error);retry.disabled=false;}
    };actions.append(retry);}
    row.append(make('span','vault-avatar',initials(name)),label,actions);el('invitation-list').append(row);
  }
}
async function openInvitations(recipient=''){
  el('invite-form').reset();el('invite-error').hidden=true;el('send-invite').disabled=true;
  el('invite-member').value=recipient;renderCredentialSelection();
  el('invite-dialog').showModal();
  try{await refreshInvitations();}catch(error){el('invite-error').textContent=error.message;el('invite-error').hidden=false;el('send-invite').disabled=true;}
}
el('invite-form').onsubmit=async event=>{
  event.preventDefault();const recipient=el('invite-member').value,handles=selectedCredentials();if(!recipient||!handles.length||!el('invite-consent').checked)return;
  el('send-invite').disabled=true;el('invite-error').hidden=true;
  try{const result=await api('/api/invite',{handles,recipient});await refreshInvitations();el('invite-dialog').close();
    const message=[result.cleanup_pending?'Access updated. Browser cleanup is pending; further browser tasks for this member are blocked.':'Access saved. This member can use the selected credentials.'];
    if(result.notification==='sent')message.push('They have been notified in Slack.');
    if(result.notification==='failed')message.push('The Slack notification could not be confirmed. Let this member know directly.');
    el('vault-message').textContent=message.join(' ');el('vault-message').hidden=false;
  }catch(error){el('invite-error').textContent=error.message;el('invite-error').hidden=false;updateInviteSelection();}
};
let personalState={};
let openingPersonal=false;
const personalLabels={name:'name',dob:'date of birth',gender:'gender',email:'primary email',phone:'primary phone',address:'primary address'};
function renderPersonalInfo(info){
  personalState=info||{};el('personal-list').replaceChildren();
  for(const button of el('personal-add').querySelectorAll('[data-add-personal]'))button.hidden=!Object.hasOwn(personalState,button.dataset.addPersonal);
  const saved=Object.entries(personalState).filter(([,item])=>item.saved);
  if(!saved.length){const empty=document.createElement('p');empty.className='hint';empty.textContent='No personal info saved in Kernel';el('personal-list').append(empty);}
  for(const [kind,item] of saved){
    const row=document.createElement('article');row.className='personal-row';
    const text=document.createElement('div'),label=document.createElement('strong'),detail=document.createElement('small');
    label.textContent=item.label;detail.textContent=item.display||item.summary||'';text.append(label,detail);
    const edit=document.createElement('button');edit.type='button';edit.textContent='Edit in Kernel';edit.setAttribute('aria-label','Edit '+personalLabels[kind]+' in Kernel');edit.onclick=()=>openPersonal(kind);
    row.append(text,edit);el('personal-list').append(row);
  }
}
async function openPersonal(kind){
  if(openingPersonal||!Object.hasOwn(personalLabels,kind))return;
  openingPersonal=true;el('personal-add').open=false;el('error').hidden=true;
  try{kernelCollection(await api('/api/personal/details',{kind}));}
  catch(error){fail(error);}finally{openingPersonal=false;}
}
for(const button of document.querySelectorAll('[data-add-personal]'))button.onclick=()=>openPersonal(button.dataset.addPersonal);
function make(tag,className='',text=''){
  const node=document.createElement(tag);node.className=className;node.textContent=text;return node;
}
function initials(name){return String(name||'').trim().split(/\s+/).slice(0,2).map(word=>word[0]||'').join('').toUpperCase();}
function vaultIcon(name){
  const paths={search:['M21 21l-4.4-4.4','M19 11a8 8 0 1 1-16 0 8 8 0 0 1 16 0'],login:['M7 11V7a5 5 0 0 1 10 0v4','M5 11h14v10H5z','M12 15v2'],api_key:['M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0','M10 11v10','M10 17h4','M10 21h4'],invite:['M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0','M3 21v-2a6 6 0 0 1 12 0v2','M20 11v6','M17 14h6']};
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  for(const [key,value] of Object.entries({viewBox:'0 0 24 24',fill:'none',stroke:'currentColor','stroke-width':'1.6','stroke-linecap':'round','stroke-linejoin':'round','aria-hidden':'true'}))svg.setAttribute(key,value);
  for(const d of paths[name]||paths.login){const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d',d);svg.append(path);}
  return svg;
}
function credentialKind(item){return item.kind==='api_key'?'API key':'Login';}
function sharedBy(item){return invitationState.members.find(member=>member.id===item.shared_by)?.name||item.shared_by||'another Slack member';}
function credentialAccess(item){
  if(item.access==='invited')return 'From '+sharedBy(item);
  const recipients=new Set(invitationState.invitations.filter(grant=>grant.handle===item.id&&grant.revoked==null).map(grant=>grant.recipient));
  return recipients.size?'Shared with '+recipients.size:'Only you';
}
function renderVaultItems(items){vaultItems=items;renderDashboard();}
function renderDashboard(){
  const owned=vaultItems.filter(item=>item.access!=='invited'),shared=vaultItems.filter(item=>item.access==='invited');
  const people=new Set(invitationState.invitations.filter(grant=>grant.revoked==null).map(grant=>grant.recipient));
  el('count-owned').textContent=owned.length;el('count-shared').textContent=shared.length;el('count-people').textContent=people.size;
  el('vault-actions').hidden=!owned.length;
  for(const tab of el('vault-tabs').querySelectorAll('[data-view]')){const active=tab.dataset.view===vaultView;tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;}
  el('vault-credentials').hidden=vaultView==='people';el('vault-sharing').hidden=vaultView!=='people';el('personal-info').hidden=vaultView!=='owned';
  el('vault-credentials').setAttribute('aria-labelledby',vaultView==='shared'?'tab-shared':'tab-owned');
  if(vaultView==='people')return;
  const list=vaultView==='shared'?shared:owned;
  for(const button of el('vault-filters').querySelectorAll('[data-filter]')){
    const kind=button.dataset.filter;el('filter-'+kind).textContent=kind==='all'?list.length:list.filter(item=>item.kind===kind).length;
    button.setAttribute('aria-pressed',String(kind===vaultFilter));
  }
  el('clear-search').hidden=!vaultQuery;el('vault-toolbar').hidden=!list.length;el('credential-table').hidden=!list.length;el('vault-empty').hidden=Boolean(list.length);
  el('empty-title').textContent=vaultView==='shared'?'Nothing shared with you yet':'No connected accounts yet';
  el('empty-description').textContent=vaultView==='shared'?'Credentials shared with you by another Slack member will appear here.':'Ask Clanker in Slack to connect an account. Enter its details securely in Kernel.';
  el('open-clanker').hidden=vaultView==='shared';el('access-column').textContent=vaultView==='shared'?'Shared by':'Access';
  const query=vaultQuery.trim().toLowerCase();
  const filtered=list.filter(item=>(vaultFilter==='all'||item.kind===vaultFilter)&&[item.label,item.identifier,item.origin,credentialKind(item),item.access==='invited'?sharedBy(item):''].join(' ').toLowerCase().includes(query));
  el('items').replaceChildren();
  for(const item of filtered){
    const row=make('article','credential-row');
    const credential=make('div','credential-name'),badge=make('span','credential-badge',initials(item.label));
    const name=make('div','credential-name-text'),kind=make('small','credential-kind');kind.append(vaultIcon(item.kind),document.createTextNode(credentialKind(item)));
    name.append(make('strong','',item.label),kind);credential.append(badge,name);
    const account=make('div','credential-account');account.append(make('span','',item.identifier||(item.kind==='api_key'?'API key':'Saved login')));
    const origin=make('small','credential-origin',item.origin||'');account.append(origin);
    const access=make('span','credential-access',credentialAccess(item));
    const details=make('button','vault-icon-button','•••');details.type='button';details.setAttribute('aria-label','Details for '+item.label);details.onclick=()=>openCredential(item);
    row.append(credential,account,access,details);el('items').append(row);
  }
  if(list.length&&!filtered.length){const empty=make('div','search-empty');empty.append(make('p','','No credentials match this search.'));const reset=make('button','dashboard-secondary','Clear filters');reset.type='button';reset.onclick=resetFilters;empty.append(reset);el('items').append(empty);}
  el('credential-count').textContent=filtered.length+' '+(filtered.length===1?'credential':'credentials');
}
function resetFilters(){vaultFilter='all';vaultQuery='';el('credential-search').value='';renderDashboard();}
function selectVaultView(view){vaultView=view;resetFilters();el('vault-message').hidden=true;}
for(const tab of el('vault-tabs').querySelectorAll('[data-view]')){
  tab.onclick=()=>selectVaultView(tab.dataset.view);
  tab.onkeydown=event=>{
    const tabs=[...el('vault-tabs').querySelectorAll('[data-view]')],index=tabs.indexOf(tab);
    let next;if(event.key==='ArrowRight')next=(index+1)%tabs.length;else if(event.key==='ArrowLeft')next=(index+tabs.length-1)%tabs.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=tabs.length-1;else return;
    event.preventDefault();selectVaultView(tabs[next].dataset.view);tabs[next].focus();
  };
}
for(const button of el('vault-filters').querySelectorAll('[data-filter]'))button.onclick=()=>{vaultFilter=button.dataset.filter;renderDashboard();};
el('credential-search').oninput=()=>{vaultQuery=el('credential-search').value;renderDashboard();};
el('clear-search').onclick=()=>{vaultQuery='';el('credential-search').value='';renderDashboard();el('credential-search').focus();};
el('close-credential').onclick=()=>el('credential-dialog').close();
el('credential-dialog').addEventListener('close',()=>{credentialDetail=null;el('credential-details').replaceChildren();el('credential-title').textContent='';el('credential-error').hidden=true;});
function openCredential(item){
  credentialDetail=item;el('credential-title').textContent=item.label;el('credential-error').hidden=true;el('credential-details').replaceChildren();
  const fields=[['Type',credentialKind(item)],['Account',item.identifier||''],['Website',item.origin||''],['Access',credentialAccess(item)],['Verification',item.login_method==='sms'?'Fresh SMS code for each sign-in':item.has_otp?'Authenticator connected':'']];
  for(const [label,value] of fields)if(value)el('credential-details').append(make('dt','',label),make('dd','',value));
  el('disconnect-credential').hidden=item.access==='invited';el('disconnect-credential').disabled=false;
  el('credential-description').textContent=item.access==='invited'?'This credential is shared with you. Its owner manages access.' : 'This credential is stored in Kernel Vault and used by Clanker for authorized tasks. Manage sharing from People with access.';
  if(item.authenticator_setup&&item.access!=='invited'){
    const button=make('button','dashboard-secondary','Connect authenticator');button.type='button';
    button.onclick=()=>openAuthenticator(item,button);el('credential-details').append(button);
  }
  el('credential-dialog').showModal();
}
async function openAuthenticator(item,button){
  button.disabled=true;el('credential-error').hidden=true;
  try{
    const status=await api('/api/authenticator/status',{handle:item.id});
    if(credentialDetail!==item)return;
    const box=make('div','authenticator-setup');
    box.append(make('p','hint',status.has_totp?'An authenticator is already connected. Save a replacement only if you changed its setup key.':'Connect the existing authenticator setup key so Clanker can generate future sign-in codes.'));
    box.append(make('p','hint','Use the setup key saved in your authenticator or password manager, not a six-digit code. This private form sends it to Kernel; it is never sent to the agent or saved on this server.'));
    const label=make('label','','Authenticator setup key'),input=make('input','');
    input.type='password';input.autocomplete='off';input.spellcheck=false;input.setAttribute('aria-label','Authenticator setup key');
    label.append(input);box.append(label);
    const consentLabel=make('label',''),consent=make('input','');consent.type='checkbox';
    consentLabel.append(consent,document.createTextNode('Allow Clanker to generate sign-in codes for this account.'));box.append(consentLabel);
    const save=make('button','dashboard-primary',status.has_totp?'Replace setup key':'Save setup key');save.type='button';box.append(save);
    save.onclick=async()=>{
      if(!consent.checked||!input.value.trim()){el('credential-error').textContent='Enter the setup key and confirm permission.';el('credential-error').hidden=false;return;}
      save.disabled=true;el('credential-error').hidden=true;
      let value=input.value.trim();input.value='';
      try{
        const pending=api('/api/authenticator/save',{handle:item.id,setup_key:value,consent:true});value='';
        await pending;
        if(credentialDetail===item){box.replaceChildren(make('p','hint','Setup key saved. It will be checked by the website on the next sign-in.'));item.has_otp=true;}
      }catch(error){if(credentialDetail===item){el('credential-error').textContent='Setup could not be confirmed. Check the account status before trying again.';el('credential-error').hidden=false;}}
      finally{value='';save.disabled=false;}
    };
    button.hidden=true;el('credential-details').append(box);
  }catch(error){if(credentialDetail===item){el('credential-error').textContent=error.message;el('credential-error').hidden=false;}button.disabled=false;}
}
el('disconnect-credential').onclick=async()=>{
  const item=credentialDetail;if(!item||item.access==='invited')return;
  const consequence=item.kind==='api_key'?'This removes the API key from Kernel and revokes its invitations.':'This removes the login from Kernel, revokes its invitations and closes its browser sessions.';
  if(!confirm('Disconnect '+item.label+'? '+consequence))return;
  el('disconnect-credential').disabled=true;el('credential-error').hidden=true;
  try{
    await api('/api/disconnect',{handle:item.id});vaultItems=vaultItems.filter(value=>value.id!==item.id);el('credential-dialog').close();renderDashboard();
    el('vault-message').textContent=item.label+' disconnected.';el('vault-message').hidden=false;await refreshInvitations();
  }catch(error){if(el('credential-dialog').open){el('credential-error').textContent=error.message;el('credential-error').hidden=false;}else fail(error);}
  finally{el('disconnect-credential').disabled=false;}
};
function showDashboard(){
  document.body.classList.add('vault-home');
  document.body.insertBefore(el('vault-header'),document.querySelector('main'));el('vault-brand').append(document.querySelector('.brand'));el('vault-header').hidden=false;
  el('request-header').append(el('vault-actions'));el('vault-actions').hidden=false;el('vault-tabs').hidden=false;
  el('search-icon').replaceChildren(vaultIcon('search'));el('empty-icon').replaceChildren(vaultIcon('login'));
  el('invite-vault').replaceChildren(vaultIcon('invite'),document.createTextNode('Manage access'));renderDashboard();
}
async function load(){
  if(loading)return;
  loading=true;el('load-status').hidden=false;el('retry').hidden=true;el('error').hidden=true;el('signin').hidden=true;requestReturn.hidden=true;
  try{
    if(location.pathname==='/vault'){
      if(!document.body.classList.contains('vault-home'))el('description').textContent='Loading your connected accounts…';
      const result=await api('/api/items',{});
      if(result.provider!=='kernel')throw new Error('Kernel Vault is unavailable. Please try again later.');
      csrf=result.csrf;el('title').textContent='Connected accounts';document.title='Connected accounts · clanker';
      el('description').textContent='Credentials are stored in Kernel Vault. Enter sensitive details securely in Kernel.';
      renderPersonalInfo(result.personal_info);renderVaultItems(result.items);showDashboard();el('inventory-note').hidden=false;
      try{await refreshInvitations();}catch(error){fail(error);el('retry').hidden=false;}
      return;
    }
    if(!access)throw new Error('Open the secure access link Clanker sent you in Slack.');
    el('title').textContent='Opening secure form';
    el('description').textContent='Checking your private access link…';
    document.querySelector('footer').textContent='Secure account access · Managed by Clanker';
    const result=await api('/api/request',access);csrf=result.csrf;
    if(result.provider==='kernel_payment'){
      await renderPayment(result);return;
    }
    if(result.provider==='kernel_managed_auth'){
      if(result.auth_status){
        const completed=result.auth_status==='completed';
        el('title').textContent=completed?'Sign-in completed':result.auth_status==='failed'?'Sign-in failed':'Sign-in attempt ended';
        el('description').textContent=completed?'Return to Slack for Clanker’s next update.':result.auth_status==='failed'?'The website sign-in ended without confirming access. Return to Slack and ask Clanker to retry sign-in.':'This sign-in attempt has ended. Return to Slack to check its result or ask Clanker to retry sign-in.';
        requestReturn.hidden=false;return;
      }
      el('title').textContent='Opening secure sign-in';
      el('description').textContent="Sign in to your account on the secure page. Clanker will continue when you're signed in.";
    }else{
      el('description').textContent='Enter your details securely in Kernel Vault.';
    }
    kernelCollection(result,true);
  }catch(error){
    if(error.status===401&&(access||location.pathname==='/vault')){
      if(location.pathname!=='/vault')el('title').textContent='Verify your Slack account';
      el('description').textContent=location.pathname==='/vault'?'Sign in with Slack to manage your connected accounts.':'Use Slack to confirm this private link belongs to you, then continue to the secure form.';
      el('signin').hidden=false;
    }else if(location.pathname!=='/vault'){
      el('title').textContent=error.status===410?'Link no longer available':"The secure link couldn't be opened";
      el('description').textContent=error.status===410?'Return to the Slack conversation and ask Clanker for a new link.':'Try again below. If it still fails, return to the Slack conversation and ask Clanker for a new link.';
      fail(new Error(error.status===410?'This private link has expired or is no longer available.':"Clanker couldn't open this secure link. Your task is still saved."));
      el('retry').hidden=error.status===410||!access;requestReturn.hidden=false;
    }else{
      if(!document.body.classList.contains('vault-home'))el('description').textContent='Your accounts couldn’t be loaded. Try again below.';
      fail(error);el('retry').hidden=false;
    }
  }finally{loading=false;el('load-status').hidden=true;}
}
el('retry').onclick=()=>load();
load();

let paymentTimer=null;
async function renderPayment(result) {
  el('title').textContent=result.merchant+' · Pay ₹'+(result.amount/100).toFixed(2);
  el('description').textContent=result.summary||'Enter your card securely to pay.';
  let panel=document.getElementById('payment-review');
  if(!panel){panel=document.createElement('section');panel.id='payment-review';document.querySelector('main').append(panel);}
  panel.replaceChildren();
  if(result.state==='review'){
    const label=document.createElement('label'),remember=document.createElement('input');
    remember.type='checkbox';label.append(remember,document.createTextNode(' Remember my card and use it when I ask Clanker to pay'));
    const note=document.createElement('p');note.textContent='Enter your card securely. Remembering lets Clanker use it when you ask to proceed with payment.';
    const button=document.createElement('button');button.textContent='Pay ₹'+(result.amount/100).toFixed(2);
    button.onclick=async()=>{button.disabled=true;try{
      await api('/api/payment/approve',{...access,approve:true,remember:remember.checked});
      await pollPayment();
    }catch(error){fail(error);button.disabled=false;}};
    panel.append(label,note,button);return;
  }
  if(result.collection_url){kernelCollection({...result,provider:'kernel'},true);return;}
  const text=document.createElement('p');
  const messages={ready:'Purchase approved. Clanker will continue in Slack.',otp_ready:'Verification received. Clanker will continue in Slack.',filled:'Card filled. Clanker is continuing checkout.',
    submitted_unknown:'Payment submitted. Clanker is checking the merchant confirmation.',
    declined:'The card network declined authorization. This order has not been confirmed.',
    provider_rejected:'Kernel could not authorize this payment. Clanker will report the blocker in Slack.',recovery_required:'The payment outcome needs reconciliation. Clanker will not repeat it.',
    expired:'Payment authorization expired. This order has not been confirmed.'};
  const cards={activating:'Card added. Kernel is still activating it with your card network for this purchase. Clanker continues in Slack when it’s ready.',
    ineligible:'Card added, but Kernel can’t use it for this purchase yet. Clanker will update you in Slack.'};
  text.textContent=cards[result.card]||messages[result.state]||'Preparing your private payment step…';panel.append(text);
  if(['approved','enrollment','card_created','creating_wallet','creating_card','authorizing','approval','creating_otp','otp'].includes(result.state))
    paymentTimer=setTimeout(pollPayment,2000);
  requestReturn.hidden=false;
}
async function pollPayment(){
  clearTimeout(paymentTimer);
  try{const result=await api('/api/request',access);csrf=result.csrf;await renderPayment(result);}
  catch(error){fail(error);requestReturn.hidden=false;}
}
