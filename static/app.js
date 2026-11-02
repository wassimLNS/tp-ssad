'use strict';
const $ = s => document.querySelector(s);
let state, selected='alice', kind=0, activeJob=null, polling=false, lastTrace=null;
let dictionaryKey='';
const descriptions=[['3 caractères · alphabet {0, 1}','Dictionnaire exhaustif des 8 mots binaires possibles.',3,8],['4 caractères · alphabet {1, 2, 3, 4}','Dictionnaire exhaustif des 256 mots numériques possibles.',4,256],['Caractères ASCII : a–z, A–Z, 0–9 et ponctuation','Force brute exhaustive ; candidats générés à la demande.',2,8836]];
const names={alice:'Alice',bob:'Bob',charlie:'Charlie'};
const defaults={2:[[3,3],[2,5]],3:[[6,24,1],[13,16,10],[20,17,15]],4:[[1,2,3,4],[0,1,2,3],[0,0,1,2],[0,0,0,1]]};
function el(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;}
let toastTimer;
function toast(text){$('#toast').textContent=text;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').textContent='',5000);}
async function api(path,data,method){const r=await fetch(path,{method:method||(data?'POST':'GET'),headers:data?{'Content-Type':'application/json'}:{},body:data?JSON.stringify(data):undefined});const v=await r.json();if(!r.ok)throw Error(v.error||'Le serveur ne peut pas traiter cette demande.');return v;}
function safe(fn){return async e=>{try{await fn(e);}catch(err){toast(err.message);}};}
function account(){return state.users.find(u=>u.name===selected);}
function setupAttackPanel(){
  const row=el('div','protection-row speed-protection-row'),text=el('div'),toggle=el('input');
  text.append(el('strong','','Détection de cadence inhumaine'),el('small','','Blocage · 3 tentatives en moins de 500 ms'));
  toggle.type='checkbox';toggle.id='speed-protection';toggle.setAttribute('role','switch');toggle.setAttribute('aria-label','Activer la détection de cadence inhumaine');row.append(text,toggle);
  $('.protection-row').after(row);
  toggle.onchange=safe(async()=>{await api('/api/protection',{user:selected,setting:'speed_protection',enabled:toggle.checked});await load();});
  const workspace=el('div','attack-workspace'),terminal=$('.terminal'),dictionary=el('aside','dictionary-panel');dictionary.id='dictionary-panel';dictionary.setAttribute('aria-label','Dictionnaire des candidats');
  const title=el('strong','','Dictionnaire'),count=el('small');count.id='dictionary-count';const list=el('div','dictionary-list');list.id='dictionary-list';list.tabIndex=0;list.setAttribute('aria-label','Liste complète des candidats');const hint=el('p');hint.id='dictionary-hint';
  dictionary.append(title,count,list,hint);terminal.before(workspace);workspace.append(terminal,dictionary);
  const progress=el('p','field-help');progress.id='resume-info';$('#run-attack').before(progress);
}
function renderDictionary(cursor){
  $('#dictionary-panel').hidden=kind===2;$('.attack-workspace').classList.toggle('no-dictionary',kind===2);
  if(kind===2)return;
  const key=`${selected}:${kind}:${cursor}`;if(dictionaryKey===key)return;dictionaryKey=key;
  const alphabet=kind===0?'01':'1234',length=kind===0?3:4,total=alphabet.length**length;
  const items=Array.from({length:total},(_,i)=>{let n=i,s='';for(let j=0;j<length;j++){s=alphabet[n%alphabet.length]+s;n=Math.floor(n/alphabet.length);}const item=el('span',i<cursor?'tried':i===cursor?'next':'',s);if(i===cursor)item.setAttribute('aria-label',`Prochain candidat : ${s}`);return item;});
  $('#dictionary-count').textContent=`${total} candidats · ordre d’essai`;
  $('#dictionary-list').replaceChildren(...items);$('#dictionary-hint').textContent=cursor<total?`Suivant : ${items[cursor].textContent}`:'Dictionnaire épuisé.';
}
async function load(){state=await api('/api/state');renderAccount();renderCredentials();syncPasswordEditor();return state;}
function renderAccount(){
  const u=account();$('#users').replaceChildren();
  for(const name of Object.keys(names)){const b=el('button','user-button'+(name===selected?' selected':''));b.type='button';b.setAttribute('aria-pressed',name===selected);b.append(el('span','avatar',names[name][0]),document.createTextNode(names[name]));b.disabled=!!activeJob;b.onclick=()=>{selected=name;$('#user').value=name;$('#password').value='';renderAccount();};$('#users').append(b);}
  $('#protection').checked=!!u.protection;$('#protection').disabled=!!activeJob;
  $('#speed-protection').checked=!!u.speed_protection;$('#speed-protection').disabled=!!activeJob;
  $('#failure-label').textContent=`${u.failures} / 9`;
  $('#attempt-dots').replaceChildren(...Array.from({length:9},(_,i)=>el('i',i<u.failures?'used':'')));
  const wait=Math.ceil(u.remaining);
  $('#account-state').textContent=u.blocked?`Compte bloqué. ${u.block_reason||'9 échecs de connexion.'} Débloquez-le pour continuer.`:wait>0?`Pause de sécurité · encore ${wait} s` :u.protection?`Protection active · ${3-u.failures%3} tentative(s) avant le prochain palier.`:'Rate limiting désactivé.';
  $('#account-state').classList.toggle('blocked-reason',!!u.blocked);
  $('#unlock').hidden=!u.blocked;$('#unlock').disabled=!!activeJob;
  $('#login-button').disabled=!!activeJob||!!u.blocked||wait>0;
  $('#run-attack').disabled=!!activeJob||!!u.blocked||wait>0;
  $('#stop-attack').hidden=!activeJob;
  document.querySelectorAll('[data-kind]').forEach(b=>{b.classList.toggle('selected',Number(b.dataset.kind)===kind);b.setAttribute('aria-pressed',Number(b.dataset.kind)===kind);b.disabled=!!activeJob;});
  const d=descriptions[kind];$('#type-info').textContent=d[0];$('#attack-description').textContent=d[1];
  const length=kind===2?u.length:d[2];
  $('.metrics > div:first-child').hidden=kind===2;$('.metrics').classList.toggle('extended',kind===2);
  $('#space').textContent=kind===2?'':d[3].toLocaleString('fr-FR');$('#length-info').textContent=`Longueur connue : ${length}`;$('#method').textContent=kind===2?'Force brute':'Dictionnaire';
  $('#length-info').hidden=kind===2;
  const cursor=u.progress?.[String(kind)]||0;
  $('#run-attack').textContent=`▷ ${cursor?'Reprendre':'Lancer'} l’attaque par ${kind===2?'force brute':'dictionnaire'}`;
  $('#resume-info').textContent=cursor?`${cursor.toLocaleString('fr-FR')} candidat(s) déjà testés · reprise au candidat suivant.`:'La recherche commence au premier candidat.';
  renderDictionary(cursor);
  $('#logout').hidden=!state.current;
}
function view(which){
  if(which!=='auth'&&!state.current){toast('Connectez-vous pour accéder à cet espace.');return;}
  $('#auth-view').hidden=which!=='auth';$('#messages-view').hidden=which!=='messages';$('#nav-auth').classList.toggle('active',which==='auth');$('#nav-msg').classList.toggle('active',which==='messages');
  $('#integrity-view').hidden=which!=='integrity';$('#nav-integrity').classList.toggle('active',which==='integrity');
  $('#breadcrumb').textContent=`ESPACE D’EXPÉRIMENTATION / ${which==='auth'?'AUTHENTIFICATION':which==='integrity'?'INTÉGRITÉ':'MESSAGERIE'}`;
  if(which==='integrity')openIntegrity();
  if(which==='messages'){$('#session-label').textContent=`Connecté en tant que ${names[state.current]}. Choisissez un destinataire et explorez les trois algorithmes.`;const previous=$('#recipient').value;$('#recipient').replaceChildren(...Object.keys(names).filter(n=>n!==state.current).map(n=>{const o=el('option','',names[n]);o.value=n;return o;}));if(previous!==state.current&&names[previous])$('#recipient').value=previous;refreshMessages().catch(e=>toast(e.message));}
}
function renderCredentials(){
  $('#credentials').replaceChildren();for(const [name,passes]of Object.entries(state.credentials)){const d=el('div','credential');d.append(el('strong','',names[name]),el('br'));['Binaire','Numérique','Étendu'].forEach((label,i)=>{d.append(document.createTextNode(`${label} : `),el('code','',passes[i]),el('br'));});$('#credentials').append(d);}
}
function renderMatrix(n){
  const box=$('#matrix');box.style.gridTemplateColumns=`repeat(${n},1fr)`;box.replaceChildren();defaults[n].forEach((r,i)=>r.forEach((v,j)=>{const input=el('input');input.type='number';input.step='1';input.min='-10000';input.max='10000';input.required=true;input.value=v;input.setAttribute('aria-label',`Clé, ligne ${i+1}, colonne ${j+1}`);box.append(input);}));
}
function cipherParams(){
  const algo=$('#algorithm').value,box=$('#cipher-params');box.replaceChildren();
  if(algo==='caesar'){
    const row=el('div','params-row');const a=el('div'),b=el('div');const l1=el('label','','Décalage');l1.htmlFor='shift';const input=el('input');input.id='shift';input.type='number';input.min=0;input.max=25;input.value=3;input.required=true;a.append(l1,input);
    const l2=el('label','','Direction');l2.htmlFor='direction';const select=el('select');select.id='direction';for(const[v,t]of [['right','Droite (+)'],['left','Gauche (−)']]){const o=el('option','',t);o.value=v;select.append(o);}b.append(l2,select);row.append(a,b);box.append(row);
    $('#cipher-warning').textContent='Faiblesse : seulement 26 décalages possibles. Les fréquences des lettres restent visibles.';
  }else if(algo==='playfair'){
    const l=el('label','','Clé Playfair');l.htmlFor='key';const i=el('input');i.id='key';i.value='MONARCHY';i.required=true;i.maxLength=100;box.append(l,i);$('#cipher-warning').textContent='Faiblesse : les fréquences des paires et les textes connus facilitent la cryptanalyse. I/J sont fusionnés.';
  }else{
    const l=el('label','','Dimension de la matrice');l.htmlFor='dimension';const s=el('select');s.id='dimension';for(const n of [2,3,4]){const o=el('option','',`${n} × ${n}`);o.value=n;s.append(o);}const m=el('div','matrix');m.id='matrix';const reset=el('button','text-button','Rétablir la matrice par défaut');reset.type='button';reset.style.marginTop='10px';reset.onclick=()=>renderMatrix(Number(s.value));s.onchange=()=>renderMatrix(Number(s.value));box.append(l,s,m,reset);renderMatrix(2);$('#cipher-warning').textContent='Faiblesse : la transformation est linéaire et vulnérable aux textes connus. La matrice doit être inversible modulo 26.';
  }
  highlightWeakness();
}
function params(){
  switch($('#algorithm').value){case 'caesar':return{shift:Number($('#shift').value),direction:$('#direction').value};case 'playfair':return{key:$('#key').value};default:const n=Number($('#dimension').value),v=[...$('#matrix').children].map(i=>Number(i.value));return{matrix:Array.from({length:n},(_,i)=>v.slice(i*n,(i+1)*n))};}
}
function matrixView(matrix,label){
  const card=el('div','matrix-explanation');card.append(el('strong','',label));
  const grid=el('div','matrix-display');grid.style.gridTemplateColumns=`repeat(${matrix.length},minmax(28px,1fr))`;
  matrix.flat().forEach(value=>grid.append(el('span','',String(value))));card.append(grid);return card;
}
function trace(t,title){
  lastTrace=t;$('#trace-title').textContent=title;const box=$('#trace-content');box.replaceChildren();box.append(el('p','',t.rule));
  box.append(el('p','',`Texte normalisé : ${t.normalized}`));if(t.prepared)box.append(el('p','',`Texte préparé : ${t.prepared}`));
  if(t.grid){const g=el('div','trace-grid');t.grid.flat().forEach(c=>g.append(el('span','',c)));box.append(g);}
  if(t.key_matrix){
    const matrices=el('div','hill-matrices');matrices.append(matrixView(t.key_matrix,'Matrice clé K · chiffrement'),matrixView(t.inverse,'Matrice inverse K⁻¹ · déchiffrement'));box.append(matrices);
    box.append(el('p','hill-operation',t.operation==='decrypt'?'Pour ce déchiffrement, on utilise K⁻¹ : P = K⁻¹ × C mod 26.':'Pour ce chiffrement, on utilise K : C = K × P mod 26.'));
    if(t.inverse_calculation){const calc=t.inverse_calculation,explanation=el('section','inverse-explanation');explanation.append(el('strong','','Comment obtient-on K⁻¹ ?'));const list=el('ol');calc.steps.forEach(step=>list.append(el('li','',step)));explanation.append(list,matrixView(calc.adjugate,'Adjointe adj(K) · cofacteurs transposés'));box.append(explanation);}
  }
  box.append(el('div','trace-result',t.result));const list=el('ol');t.steps.forEach(s=>list.append(el('li','',s)));box.append(list);$('#trace-panel').scrollIntoView({behavior:'smooth',block:'nearest'});
}
async function refreshMessages(){
  const data=await api('/api/messages'),box=$('#message-list');box.replaceChildren();
  if(!data.messages.length){box.append(el('div','empty','Aucun message pour le moment.\nEnvoyez le premier message chiffré.'));return;}
  for(const m of data.messages){const sent=m.sender===state.current;const d=el('article','message-item'),meta=el('div','meta');meta.append(el('strong','',`${names[m.sender]} → ${names[m.recipient]}`),el('span','',m.algorithm.toUpperCase()));d.append(meta,el('div','cipher',m.ciphertext),el('p','field-help',new Date(m.created*1000).toLocaleString('fr-FR')));
    if(!sent){const b=el('button','secondary','Déchiffrer et expliquer ↗');b.onclick=safe(async()=>{const data=await api(`/api/messages/${m.id}/decrypt`,{});trace(data.trace,`Déchiffrement · ${m.algorithm.toUpperCase()}`);});d.append(b);}else d.append(el('small','muted','Envoyé · le destinataire peut déchiffrer'));
    const details=el('details','field-help'),summary=el('summary','','Paramètres du message');details.append(summary,el('p','',JSON.stringify(JSON.parse(m.params))));d.append(details);box.append(d);
  }
}
document.querySelectorAll('[data-kind]').forEach(b=>b.onclick=()=>{kind=Number(b.dataset.kind);$('#password').value='';renderAccount();});
$('#reveal').onclick=()=>{const p=$('#password');p.type=p.type==='password'?'text':'password';$('#reveal').setAttribute('aria-label',p.type==='password'?'Afficher le mot de passe':'Masquer le mot de passe');};
$('#protection').onchange=safe(async()=>{await api('/api/protection',{user:selected,enabled:$('#protection').checked});await load();});
$('#unlock').onclick=safe(async()=>{await api('/api/unlock',{user:selected});await load();toast('Compte débloqué. Le compteur est remis à zéro.');});
$('#login-form').onsubmit=safe(async e=>{e.preventDefault();const r=await api('/api/login',{user:selected,kind,password:$('#password').value});await load();if(r.state==='success'){$('#password').value='';view('messages');toast(`Bienvenue, ${names[state.current]}.`);}else toast(r.state==='blocked'?`Compte bloqué. ${r.account.block_reason}`:r.state==='cooldown'?'Trois échecs : pause de 10 secondes.':'Mot de passe incorrect.');});
$('#run-attack').onclick=safe(async()=>{
  const r=await api('/api/attack',{user:selected,kind});activeJob=r.id;$('#attack-badge').textContent='EN COURS';renderAccount();
});
$('#stop-attack').onclick=safe(async()=>{if(activeJob)await api(`/api/attack/${activeJob}`,null,'DELETE');});
async function poll(){
  if(polling)return;polling=true;
  try{
    if(activeJob){const j=await api(`/api/attack/${activeJob}`);const stateLabels={running:'En cours',success:'Mot de passe trouvé',cooldown:'Pause de sécurité · 10 s',blocked:'Compte bloqué',cancelled:'Attaque arrêtée',exhausted:'Recherche terminée',error:'Erreur serveur'};
      $('#attack-badge').textContent=stateLabels[j.state].toUpperCase();
      $('#attack-log').textContent=`> Cible locale : ${names[j.user]}\n> ${stateLabels[j.state]}\n> Reprise à la position : ${(j.start_index+1).toLocaleString('fr-FR')}\n> Tentatives de cette exécution : ${j.attempts.toLocaleString('fr-FR')}\n> Dernier candidat : ${j.candidate||'—'}${j.elapsed?`\n> Durée : ${(j.elapsed*1000).toFixed(2)} ms · ${Math.round(j.attempts/Math.max(j.elapsed,.000001)).toLocaleString('fr-FR')} essais/s`:''}${j.found?`\n> Mot de passe trouvé : ${j.found}\n> Connexion automatique…`:''}`;
      if(j.state==='success'){
        await api(`/api/attack/${activeJob}/connect`,{});activeJob=null;await load();$('#password').value='';view('messages');toast(`Mot de passe trouvé : ${j.found}. Connexion automatique à ${names[j.user]}.`);return;
      }
      if(j.state!=='running')activeJob=null;
    }
    await load();
    if(account().blocked&&account().block_reason&&!$('#attack-log').textContent.includes(account().block_reason))$('#attack-log').textContent+=`\n> Motif : ${account().block_reason}`;
  }catch(e){toast(e.message);}finally{polling=false;}
}
$('#nav-auth').onclick=()=>view('auth');$('#nav-msg').onclick=()=>view('messages');
$('#logout').onclick=safe(async()=>{await api('/api/logout',{});await load();lastTrace=null;clearIntegrity();$('#message-text').value='';$('#algorithm').value='caesar';cipherParams();$('#trace-title').textContent='L’algorithme, étape par étape';$('#trace-content').textContent='Envoyez ou déchiffrez un message pour explorer sa transformation.';$('#message-list').replaceChildren();view('auth');});
$('#algorithm').onchange=cipherParams;
$('#refresh').onclick=safe(refreshMessages);
$('#message-form').onsubmit=safe(async e=>{e.preventDefault();$('#send').disabled=true;try{const r=await api('/api/messages',{recipient:$('#recipient').value,algorithm:$('#algorithm').value,params:params(),text:$('#message-text').value});trace(r.trace,`Chiffrement · ${$('#algorithm').value.toUpperCase()}`);await refreshMessages();toast('Message chiffré et envoyé.');}finally{$('#send').disabled=false;}});
setupAttackPanel();
setupIntegrityPanel();
setupDemoControls();
safe(async()=>{await load();renderCredentials();cipherParams();view(state.current?'messages':'auth');setInterval(poll,600);setInterval(()=>{if(state.current&&!$('#messages-view').hidden)refreshMessages().catch(()=>{});},5000);})();
