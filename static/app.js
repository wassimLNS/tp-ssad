'use strict';
const $ = s => document.querySelector(s);
let state, selected='alice', kind=0, activeJob=null, polling=false, lastTrace=null;
let dictionaryKey='';
const descriptions=[['3 caractères · alphabet {0, 1}','Dictionnaire exhaustif des 8 mots binaires possibles.',3,8],['4 caractères · alphabet {1, 2, 3, 4}','Dictionnaire exhaustif des 256 mots numériques possibles.',4,256],['Caractères ASCII : a–z, A–Z, 0–9 et ponctuation','Force brute exhaustive ; candidats générés à la demande.',2,8836]];
const names={alice:'Alice',bob:'Bob',charlie:'Charlie'};
const defaults={2:[[3,3],[2,5]],3:[[6,24,1],[13,16,10],[20,17,15]],4:[[1,2,3,4],[0,1,2,3],[0,0,1,2],[0,0,0,1]]};
// --- Small DOM/API helpers shared by the three screens; the backend remains the source of truth. ---
function createDomElement(tag,cls,text){const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;}
let toastTimer;
function showNotification(text){$('#toast').textContent=text;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').textContent='',5000);}
async function sendApiRequest(path,data,method){const r=await fetch(path,{method:method||(data?'POST':'GET'),headers:data?{'Content-Type':'application/json'}:{},body:data?JSON.stringify(data):undefined});const v=await r.json();if(!r.ok)throw Error(v.error||'Le serveur ne peut pas traiter cette demande.');return v;}
function handleAsyncUiAction(fn){return async e=>{try{await fn(e);}catch(err){showNotification(err.message);}};}
function getSelectedAccount(){return state.users.find(u=>u.name===selected);}
// ============================================================================
// INTERFACE AUTHENTIFICATION : PROTECTIONS, DICTIONNAIRES ET COMPTEURS
// Affichage des informations du backend ; les controles reels sont dans server.py.
// ============================================================================
function buildAuthenticationAttackPanel(){
  const row=createDomElement('div','protection-row speed-protection-row'),text=createDomElement('div'),toggle=createDomElement('input');
  text.append(createDomElement('strong','','Détection de cadence inhumaine'),createDomElement('small','','Blocage · 3 tentatives en moins de 500 ms'));
  toggle.type='checkbox';toggle.id='speed-protection';toggle.setAttribute('role','switch');toggle.setAttribute('aria-label','Activer la détection de cadence inhumaine');row.append(text,toggle);
  $('.protection-row').after(row);
  toggle.onchange=handleAsyncUiAction(async()=>{await sendApiRequest('/api/protection',{user:selected,setting:'speed_protection',enabled:toggle.checked});await refreshApplicationState();});
  const workspace=createDomElement('div','attack-workspace'),terminal=$('.terminal'),dictionary=createDomElement('aside','dictionary-panel');dictionary.id='dictionary-panel';dictionary.setAttribute('aria-label','Dictionnaire des candidats');
  const title=createDomElement('strong','','Dictionnaire'),count=createDomElement('small');count.id='dictionary-count';const list=createDomElement('div','dictionary-list');list.id='dictionary-list';list.tabIndex=0;list.setAttribute('aria-label','Liste complète des candidats');const hint=createDomElement('p');hint.id='dictionary-hint';
  dictionary.append(title,count,list,hint);terminal.before(workspace);workspace.append(terminal,dictionary);
  const progress=createDomElement('p','field-help');progress.id='resume-info';$('#run-attack').before(progress);
}
function renderPasswordCandidateDictionary(cursor){
  $('#dictionary-panel').hidden=kind===2;$('.attack-workspace').classList.toggle('no-dictionary',kind===2);
  if(kind===2)return;
  const key=`${selected}:${kind}:${cursor}`;if(dictionaryKey===key)return;dictionaryKey=key;
  const alphabet=kind===0?'01':'1234',length=kind===0?3:4,total=alphabet.length**length;
  const items=Array.from({length:total},(_,i)=>{let n=i,s='';for(let j=0;j<length;j++){s=alphabet[n%alphabet.length]+s;n=Math.floor(n/alphabet.length);}const item=createDomElement('span',i<cursor?'tried':i===cursor?'next':'',s);if(i===cursor)item.setAttribute('aria-label',`Prochain candidat : ${s}`);return item;});
  $('#dictionary-count').textContent=`${total} candidats · ordre d’essai`;
  $('#dictionary-list').replaceChildren(...items);$('#dictionary-hint').textContent=cursor<total?`Suivant : ${items[cursor].textContent}`:'Dictionnaire épuisé.';
}
async function refreshApplicationState(){state=await sendApiRequest('/api/state');renderAccountSecurityStatus();renderDemoAccountCredentials();syncDemoPasswordEditor();return state;}
function renderAccountSecurityStatus(){
  const u=getSelectedAccount();$('#users').replaceChildren();
  for(const name of Object.keys(names)){const b=createDomElement('button','user-button'+(name===selected?' selected':''));b.type='button';b.setAttribute('aria-pressed',name===selected);b.append(createDomElement('span','avatar',names[name][0]),document.createTextNode(names[name]));b.disabled=!!activeJob;b.onclick=()=>{selected=name;$('#user').value=name;$('#password').value='';renderAccountSecurityStatus();};$('#users').append(b);}
  $('#protection').checked=!!u.protection;$('#protection').disabled=!!activeJob;
  $('#speed-protection').checked=!!u.speed_protection;$('#speed-protection').disabled=!!activeJob;
  $('#failure-label').textContent=`${u.failures} / 9`;
  $('#attempt-dots').replaceChildren(...Array.from({length:9},(_,i)=>createDomElement('i',i<u.failures?'used':'')));
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
  renderPasswordCandidateDictionary(cursor);
  $('#logout').hidden=!state.current;
}
// --- Screen navigation and cipher controls: changing algorithms rebuilds their editable parameters. ---
function showApplicationScreen(which){
  if(which!=='auth'&&!state.current){showNotification('Connectez-vous pour accéder à cet espace.');return;}
  $('#auth-view').hidden=which!=='auth';$('#messages-view').hidden=which!=='messages';$('#nav-auth').classList.toggle('active',which==='auth');$('#nav-msg').classList.toggle('active',which==='messages');
  $('#integrity-view').hidden=which!=='integrity';$('#nav-integrity').classList.toggle('active',which==='integrity');
  $('#breadcrumb').textContent=`ESPACE D’EXPÉRIMENTATION / ${which==='auth'?'AUTHENTIFICATION':which==='integrity'?'INTÉGRITÉ':'MESSAGERIE'}`;
  if(which==='integrity')openIntegrityWorkspace();
  if(which==='messages'){$('#session-label').textContent=`Connecté en tant que ${names[state.current]}. Choisissez un destinataire et explorez les trois algorithmes.`;const previous=$('#recipient').value;$('#recipient').replaceChildren(...Object.keys(names).filter(n=>n!==state.current).map(n=>{const o=createDomElement('option','',names[n]);o.value=n;return o;}));if(previous!==state.current&&names[previous])$('#recipient').value=previous;refreshCipherMessageInbox().catch(e=>showNotification(e.message));}
}
function renderDemoAccountCredentials(){
  $('#credentials').replaceChildren();for(const [name,passes]of Object.entries(state.credentials)){const d=createDomElement('div','credential');d.append(createDomElement('strong','',names[name]),createDomElement('br'));['Binaire','Numérique','Étendu'].forEach((label,i)=>{d.append(document.createTextNode(`${label} : `),createDomElement('code','',passes[i]),createDomElement('br'));});$('#credentials').append(d);}
}
function renderEditableHillMatrix(n){
  const box=$('#matrix');box.style.gridTemplateColumns=`repeat(${n},1fr)`;box.replaceChildren();defaults[n].forEach((r,i)=>r.forEach((v,j)=>{const input=createDomElement('input');input.type='number';input.step='1';input.min='-10000';input.max='10000';input.required=true;input.value=v;input.setAttribute('aria-label',`Clé, ligne ${i+1}, colonne ${j+1}`);box.append(input);}));
}
function renderCipherParameterControls(){
  const algo=$('#algorithm').value,box=$('#cipher-params');box.replaceChildren();
  if(algo==='caesar'){
    const row=createDomElement('div','params-row');const a=createDomElement('div'),b=createDomElement('div');const l1=createDomElement('label','','Décalage');l1.htmlFor='shift';const input=createDomElement('input');input.id='shift';input.type='number';input.min=0;input.max=25;input.value=3;input.required=true;a.append(l1,input);
    const l2=createDomElement('label','','Direction');l2.htmlFor='direction';const select=createDomElement('select');select.id='direction';for(const[v,t]of [['right','Droite (+)'],['left','Gauche (−)']]){const o=createDomElement('option','',t);o.value=v;select.append(o);}b.append(l2,select);row.append(a,b);box.append(row);
    $('#cipher-warning').textContent='Faiblesse : seulement 26 décalages possibles. Les fréquences des lettres restent visibles.';
  }else if(algo==='playfair'){
    const l=createDomElement('label','','Clé Playfair');l.htmlFor='key';const i=createDomElement('input');i.id='key';i.value='MONARCHY';i.required=true;i.maxLength=100;box.append(l,i);$('#cipher-warning').textContent='Faiblesse : les fréquences des paires et les textes connus facilitent la cryptanalyse. I/J sont fusionnés.';
  }else{
    const l=createDomElement('label','','Dimension de la matrice');l.htmlFor='dimension';const s=createDomElement('select');s.id='dimension';for(const n of [2,3,4]){const o=createDomElement('option','',`${n} × ${n}`);o.value=n;s.append(o);}const m=createDomElement('div','matrix');m.id='matrix';const reset=createDomElement('button','text-button','Rétablir la matrice par défaut');reset.type='button';reset.style.marginTop='10px';reset.onclick=()=>renderEditableHillMatrix(Number(s.value));s.onchange=()=>renderEditableHillMatrix(Number(s.value));box.append(l,s,m,reset);renderEditableHillMatrix(2);$('#cipher-warning').textContent='Faiblesse : la transformation est linéaire et vulnérable aux textes connus. La matrice doit être inversible modulo 26.';
  }
  highlightSelectedCipherWeaknesses();
}
function readSelectedCipherParameters(){
  switch($('#algorithm').value){case 'caesar':return{shift:Number($('#shift').value),direction:$('#direction').value};case 'playfair':return{key:$('#key').value};default:const n=Number($('#dimension').value),v=[...$('#matrix').children].map(i=>Number(i.value));return{matrix:Array.from({length:n},(_,i)=>v.slice(i*n,(i+1)*n))};}
}
// ============================================================================
// AFFICHAGE DES EXPLICATIONS DU CHIFFREMENT ET DU DECHIFFREMENT
// Presentation des etapes, des matrices K / K^-1 et du calcul de l'inverse.
// ============================================================================
function createMatrixDisplay(matrix,label){
  const card=createDomElement('div','matrix-explanation');card.append(createDomElement('strong','',label));
  const grid=createDomElement('div','matrix-display');grid.style.gridTemplateColumns=`repeat(${matrix.length},minmax(28px,1fr))`;
  matrix.flat().forEach(value=>grid.append(createDomElement('span','',String(value))));card.append(grid);return card;
}
function renderCipherTransformationExplanation(t,title){
  lastTrace=t;$('#trace-title').textContent=title;const box=$('#trace-content');box.replaceChildren();box.append(createDomElement('p','',t.rule));
  box.append(createDomElement('p','',`Texte normalisé : ${t.normalized}`));if(t.prepared)box.append(createDomElement('p','',`Texte préparé : ${t.prepared}`));
  if(t.grid){const g=createDomElement('div','trace-grid');t.grid.flat().forEach(c=>g.append(createDomElement('span','',c)));box.append(g);}
  if(t.key_matrix){
    const matrices=createDomElement('div','hill-matrices');matrices.append(createMatrixDisplay(t.key_matrix,'Matrice clé K · chiffrement'),createMatrixDisplay(t.inverse,'Matrice inverse K⁻¹ · déchiffrement'));box.append(matrices);
    box.append(createDomElement('p','hill-operation',t.operation==='decrypt'?'Pour ce déchiffrement, on utilise K⁻¹ : P = K⁻¹ × C mod 26.':'Pour ce chiffrement, on utilise K : C = K × P mod 26.'));
    if(t.inverse_calculation){const calc=t.inverse_calculation,explanation=createDomElement('section','inverse-explanation');explanation.append(createDomElement('strong','','Comment obtient-on K⁻¹ ?'));const list=createDomElement('ol');calc.steps.forEach(step=>list.append(createDomElement('li','',step)));explanation.append(list,createMatrixDisplay(calc.adjugate,'Adjointe adj(K) · cofacteurs transposés'));box.append(explanation);}
  }
  box.append(createDomElement('div','trace-result',t.result));const list=createDomElement('ol');t.steps.forEach(s=>list.append(createDomElement('li','',s)));box.append(list);$('#trace-panel').scrollIntoView({behavior:'smooth',block:'nearest'});
}
async function refreshCipherMessageInbox(){
  const data=await sendApiRequest('/api/messages'),box=$('#message-list');box.replaceChildren();
  if(!data.messages.length){box.append(createDomElement('div','empty','Aucun message pour le moment.\nEnvoyez le premier message chiffré.'));return;}
  for(const m of data.messages){const sent=m.sender===state.current;const d=createDomElement('article','message-item'),meta=createDomElement('div','meta');meta.append(createDomElement('strong','',`${names[m.sender]} → ${names[m.recipient]}`),createDomElement('span','',m.algorithm.toUpperCase()));d.append(meta,createDomElement('div','cipher',m.ciphertext),createDomElement('p','field-help',new Date(m.created*1000).toLocaleString('fr-FR')));
    if(!sent){const b=createDomElement('button','secondary','Déchiffrer et expliquer ↗');b.onclick=handleAsyncUiAction(async()=>{const data=await sendApiRequest(`/api/messages/${m.id}/decrypt`,{});renderCipherTransformationExplanation(data.trace,`Déchiffrement · ${m.algorithm.toUpperCase()}`);});d.append(b);}else d.append(createDomElement('small','muted','Envoyé · le destinataire peut déchiffrer'));
    const details=createDomElement('details','field-help'),summary=createDomElement('summary','','Paramètres du message');details.append(summary,createDomElement('p','',JSON.stringify(JSON.parse(m.params))));d.append(details);box.append(d);
  }
}
// ============================================================================
// BOUTONS DE CONNEXION / ATTAQUE ET SUIVI DU RESULTAT
// pollAttackProgressAndAccountStatus() suit le job et ouvre automatiquement la messagerie apres un succes.
// ============================================================================
document.querySelectorAll('[data-kind]').forEach(b=>b.onclick=()=>{kind=Number(b.dataset.kind);$('#password').value='';renderAccountSecurityStatus();});
$('#reveal').onclick=()=>{const p=$('#password');p.type=p.type==='password'?'text':'password';$('#reveal').setAttribute('aria-label',p.type==='password'?'Afficher le mot de passe':'Masquer le mot de passe');};
$('#protection').onchange=handleAsyncUiAction(async()=>{await sendApiRequest('/api/protection',{user:selected,enabled:$('#protection').checked});await refreshApplicationState();});
$('#unlock').onclick=handleAsyncUiAction(async()=>{await sendApiRequest('/api/unlock',{user:selected});await refreshApplicationState();showNotification('Compte débloqué. Le compteur est remis à zéro.');});
$('#login-form').onsubmit=handleAsyncUiAction(async e=>{e.preventDefault();const r=await sendApiRequest('/api/login',{user:selected,kind,password:$('#password').value});await refreshApplicationState();if(r.state==='success'){$('#password').value='';showApplicationScreen('messages');showNotification(`Bienvenue, ${names[state.current]}.`);}else showNotification(r.state==='blocked'?`Compte bloqué. ${r.account.block_reason}`:r.state==='cooldown'?'Trois échecs : pause de 10 secondes.':'Mot de passe incorrect.');});
$('#run-attack').onclick=handleAsyncUiAction(async()=>{
  const r=await sendApiRequest('/api/attack',{user:selected,kind});activeJob=r.id;$('#attack-badge').textContent='EN COURS';renderAccountSecurityStatus();
});
$('#stop-attack').onclick=handleAsyncUiAction(async()=>{if(activeJob)await sendApiRequest(`/api/attack/${activeJob}`,null,'DELETE');});
async function pollAttackProgressAndAccountStatus(){
  if(polling)return;polling=true;
  try{
    if(activeJob){const j=await sendApiRequest(`/api/attack/${activeJob}`);const stateLabels={running:'En cours',success:'Mot de passe trouvé',cooldown:'Pause de sécurité · 10 s',blocked:'Compte bloqué',cancelled:'Attaque arrêtée',exhausted:'Recherche terminée',error:'Erreur serveur'};
      $('#attack-badge').textContent=stateLabels[j.state].toUpperCase();
      $('#attack-log').textContent=`> Cible locale : ${names[j.user]}\n> ${stateLabels[j.state]}\n> Reprise à la position : ${(j.start_index+1).toLocaleString('fr-FR')}\n> Tentatives de cette exécution : ${j.attempts.toLocaleString('fr-FR')}\n> Dernier candidat : ${j.candidate||'—'}${j.elapsed?`\n> Durée : ${(j.elapsed*1000).toFixed(2)} ms · ${Math.round(j.attempts/Math.max(j.elapsed,.000001)).toLocaleString('fr-FR')} essais/s`:''}${j.found?`\n> Mot de passe trouvé : ${j.found}\n> Connexion automatique…`:''}`;
      if(j.state==='success'){
        await sendApiRequest(`/api/attack/${activeJob}/connect`,{});activeJob=null;await refreshApplicationState();$('#password').value='';showApplicationScreen('messages');showNotification(`Mot de passe trouvé : ${j.found}. Connexion automatique à ${names[j.user]}.`);return;
      }
      if(j.state!=='running')activeJob=null;
    }
    await refreshApplicationState();
    if(getSelectedAccount().blocked&&getSelectedAccount().block_reason&&!$('#attack-log').textContent.includes(getSelectedAccount().block_reason))$('#attack-log').textContent+=`\n> Motif : ${getSelectedAccount().block_reason}`;
  }catch(e){showNotification(e.message);}finally{polling=false;}
}
$('#nav-auth').onclick=()=>showApplicationScreen('auth');$('#nav-msg').onclick=()=>showApplicationScreen('messages');
$('#logout').onclick=handleAsyncUiAction(async()=>{await sendApiRequest('/api/logout',{});await refreshApplicationState();lastTrace=null;clearIntegrityWorkspace();$('#message-text').value='';$('#algorithm').value='caesar';renderCipherParameterControls();$('#trace-title').textContent='L’algorithme, étape par étape';$('#trace-content').textContent='Envoyez ou déchiffrez un message pour explorer sa transformation.';$('#message-list').replaceChildren();showApplicationScreen('auth');});
$('#algorithm').onchange=renderCipherParameterControls;
$('#refresh').onclick=handleAsyncUiAction(refreshCipherMessageInbox);
$('#message-form').onsubmit=handleAsyncUiAction(async e=>{e.preventDefault();$('#send').disabled=true;try{const r=await sendApiRequest('/api/messages',{recipient:$('#recipient').value,algorithm:$('#algorithm').value,params:readSelectedCipherParameters(),text:$('#message-text').value});renderCipherTransformationExplanation(r.trace,`Chiffrement · ${$('#algorithm').value.toUpperCase()}`);await refreshCipherMessageInbox();showNotification('Message chiffré et envoyé.');}finally{$('#send').disabled=false;}});
// --- Build optional panels before the first state fetch, then start account and inbox refreshes. ---
buildAuthenticationAttackPanel();
buildIntegrityDemonstrationPanel();
buildDemoCustomizationControls();
handleAsyncUiAction(async()=>{await refreshApplicationState();renderDemoAccountCredentials();renderCipherParameterControls();showApplicationScreen(state.current?'messages':'auth');setInterval(pollAttackProgressAndAccountStatus,600);setInterval(()=>{if(state.current&&!$('#messages-view').hidden)refreshCipherMessageInbox().catch(()=>{});},5000);})();
