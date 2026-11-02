'use strict';
let integrityMessages=[], integritySelected=null;
// ============================================================================
// INTERFACE INTEGRITE : ENVOYER UN MESSAGE ET COMPARER SES HASHES SHA-256
// Les calculs et autorisations sont effectues dans server.py.
// ============================================================================
function buildIntegrityDemonstrationPanel(){
  const section=document.createElement('section');section.id='integrity-view';section.hidden=true;
  section.innerHTML=`<div class="page-heading"><div><div class="eyebrow">03 / INTÉGRITÉ DES MESSAGES</div><h1>Le même message.<br>La même empreinte<span>.</span></h1><p id="integrity-session"></p></div><div class="heading-icon">#</div></div>
  <div class="message-layout"><section class="card"><div class="card-top"><h2>Envoyer un message témoin</h2><span class="tag">SHA-256</span></div>
  <form id="integrity-form"><label for="integrity-recipient">Destinataire du message témoin</label><select id="integrity-recipient"></select><label for="integrity-text">Message original</label><textarea id="integrity-text" rows="4" maxlength="4000" required placeholder="Bonjour Bob, rendez-vous à 14 h."></textarea><p class="field-help">Le texte exact est conservé : accents, espaces, ponctuation et retours à la ligne. Hash calculé sur ses octets UTF-8.</p><button class="primary full" id="integrity-send">Envoyer avec son hash <span>→</span></button></form></section>
  <section class="card integrity-inbox"><div class="card-top"><h2>Messages témoins</h2><button id="integrity-refresh" class="text-button">Actualiser ↻</button></div><div id="integrity-list"></div></section></div>
  <section class="card integrity-inspector" id="integrity-inspector"><div class="card-top"><h2>Comparer l’envoi et la réception</h2><span class="tag">VÉRIFICATION</span></div><div id="integrity-comparison" class="muted">Envoyez ou sélectionnez un message pour comparer les empreintes.</div></section>
  <p class="field-help">Démonstration indépendante du chiffrement : le hash de l’expéditeur est conservé comme référence. SHA-256 détecte ici une modification du message ; il ne prouve pas à lui seul l’identité de l’expéditeur.</p>`;
  document.querySelector('footer').before(section);
  $('#nav-integrity').onclick=()=>showApplicationScreen('integrity');
  $('#integrity-refresh').onclick=handleAsyncUiAction(refreshIntegrityMessageInbox);
  $('#integrity-form').onsubmit=handleAsyncUiAction(async e=>{e.preventDefault();$('#integrity-send').disabled=true;try{const r=await sendApiRequest('/api/integrity',{recipient:$('#integrity-recipient').value,text:$('#integrity-text').value});integritySelected=r.message.id;await refreshIntegrityMessageInbox();showNotification('Message et hash SHA-256 envoyés au destinataire.');}finally{$('#integrity-send').disabled=false;}});
}
function openIntegrityWorkspace(){
  $('#integrity-session').textContent=`Connecté en tant que ${names[state.current]}. Comparez l’empreinte de l’expéditeur à celle recalculée par le destinataire.`;
  const select=$('#integrity-recipient'),previous=select.value;select.replaceChildren();
  Object.keys(names).filter(n=>n!==state.current).forEach(n=>{const o=createDomElement('option','',names[n]);o.value=n;select.append(o);});
  if(previous!==state.current&&names[previous])select.value=previous;
  refreshIntegrityMessageInbox().catch(e=>showNotification(e.message));
}
async function refreshIntegrityMessageInbox(){
  const r=await sendApiRequest('/api/integrity');integrityMessages=r.messages;
  const list=$('#integrity-list');list.replaceChildren();
  if(!integrityMessages.length){list.append(createDomElement('div','empty','Aucun message témoin. Envoyez un message avec son empreinte SHA-256.'));integritySelected=null;$('#integrity-comparison').textContent='Envoyez ou sélectionnez un message pour comparer les empreintes.';return;}
  if(!integrityMessages.some(m=>m.id===integritySelected))integritySelected=integrityMessages[0].id;
  for(const m of integrityMessages){const b=createDomElement('button','integrity-message'+(m.id===integritySelected?' selected':''));b.type='button';b.append(createDomElement('strong','',`${names[m.sender]} → ${names[m.recipient]}`),createDomElement('span','',m.original_text.slice(0,80)),createDomElement('small',m.valid?'hash-ok':'hash-error',m.valid?'Empreintes identiques':'Empreintes différentes'));
    b.onclick=()=>{integritySelected=m.id;refreshIntegrityMessageInbox().catch(e=>showNotification(e.message));};list.append(b);}
  renderIntegrityComparison(integrityMessages.find(m=>m.id===integritySelected));
}
function createHashDisplayField(label,value){const box=createDomElement('div','hash-field');box.append(createDomElement('small','',label),createDomElement('code','',value));return box;}
// --- Compare the immutable sent hash with the server's recalculated hash of the received copy. ---
// Recipient-only actions simulate tampering or restore the original; hashes are never edited in the UI.
function renderIntegrityComparison(m){
  const box=$('#integrity-comparison');box.replaceChildren();const recipient=m.recipient===state.current;
  const comparison=createDomElement('div','integrity-columns'),sent=createDomElement('div','integrity-side'),received=createDomElement('div','integrity-side');
  sent.append(createDomElement('h3','',`À l’envoi · ${names[m.sender]}`),createDomElement('small','','MESSAGE ORIGINAL'),createDomElement('div','integrity-message-text',m.original_text),createHashDisplayField('HASH SHA-256 ENVOYÉ',m.sent_hash));
  received.append(createDomElement('h3','',`À la réception · ${names[m.recipient]}`),createDomElement('small','','MESSAGE REÇU'),createDomElement('div','integrity-message-text',m.received_text),createHashDisplayField('HASH REÇU AVEC LE MESSAGE',m.sent_hash),createHashDisplayField('HASH RECALCULÉ SUR LE MESSAGE REÇU',m.received_hash));
  comparison.append(sent,received);box.append(comparison);
  const result=createDomElement('div','integrity-verdict '+(m.valid?'valid':'invalid'));result.setAttribute('role','status');result.append(createDomElement('strong','',m.valid?'✓ Intégrité vérifiée · hashes identiques':'✕ Erreur d’intégrité · hashes différents'),createDomElement('p','',m.valid?'Le destinataire a reçu le même message. Son hash SHA-256 recalculé correspond au hash envoyé.':'Le hash du message reçu ne correspond pas au hash envoyé par l’expéditeur. Le message a été modifié.'));box.append(result);
  if(recipient){
    const actions=createDomElement('div','integrity-actions'),verify=createDomElement('button','secondary','Vérifier l’intégrité');verify.type='button';verify.onclick=handleAsyncUiAction(async()=>{const r=await sendApiRequest(`/api/integrity/${m.id}/verify`,{});renderIntegrityComparison(r.message);showNotification(r.message.valid?'Intégrité vérifiée : les deux hashes correspondent.':'Erreur : le hash recalculé diffère du hash reçu.');});actions.append(verify);box.append(actions);
    const simulation=createDomElement('section','tamper-panel');simulation.append(createDomElement('h3','','Simuler une modification pendant le transport'),createDomElement('p','field-help','Modifiez la copie reçue : le hash envoyé reste inchangé. Vous pouvez ensuite rétablir le message original.'));
    const label=createDomElement('label','','Copie reçue à modifier');label.htmlFor='tamper-text';const input=createDomElement('textarea');input.id='tamper-text';input.rows=3;input.maxLength=4000;input.value=m.received_text;
    const buttons=createDomElement('div','integrity-actions'),tamper=createDomElement('button','danger','Simuler la modification'),restore=createDomElement('button','secondary','Rétablir le message original');tamper.type=restore.type='button';
    tamper.onclick=handleAsyncUiAction(async()=>{const changed=input.value===m.original_text?m.original_text.slice(0,3989)+' [modifié]':input.value;await sendApiRequest(`/api/integrity/${m.id}/tamper`,{text:changed});await refreshIntegrityMessageInbox();showNotification('Modification simulée : erreur d’intégrité détectée.');});
    restore.onclick=handleAsyncUiAction(async()=>{await sendApiRequest(`/api/integrity/${m.id}/tamper`,{restore:true});await refreshIntegrityMessageInbox();showNotification('Message original rétabli : les empreintes correspondent.');});buttons.append(tamper,restore);simulation.append(label,input,buttons);box.append(simulation);
  }else box.append(createDomElement('p','field-help',`Connectez-vous en tant que ${names[m.recipient]} pour vérifier la réception et simuler une modification.`));
}
function clearIntegrityWorkspace(){
  integrityMessages=[];integritySelected=null;$('#integrity-text').value='';$('#integrity-list').replaceChildren();$('#integrity-comparison').textContent='Envoyez ou sélectionnez un message pour comparer les empreintes.';
}
