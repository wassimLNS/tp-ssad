'use strict';
let passwordEditorKey='';
function setupDemoControls(){
  const details=el('details','demo-details password-editor');details.id='password-editor';
  const summary=el('summary','','Personnaliser les mots de passe');summary.append(el('span','','PRÉPARER UNE ATTAQUE ↗'));details.append(summary);
  const form=el('form','password-editor-form');form.id='password-editor-form';
  for(const [id,title,options] of [['edit-user','Compte à modifier',Object.entries(names)],['edit-kind','Format à modifier',[['0','Binaire · 3 caractères'],['1','Numérique · 4 caractères'],['2','Étendu · caractères variés']]]]){
    const group=el('div'),label=el('label','',title),select=el('select');label.htmlFor=id;select.id=id;options.forEach(([v,t])=>{const o=el('option','',t);o.value=v;select.append(o);});select.onchange=()=>syncPasswordEditor();group.append(label,select);form.append(group);
  }
  const group=el('div'),label=el('label','','Nouveau mot de passe de démonstration'),input=el('input');label.htmlFor='edit-password';input.id='edit-password';input.type='text';input.autocomplete='off';input.required=true;input.spellcheck=false;group.append(label,input);form.append(group);
  const button=el('button','primary','Enregistrer le mot de passe');button.type='submit';button.id='save-password';form.append(button);details.append(form);
  const help=el('p');help.id='password-format-help';details.append(help,el('p','','Le changement débloque le compte et remet à zéro ses compteurs ainsi que la recherche du format modifié. Les deux autres mots de passe sont conservés.'));
  $('.demo-details').after(details);
  form.onsubmit=safe(async e=>{e.preventDefault();button.disabled=true;try{await api('/api/passwords',{user:$('#edit-user').value,kind:Number($('#edit-kind').value),password:input.value});await load();toast('Mot de passe enregistré. Le compte est prêt pour une nouvelle démonstration.');}finally{button.disabled=false;}});
  const clear=el('button','danger','Vider les messages');clear.type='button';clear.id='clear-messages';
  const actions=el('div','conversation-actions');$('#refresh').before(actions);actions.append($('#refresh'),clear);
  const hint=el('p','field-help','Réinitialisation : supprime tous les messages chiffrés des trois comptes. Les messages de l’onglet Intégrité sont conservés.');$('#message-list').before(hint);
  clear.onclick=safe(async()=>{clear.disabled=true;try{const r=await api('/api/messages',null,'DELETE');lastTrace=null;$('#trace-title').textContent='L’algorithme, étape par étape';$('#trace-content').textContent='Envoyez ou déchiffrez un message pour explorer sa transformation.';await refreshMessages();toast(`${r.deleted} message(s) supprimé(s). La messagerie est vide.`);}finally{clear.disabled=false;}});
  const section=el('section','card weaknesses-card');section.id='cipher-weaknesses';const heading=el('div','card-top');heading.append(el('h2','','Faiblesses des chiffrements classiques'),el('span','tag','LIMITES'));section.append(heading);
  const cards=el('div','weaknesses-grid');
  const data=[['hill','Hill',[
    'Entièrement linéaire : k blocs connus de k lettres (k² lettres) suffisent à retrouver la clé si leur matrice P est inversible modulo 26 : K = C × P⁻¹ mod 26.',
    'Toute matrice ne convient pas : det(K) doit être premier avec 26, sinon le déchiffrement unique est impossible.',
    'Le remplissage X complète le dernier bloc et reste après déchiffrement. Sans la longueur originale, il ne peut pas toujours être distingué des vrais X finaux.'
  ]],['playfair','Playfair',[
    'Les fréquences des paires, les motifs répétés et les textes connus facilitent la cryptanalyse : les lettres sont traitées deux par deux.',
    'La grille 5 × 5 fusionne I et J : on ne peut pas retrouver automatiquement la lettre originale.',
    'Les lettres de séparation ou de remplissage X (ou Q entre deux X) restent après déchiffrement ; leur suppression automatique serait ambiguë.'
  ]],['caesar','Caesar',[
    'Seulement 26 décalages possibles, dont le décalage nul : une recherche exhaustive est immédiate.',
    'Une même lettre est toujours remplacée par la même lettre : les fréquences et les motifs répétés restent exploitables.',
    'Une seule correspondance connue entre une lettre claire et sa lettre chiffrée révèle le décalage modulo 26.'
  ]]];
  for(const [id,title,items] of data){const card=el('article','weakness-card');card.id=`weakness-${id}`;card.append(el('h3','',`Faiblesses de ${title}`));const list=el('ul');items.forEach(t=>list.append(el('li','',t)));card.append(list);cards.append(card);}
  section.append(cards);$('#trace-panel').before(section);$('#cipher-warning').hidden=true;
}
function syncPasswordEditor(){
  if(!state?.credentials||!$('#edit-user'))return;
  const name=$('#edit-user').value,type=Number($('#edit-kind').value),password=state.credentials[name][type];
  const key=JSON.stringify([name,type,password]);if(key===passwordEditorKey)return;passwordEditorKey=key;
  const input=$('#edit-password');input.value=password;input.maxLength=type===0?3:type===1?4:32;
  input.pattern=type===0?'[01]{3}':type===1?'[1-4]{4}':'[!-~]{1,32}';
  $('#password-format-help').textContent=type===0?'Format : exactement 3 caractères parmi 0 et 1.':type===1?'Format : exactement 4 caractères parmi 1, 2, 3 et 4.':'Format : 1 à 32 caractères ASCII imprimables sans espace. Une recherche exhaustive devient très longue quand le mot de passe grandit ; vous pouvez arrêter l’attaque.';
}
function highlightWeakness(){
  document.querySelectorAll('.weakness-card').forEach(card=>card.classList.toggle('selected',card.id===`weakness-${$('#algorithm').value}`));
}
