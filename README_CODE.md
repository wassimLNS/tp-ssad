# Cipher Lab — Guide du code

Ce guide explique l'organisation et le fonctionnement du projet. Pour présenter l'application ou utiliser ses boutons, consulter [le guide de l'interface](README_INTERFACE.md).

## Installer et lancer

Depuis le dossier du projet, avec Python 3.10 ou plus récent :

```powershell
python -m pip install -r requirements.txt
python server.py
```

Ouvrir ensuite http://127.0.0.1:5000. Sous Windows, `lancer.bat` lance aussi le serveur si Flask est installé. Garder le terminal ouvert et utiliser `Ctrl+C` pour arrêter le serveur. Aucun outil de compilation JavaScript n'est nécessaire.

## Organisation

- `server.py` : serveur Flask, sessions, SQLite, authentification, protections, attaques, messagerie et intégrité.
- `crypto_lab.py` : Caesar, Playfair et Hill, calcul matriciel et explications des transformations.
- `static/index.html` : structure des écrans et chargement des ressources.
- `static/app.js` : navigation, connexion, suivi des attaques, paramètres des chiffrements et conversations.
- `static/integrity.js` : comparaison des messages et hashes, modification simulée et restauration.
- `static/demo-controls.js` : personnalisation des mots de passe, bouton de réinitialisation et faiblesses des chiffrements.
- `static/*.css` : styles généraux et styles des différentes parties de l'interface.
- `tests/test_lab.py` : tests mathématiques et tests du backend.
- `requirements.txt` : dépendance Flask ; les autres modules Python utilisés appartiennent à la bibliothèque standard.
- `lab.sqlite3` : base créée automatiquement au premier lancement, exclue du suivi Git.

Les commentaires de section repèrent les grandes responsabilités. Les explications détaillées sont regroupées dans ce guide pour éviter de surcharger les fonctions.

## Base de données et sessions

`initialize_database_and_demo_accounts()` crée les tables manquantes et ajoute les colonnes nécessaires sans effacer les données existantes. `open_database_connection()` ouvre une connexion courte, gère la transaction et ferme la connexion, y compris en cas d'erreur.

- `users` contient les trois comptes, le sel, les empreintes des trois secrets, les identifiants de démonstration personnalisés, la longueur du secret étendu et l'état des protections.
- `attack_progress` conserve la position du prochain candidat, séparément pour chaque compte et chaque format.
- `messages` conserve l'expéditeur, le destinataire, l'algorithme, ses paramètres, le texte chiffré et la date. Le texte clair n'y est pas stocké.
- `integrity_messages` conserve le texte original, la copie reçue, le hash envoyé et les deux participants. Cette démonstration conserve volontairement le texte en clair.

Les données SQLite persistent après redémarrage. Les attaques en cours (`JOBS`) restent en mémoire et la clé de session Flask est renouvelée au lancement : un redémarrage demande donc une nouvelle connexion.

## Authentification et protections

`verify_password_and_apply_protections()` est le point commun aux essais manuels et aux attaques protégées. Un verrou empêche deux essais de modifier simultanément le même état de contrôle. Les formats sont : trois caractères `0/1`, quatre caractères `1/2/3/4`, puis un secret étendu de 1 à 32 caractères ASCII imprimables sans espace.

Le rate limiting compte les échecs par compte, tous formats confondus : pause de 10 secondes aux échecs 3 et 6, puis blocage au neuvième. Les essais refusés pendant une pause ne consomment pas de tentative. Un succès remet le compteur à zéro.

La détection de cadence est indépendante : trois essais admis en moins de 500 ms bloquent le compte avant la vérification du troisième secret. Le motif est conservé et renvoyé à l'interface. Désactiver un interrupteur ne supprime pas un blocage déjà acquis.

`/api/passwords` valide le nouveau secret, actualise son empreinte et sa valeur de démonstration, puis conserve les deux autres formats. Le changement débloque le compte, efface ses compteurs et réinitialise la recherche du format modifié. Il est refusé pendant une attaque sur ce compte et invalide les anciens succès d'attaque encore disponibles pour une connexion automatique.

## Moteur d'attaque

`generate_password_candidates_from_index()` énumère les 8 mots binaires, les 256 mots numériques ou les chaînes de l'alphabet étendu de 94 caractères. Il accède directement à une position sauvegardée et génère les suffixes à la demande : aucun dictionnaire complet de force brute n'est chargé en mémoire.

`run_password_attack()` s'exécute dans un thread. Si une protection est active, chaque candidat passe par `verify_password_and_apply_protections()`. Lorsque les deux protections sont désactivées, le sel et l'empreinte sont préchargés pour éviter une requête SQLite par candidat. Les modifications de protection sont interdites pendant la recherche.

À l'arrêt, le prochain index est sauvegardé. Après une pause, le bouton de reprise continue donc au candidat suivant. Un succès remet la position de ce format à zéro. Le déblocage de démonstration réinitialise toutes les positions du compte.

Le navigateur interroge l'état du job puis appelle `/api/attack/<id>/connect` s'il réussit. Cette requête crée la session de connexion sans vérifier une seconde fois le mot de passe. Seule la session ayant lancé l'attaque peut revendiquer ce succès, une seule fois. La durée et le débit affichés sont mesurés côté serveur.

## Chiffrement et explications

`encrypt_or_decrypt_message()` renvoie le résultat et une trace structurée. Le navigateur affiche les calculs reçus ; il ne réimplémente pas les chiffrements.

- **Caesar** : alphabet `A=0…Z=25`, décalage de 0 à 25, direction gauche ou droite. Le signe est inversé au déchiffrement.
- **Playfair** : grille 5 × 5 issue de la clé, fusion I/J, traitement par paires. Une répétition est séparée par X, ou Q pour deux X. Les lettres ajoutées restent après déchiffrement.
- **Hill** : vecteurs colonnes, matrices 2 × 2 à 4 × 4, calcul modulo 26. Le déterminant doit être premier avec 26. L'inverse est obtenu par `K⁻¹ = det(K)⁻¹ × adj(K) mod 26`. La trace distingue la clé, son inverse et l'opération effectuée. Les X complétant le dernier bloc sont conservés.

Les trois chiffrements normalisent les accents et ne conservent que les lettres A–Z, avec une limite de 2 000 lettres. Les paramètres sont transmis avec le message pour permettre la démonstration du déchiffrement par le destinataire.

## Intégrité

SHA-256 est calculé sur le texte exact encodé en UTF-8, sans la normalisation des chiffrements classiques. `compare_sent_and_received_hashes()` recalcule l'empreinte de la copie reçue et la compare au hash envoyé avec `secrets.compare_digest()`.

La simulation modifie uniquement `received_text`. Le texte original et `sent_hash` restent fixes. La restauration recopie le texte original dans la copie reçue. Seul le destinataire peut vérifier, modifier ou restaurer cette copie ; les deux participants peuvent consulter le message.

## Principales routes

- `GET /api/state` : comptes, session et identifiants de démonstration actuels.
- `POST /api/login`, `/api/logout` : connexion et déconnexion.
- `POST /api/passwords`, `/api/protection`, `/api/unlock` : réglages du laboratoire.
- `POST /api/attack` : démarrage ; `GET` et `DELETE /api/attack/<id>` : suivi et arrêt ; `POST /api/attack/<id>/connect` : connexion après succès.
- `GET`, `POST` et `DELETE /api/messages` : consultation, envoi et réinitialisation globale de la messagerie chiffrée.
- `POST /api/messages/<id>/decrypt` : déchiffrement réservé au destinataire.
- `GET` et `POST /api/integrity` : consultation et envoi des messages témoins.
- `POST /api/integrity/<id>/verify` et `/api/integrity/<id>/tamper` : contrôle et modification de la copie reçue. Le corps `{ "restore": true }` sur la seconde route restaure l'original.

## Vérification et limites

```powershell
python -m unittest discover -s tests -v
node --check static/app.js
node --check static/integrity.js
node --check static/demo-controls.js
```

Node est facultatif pour exécuter l'application ; il sert ici uniquement à vérifier la syntaxe JavaScript. Les tests du backend utilisent chacun une base temporaire et ne vident pas les messages de la présentation.

Le projet est un laboratoire local. Les mots de passe fictifs sont volontairement visibles et conservés comme données de démonstration ; l'authentification compare des empreintes SHA-256 salées et rapides pour rendre les attaques observables. Les chiffrements classiques ne conviennent pas à des échanges confidentiels réels. Le hash d'intégrité suppose une référence fiable : SHA-256 seul n'authentifie pas l'expéditeur.
