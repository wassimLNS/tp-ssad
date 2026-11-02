# Cipher Lab — Guide de l'interface

Ce guide permet de tester l'application et de préparer sa présentation. L'architecture est décrite dans [le guide du code](README_CODE.md).

## Ouvrir l'application

Lancer `lancer.bat` sous Windows si les dépendances sont déjà installées, ou suivre les commandes de démarrage du [README principal](README.md). Ouvrir ensuite http://127.0.0.1:5000 et garder le serveur ouvert pendant la démonstration.

Trois onglets sont disponibles : **Authentification**, **Messagerie** et **Intégrité**. Les deux derniers nécessitent une connexion. Après une mise à jour de l'application, actualiser la page avec F5.

## 1. Authentification

Choisir Alice, Bob ou Charlie, sélectionner le format de mot de passe et saisir le secret correspondant. Un seul des trois secrets suffit pour se connecter.

Les valeurs initiales sont :

- **Alice** : binaire `101`, numérique `1234`, étendu `a+`.
- **Bob** : binaire `011`, numérique `2341`, étendu `b*`.
- **Charlie** : binaire `110`, numérique `3412`, étendu `c1`.

Si les secrets ont été personnalisés, ouvrir **Identifiants de démonstration** pour voir leurs valeurs actuelles.

### Tester une attaque

Le bouton de simulation utilise un dictionnaire pour les formats binaire et numérique. Le panneau à droite affiche tous leurs candidats, dans l'ordre des essais : 8 pour le binaire et 256 pour le numérique.

Pour le format étendu, le bouton utilise une force brute sur les minuscules, majuscules, chiffres et signes ASCII imprimables sans espace. Le nombre de combinaisons et la longueur connue du serveur ne sont pas affichés dans ce mode.

Le moniteur présente l'état, le nombre d'essais, le dernier candidat et, à la fin de l'exécution, sa durée et son débit. **Arrêter l'attaque** permet d'interrompre une recherche longue. Lorsqu'un secret est trouvé, la connexion à son compte est automatique.

Après une pause de sécurité, relancer avec **Reprendre l'attaque** : la recherche continue au candidat suivant. La position est conservée séparément pour chaque compte et chaque format.

### Comprendre les protections

**Protection des tentatives — Rate limiting** : les essais manuels et automatiques partagent un compteur par compte. Les échecs 3 et 6 déclenchent une pause de 10 secondes ; le neuvième bloque le compte. Une connexion réussie remet le compteur à zéro.

**Détection de cadence inhumaine** : trois essais en moins de 500 ms bloquent le compte avec un motif explicite. Cet interrupteur est indépendant du rate limiting et désactivé par défaut.

Les interrupteurs sont indisponibles pendant une attaque en cours. Les désactiver ne supprime pas un blocage existant. **Débloquer le compte · réinitialiser** remet à zéro les compteurs et les positions de recherche du compte pour recommencer une démonstration.

### Personnaliser un mot de passe

1. Ouvrir **Personnaliser les mots de passe**, sous les identifiants de démonstration.
2. Choisir le compte et le format à modifier.
3. Saisir le nouveau secret puis cliquer sur **Enregistrer le mot de passe**.

Le binaire accepte exactement 3 caractères parmi `0` et `1`. Le numérique accepte exactement 4 caractères parmi `1`, `2`, `3` et `4`. Le format étendu accepte de 1 à 32 caractères ASCII imprimables sans espace.

L'enregistrement conserve les deux autres secrets et persiste après redémarrage. Il débloque le compte, réinitialise ses compteurs et remet la recherche du format modifié au premier candidat. Les longs secrets étendus demandent beaucoup plus de temps à explorer ; commencer avec un ou deux caractères pour une démonstration rapide.

## 2. Messagerie

Après connexion, choisir un autre utilisateur comme destinataire, un algorithme et ses paramètres. Saisir un message puis cliquer sur **Chiffrer et envoyer**.

- **Caesar** : décalage de 0 à 25 et direction gauche ou droite. Valeur initiale : 3 vers la droite.
- **Playfair** : clé textuelle, initialement `MONARCHY`.
- **Hill** : dimension 2 × 2, 3 × 3 ou 4 × 4 et coefficients de la matrice. Chaque dimension propose une clé inversible par défaut. **Rétablir la matrice par défaut** permet de revenir à cette clé.

Le texte est converti en lettres A–Z : les accents sont normalisés et les espaces, chiffres et signes retirés. La limite est de 2 000 lettres. Les X ou Q ajoutés par certains chiffrements peuvent rester dans le résultat déchiffré.

L'explication du chiffrement apparaît après l'envoi. Pour Hill, elle montre la matrice clé K, son inverse K⁻¹, un résumé du calcul de l'inverse et les transformations de chaque bloc.

### Recevoir et déchiffrer

Se déconnecter, puis se connecter au compte destinataire. Dans **Conversations**, cliquer sur **Déchiffrer et expliquer** pour afficher le message et les étapes inverses. Le bouton est réservé au destinataire. Les conversations s'actualisent régulièrement ; **Actualiser** force leur rechargement.

Les onglets d'un même navigateur partagent généralement une session. Pour montrer deux utilisateurs en même temps, utiliser deux profils ou contextes de navigation isolés.

### Présenter les faiblesses

La section **Faiblesses des chiffrements classiques** affiche les limites des trois algorithmes et met en évidence celui sélectionné :

- Hill : transformation linéaire, récupération possible de la clé à partir de blocs connus formant une matrice inversible, contrainte sur le déterminant et ambiguïté des X finaux.
- Playfair : fréquences de paires, fusion I/J et lettres de remplissage ambiguës.
- Caesar : très petit nombre de clés, fréquences conservées et décalage retrouvé à partir d'une correspondance connue.

### Vider les messages

**Vider les messages** supprime tous les messages chiffrés des trois comptes et efface l'explication affichée. Les comptes, mots de passe et messages de l'onglet Intégrité sont conservés. Utiliser ce bouton pour préparer une nouvelle démonstration.

## 3. Intégrité SHA-256

Dans **Intégrité**, choisir un destinataire, saisir un message et cliquer sur **Envoyer avec son hash**. Ici, le texte exact est conservé, y compris accents, espaces, ponctuation et retours à la ligne, avec une limite de 4 000 caractères.

Le panneau de comparaison montre le message original et son hash SHA-256, puis le message reçu, le hash reçu avec lui et le hash recalculé. Si le message est intact, les empreintes sont identiques et l'indicateur est vert.

Se connecter au compte destinataire pour accéder aux actions :

1. **Vérifier l'intégrité** compare à nouveau les empreintes.
2. Dans **Copie reçue à modifier**, changer un mot ou un chiffre, puis cliquer sur **Simuler la modification**. Sans modification manuelle, le bouton ajoute lui-même un marqueur.
3. Le hash envoyé reste inchangé, mais celui du message reçu change : une erreur rouge signale la différence.
4. **Rétablir le message original** restaure la copie et remet l'indicateur au vert.

Cette partie illustre la détection d'une modification en supposant que le hash de référence est fiable ; un hash seul ne prouve pas l'identité de l'expéditeur.

## Scénario court pour la présentation

1. Avec les secrets initiaux, choisir Alice en numérique, activer uniquement le rate limiting et lancer trois exécutions séparées par les pauses : montrer le blocage au neuvième échec.
2. Débloquer le compte, activer la détection de cadence et relancer : montrer le blocage rapide et son motif.
3. Débloquer, désactiver les deux protections et lancer une attaque : montrer la connexion automatique après découverte.
4. Envoyer un message d'Alice à Bob avec Hill ; se connecter en Bob et présenter le déchiffrement, l'inverse et les faiblesses.
5. Dans Intégrité, envoyer un message témoin à un autre compte, s'y connecter, simuler un changement de rendez-vous de 14 h à 18 h, puis restaurer l'original.

Si un compte est bloqué, utiliser son bouton de déblocage. Si le serveur a redémarré, se reconnecter : les messages et les mots de passe personnalisés sont conservés.
