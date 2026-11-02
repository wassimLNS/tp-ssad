# Cipher Lab — SSAD

Application pédagogique locale : backend Python/Flask, base SQLite persistante et interface en français. Authentification, chiffrement et démonstration d'intégrité SHA-256.

## Démarrage

Python 3.10 ou plus récent :

```powershell
python -m pip install -r requirements.txt
python server.py
```

Ouvrir http://127.0.0.1:5000. Sur Windows, `lancer.bat` lance le serveur si Flask est installé. Le serveur écoute uniquement sur la machine locale. Aucun service externe n'est nécessaire. La base `lab.sqlite3` est créée automatiquement. Les messages et blocages persistent après redémarrage ; les sessions et attaques en cours sont réinitialisées.

## Comptes de démonstration

- Alice : binaire `101` ; numérique `1234` ; étendu `a+`.
- Bob : binaire `011` ; numérique `2341` ; étendu `b*`.
- Charlie : binaire `110` ; numérique `3412` ; étendu `c1`.

Un seul des trois secrets suffit à se connecter. Les identifiants sont aussi accessibles dans le volet de démonstration de l'interface. Ce sont exclusivement des comptes de laboratoire.

## Scénario de présentation

1. Choisir Alice, numérique, protection active. Lancer le dictionnaire : trois échecs, pause de 10 secondes.
2. Attendre puis relancer deux fois : au neuvième échec le compte est bloqué, tous types de mots de passe confondus. Le bouton de déblocage remet le compteur à zéro.
3. Désactiver la protection après déblocage puis lancer l'attaque : le secret est trouvé et la connexion à la messagerie est automatique. Refaire avec le format numérique et le format étendu. Les deux dictionnaires complets sont visibles dans un panneau à droite du moniteur ; le nombre de combinaisons n'est pas affiché pour le format étendu.
4. Se connecter avec l'un des trois secrets. Choisir Bob, un algorithme et ses paramètres, puis envoyer un message et consulter les calculs.
5. Se déconnecter, se connecter en Bob, déchiffrer le message : explication inverse et résultat s'affichent. Deux fenêtres privées distinctes permettent aussi deux sessions simultanées.
6. Essayer les trois algorithmes, les directions Caesar, les clés Playfair et les matrices Hill 2×2, 3×3, 4×4. Essayer une matrice non inversible pour montrer sa validation.

## Sémantique des tentatives

La protection est propre au compte et vérifiée dans le backend. Le même compteur est utilisé pour les trois formats et pour les échecs manuels et automatiques. Après les échecs 3 et 6, le compte est indisponible pendant 10 secondes. Le neuvième échec bloque le compte. Un succès remet le compteur à zéro. Les requêtes pendant une pause ne consomment aucun essai. L'attaque s'arrête à chaque pause et doit être relancée après celle-ci : elle reprend au candidat suivant, sans rejouer les précédents. La position est sauvegardée en SQLite séparément pour chaque utilisateur et chaque type, même après rechargement ou redémarrage. Un succès remet la recherche de ce type à son début ; le bouton de déblocage réinitialise toutes les positions du compte pour recommencer la démonstration. Désactiver la protection ne supprime ni un délai en cours ni un blocage existant. Les échecs pendant la désactivation ne sont pas comptés. Une seule attaque par compte est autorisée et les essais manuels attendent sa fin. La connexion automatique après découverte ne consomme aucune tentative supplémentaire et est réservée à la session ayant lancé l'attaque.

Une seconde protection, indépendante et désactivée par défaut, est disponible sous le rate limiting : **détection de cadence inhumaine**. Trois tentatives en moins de 500 ms, tous formats et méthodes confondus, provoquent un blocage immédiat et persistant du compte avec le motif explicite « Activité automatisée détectée ». Le troisième candidat est rejeté avant vérification du secret. Cette protection fonctionne même quand le rate limiting est désactivé. La désactiver ne débloque pas un compte déjà bloqué ; le bouton de démonstration reste nécessaire. Seules les tentatives effectivement admises hors pause sont observées, et une connexion réussie réinitialise l'historique de cadence. Le seuil est un choix pédagogique, pas une preuve absolue d'automatisation.

## Attaques et performance

Le premier dictionnaire est exactement `{0,1}³` (8 candidats), le deuxième `{1,2,3,4}⁴` (256 candidats), dans l'ordre lexicographique. Ils sont énumérés sans fichier externe. La force brute utilise les 94 caractères ASCII imprimables sans espace : minuscules, majuscules, chiffres, ponctuation, dont `+` et `*`. Sa longueur est connue du serveur et l'espace vaut `94^longueur`. Les secrets étendus initiaux ont deux caractères pour que la démonstration reste rapide.

Les candidats sont produits à la demande avec `itertools.product` pour les suffixes (mémoire constante), avec préchargement du sel et de l'empreinte et sans accès SQLite par candidat quand les deux protections sont désactivées. Une reprise accède directement à la position sauvegardée, sans réénumérer les candidats précédents. La politique est revérifiée toutes les 128 propositions dans le mode sans protection ; les changements de protection sont refusés pendant une attaque. Avec l'une ou l'autre protection, chaque candidat utilise le même contrôle atomique que le formulaire. Durée réelle, nombre d'essais et débit sont affichés. La durée inclut les contrôles du backend, sans le délai de rafraîchissement de l'écran. L'optimisation ne supprime pas la croissance exponentielle : de longs secrets peuvent rester impossibles à épuiser dans un temps raisonnable.

## Conventions de chiffrement

- Accents décomposés, majuscules A–Z uniquement ; espaces, chiffres et ponctuation retirés explicitement. Maximum 2 000 lettres par message.
- Caesar : A=0, décalage 0–25 à droite ou à gauche ; signe inversé au déchiffrement.
- Playfair : grille 5×5, clé MONARCHY par défaut, fusion I/J, paires répétées séparées par X (Q pour deux X), complément final de même règle. Les remplissages sont conservés au déchiffrement car leur suppression serait ambiguë.
- Hill : vecteurs colonnes, calcul modulo 26, dimensions 2–4. Les matrices doivent avoir un déterminant premier avec 26. Clés inversibles par défaut pour chaque dimension. Complément final X conservé au déchiffrement.
- La base stocke le texte chiffré et les paramètres, sans stocker le texte clair. Le serveur réserve le déchiffrement au destinataire. Les explications du chiffrement sont retournées à l'envoi ; celles du déchiffrement sont calculées à la demande.

## Intégrité SHA-256

Après connexion, ouvrir l'onglet **Intégrité**, choisir un destinataire et envoyer un message témoin. Cet espace est indépendant des chiffrements classiques : il conserve le texte exact, y compris accents, espaces, ponctuation et retours à la ligne (maximum 4 000 caractères). Le backend calcule SHA-256 sur les octets UTF-8 et enregistre une copie originale, une copie reçue et le hash envoyé. Les données persistent dans la table SQLite `integrity_messages`.

Se connecter ensuite au compte destinataire et sélectionner le message. L'interface affiche le message et le hash à l'envoi, le message reçu, le hash reçu et le hash recalculé. **Vérifier l'intégrité** compare les empreintes dans le backend. **Simuler la modification** utilise le texte modifié dans le champ prévu ; si rien n'est modifié, le bouton ajoute automatiquement « [modifié] ». Le hash envoyé reste intact : une erreur rouge signale que le hash recalculé ne correspond plus au hash reçu. **Rétablir le message original** restaure la copie reçue et fait repasser le contrôle au vert. Seul le destinataire peut vérifier, altérer ou restaurer sa copie ; les autres comptes n'accèdent pas au message.

Cette expérience suppose que le hash de référence est fiable. Un hash SHA-256 seul n'authentifie pas l'expéditeur et ne protège pas contre un attaquant qui pourrait remplacer simultanément le message et le hash.

## Limites pédagogiques

Cette application est conçue pour un TP local, pas pour protéger des communications réelles. Caesar, Playfair et Hill sont vulnérables à la cryptanalyse. Les clés sont transportées avec les messages pour permettre la démonstration ; aucun échange de clé sécurisé n'est implémenté.

Les mots de passe sont vérifiés via SHA-256 salé pour garder la recherche exhaustive observable rapidement. Cette fonction rapide et les secrets fournis ne conviennent pas à une authentification réelle, qui demanderait notamment Argon2id/scrypt, des secrets longs et aucun endpoint public de déblocage ou de révélation des identifiants. Les boutons de protection et déblocage sont volontairement accessibles dans ce laboratoire. La limitation porte sur le compte, pas sur l'adresse IP. Aucune attaque n'accepte de cible externe.

## Vérification

```powershell
python -m unittest discover -s tests -v
```

Les tests utilisent une base temporaire distincte, contrôlent les vecteurs de chiffrement, les tentatives partagées, les deux pauses simulées, le blocage final, les attaques et les autorisations des messages.
