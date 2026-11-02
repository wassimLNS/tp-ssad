"""Classical ciphers, with reproducible teaching traces (Latin A-Z)."""
import math
import unicodedata


# ============================================================================
# OUTILS COMMUNS : NORMALISATION ET CALCUL MATRICIEL
# Alphabet A-Z, determinant, adjointe et inverse de matrice modulo 26.
# ============================================================================
def normalize_latin_letters(text):
    return ''.join(c for c in unicodedata.normalize('NFD', text).upper() if 'A' <= c <= 'Z')


def calculate_matrix_determinant(m):
    if len(m) == 1:
        return m[0][0]
    return sum((-1)**j * m[0][j] * calculate_matrix_determinant([r[:j]+r[j+1:] for r in m[1:]]) for j in range(len(m)))


def calculate_matrix_adjugate(m):
    n = len(m)
    return [[(-1)**(i+j) * calculate_matrix_determinant([r[:i]+r[i+1:] for k,r in enumerate(m) if k != j]) for j in range(n)] for i in range(n)]


def calculate_matrix_inverse_mod26(m):
    d = calculate_matrix_determinant(m) % 26
    if math.gcd(d, 26) != 1:
        raise ValueError('Matrice non inversible modulo 26 : le déterminant doit être premier avec 26.')
    return [[(pow(d, -1, 26) * x) % 26 for x in row] for row in calculate_matrix_adjugate(m)]


# ============================================================================
# CHIFFREMENT / DECHIFFREMENT : LES TROIS ALGORITHMES
# decrypt=False pour chiffrer ; decrypt=True pour dechiffrer.
# Chaque branche renvoie le resultat et les etapes expliquees dans l'interface.
# ============================================================================
def encrypt_or_decrypt_message(text, algorithm, params, decrypt=False):
    source = normalize_latin_letters(text)
    if not source:
        raise ValueError('Saisissez au moins une lettre latine.')
    if len(source) > 2000:
        raise ValueError('Maximum : 2 000 lettres par message.')
    steps = []
    info = {'normalized': source, 'steps': steps}
    # ========================================================================
    # CAESAR : DECALAGE DES LETTRES MODULO 26
    # La direction fixe le signe ; le dechiffrement inverse ce signe.
    # ========================================================================
    if algorithm == 'caesar':
        shift = int(params.get('shift', 3))
        if not 0 <= shift <= 25:
            raise ValueError('Le décalage doit être entre 0 et 25.')
        direction = params.get('direction', 'right')
        if direction not in ('right', 'left'):
            raise ValueError('Direction invalide.')
        k = shift * (1 if direction == 'right' else -1) * (-1 if decrypt else 1)
        result = ''
        for c in source:
            x = ord(c)-65
            y = (x+k) % 26
            result += chr(y+65)
            steps.append(f'{c} ({x}) → ({x} + ({k})) mod 26 = {y} → {chr(y+65)}')
        info['rule'] = f'Alphabet A=0…Z=25 ; décalage effectif {k} modulo 26.'
    # ========================================================================
    # PLAYFAIR : GRILLE 5 x 5 ET SUBSTITUTION PAR PAIRES
    # Preparation des paires, puis regles ligne / colonne / rectangle.
    # ========================================================================
    elif algorithm == 'playfair':
        # Playfair prepares digraphs before substitution; retain filler letters to avoid ambiguous removal.
        key = normalize_latin_letters(str(params.get('key', 'MONARCHY'))).replace('J','I')
        if not key:
            raise ValueError('La clé Playfair doit contenir une lettre.')
        grid = ''.join(dict.fromkeys(key+'ABCDEFGHIKLMNOPQRSTUVWXYZ'))
        info['grid'] = [list(grid[i:i+5]) for i in range(0,25,5)]
        source = source.replace('J','I')
        pairs = []
        i = 0
        if decrypt and len(source) % 2:
            raise ValueError('Le texte Playfair chiffré doit avoir une longueur paire.')
        while i < len(source):
            a = source[i]
            filler = 'Q' if a == 'X' else 'X'
            if decrypt:
                b = source[i+1]; i += 2
            elif i+1 == len(source) or source[i+1] == a:
                b = filler; i += 1
            else:
                b = source[i+1]; i += 2
            pairs.append(a+b)
        result = ''
        delta = -1 if decrypt else 1
        for pair in pairs:
            a,b = pair
            r,c = divmod(grid.index(a),5); s,t = divmod(grid.index(b),5)
            if r == s:
                out = grid[r*5+(c+delta)%5]+grid[s*5+(t+delta)%5]; rule = 'même ligne'
            elif c == t:
                out = grid[((r+delta)%5)*5+c]+grid[((s+delta)%5)*5+t]; rule = 'même colonne'
            else:
                out = grid[r*5+t]+grid[s*5+c]; rule = 'rectangle : échange des colonnes'
            result += out; steps.append(f'{pair} → {out} · {rule}')
        info['prepared'] = ''.join(pairs)
        info['rule'] = 'Grille 5 × 5 ; J devient I. Insertion de X (ou Q entre deux X). Les lettres de remplissage sont conservées au déchiffrement car leur suppression serait ambiguë.'
    # ========================================================================
    # HILL : MULTIPLICATION MATRICIELLE MODULO 26
    # Chiffrement avec K ; dechiffrement avec K^-1.
    # Calcul de l'inverse et explication de chaque bloc de lettres.
    # ========================================================================
    elif algorithm == 'hill':
        # Keep the original key separate from its inverse and from the matrix used for this operation.
        # The trace exposes the determinant, modular inverse and adjugate used to construct K^-1.
        m = params.get('matrix', [[3,3],[2,5]])
        if not isinstance(m,list) or len(m) not in (2,3,4) or any(not isinstance(r,list) or len(r)!=len(m) for r in m):
            raise ValueError('Choisissez une matrice carrée de dimension 2, 3 ou 4.')
        if any(type(x) is not int or abs(x)>10000 for row in m for x in row):
            raise ValueError('Les coefficients doivent être des entiers entre -10 000 et 10 000.')
        m = [[x%26 for x in r] for r in m]
        inv = calculate_matrix_inverse_mod26(m)
        used = inv if decrypt else m
        n = len(m)
        if decrypt and len(source)%n:
            raise ValueError('La longueur du texte Hill doit être un multiple de la dimension.')
        padding = (-len(source))%n
        source += 'X'*padding
        determinant = calculate_matrix_determinant(m)
        d = determinant % 26
        scalar = pow(d, -1, 26)
        determinant_formula = f'{m[0][0]} × {m[1][1]} − {m[0][1]} × {m[1][0]} = ' if n == 2 else ''
        info.update(matrix=used, key_matrix=m, inverse=inv, operation='decrypt' if decrypt else 'encrypt', padding=padding, prepared=source,
                    inverse_calculation={
                        'determinant':determinant, 'det_mod':d, 'scalar_inverse':scalar,
                        'adjugate':calculate_matrix_adjugate(m),
                        'steps':[
                            f'Déterminant : det(K) = {determinant_formula}{determinant} ≡ {d} (mod 26).',
                            f'PGCD({d}, 26) = 1 : K est inversible. L’inverse de {d} modulo 26 est {scalar}, car {d} × {scalar} = {d*scalar} ≡ 1 (mod 26).',
                            'On calcule la comatrice (cofacteurs signés), puis on la transpose pour obtenir adj(K).',
                            f'K⁻¹ = {scalar} × adj(K) mod 26 : chaque coefficient est multiplié par {scalar}, puis réduit modulo 26.'
                        ]})
        result = ''
        for i in range(0,len(source),n):
            block = source[i:i+n]; v = [ord(c)-65 for c in block]
            sums = [sum(a*b for a,b in zip(row,v)) for row in used]
            out = ''.join(chr(x%26+65) for x in sums)
            result += out
            symbol = 'K⁻¹' if decrypt else 'K'
            steps.append(f'{block} → vecteur {v} ; {symbol} × v = {sums} ; mod 26 → {[x%26 for x in sums]} → {out}')
        info['rule'] = 'Vecteurs colonnes, A=0…Z=25. C = K × P mod 26 ; P = K⁻¹ × C mod 26. Complément par X, conservé au déchiffrement.'
    else:
        raise ValueError('Algorithme inconnu.')
    info['result'] = result
    return info
