import hashlib
import itertools
import json
import logging
import secrets
import sqlite3
import string
import threading
import time
from pathlib import Path
from contextlib import contextmanager
from flask import Flask, request, jsonify, session, send_from_directory
from crypto_lab import encrypt_or_decrypt_message

ROOT = Path(__file__).parent
app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=65536, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict')
DB = ROOT/'lab.sqlite3'
LOCK = threading.RLock()
JOBS = {}
ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
DEMO = {'alice': ['101','1234','a+'], 'bob': ['011','2341','b*'], 'charlie': ['110','3412','c1']}

# ============================================================================
# BASE DE DONNEES SQLITE
# Connexions, creation des tables et conservation des donnees apres redemarrage.
# ============================================================================
@contextmanager
def open_database_connection():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    try:
        with c:
            yield c
    finally:
        c.close()

def hash_salted_password(salt, password):
    return hashlib.sha256((salt+password).encode()).hexdigest()

def initialize_database_and_demo_accounts():
    with open_database_connection() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hashes TEXT, length INTEGER, failures INTEGER DEFAULT 0, until REAL DEFAULT 0, blocked INTEGER DEFAULT 0, protection INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, algorithm TEXT, params TEXT, ciphertext TEXT, created REAL);
        CREATE TABLE IF NOT EXISTS integrity_messages(id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, original_text TEXT, received_text TEXT, sent_hash TEXT, created REAL);
        CREATE TABLE IF NOT EXISTS attack_progress(name TEXT, kind INTEGER, next_index INTEGER DEFAULT 0, PRIMARY KEY(name,kind));''')
        columns = {r['name'] for r in c.execute('PRAGMA table_info(users)')}
        for column, definition in [('speed_protection','INTEGER DEFAULT 0'),('block_reason',"TEXT DEFAULT ''"),('recent_attempts',"TEXT DEFAULT '[]'"),('demo_passwords','TEXT')]:
            if column not in columns:
                c.execute(f'ALTER TABLE users ADD COLUMN {column} {definition}')
        for name, passwords in DEMO.items():
            salt = secrets.token_hex(16)
            c.execute('INSERT OR IGNORE INTO users(name,salt,hashes,length) VALUES(?,?,?,?)',(name,salt,json.dumps([hash_salted_password(salt,p) for p in passwords]),len(passwords[2])))
            c.execute('UPDATE users SET demo_passwords=? WHERE name=? AND demo_passwords IS NULL',(json.dumps(passwords),name))

def get_user_record(name):
    with open_database_connection() as c: return c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()

def get_account_security_status(name):
    u = get_user_record(name)
    if u is None: raise ValueError('Compte inconnu.')
    with open_database_connection() as c:
        progress = {str(r['kind']):r['next_index'] for r in c.execute('SELECT kind,next_index FROM attack_progress WHERE name=?',(name,))}
    return {k:u[k] for k in ('name','failures','blocked','protection','speed_protection','block_reason','length')} | {'remaining':max(0,u['until']-time.time()), 'progress':progress}

# ============================================================================
# AUTHENTIFICATION ET PROTECTIONS : POINT DE CONTROLE COMMUN
# Les essais manuels et les attaques protegees passent tous par verify_password_and_apply_protections().
# Le verrou protege la verification et la mise a jour des compteurs partages.
# ============================================================================
def verify_password_and_apply_protections(name, kind, password):
    with LOCK:
        u = get_user_record(name)
        if u['blocked']: return {'state':'blocked','consumed':False}
        now = time.time()
        if u['until'] > now: return {'state':'cooldown','consumed':False}
        if u['speed_protection']:
            # DETECTION DE CADENCE : 3 essais en moins de 500 ms bloquent le compte.
            recent = [t for t in json.loads(u['recent_attempts']) if now-t < 0.5]
            recent.append(now)
            with open_database_connection() as c:
                c.execute('UPDATE users SET recent_attempts=? WHERE name=?',(json.dumps(recent),name))
                if len(recent) >= 3:
                    reason = 'Activité automatisée détectée : 3 tentatives en moins de 500 ms, une cadence inhumaine.'
                    c.execute('UPDATE users SET blocked=1,block_reason=? WHERE name=?',(reason,name))
                    return {'state':'blocked','consumed':True,'reason':reason}
        if secrets.compare_digest(hash_salted_password(u['salt'],password),json.loads(u['hashes'])[kind]):
            with open_database_connection() as c: c.execute("UPDATE users SET failures=0,until=0,recent_attempts='[]' WHERE name=?",(name,))
            return {'state':'success','consumed':True}
        if u['protection']:
            # RATE LIMITING : pause de 10 s aux echecs 3 et 6 ; blocage au 9e.
            count = u['failures']+1
            with open_database_connection() as c:
                c.execute('UPDATE users SET failures=?,until=?,blocked=?,block_reason=? WHERE name=?',(count,now+10 if count%3==0 and count<9 else 0,int(count>=9),'Rate limiting : 9 échecs de connexion sur ce compte.' if count>=9 else '',name))
            return {'state':'blocked' if count>=9 else 'cooldown' if count%3==0 else 'failure','consumed':True}
        return {'state':'failure','consumed':True}

# ============================================================================
# ATTAQUES PAR DICTIONNAIRE ET FORCE BRUTE
# generate_password_candidates_from_index() reprend directement a l'index sauvegarde, sans rejouer les essais.
# run_password_attack() teste les candidats dans un thread et sauvegarde la prochaine position.
# ============================================================================
def generate_password_candidates_from_index(alphabet, length, start):
    """Jump directly to the saved index, then enumerate suffixes in C, without replay."""
    if start >= len(alphabet)**length:
        return
    digits = [0]*length
    for i in range(length-1,-1,-1):
        start, digits[i] = divmod(start,len(alphabet))
    yield ''.join(alphabet[d] for d in digits)
    for pivot in range(length-1,-1,-1):
        prefix = ''.join(alphabet[d] for d in digits[:pivot])
        for digit in range(digits[pivot]+1,len(alphabet)):
            for suffix in itertools.product(alphabet,repeat=length-pivot-1):
                yield prefix+alphabet[digit]+''.join(suffix)

def save_attack_resume_position(name, kind, index):
    with open_database_connection() as c:
        c.execute('INSERT INTO attack_progress(name,kind,next_index) VALUES(?,?,?) ON CONFLICT(name,kind) DO UPDATE SET next_index=excluded.next_index',(name,kind,index))

def run_password_attack(job):
    start = time.perf_counter()
    u = get_user_record(job['user']); kind=job['kind']
    alphabet = '01' if kind==0 else '1234' if kind==1 else ALPHABET
    # TYPES 0/1 : dictionnaires exhaustifs ; TYPE 2 : force brute a longueur connue.
    length = 3 if kind==0 else 4 if kind==1 else u['length']
    target = json.loads(u['hashes'])[kind]; salt=u['salt']
    next_index = job.get('start_index',0)
    try:
        for candidate in generate_password_candidates_from_index(alphabet,length,next_index):
            if job['cancel']: job['state']='cancelled'; break
            # Protected path uses precisely the same atomic operation as manual login.
            # Unprotected path avoids SQLite per candidate; recheck policy every 128 guesses.
            if job['attempts']%128==0:
                u=get_user_record(job['user'])
            if u['protection'] or u['speed_protection'] or u['blocked'] or u['until']>time.time():
                with LOCK:
                    current=get_account_security_status(job['user'])
                    if current['blocked'] or current['remaining']>0:
                        job['state']='blocked' if current['blocked'] else 'cooldown'
                        break
                    result=verify_password_and_apply_protections(job['user'],kind,candidate)
            else:
                result={'state':'success' if secrets.compare_digest(hash_salted_password(salt,candidate),target) else 'failure','consumed':True}
                if result['state']=='success': result=verify_password_and_apply_protections(job['user'],kind,candidate)
            if result.get('consumed',True):
                job['attempts']+=1; job['candidate']=candidate
                next_index+=1
            if result['state']!='failure':
                job['state']=result['state']
                if result['state']=='success': job['found']=candidate
                break
        else: job['state']='exhausted'
    except Exception:
        job['state']='error'
    finally:
        with LOCK:
            save_attack_resume_position(job['user'],kind,0 if job['state']=='success' else next_index)
        job['next_index']=next_index
        job['elapsed']=time.perf_counter()-start

@app.errorhandler(ValueError)
def respond_to_validation_error(e): return jsonify(error=str(e)),400

@app.get('/')
def serve_application_page(): return send_from_directory('static','index.html')

# ============================================================================
# COMPTES ET MOTS DE PASSE PERSONNALISABLES
# Validation des formats, mise a jour des secrets, deblocage et connexion manuelle.
# ============================================================================
@app.get('/api/state')
def get_application_state(): return jsonify(users=[get_account_security_status(n) for n in DEMO], current=session.get('user'), alphabet=ALPHABET, credentials={n:json.loads(get_user_record(n)['demo_passwords']) for n in DEMO})

@app.post('/api/passwords')
def update_demo_account_password():
    d=request.get_json(); name=d.get('user'); get_account_security_status(name)
    kind=d.get('kind'); password=d.get('password')
    if type(kind) is not int or kind not in (0,1,2): raise ValueError('Type de mot de passe invalide.')
    if not isinstance(password,str): raise ValueError('Saisissez un mot de passe.')
    if kind==0 and (len(password)!=3 or any(c not in '01' for c in password)):
        raise ValueError('Binaire : exactement 3 caractères parmi 0 et 1.')
    if kind==1 and (len(password)!=4 or any(c not in '1234' for c in password)):
        raise ValueError('Numérique : exactement 4 caractères parmi 1, 2, 3 et 4.')
    if kind==2 and (not 1<=len(password)<=32 or any(c not in ALPHABET for c in password)):
        raise ValueError('Étendu : 1 à 32 caractères ASCII imprimables, sans espace.')
    with LOCK:
        if any(j['state']=='running' and j['user']==name for j in JOBS.values()): raise ValueError('Arrêtez l’attaque avant de modifier le mot de passe.')
        u=get_user_record(name); passwords=json.loads(u['demo_passwords']); hashes=json.loads(u['hashes'])
        passwords[kind]=password; hashes[kind]=hash_salted_password(u['salt'],password)
        with open_database_connection() as c:
            c.execute("UPDATE users SET demo_passwords=?,hashes=?,length=?,failures=0,until=0,blocked=0,block_reason='',recent_attempts='[]' WHERE name=?",(json.dumps(passwords),json.dumps(hashes),len(passwords[2]),name))
            c.execute('DELETE FROM attack_progress WHERE name=? AND kind=?',(name,kind))
        for j in JOBS.values():
            if j['user']==name: j['claimed']=True
    return jsonify(ok=True,account=get_account_security_status(name))

@app.post('/api/protection')
def update_account_protection_setting():
    data=request.get_json(); name=data['user']; get_account_security_status(name)
    setting=data.get('setting','protection')
    if setting not in ('protection','speed_protection'): raise ValueError('Protection inconnue.')
    with LOCK, open_database_connection() as c:
        if any(j['state']=='running' and j['user']==name for j in JOBS.values()): raise ValueError('Arrêtez l’attaque avant de modifier les protections.')
        c.execute(f"UPDATE users SET {setting}=?,recent_attempts='[]' WHERE name=?",(int(bool(data['enabled'])),name))
    return jsonify(get_account_security_status(name))

@app.post('/api/unlock')
def unlock_account_and_reset_attempts():
    name=request.get_json()['user']; get_account_security_status(name)
    with LOCK:
        for j in JOBS.values():
            if j['user']==name and j['state']=='running': raise ValueError('Arrêtez l’attaque avant de débloquer le compte.')
        with open_database_connection() as c:
            c.execute("UPDATE users SET failures=0,until=0,blocked=0,block_reason='',recent_attempts='[]' WHERE name=?",(name,))
            c.execute('DELETE FROM attack_progress WHERE name=?',(name,))
    return jsonify(get_account_security_status(name))

@app.post('/api/login')
def authenticate_manual_login():
    d=request.get_json(); name=d['user']; get_account_security_status(name); kind=int(d['kind'])
    if kind not in (0,1,2): raise ValueError('Type invalide.')
    with LOCK:
        if any(j['state']=='running' and j['user']==name for j in JOBS.values()): raise ValueError('Arrêtez l’attaque avant une tentative manuelle.')
        result=verify_password_and_apply_protections(name,kind,str(d.get('password','')))
    if result['state']=='success': session['user']=name
    return jsonify(result | {'account':get_account_security_status(name)})

@app.post('/api/logout')
def clear_authenticated_session(): session.clear(); return jsonify(ok=True)

# ============================================================================
# COMMANDES DES ATTAQUES ET CONNEXION AUTOMATIQUE
# Demarrer, suivre et arreter un job ; connecter sa session apres un succes.
# Le thread ne peut pas creer le cookie : la route /connect termine la connexion.
# ============================================================================
@app.post('/api/attack')
def start_password_attack():
    d=request.get_json(); name=d['user']; get_account_security_status(name); kind=int(d['kind'])
    if kind not in (0,1,2): raise ValueError('Type invalide.')
    with LOCK:
        if any(j['state']=='running' and j['user']==name for j in JOBS.values()): raise ValueError('Une attaque est déjà en cours pour ce compte.')
        if get_account_security_status(name)['blocked'] or get_account_security_status(name)['remaining']>0: raise ValueError('Le compte est bloqué ou en pause de sécurité.')
        with open_database_connection() as c:
            saved=c.execute('SELECT next_index FROM attack_progress WHERE name=? AND kind=?',(name,kind)).fetchone()
        start_index=saved['next_index'] if saved else 0
        jid=secrets.token_urlsafe(20)
        job={'id':jid,'user':name,'kind':kind,'state':'running','attempts':0,'candidate':'','found':None,'elapsed':0,'cancel':False,'start_index':start_index,'next_index':start_index,'owner':session.setdefault('attack_owner',secrets.token_urlsafe(24))}
        JOBS[jid]=job
        threading.Thread(target=run_password_attack,args=(job,),daemon=True).start()
    return jsonify(id=jid)

@app.route('/api/attack/<jid>',methods=['GET','DELETE'])
def get_attack_status_or_request_cancellation(jid):
    if jid not in JOBS: raise ValueError('Attaque inconnue.')
    j=JOBS[jid]
    if j.get('owner') != session.get('attack_owner'): raise ValueError('Cette attaque appartient à une autre session.')
    if request.method=='DELETE': j['cancel']=True
    return jsonify({k:v for k,v in j.items() if k not in ('cancel','owner')})

@app.post('/api/attack/<jid>/connect')
def connect_session_after_successful_attack(jid):
    with LOCK:
        j=JOBS.get(jid)
        if not j or j.get('owner') != session.get('attack_owner'): raise ValueError('Attaque inconnue pour cette session.')
        if j['state']!='success' or j.get('claimed'): raise ValueError('Aucune authentification réussie à valider.')
        u=get_account_security_status(j['user'])
        if u['blocked'] or u['remaining']>0: raise ValueError('Le compte est actuellement bloqué ou en pause.')
        j['claimed']=True
        session['user']=j['user']
    return jsonify(current=j['user'])

def require_authenticated_user():
    if session.get('user') not in DEMO: raise ValueError('Connectez-vous pour accéder à la messagerie.')
    return session['user']

# ============================================================================
# MESSAGERIE : ENVOI, RECEPTION, DECHIFFREMENT ET REINITIALISATION
# Stockage du texte chiffre et des parametres ; dechiffrement reserve au recepteur.
# Les calculs des trois chiffrements se trouvent dans crypto_lab.py.
# ============================================================================
@app.route('/api/messages',methods=['GET','POST','DELETE'])
def handle_cipher_message_requests():
    name=require_authenticated_user()
    if request.method=='DELETE':
        with open_database_connection() as c:
            count=c.execute('DELETE FROM messages').rowcount
        return jsonify(ok=True,deleted=count)
    if request.method=='GET':
        with open_database_connection() as c:
            rows=c.execute('SELECT * FROM messages WHERE sender=? OR recipient=? ORDER BY id DESC',(name,name)).fetchall()
        return jsonify(messages=[dict(r) for r in rows])
    d=request.get_json(); recipient=d.get('recipient')
    if recipient not in DEMO or recipient==name: raise ValueError('Choisissez un autre destinataire.')
    params=d.get('params',{}); algorithm=d.get('algorithm'); trace=encrypt_or_decrypt_message(d.get('text',''),algorithm,params)
    with open_database_connection() as c: c.execute('INSERT INTO messages(sender,recipient,algorithm,params,ciphertext,created) VALUES(?,?,?,?,?,?)',(name,recipient,algorithm,json.dumps(params),trace['result'],time.time()))
    return jsonify(trace=trace)

@app.post('/api/messages/<int:mid>/decrypt')
def decrypt_received_message(mid):
    name=require_authenticated_user()
    with open_database_connection() as c: m=c.execute('SELECT * FROM messages WHERE id=? AND recipient=?',(mid,name)).fetchone()
    if m is None: raise ValueError('Seul le destinataire peut déchiffrer ce message.')
    return jsonify(trace=encrypt_or_decrypt_message(m['ciphertext'],m['algorithm'],json.loads(m['params']),True))

# ============================================================================
# INTEGRITE SHA-256 ET SIMULATION DE MODIFICATION
# Le hash envoye reste fixe ; on recalcule le hash de la copie recue en UTF-8.
# Modifier cette copie provoque une difference ; la restauration retablit l'egalite.
# ============================================================================
def compare_sent_and_received_hashes(m):
    data=dict(m)
    data['received_hash']=hashlib.sha256(m['received_text'].encode('utf-8')).hexdigest()
    data['valid']=secrets.compare_digest(m['sent_hash'],data['received_hash'])
    return data

def get_integrity_message_for_recipient(mid):
    name=require_authenticated_user()
    with open_database_connection() as c:
        m=c.execute('SELECT * FROM integrity_messages WHERE id=? AND recipient=?',(mid,name)).fetchone()
    if m is None: raise ValueError('Seul le destinataire peut vérifier ou modifier la copie reçue.')
    return m

@app.route('/api/integrity',methods=['GET','POST'])
def handle_integrity_message_requests():
    name=require_authenticated_user()
    if request.method=='GET':
        with open_database_connection() as c:
            rows=c.execute('SELECT * FROM integrity_messages WHERE sender=? OR recipient=? ORDER BY id DESC',(name,name)).fetchall()
        return jsonify(messages=[compare_sent_and_received_hashes(m) for m in rows])
    d=request.get_json(); recipient=d.get('recipient'); text=d.get('text')
    if recipient not in DEMO or recipient==name: raise ValueError('Choisissez un autre destinataire.')
    if not isinstance(text,str) or not text.strip() or len(text)>4000: raise ValueError('Saisissez un message de 1 à 4 000 caractères.')
    sent_hash=hashlib.sha256(text.encode('utf-8')).hexdigest()
    with open_database_connection() as c:
        cur=c.execute('INSERT INTO integrity_messages(sender,recipient,original_text,received_text,sent_hash,created) VALUES(?,?,?,?,?,?)',(name,recipient,text,text,sent_hash,time.time()))
        mid=cur.lastrowid
        m=c.execute('SELECT * FROM integrity_messages WHERE id=?',(mid,)).fetchone()
    return jsonify(message=compare_sent_and_received_hashes(m))

@app.post('/api/integrity/<int:mid>/verify')
def verify_received_message_integrity(mid):
    return jsonify(message=compare_sent_and_received_hashes(get_integrity_message_for_recipient(mid)))

@app.post('/api/integrity/<int:mid>/tamper')
def modify_or_restore_received_integrity_message(mid):
    m=get_integrity_message_for_recipient(mid); d=request.get_json()
    if d.get('restore') is True:
        text=m['original_text']
    else:
        text=d.get('text')
        if not isinstance(text,str) or len(text)>4000: raise ValueError('Maximum : 4 000 caractères dans la copie reçue.')
        if text==m['original_text']: raise ValueError('Modifiez le message pour simuler une altération.')
    with open_database_connection() as c:
        c.execute('UPDATE integrity_messages SET received_text=? WHERE id=?',(text,mid))
        m=c.execute('SELECT * FROM integrity_messages WHERE id=?',(mid,)).fetchone()
    return jsonify(message=compare_sent_and_received_hashes(m))

# --- Local application entry point and common response headers. ---
@app.after_request
def add_common_response_headers(response):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    return response

initialize_database_and_demo_accounts()
if __name__=='__main__':
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    print('SSAD Cipher Lab : http://127.0.0.1:5000',flush=True)
    app.run(host='127.0.0.1',port=5000,threaded=True,debug=False)
