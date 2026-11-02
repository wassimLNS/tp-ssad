import hashlib
import itertools
import json
import secrets
import sqlite3
import string
import threading
import time
from pathlib import Path
from contextlib import contextmanager
from flask import Flask, request, jsonify, session, send_from_directory
from crypto_lab import transform

ROOT = Path(__file__).parent
app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=65536, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict')
DB = ROOT/'lab.sqlite3'
LOCK = threading.RLock()
JOBS = {}
ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
DEMO = {'alice': ['101','1234','a+'], 'bob': ['011','2341','b*'], 'charlie': ['110','3412','c1']}

@contextmanager
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    try:
        with c:
            yield c
    finally:
        c.close()

def digest(salt, password):
    return hashlib.sha256((salt+password).encode()).hexdigest()

def init():
    with db() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt TEXT, hashes TEXT, length INTEGER, failures INTEGER DEFAULT 0, until REAL DEFAULT 0, blocked INTEGER DEFAULT 0, protection INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, algorithm TEXT, params TEXT, ciphertext TEXT, created REAL);''')
        for name, passwords in DEMO.items():
            salt = secrets.token_hex(16)
            c.execute('INSERT OR IGNORE INTO users(name,salt,hashes,length) VALUES(?,?,?,?)',(name,salt,json.dumps([digest(salt,p) for p in passwords]),len(passwords[2])))

def user(name):
    with db() as c: return c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()

def status(name):
    u = user(name)
    if u is None: raise ValueError('Compte inconnu.')
    return {k:u[k] for k in ('name','failures','blocked','protection','length')} | {'remaining':max(0,u['until']-time.time())}

def attempt(name, kind, password):
    with LOCK:
        u = user(name)
        if u['blocked']: return {'state':'blocked'}
        if u['until'] > time.time(): return {'state':'cooldown'}
        if secrets.compare_digest(digest(u['salt'],password),json.loads(u['hashes'])[kind]):
            with db() as c: c.execute('UPDATE users SET failures=0,until=0 WHERE name=?',(name,))
            return {'state':'success'}
        if u['protection']:
            count = u['failures']+1
            with db() as c:
                c.execute('UPDATE users SET failures=?,until=?,blocked=? WHERE name=?',(count,time.time()+10 if count%3==0 and count<9 else 0,int(count>=9),name))
            return {'state':'blocked' if count>=9 else 'cooldown' if count%3==0 else 'failure'}
        return {'state':'failure'}

def worker(job):
    start = time.perf_counter()
    u = user(job['user']); kind=job['kind']
    alphabet = '01' if kind==0 else '1234' if kind==1 else ALPHABET
    length = 3 if kind==0 else 4 if kind==1 else u['length']
    target = json.loads(u['hashes'])[kind]; salt=u['salt']
    try:
        for chars in itertools.product(alphabet,repeat=length):
            if job['cancel']: job['state']='cancelled'; break
            candidate = ''.join(chars)
            # Protected path uses precisely the same atomic operation as manual login.
            # Unprotected path avoids SQLite per candidate; recheck policy every 128 guesses.
            if job['attempts']%128==0:
                u=user(job['user'])
            if u['protection'] or u['blocked'] or u['until']>time.time():
                with LOCK:
                    current=status(job['user'])
                    if current['blocked'] or current['remaining']>0:
                        job['state']='blocked' if current['blocked'] else 'cooldown'
                        break
                    result=attempt(job['user'],kind,candidate)
            else:
                result={'state':'success' if secrets.compare_digest(digest(salt,candidate),target) else 'failure'}
                if result['state']=='success': result=attempt(job['user'],kind,candidate)
            job['attempts']+=1; job['candidate']=candidate
            if result['state']!='failure':
                job['state']=result['state']
                if result['state']=='success': job['found']=candidate
                break
        else: job['state']='exhausted'
    except Exception:
        job['state']='error'
    finally:
        job['elapsed']=time.perf_counter()-start

@app.errorhandler(ValueError)
def bad(e): return jsonify(error=str(e)),400

@app.get('/')
def index(): return send_from_directory('static','index.html')

@app.get('/api/state')
def state(): return jsonify(users=[status(n) for n in DEMO], current=session.get('user'), alphabet=ALPHABET, credentials=DEMO)

@app.post('/api/protection')
def protection():
    data=request.get_json(); name=data['user']; status(name)
    with LOCK, db() as c: c.execute('UPDATE users SET protection=? WHERE name=?',(int(bool(data['enabled'])),name))
    return jsonify(status(name))

@app.post('/api/unlock')
def unlock():
    name=request.get_json()['user']; status(name)
    with LOCK:
        for j in JOBS.values():
            if j['user']==name and j['state']=='running': raise ValueError('Arrêtez l’attaque avant de débloquer le compte.')
        with db() as c: c.execute('UPDATE users SET failures=0,until=0,blocked=0 WHERE name=?',(name,))
    return jsonify(status(name))

@app.post('/api/login')
def login():
    d=request.get_json(); name=d['user']; status(name); kind=int(d['kind'])
    if kind not in (0,1,2): raise ValueError('Type invalide.')
    with LOCK:
        if any(j['state']=='running' and j['user']==name for j in JOBS.values()): raise ValueError('Arrêtez l’attaque avant une tentative manuelle.')
        result=attempt(name,kind,str(d.get('password','')))
    if result['state']=='success': session['user']=name
    return jsonify(result | {'account':status(name)})

@app.post('/api/logout')
def logout(): session.clear(); return jsonify(ok=True)

@app.post('/api/attack')
def attack():
    d=request.get_json(); name=d['user']; status(name); kind=int(d['kind'])
    if kind not in (0,1,2): raise ValueError('Type invalide.')
    with LOCK:
        if any(j['state']=='running' and j['user']==name for j in JOBS.values()): raise ValueError('Une attaque est déjà en cours pour ce compte.')
        jid=secrets.token_urlsafe(20)
        job={'id':jid,'user':name,'kind':kind,'state':'running','attempts':0,'candidate':'','found':None,'elapsed':0,'cancel':False}
        JOBS[jid]=job
        threading.Thread(target=worker,args=(job,),daemon=True).start()
    return jsonify(id=jid)

@app.route('/api/attack/<jid>',methods=['GET','DELETE'])
def job(jid):
    if jid not in JOBS: raise ValueError('Attaque inconnue.')
    j=JOBS[jid]
    if request.method=='DELETE': j['cancel']=True
    return jsonify({k:v for k,v in j.items() if k!='cancel'})

def authenticated():
    if session.get('user') not in DEMO: raise ValueError('Connectez-vous pour accéder à la messagerie.')
    return session['user']

@app.route('/api/messages',methods=['GET','POST'])
def messages():
    name=authenticated()
    if request.method=='GET':
        with db() as c:
            rows=c.execute('SELECT * FROM messages WHERE sender=? OR recipient=? ORDER BY id DESC',(name,name)).fetchall()
        return jsonify(messages=[dict(r) for r in rows])
    d=request.get_json(); recipient=d.get('recipient')
    if recipient not in DEMO or recipient==name: raise ValueError('Choisissez un autre destinataire.')
    params=d.get('params',{}); algorithm=d.get('algorithm'); trace=transform(d.get('text',''),algorithm,params)
    with db() as c: c.execute('INSERT INTO messages(sender,recipient,algorithm,params,ciphertext,created) VALUES(?,?,?,?,?,?)',(name,recipient,algorithm,json.dumps(params),trace['result'],time.time()))
    return jsonify(trace=trace)

@app.post('/api/messages/<int:mid>/decrypt')
def decrypt(mid):
    name=authenticated()
    with db() as c: m=c.execute('SELECT * FROM messages WHERE id=? AND recipient=?',(mid,name)).fetchone()
    if m is None: raise ValueError('Seul le destinataire peut déchiffrer ce message.')
    return jsonify(trace=transform(m['ciphertext'],m['algorithm'],json.loads(m['params']),True))

@app.after_request
def headers(response):
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    return response

init()
if __name__=='__main__':
    print('SSAD Cipher Lab : http://127.0.0.1:5000',flush=True)
    app.run(host='127.0.0.1',port=5000,threaded=True,debug=False)
