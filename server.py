import os, json, sqlite3, secrets, time, hmac
from pathlib import Path
from functools import wraps
from contextlib import contextmanager
from flask import Flask, request, jsonify, session, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).parent
DATA = Path(os.environ.get('NOCTUNE_DATA', str(ROOT / 'data')))
DATA.mkdir(parents=True, exist_ok=True)
MEDIA = DATA / 'audio'; MEDIA.mkdir(exist_ok=True)
secret_file = DATA / 'session.key'
if not secret_file.exists(): secret_file.write_text(secrets.token_hex(32)); secret_file.chmod(0o600)
setup_file = ROOT / 'ADMIN_SETUP.txt'
if not (DATA / 'setup.key').exists():
    token = secrets.token_urlsafe(24)
    (DATA / 'setup.key').write_text(token)
    (DATA / 'setup.key').chmod(0o600)
    setup_file.write_text('NOCTUNE — ADMIN SETUP\n\nOpen the live website, click Sign in, then Set up admin.\nEnter this one-time setup code:\n\n' + token + '\n\nChoose your own username and a password of at least 12 characters.\nKeep this file private. The setup code stops working after the first admin is created.\nDo not enter your hosting-provider passwords here.\n')
app = Flask(__name__, static_folder=None)
app.secret_key = secret_file.read_text()
app.config.update(MAX_CONTENT_LENGTH=32*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','1')=='1')
LIMIT = int(os.environ.get('MAX_STORAGE_MB','80'))*1024*1024
attempts = {}
@contextmanager
def connect():
    c=sqlite3.connect(DATA/'library.sqlite',timeout=20); c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    try:
        with c: yield c
    finally: c.close()
with connect() as c:
    c.executescript('''CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, password TEXT, admin INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS songs(id TEXT PRIMARY KEY,title TEXT,artist TEXT,mood TEXT,filename TEXT,path TEXT,size INTEGER,added INTEGER,plays INTEGER DEFAULT 0,download_allowed INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS likes(user_id TEXT,song_id TEXT,PRIMARY KEY(user_id,song_id),FOREIGN KEY(user_id) REFERENCES users(id),FOREIGN KEY(song_id) REFERENCES songs(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS playlists(user_id TEXT PRIMARY KEY,payload TEXT,FOREIGN KEY(user_id) REFERENCES users(id));''')
def user():
    with connect() as c:
        r=c.execute('SELECT id,username,admin FROM users WHERE id=?',(session.get('uid',''),)).fetchone()
        return dict(r) if r else None
def auth(admin=False):
    def wrap(fn):
        @wraps(fn)
        def run(*a,**kw):
            u=user()
            if not u: return jsonify(error='Please sign in first.'),401
            if admin and not u['admin']: return jsonify(error='Only the administrator can do that.'),403
            return fn(*a,**kw)
        return run
    return wrap
@app.before_request
def csrf():
    if request.method not in ('GET','HEAD','OPTIONS') and request.headers.get('X-Noctune')!='1': abort(403)
@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options']='nosniff'
    r.headers['Referrer-Policy']='same-origin'
    if request.path.startswith('/api/'): r.headers['Cache-Control']='no-store'
    return r
@app.errorhandler(413)
def too_big(e): return jsonify(error='File too large. Each upload must be under 30 MB.'),413
@app.errorhandler(400)
def bad(e): return jsonify(error='Invalid request.'),400
@app.errorhandler(403)
def forbidden(e): return jsonify(error='Request not permitted.'),403
@app.errorhandler(404)
def missing(e): return jsonify(error='Not found.'),404
@app.get('/')
def index(): return send_file(ROOT/'index.html')
@app.get('/api/state')
def state():
    u=user()
    with connect() as c:
        liked={r[0] for r in c.execute('SELECT song_id FROM likes WHERE user_id=?',(u['id'] if u else '',))}
        songs=[]
        for r in c.execute('SELECT * FROM songs ORDER BY added DESC'):
            s=dict(r);s.pop('path');s['liked']=s['id'] in liked;s['lastPlayed']=0;s['download_allowed']=bool(s['download_allowed']);songs.append(s)
        p=c.execute('SELECT payload FROM playlists WHERE user_id=?',(u['id'] if u else '',)).fetchone()
        admin_exists=bool(c.execute('SELECT 1 FROM users WHERE admin=1').fetchone())
    return jsonify(user=u,songs=songs,playlists=json.loads(p[0]) if p else [],setupRequired=not admin_exists,storageLimit=LIMIT,storageUsed=sum(s['size'] for s in songs))
@app.post('/api/auth/<action>')
def login(action):
    d=request.get_json() or {}; name=str(d.get('username','')).strip();pw=str(d.get('password',''))
    # Bound password work and failed attempts; no third-party authentication service.
    if len(name)>60 or len(pw)>256: abort(400)
    key=request.remote_addr or 'unknown'; now=time.time()
    attempts[key]=[t for t in attempts.get(key,[]) if now-t<300]
    if len(attempts[key])>=30:return jsonify(error='Too many attempts. Wait five minutes.'),429
    attempts[key].append(now)
    if action=='logout':session.clear();return jsonify(ok=True)
    if action not in ('login','register','setup'):abort(404)
    with connect() as c:
        if action in ('register','setup'):
            if len(name)<3 or len(pw)<12:return jsonify(error='Use a username of 3–60 characters and a password of at least 12 characters.'),400
            c.execute('BEGIN IMMEDIATE')
            if action=='setup':
                if c.execute('SELECT 1 FROM users WHERE admin=1').fetchone():return jsonify(error='An administrator is already configured.'),403
                if not hmac.compare_digest(str(d.get('code','')), (DATA/'setup.key').read_text()):return jsonify(error='Incorrect setup code.'),403
            if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]>=200:return jsonify(error='Preview account limit reached.'),409
            uid=secrets.token_hex(16)
            try:c.execute('INSERT INTO users VALUES(?,?,?,?)',(uid,name,generate_password_hash(pw),int(action=='setup')))
            except sqlite3.IntegrityError:return jsonify(error='That username is already taken.'),409
        else:
            r=c.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone()
            if not r or not check_password_hash(r['password'],pw):return jsonify(error='Incorrect username or password.'),401
            uid=r['id']
    session.clear();session['uid']=uid
    return jsonify(ok=True)
@app.post('/api/songs')
@auth(admin=True)
def upload():
    if request.form.get('rights')!='yes':return jsonify(error='Confirm you have permission to publish this music.'),400
    f=request.files.get('file')
    if not f or not f.filename:abort(400)
    name=secure_filename(f.filename) or 'track.mp3';ext=Path(name).suffix.lower()
    types={'.mp3':'audio/mpeg','.m4a':'audio/mp4','.wav':'audio/wav','.ogg':'audio/ogg','.flac':'audio/flac','.aac':'audio/aac'}
    if ext not in types:return jsonify(error='Choose MP3, M4A, WAV, OGG, FLAC, or AAC.'),400
    content=f.read(30*1024*1024+1);size=len(content)
    if size>30*1024*1024 or size<12:return jsonify(error='Audio must be between 12 bytes and 30 MB.'),400
    valid=(content[:3]==b'ID3' or content[0]==255 and content[1]&224==224 or content[:4] in (b'RIFF',b'OggS',b'fLaC') or content[4:8]==b'ftyp')
    if not valid:return jsonify(error='This file does not look like supported audio.'),400
    sid=secrets.token_hex(16);path=MEDIA/(sid+ext)
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        used,count=c.execute('SELECT COALESCE(SUM(size),0),COUNT(*) FROM songs').fetchone()
        if count>=1000 or used+size>LIMIT:return jsonify(error='Preview storage limit reached. Move to permanent storage before adding more music.'),409
        title=request.form.get('title',Path(f.filename).stem).strip()[:200] or 'Untitled'
        artist=request.form.get('artist','Unknown artist').strip()[:200] or 'Unknown artist'
        path.write_bytes(content)
        try:c.execute('INSERT INTO songs VALUES(?,?,?,?,?,?,?,?,?,?)',(sid,title,artist,request.form.get('mood','Unsorted')[:100],name,path.name,size,int(time.time()*1000),0,int(request.form.get('download')=='yes')))
        except Exception:path.unlink(missing_ok=True);raise
    return jsonify(ok=True,id=sid),201
@app.patch('/api/songs/<sid>')
@auth(admin=True)
def edit(sid):
    d=request.get_json() or {}
    with connect() as c:
        if not c.execute('SELECT 1 FROM songs WHERE id=?',(sid,)).fetchone():abort(404)
        c.execute('UPDATE songs SET title=?,artist=?,mood=?,download_allowed=? WHERE id=?',(str(d.get('title','Untitled'))[:200],str(d.get('artist','Unknown artist'))[:200],str(d.get('mood','Unsorted'))[:100],int(bool(d.get('download_allowed'))),sid))
    return jsonify(ok=True)
@app.delete('/api/songs/<sid>')
@auth(admin=True)
def delete(sid):
    with connect() as c:
        r=c.execute('SELECT path FROM songs WHERE id=?',(sid,)).fetchone()
        if not r:abort(404)
        c.execute('DELETE FROM songs WHERE id=?',(sid,))
    (MEDIA/r['path']).unlink(missing_ok=True)
    return jsonify(ok=True)
@app.get('/media/<sid>')
def media(sid):
    with connect() as c:r=c.execute('SELECT * FROM songs WHERE id=?',(sid,)).fetchone()
    if not r:abort(404)
    downloading=request.args.get('download')=='1'
    if downloading and not r['download_allowed']:abort(403)
    types={'.mp3':'audio/mpeg','.m4a':'audio/mp4','.wav':'audio/wav','.ogg':'audio/ogg','.flac':'audio/flac','.aac':'audio/aac'}
    return send_file(MEDIA/r['path'],mimetype=types.get(Path(r['path']).suffix,'application/octet-stream'),conditional=True,as_attachment=downloading,download_name=r['filename'])
@app.post('/api/songs/<sid>/play')
def play(sid):
    # At most one counted play per song/session per minute.
    key='played:'+sid
    if time.time()-session.get(key,0)>60:
        with connect() as c:c.execute('UPDATE songs SET plays=plays+1 WHERE id=?',(sid,))
        session[key]=time.time()
        keys=[k for k in session if k.startswith('played:')]
        if len(keys)>20:session.pop(min(keys,key=lambda k:session[k]),None)
    return jsonify(ok=True)
@app.put('/api/likes/<sid>')
@auth()
def like(sid):
    with connect() as c:
        if not c.execute('SELECT 1 FROM songs WHERE id=?',(sid,)).fetchone():abort(404)
        if (request.get_json() or {}).get('liked'):c.execute('INSERT OR IGNORE INTO likes VALUES(?,?)',(session['uid'],sid))
        else:c.execute('DELETE FROM likes WHERE user_id=? AND song_id=?',(session['uid'],sid))
    return jsonify(ok=True)
@app.put('/api/playlists')
@auth()
def playlists():
    p=request.get_json()
    if not isinstance(p,list) or len(p)>100:abort(400)
    clean=[]
    with connect() as c:
        valid={r[0] for r in c.execute('SELECT id FROM songs')}
        for x in p:
            if not isinstance(x,dict) or not isinstance(x.get('ids'),list):abort(400)
            clean.append({'id':str(x.get('id',''))[:80],'name':str(x.get('name','Playlist'))[:70],'ids':list(dict.fromkeys(str(i) for i in x['ids'][:1000] if str(i) in valid))})
        c.execute('INSERT OR REPLACE INTO playlists VALUES(?,?)',(session['uid'],json.dumps(clean)))
    return jsonify(ok=True)
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT','3001')),debug=False)
