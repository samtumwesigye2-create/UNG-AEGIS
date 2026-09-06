from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime,timezone
import json,os,psycopg,urllib.error,urllib.request
from psycopg.rows import dict_row
app=FastAPI(title='UNG-AEGIS',version='0.2.0'); DB=os.getenv('DATABASE_URL',''); JANUS_BASE_URL=os.getenv('JANUS_BASE_URL','https://ung-iam-production.up.railway.app').rstrip('/')
def auth(p,h):
 if not h or not h.lower().startswith('bearer '): raise HTTPException(401,'JANUS bearer token required')
 req=urllib.request.Request(JANUS_BASE_URL+'/v1/auth/introspect',data=b'',method='POST',headers={'Authorization':h})
 try:
  with urllib.request.urlopen(req,timeout=5) as r:d=json.loads(r.read().decode())
 except urllib.error.HTTPError as e:
  if e.code in (401,403): raise HTTPException(401,'JANUS token invalid or expired')
  raise HTTPException(503,'JANUS authorization unavailable')
 except Exception: raise HTTPException(503,'JANUS authorization unavailable')
 principal=d.get('principal') or {}; perms=set(principal.get('permissions') or [])
 if p not in perms and 'ung.admin' not in perms: raise HTTPException(403,f'Missing JANUS permission: {p}')
 return principal
def db(): return psycopg.connect(DB,row_factory=dict_row)
@app.on_event('startup')
def init():
 if DB:
  with db() as c:c.execute('CREATE TABLE IF NOT EXISTS aegis_policies(id UUID PRIMARY KEY,name TEXT,scope TEXT,action TEXT,enabled BOOLEAN,created_at TIMESTAMPTZ)');c.execute('CREATE TABLE IF NOT EXISTS aegis_decisions(id UUID PRIMARY KEY,policy_id UUID,subject TEXT,resource TEXT,decision TEXT,created_at TIMESTAMPTZ)')
class Policy(BaseModel): name:str;scope:str;action:str;enabled:bool=True
class Evaluate(BaseModel): subject:str;resource:str;scope:str;action:str
@app.get('/health')
def health():return {'status':'ok','service':'UNG-AEGIS','version':'0.2.0'}
@app.get('/ready')
def ready():
 try:
  with db() as c:c.execute('SELECT 1')
  return {'status':'ready','database':'connected','janus':JANUS_BASE_URL}
 except:return {'status':'degraded','database':'unavailable','janus':JANUS_BASE_URL}
@app.get('/v1/system')
def system():return {'system_id':'UNG-AEGIS','domain':'protective-policy-enforcement','capabilities':['protection-policies','access-enforcement','decision-audit','janus-bearer-auth']}
@app.get('/v1/policies')
def policies(authorization:str|None=Header(None)):
 auth('aegis.policies.read',authorization)
 with db() as c:return c.execute('SELECT * FROM aegis_policies ORDER BY created_at DESC').fetchall()
@app.post('/v1/policies',status_code=201)
def add_policy(b:Policy,authorization:str|None=Header(None)):
 auth('aegis.policies.write',authorization);i=str(uuid4());t=datetime.now(timezone.utc)
 with db() as c:return c.execute('INSERT INTO aegis_policies VALUES(%s,%s,%s,%s,%s,%s) RETURNING *',(i,b.name,b.scope,b.action,b.enabled,t)).fetchone()
@app.post('/v1/evaluate')
def evaluate(b:Evaluate,authorization:str|None=Header(None)):
 auth('aegis.evaluate',authorization)
 with db() as c:
  p=c.execute('SELECT * FROM aegis_policies WHERE enabled=true AND scope=%s AND action=%s ORDER BY created_at DESC LIMIT 1',(b.scope,b.action)).fetchone();d='allow' if p else 'deny';r=c.execute('INSERT INTO aegis_decisions VALUES(%s,%s,%s,%s,%s,%s) RETURNING *',(str(uuid4()),p['id'] if p else None,b.subject,b.resource,d,datetime.now(timezone.utc))).fetchone();return r
