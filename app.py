from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime,timezone
import os,psycopg
from psycopg.rows import dict_row
app=FastAPI(title='UNG-AEGIS',version='0.1.0'); DB=os.getenv('DATABASE_URL','')
def auth(p,h):
 if p not in {x.strip() for x in (h or '').split(',')} and 'ung.admin' not in (h or ''): raise HTTPException(403,'JANUS permission required')
def db(): return psycopg.connect(DB,row_factory=dict_row)
@app.on_event('startup')
def init():
 if DB:
  with db() as c:c.execute('CREATE TABLE IF NOT EXISTS aegis_policies(id UUID PRIMARY KEY,name TEXT,scope TEXT,action TEXT,enabled BOOLEAN,created_at TIMESTAMPTZ)');c.execute('CREATE TABLE IF NOT EXISTS aegis_decisions(id UUID PRIMARY KEY,policy_id UUID,subject TEXT,resource TEXT,decision TEXT,created_at TIMESTAMPTZ)')
class Policy(BaseModel): name:str;scope:str;action:str;enabled:bool=True
class Evaluate(BaseModel): subject:str;resource:str;scope:str;action:str
@app.get('/health')
def health():return {'status':'ok','service':'UNG-AEGIS','version':'0.1.0'}
@app.get('/ready')
def ready():
 try:
  with db() as c:c.execute('SELECT 1')
  return {'status':'ready','database':'connected'}
 except:return {'status':'degraded','database':'unavailable'}
@app.get('/v1/system')
def system():return {'system_id':'UNG-AEGIS','domain':'protective-policy-enforcement','capabilities':['protection-policies','access-enforcement','decision-audit']}
@app.get('/v1/policies')
def policies(x_ung_permissions:str|None=Header(None)):
 auth('aegis.policies.read',x_ung_permissions)
 with db() as c:return c.execute('SELECT * FROM aegis_policies ORDER BY created_at DESC').fetchall()
@app.post('/v1/policies',status_code=201)
def add_policy(b:Policy,x_ung_permissions:str|None=Header(None)):
 auth('aegis.policies.write',x_ung_permissions);i=str(uuid4());t=datetime.now(timezone.utc)
 with db() as c:return c.execute('INSERT INTO aegis_policies VALUES(%s,%s,%s,%s,%s,%s) RETURNING *',(i,b.name,b.scope,b.action,b.enabled,t)).fetchone()
@app.post('/v1/evaluate')
def evaluate(b:Evaluate,x_ung_permissions:str|None=Header(None)):
 auth('aegis.evaluate',x_ung_permissions)
 with db() as c:
  p=c.execute('SELECT * FROM aegis_policies WHERE enabled=true AND scope=%s AND action=%s ORDER BY created_at DESC LIMIT 1',(b.scope,b.action)).fetchone();d='allow' if p else 'deny';r=c.execute('INSERT INTO aegis_decisions VALUES(%s,%s,%s,%s,%s,%s) RETURNING *',(str(uuid4()),p['id'] if p else None,b.subject,b.resource,d,datetime.now(timezone.utc))).fetchone();return r
