import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
SOURCE=Path(os.environ.get('RESEARCH_SERVER_SOURCE',str(Path(__file__).resolve().parents[3]/'production/server')))
if not SOURCE.is_dir():pytest.skip('Set RESEARCH_SERVER_SOURCE',allow_module_level=True)
sys.path.insert(0,str(SOURCE));sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
from app import create_app
from store import Store

@pytest.fixture
def system(tmp_path,monkeypatch):
    release=tmp_path/'release';release.mkdir();data=b'archive';sha=hashlib.sha256(data).hexdigest();manifest={'sha256':sha,'version':'direct-test'}
    (release/(sha+'.zip')).write_bytes(data);(release/'current.json').write_text(json.dumps(manifest))
    payload={'schema':1,'revision':'direct-test','issued_at':time.time()-1,'expires_at':time.time()+3600,'model':'abliterated-model-large-flash','release':manifest,'model_catalog_sha256':'a'*64,'install_instructions':'Signed installation instructions only','reuse_instructions':'Signed reuse instructions'}
    envelope={'payload':base64.b64encode(json.dumps(payload).encode()).decode(),'signature':base64.b64encode(b'server-shape-test-client-verifies-RSA').decode()}
    signed=tmp_path/'signed.json';signed.write_text(json.dumps(envelope))
    monkeypatch.setenv('HELPER_BOOTSTRAP_RELEASES',str(release));monkeypatch.setenv('HELPER_BOOTSTRAP_SIGNED_SETUP',str(signed))
    store=Store(tmp_path/'db','a'*40,'b'*40);app=create_app(store);client=TestClient(app)
    def enroll(name):
        data=store.redeem(store.enroll()['code'],name,'nonce-123456789012345',name,'Darwin')
        return data['device_id'],{'Authorization':'Bearer '+data['device_token']}
    device,h=enroll('direct-device-12345678');other,oh=enroll('other-device-123456789')
    return store,client,device,h,other,oh,envelope

def create(c,h,**extra):
    return c.post('/api/device/helper-bootstrap/direct-sessions',headers=h,json={'provider':'codex','idempotency_key':'direct-key-12345',**extra})

def test_direct_signed_idempotence_no_local_paths_no_model_token(system):
    store,c,device,h,other,oh,envelope=system
    first=create(c,h);assert first.status_code==200,first.text
    session=first.json();assert create(c,h).json()['id']==session['id']
    base='/api/device/helper-bootstrap/sessions/'+session['id']
    assert c.get(base,headers=oh).status_code==404
    assert c.get(base+'/instructions',headers=oh).status_code==404
    instructions=c.get(base+'/instructions',headers=h).json()
    assert instructions['signed_setup']==envelope
    assert instructions['instructions']=='Signed installation instructions only'
    assert c.post(base+'/attempt',headers=h,json={'previous_runner_stopped':True}).status_code==409
    assert create(c,h,installation_root='/Users/private').status_code==422
    assert create(c,{}).status_code==401
    assert create(c,h,provider='claude').status_code==409
    with store.db() as db:
        row=db.execute('SELECT document FROM helper_bootstrap_sessions WHERE id=?',(session['id'],)).fetchone()
        assert set(json.loads(row['document']))=={'provider','idempotency_key','origin','release','model','signed_setup','executor'}
        assert db.execute('SELECT count(*) FROM helper_bootstrap_tokens').fetchone()[0]==0
    assert create(c,oh).json()['id']!=session['id']

def test_direct_heartbeat_gates_queued_task(system,monkeypatch):
    store,c,device,h,other,oh,envelope=system
    session=create(c,h).json();base='/api/device/helper-bootstrap/sessions/'+session['id']
    task=store.create_task(device,'Research','Question','codex','research','task-key-12345')['task_id']
    assert not store.work(device)['can_start'] and store.claim(device,'worker')['task'] is None
    now=time.time()+1;monkeypatch.setattr(time,'time',lambda:now)
    store.heartbeat(device,{'source':'helper','instance_id':'one'})
    assert c.get(base,headers=h).json()['status']=='pending'
    now+=15;store.heartbeat(device,{'source':'helper','instance_id':'one'})
    assert c.get(base,headers=h).json()['status']=='ready'
    assert store.claim(device,'worker')['task']['id']==task
    assert c.post(base+'/attempt',headers=h,json={'previous_runner_stopped':True}).status_code==409

def test_direct_requires_configured_signed_envelope(system,monkeypatch):
    store,c,device,h,other,oh,envelope=system
    monkeypatch.delenv('HELPER_BOOTSTRAP_SIGNED_SETUP')
    assert create(c,h).status_code==503
    with store.db() as db:assert db.execute('SELECT count(*) FROM helper_bootstrap_sessions').fetchone()[0]==0
