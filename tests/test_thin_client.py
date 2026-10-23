"""Thin client never executes setup; all research requests remain idempotent."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import pytest

SCRIPT=Path(__file__).resolve().parents[1]/'skills/research/scripts/ask.py'
spec=importlib.util.spec_from_file_location('thin_client',SCRIPT)
client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
SID='11111111-1111-4111-8111-111111111111'
TID='22222222-2222-4222-8222-222222222222'

@pytest.fixture
def service(tmp_path,monkeypatch):
    key=tmp_path/'test-key.pem'
    subprocess.run(['/usr/bin/openssl','genrsa','-out',str(key),'3072'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    public=subprocess.check_output(['/usr/bin/openssl','rsa','-in',str(key),'-pubout'],stderr=subprocess.DEVNULL).decode()
    monkeypatch.setattr(client,'PUBLIC_KEY',public)
    instructions='Read HELPER_RUNNER_CONTEXT. This signed test text is not executable by the client.'
    document={'schema':1,'revision':'fixture','issued_at':time.time()-10,'expires_at':time.time()+3600,
              'model':client.EXPECTED_MODEL,'release':{'sha256':'a'*64},'model_catalog_sha256':'b'*64,
              'install_instructions':instructions,'reuse_instructions':'Verify existing connection.'}
    payload=json.dumps(document).encode();(tmp_path/'payload').write_bytes(payload)
    signature=subprocess.check_output(['/usr/bin/openssl','dgst','-sha256','-sign',str(key),str(tmp_path/'payload')])
    envelope={'signed_setup':{'payload':base64.b64encode(payload).decode(),'signature':base64.b64encode(signature).decode()}}
    evidence={'calls':[],'tasks':{},'setup_ready':False,'completed':False,'lost_ack':False,'downloads':0}
    report=b'# Report\nSource: https://example.com/source\n'
    def api(config,path,body=None,authenticated=True):
        evidence['calls'].append((path,body,authenticated))
        if path=='/api/admin/enrollments':return {'code':'fixture-enrollment'}
        if path=='/api/enroll/redeem':return {'device_id':body['device_id'],'device_token':'private-device-token'}
        if path=='/api/device/helper-bootstrap/direct-sessions':
            assert set(body)=={'provider','idempotency_key'}
            return {'id':SID,'instructions_url':'https://untrusted.example/never-fetch'}
        if path==client.PREFIX+'/'+SID:return {'id':SID,'status':'ready' if evidence['setup_ready'] else 'pending'}
        if path.endswith('/instructions'):return envelope
        if path=='/api/device/research/tasks':
            evidence['tasks'].setdefault(body['idempotency_key'], {'id':TID,'payload':body})
            assert evidence['tasks'][body['idempotency_key']]['payload']==body
            if evidence['lost_ack']:
                evidence['lost_ack']=False
                raise RuntimeError('Server connection failed')
            return {'task_id':TID,'state':'pending'}
        if path.startswith('/api/device/research/tasks/'):
            return {'id':TID,'device_id':config['device_id'],'state':'completed' if evidence['completed'] else 'pending',
                    'result':{'outputs':[{'id':'file','path':'report.md','size':len(report),'sha256':hashlib.sha256(report).hexdigest()}]}}
        raise AssertionError(path)
    def download(config,path,stream,size,digest):
        evidence['downloads']+=1
        assert hashlib.sha256(report).hexdigest()==digest
        stream.write(report)
    monkeypatch.setattr(client,'api',api)
    monkeypatch.setattr(client,'download',download)
    monkeypatch.setattr(client,'prerequisites',lambda provider:{provider:'/selected/'+provider})
    return tmp_path/'state',evidence,envelope


def test_first_use_returns_verified_instructions_without_execution(service):
    state,evidence,_=service
    output,code=client.submit(state,'research this','codex',client.SERVER)
    assert code==0 and output['status']=='setup_required'
    text=Path(output['instructions_path']).read_text()
    assert hashlib.sha256(text.encode()).hexdigest()==output['instructions_sha256']
    context=client.read(output['context_path'])
    assert context['installation_root']==str(state)
    assert context['credential_file']==str(state/'device.json')
    assert context['session_id']==SID and context['model']==client.EXPECTED_MODEL
    assert output['python_interpreter']==sys.executable
    assert 'private-device-token' not in json.dumps(output)
    assert len(evidence['tasks'])==1
    assert not any(path.endswith('/attempt') or 'untrusted.example' in path for path,_,_ in evidence['calls'])
    assert not (state/'runtime').exists()
    assert Path(output['context_path']).stat().st_mode & 0o777==0o600


def test_same_question_dedupes_and_lost_ack_recovers(service):
    state,evidence,_=service
    evidence['lost_ack']=True
    with pytest.raises(RuntimeError,match='connection failed'):
        client.submit(state,'same question','codex',client.SERVER)
    output,_=client.submit(state,'same question','codex',client.SERVER)
    again,_=client.submit(state,'same question','codex',client.SERVER)
    assert output['job_id']==again['job_id'] and len(evidence['tasks'])==1
    assert len(list((state/'jobs').glob('ask_*')))==1


def test_status_after_ready_and_verified_report_reuse(service):
    state,evidence,_=service
    first,_=client.submit(state,'test report','claude',client.SERVER)
    job=client.read(client.job_path(state,first['job_id'])/'receipt.json')
    pending,code=client.inspect(state,job,True)
    assert code==2 and pending['status']=='setup_required'
    evidence['setup_ready']=True
    pending,code=client.inspect(state,job,True)
    assert code==2 and pending['status']=='pending'
    evidence['completed']=True
    report,code=client.inspect(state,job,True)
    assert code==0 and report['status']=='ready'
    assert '# Report' in report['report'] and 'Untrusted' in report['content_trust']
    client.inspect(state,job,True)
    assert evidence['downloads']==1
    assert not any(path.endswith('/attempt') for path,_,_ in evidence['calls'])


def test_tampered_instructions_cannot_queue_research(service):
    state,evidence,envelope=service
    envelope['signed_setup']['payload']=base64.b64encode(b'{}').decode()
    with pytest.raises(RuntimeError,match='signature'):
        client.submit(state,'do not submit','codex',client.SERVER)
    assert not evidence['tasks']
    assert not (state/'verified-setup/context.json').exists()


def test_enrollment_uses_generic_label_no_hostname(service):
    state,evidence,_=service
    client.submit(state,'generic enrollment','codex',client.SERVER)
    enrolled=next(body for path,body,_ in evidence['calls'] if path=='/api/enroll/redeem')
    assert enrolled['label']=='Research PC' and enrolled['platform']=='darwin'
    session=next(body for path,body,_ in evidence['calls'] if path.endswith('/direct-sessions'))
    assert set(session)=={'provider','idempotency_key'}


def test_bad_prerequisites_do_not_create_state(tmp_path,monkeypatch):
    state=tmp_path/'uncreated'
    def fail(provider):raise RuntimeError('Broken Python')
    monkeypatch.setattr(client,'prerequisites',fail)
    with pytest.raises(RuntimeError,match='Broken Python'):client.submit(state,'question','codex',client.SERVER)
    assert not state.exists()


def test_client_has_no_agent_start_or_dynamic_code_execution():
    source=SCRIPT.read_text()
    assert 'Popen(' not in source
    assert 'start_new_session' not in source
    assert 'bypassPermissions' not in source
    assert 'danger-full-access' not in source
    assert source.count('subprocess.run(')==1
    assert "'/usr/bin/openssl', 'dgst', '-sha256', '-verify'" in source


def test_changed_setup_text_fails_and_repeat_question_refreshes(service):
    state,evidence,_=service
    first,_=client.submit(state,'drift test','codex',client.SERVER)
    instructions=Path(first['instructions_path'])
    instructions.write_text('changed commands')
    job=client.read(client.job_path(state,first['job_id'])/'receipt.json')
    with pytest.raises(RuntimeError,match='instructions changed'):client.inspect(state,job,False)
    refreshed,_=client.submit(state,'drift test','codex',client.SERVER)
    assert refreshed['job_id']==first['job_id'] and len(evidence['tasks'])==1
    assert 'changed commands' not in instructions.read_text()


def test_context_drift_or_foreign_paths_fail(service):
    state,_,_=service
    first,_=client.submit(state,'context test','codex',client.SERVER)
    session=client.read(state/'session.json')
    job=client.read(client.job_path(state,first['job_id'])/'receipt.json')
    with pytest.raises(RuntimeError,match='private paths'):
        client.setup_output(state,job,{**session,'instructions_path':'/elsewhere/setup.md'})
    context=client.read(first['context_path']);context['credential_file']='/elsewhere/private.json'
    client.save(first['context_path'],context)
    with pytest.raises(RuntimeError,match='context changed'):client.setup_output(state,job,session)


def test_pending_upload_and_unsafe_report_do_not_publish(service,monkeypatch):
    state,_,_=service
    first,_=client.submit(state,'outputs test','codex',client.SERVER)
    job=client.read(client.job_path(state,first['job_id'])/'receipt.json')
    config=client.read(state/'device.json')
    report={'id':'upload','path':'report.md','size':5,'sha256':hashlib.sha256(b'hello').hexdigest(),'delivery':'background'}
    monkeypatch.setattr(client,'api',lambda *a,**k:{'state':'uploading'})
    assert client.retrieve(state,job,config,{'result':{'outputs':[report]}}) is False
    assert not (client.job_path(state,job['job_id'])/'results/report.md').exists()
    with pytest.raises(RuntimeError,match='Unsafe'):
        client.retrieve(state,job,config,{'result':{'outputs':[{**report,'path':'../outside'},report]}})
    with pytest.raises(RuntimeError,match='did not provide'):
        client.retrieve(state,job,config,{'result':{'outputs':[{**report,'generated_response':True}]}})


def test_failed_download_does_not_publish_partial_report(service,monkeypatch):
    state,_,_=service
    first,_=client.submit(state,'bad download','codex',client.SERVER)
    job=client.read(client.job_path(state,first['job_id'])/'receipt.json')
    config=client.read(state/'device.json')
    def bad_download(config,path,stream,size,digest):
        stream.write(b'wrong')
        raise RuntimeError('Result checksum failed')
    monkeypatch.setattr(client,'download',bad_download)
    report={'id':'file','path':'report.md','size':5,'sha256':hashlib.sha256(b'hello').hexdigest()}
    with pytest.raises(RuntimeError,match='checksum'):
        client.retrieve(state,job,config,{'result':{'outputs':[report]}})
    folder=client.job_path(state,job['job_id'])/'results'
    assert not (folder/'report.md').exists() and not list(folder.glob('.download-*'))
