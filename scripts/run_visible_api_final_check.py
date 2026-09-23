#!/usr/bin/env python3
"""Run the eight exposed questions through an isolated real API and worker.

Preserves the reviewed source scope; never makes new sources eligible just to
obtain a passing answer. Credentials are written privately and never printed.
"""
import hashlib
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT=Path(__file__).resolve().parents[1]
STATE='ge-dev-chat-20260923-r6'
RUN=ROOT/'data/development-runtime'/STATE
PY=str(ROOT/'.venv/bin/python')


def main():
    global STATE,RUN
    parser=argparse.ArgumentParser()
    parser.add_argument('--state',default=STATE)
    parser.add_argument('--only',nargs='*')
    args=parser.parse_args()
    if not __import__('re').fullmatch(r'ge-dev-chat-20260923-r\d+',args.state):raise ValueError('Invalid run ID')
    STATE=args.state;RUN=ROOT/'data/development-runtime'/STATE
    candidate='ge-dev-chat-eng-'+STATE.rsplit('-',1)[-1]
    if RUN.exists():raise RuntimeError('Run identity is already spent')
    for port in (8776,8777):
        with socket.socket() as sock:
            if sock.connect_ex(('127.0.0.1',port))==0:raise RuntimeError('Expected port is already owned')
    previous=json.loads((ROOT/'data/development-runtime/ge-dev-chat-20260923-r5/GE-QWEN-DEVELOPMENT-RETRIEVAL.json').read_text())
    command=[PY,'-m','scripts.ge_qwen_prepare_development_retrieval','--state-id',STATE,
             '--candidate-build-id',candidate,'--subject',previous['subject']]
    for key in ('generation','prepared_build','complete_context'):
        command += ['--'+key.replace('_','-'),previous[key]['path']]
    for row in previous['retrievals']:command+=['--retrieval',row['path']]
    for row in previous['sources']:
        command+=['--source','|'.join(row[k] for k in ('capture_sha256','source_sha256','source_identity_id','title','canonical_url','source_type'))]
    prepared=json.loads(subprocess.check_output(command,cwd=ROOT,text=True))
    scope='Owner FINAL CHECK: five exposed GE cases, two essays and one PB, signed-in Codex, output validation and non-weight fixes. Isolated development only; no ACTIVE, source admission, training or protected-bank access.\n'
    (RUN/'OWNER-DEVELOPMENT-SCOPE.md').write_text(scope)
    env={**os.environ,'PYTHONPATH':'backend','LEGALBOT_DEVELOPMENT_STATE_ID':STATE,
         'LEGALBOT_DEVELOPMENT_CANDIDATE_BUILD_ID':candidate,
         'LEGALBOT_DEVELOPMENT_RETRIEVAL_MANIFEST_SHA256':prepared['manifest_sha256'],
         'LEGALBOT_ENV':'development','LEGALBOT_HOST':'127.0.0.1','LEGALBOT_PORT':'8776',
         'LEGALBOT_LIVE_PROFILE':'standard','LEGALBOT_TEST_MODE':'false',
         'LEGALBOT_OFFICIAL_RESEARCH_ENABLED':'false','LEGALBOT_XERJ_ENABLED':'false',
         'LEGALBOT_PHOENIX_ENABLED':'false','LEGALBOT_ONLINE_MODE':'local_only',
         'LEGALBOT_MODEL_URL':'http://127.0.0.1:8778','LEGALBOT_MODEL_ID':'mlx-community/Qwen3.5-9B-4bit'}
    env.pop('LEGALBOT_DEVELOPMENT_CHAT_AUTHORITY_SHA256',None)
    authority=json.loads(subprocess.check_output([PY,'scripts/ge_prepare_development_chat.py',
        '--run-id',STATE,'--owner-scope-sha256',hashlib.sha256(scope.encode()).hexdigest(),
        '--hours','2','--codex-model','gpt-5.5','--codex-auth-mode','chatgpt_signin'],cwd=ROOT,env=env,text=True))
    fd=os.open(RUN/'.owner-access-key',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as handle:handle.write(authority['access_key_once'])
    env['LEGALBOT_DEVELOPMENT_CHAT_AUTHORITY_SHA256']=authority['authority_sha256']
    headers={'X-Development-Chat-Authority-SHA256':authority['authority_sha256'],
             'X-Development-Chat-Access-Key':authority['access_key_once'],
             'X-Development-Chat-Route':'codex_bridge','X-Development-Chat-Remote-Consent':'yes'}
    logs=RUN/'logs';logs.mkdir(exist_ok=True)
    processes=[];handles=[];results=[]
    try:
        for name,process_args in [('api',[PY,'-m','uvicorn','app.api:app','--host','127.0.0.1','--port','8776']),
                          ('worker',[PY,'-m','app.cli','worker'])]:
            handle=(logs/f'final-{name}.log').open('x');handles.append(handle)
            processes.append(subprocess.Popen(process_args,cwd=ROOT,env=env,stdout=handle,stderr=handle,start_new_session=True))
        with httpx.Client(base_url='http://127.0.0.1:8776',timeout=15,trust_env=False) as client:
            for _ in range(60):
                try:
                    response=client.get('/health')
                    if response.status_code in (200,404):break
                except httpx.ConnectError:pass
                time.sleep(.5)
            bank=json.loads((ROOT/'data/evaluations/visible-final-check-20260923/PRACTICE-QUESTIONS-50.json').read_text())
            for row in [r for r in bank['questions'] if r['selected_for_visible_run']]:
                turns=[(row['id'],row['question'])]
                if row.get('follow_up'):turns.append((row['id']+'-followup',row['question']+'\n\n'+row['follow_up']))
                for case_id,question in turns:
                    if args.only and case_id not in args.only:continue
                    response=client.post('/api/v1/questions',headers={**headers,'X-Idempotency-Key':STATE+'-'+case_id},json={
                        'question':question,'task_type':row['task_type'],
                        'jurisdiction':'England' if 'followup' in case_id else row['jurisdiction'],
                        'as_of_date':row['as_of_date'],'word_target':row['word_target'],'online_mode':'local_only'})
                    result={'case_id':case_id,'http_status':response.status_code}
                    if response.status_code==202:
                        job_id=response.json()['job_id'];result['job_id']=job_id
                        for _ in range(600):
                            status=client.get('/api/v1/jobs/'+job_id,headers=headers)
                            status.raise_for_status();job=status.json()
                            if job.get('status') in ('completed','held_for_review','system_error','cancelled','failed'):
                                result['terminal']=job;break
                            time.sleep(1)
                        else:result['terminal']={'status':'test_deadline_exceeded'}
                    else:result['response']=response.json()
                    results.append(result)
                    (RUN/(case_id+'-RESULT.json')).write_text(json.dumps(result,indent=2)+'\n')
                    print(json.dumps({'case_id':case_id,'http_status':result['http_status'],
                                      'status':result.get('terminal',{}).get('status')}),flush=True)
    finally:
        for process in processes:
            if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
        for process in processes:
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
        for handle in handles:handle.close()
        (RUN/'FINAL-CHECK.json').write_text(json.dumps({'state_id':STATE,'authority_sha256':authority['authority_sha256'],
            'retrieval_manifest_sha256':prepared['manifest_sha256'],'results':results,
            'owned_services_stopped':all(p.poll() is not None for p in processes),
            'source_scope':'England consumer-law 2026-09-05','current_date_source_scope_expanded':False},indent=2)+'\n')

if __name__=='__main__':main()
