"""No real models, bank reads, or filesystem changes in continuation gate tests."""
from pathlib import Path
from types import SimpleNamespace
from contextlib import nullcontext
from unittest.mock import patch
import sys

import pytest


def forbidden_runner_call(*args, **kwargs):
    raise AssertionError('synthetic test attempted an unbound runner API')


# Import coordinators without the model/runtime dependency tree or any real run
# bindings. Every effect exercised below uses explicit synthetic implementations.
runner_stub = SimpleNamespace(
    PRIVATE=Path('/synthetic/restricted'), PUBLIC=Path('/synthetic/public'),
    AUTHOR_PROMPT='synthetic author', ORACLE_PROMPT='synthetic oracle',
    BANK_REVIEW_PROMPT='synthetic review', safe_path=lambda p:None,
    **dict.fromkeys(('require_scope_amendment', 'prepare_oracles', 'prepare_fixtures',
                     'collect', 'status', 'invoke', 'read'), forbidden_runner_call))
with patch.dict(sys.modules, {'scripts.run_ge_codex_unseen': runner_stub}):
    from scripts.continue_authorized_ge_codex_unseen import continue_route
    from scripts import continue_authorized_ge_codex_unseen as controller


def harness(monkeypatch):
    events=[]
    writes={}
    monkeypatch.setattr(Path,"exists",lambda p:p.name in writes)
    monkeypatch.setattr(controller.creation, 'coordinator_lock', lambda r:nullcontext())
    monkeypatch.setattr(controller.creation, 'active_jobs', lambda r=None:0)
    def event(name,result=None):
        def call(*args):
            events.append((name,*args))
            return result
        return call
    def write(path, value):
        if path.name in writes:
            raise FileExistsError('synthetic create-only write')
        writes[path.name] = value
    r=SimpleNamespace(ROOT=Path('/synthetic'),PUBLIC=Path('/synthetic/public'),RUN_ID='synthetic',
        safe_path=lambda p:None,require_execution_authority=event('authority'),
        write=write,read=lambda p:writes[p.name],seal=lambda x:x,sha=lambda p:'synthetic-hash',
        digest=lambda x:'synthetic-digest',seal_bank=event('seal',{'bank_sealed':True}),
        prepare_candidates=event('freeze'),run=event('run'),
        prepare_followups=event('followup-preparation'),prepare_reviews=event('review-preparation'),
        finalise=event('finalise',{'overall_state':'SYNTHETIC_COMPLETE'}))
    monkeypatch.setattr(controller,'require_research_runtime',lambda r:event('research',{'status':'PASS'})())
    monkeypatch.setattr(controller,'require_plan_execution',lambda r:event('plan',{'accepted_plan_sha256':'plan-hash'})())
    monkeypatch.setattr(controller,'_pid_running',lambda pid:False)
    return r,events,writes,event


@pytest.mark.parametrize('status,terminal,ready',[
    ('NOT_TERMINAL',False,False),('CREATED',True,False),('NO_OP',True,False),
    ('NOT_TERMINAL',True,True),('CREATED',False,True)])
def test_construction_gap_never_reaches_candidate(monkeypatch,status,terminal,ready):
    r,events,writes,event=harness(monkeypatch)
    result=continue_route(r,event('drain'),lambda r:{'status':status,'outcome':{
        'terminal':terminal,'construction_ready':ready,'overall_state':'SYNTHETIC_HOLD'}})
    assert result['candidate_executed'] is False
    assert events==[('authority',),('drain',)]
    assert writes['CONTINUOUS-RUN-START.json']['training'] is False


def ready(r):
    return {'status':'CREATED','outcome':{'terminal':True,'construction_ready':True}}


def test_bank_gate_remains_mandatory_after_construction_flags(monkeypatch):
    r,events,writes,event=harness(monkeypatch)
    r.seal_bank=event('seal',{'bank_sealed':False,'construction_holds':1})
    result=continue_route(r,event('drain'),ready)
    assert result['candidate_executed'] is False
    assert events==[('authority',),('drain',),('research',),('seal',)]
    assert 'CONTINUOUS-SEAL-HOLD.json' in writes


def test_authorized_pass_uses_all_gates_and_each_stage_once(monkeypatch):
    r,events,writes,event=harness(monkeypatch)
    assert continue_route(r,event('drain'),ready)=={'overall_state':'SYNTHETIC_COMPLETE'}
    assert events==[('authority',),('drain',),('research',),('seal',),('research',),('freeze',),('run','candidate'),
        ('followup-preparation',),('run','followup'),('review-preparation',),
        ('run','review'),('finalise',)]


def test_frozen_runtime_error_stops_before_model_without_retry(monkeypatch):
    r,events,writes,event=harness(monkeypatch)
    def fail():
        events.append(('freeze-failed',))
        raise RuntimeError('synthetic private detail')
    r.prepare_candidates=fail
    with pytest.raises(RuntimeError):
        continue_route(r,event('drain'),ready)
    assert not any(x[0]=='run' for x in events)
    failure=writes['CONTINUOUS-RUN-FAILURE.json']
    assert failure['stage']=='RUNTIME_FREEZE' and failure['automatic_retry'] is False
    assert 'synthetic private detail' not in str(failure)


@pytest.mark.parametrize('existing',['CONTINUOUS-RUN-START.json','BANK-SEAL.json',
    'RUN-FREEZE.json','ONE-PASS-START.json','STATE-TRANSITION-RECEIPT.json'])
def test_existing_attempt_or_later_gate_cannot_replay(monkeypatch,existing):
    r,events,writes,event=harness(monkeypatch)
    monkeypatch.setattr(Path,'exists',lambda p:p.name==existing)
    with pytest.raises(RuntimeError,match='already attempted'):
        continue_route(r,event('drain'),ready)
    assert events==[('authority',)] and not writes


def test_creation_supervisor_stops_when_upstream_hold_prevents_downstream_jobs(monkeypatch):
    supervisor = controller.creation
    monkeypatch.setattr(supervisor.run,'require_scope_amendment',lambda:None)
    monkeypatch.setattr(supervisor.run,'prepare_oracles',lambda:None)
    monkeypatch.setattr(supervisor.run,'prepare_fixtures',lambda:None)
    monkeypatch.setattr(supervisor.run,'collect',lambda *args:[])
    monkeypatch.setattr(supervisor.run,'status',lambda:{})
    monkeypatch.setattr(supervisor,'prepare_parts',lambda r:None)
    monkeypatch.setattr(supervisor,'assemble_parts',lambda r:None)
    monkeypatch.setattr(supervisor.authorparts,'prepare_parts',lambda r:None)
    monkeypatch.setattr(supervisor.authorparts,'assemble_parts',lambda r:None)
    monkeypatch.setattr(supervisor.preseal_repair,'prepare_repairs',lambda r:None)
    monkeypatch.setattr(supervisor.preseal_repair,'prepare_rereviews',lambda r:None)
    monkeypatch.setattr(supervisor,'advance_fixture_repairs',lambda:None)
    monkeypatch.setattr(supervisor,'active_jobs',lambda:0)
    monkeypatch.setattr(supervisor,'active_work',lambda:set())
    monkeypatch.setattr(supervisor,'inspect_outcome',lambda r:{
        'terminal':True,'overall_state':'CONSTRUCTION_TERMINAL_HOLD'})
    monkeypatch.setattr(Path,'glob',lambda *args:iter([]))
    monkeypatch.setattr(supervisor.time,'sleep',lambda seconds:pytest.fail('must not keep polling held stages'))
    supervisor.main(lock_held=True)


def resume_records(r, writes):
    writes.update({
        'CONTINUOUS-RUN-START.json': {'run_id':r.RUN_ID, 'preserved':'original start'},
        'CONTINUOUS-RUN-FAILURE.json': {'preserved':'original failure'},
        'CONSTRUCTION-OUTCOME.json': {'preserved':'original outcome'},
        'DISPATCH-INTERRUPTION-COMPLETE.json': {'run_id':r.RUN_ID,
            'original_start_sha256':'synthetic-hash', 'coordinator_pid':97088}})


def schema_resume_records(r, writes):
    resume_records(r, writes)
    writes.update({
        controller.RESUME_START: {'run_id': r.RUN_ID, 'coordinator_pid': 29112},
        'SCHEMA-REPAIR-DISPATCH-PAUSE.json': {'run_id': r.RUN_ID, 'coordinator_pid': 29112,
            'resume_start_sha256': 'synthetic-hash', 'reason': 'FIXTURE_REMOTE_SCHEMA_MISSING_EXPLICIT_TYPE'},
        'SCHEMA-REPAIR-DISPATCH-DRAINED.json': {'run_id': r.RUN_ID, 'coordinator_pid': 29112,
            'pause_sha256': 'synthetic-hash', 'active_jobs': 0, 'exit_code': 130}})


def test_schema_resume_is_exact_once_and_construction_hold_still_blocks_unseen(monkeypatch):
    r, events, writes, event = harness(monkeypatch)
    schema_resume_records(r, writes)
    before = dict(writes)
    def publish(r, *, schema_repair_resume):
        assert schema_repair_resume is True
        return {'status':'CREATED', 'outcome':{'terminal':True, 'construction_ready':False,
                                             'overall_state':'SYNTHETIC_HOLD'}}
    result = continue_route(r, event('drain'), publish, schema_repair_resume=True)
    assert result['candidate_executed'] is False and not any(e[0] == 'seal' for e in events)
    assert all(writes[name] == value for name, value in before.items())
    assert writes[controller.SCHEMA_RESUME_START]['no_third_fixture_attempt'] is True
    with pytest.raises(RuntimeError, match='already attempted'):
        continue_route(r, event('forbidden'), publish, schema_repair_resume=True)


@pytest.mark.parametrize('defect', ['pid', 'active', 'exit', 'pause', 'bank_marker'])
def test_schema_resume_refuses_undrained_or_unrelated_attempt(monkeypatch, defect):
    r, events, writes, event = harness(monkeypatch)
    schema_resume_records(r, writes)
    if defect == 'pid':
        monkeypatch.setattr(controller, '_pid_running', lambda pid: True)
    elif defect == 'active':
        monkeypatch.setattr(controller.creation, 'active_jobs', lambda r: 1)
    elif defect == 'exit':
        writes['SCHEMA-REPAIR-DISPATCH-DRAINED.json']['exit_code'] = 1
    elif defect == 'pause':
        writes['SCHEMA-REPAIR-DISPATCH-PAUSE.json']['reason'] = 'other failure'
    else:
        writes['BANK-SEAL.json'] = {}
    with pytest.raises(RuntimeError):
        continue_route(r, event('forbidden'), ready, schema_repair_resume=True)
    assert not any(e[0] == 'forbidden' for e in events)


def test_resume_requires_exact_plan_and_preserves_original_receipts(monkeypatch):
    r, events, writes, event = harness(monkeypatch)
    resume_records(r, writes)
    before = dict(writes)
    def publish(r, *, resume):
        assert resume is True
        events.append(('publish-resume',))
        return ready(r)
    assert continue_route(r,event('drain'),publish,resume=True)['overall_state']=='SYNTHETIC_COMPLETE'
    assert all(writes[name] == value for name, value in before.items())
    start = writes[controller.RESUME_START]
    assert start['original_start_sha256'] == start['interruption_complete_sha256'] == 'synthetic-hash'
    assert start['plan_execution_sha256'] == 'synthetic-hash'
    assert start['accepted_plan_sha256'] == 'plan-hash'
    assert start['prior_coordinator_pid'] == 97088 and start['active_jobs_at_start'] == 0
    assert events[:4] == [('authority',),('plan',),('drain',),('publish-resume',)]
    with pytest.raises(RuntimeError,match='already attempted'):
        continue_route(r,event('must-not-drain'),publish,resume=True)


@pytest.mark.parametrize('defect', ['plan','original','interruption','hash','pid','active'])
def test_resume_cannot_start_until_old_dispatch_fully_drains(monkeypatch,defect):
    r, events, writes, event = harness(monkeypatch)
    resume_records(r, writes)
    if defect == 'plan':
        monkeypatch.setattr(controller,'require_plan_execution',forbidden_runner_call)
    elif defect == 'original':
        writes['CONTINUOUS-RUN-START.json']['run_id'] = 'wrong'
    elif defect == 'interruption':
        writes['DISPATCH-INTERRUPTION-COMPLETE.json']['run_id'] = 'wrong'
    elif defect == 'hash':
        writes['DISPATCH-INTERRUPTION-COMPLETE.json']['original_start_sha256'] = 'wrong'
    elif defect == 'pid':
        monkeypatch.setattr(controller,'_pid_running',lambda pid:True)
    else:
        monkeypatch.setattr(controller.creation,'active_jobs',lambda r:1)
    before = dict(writes)
    with pytest.raises((RuntimeError,AssertionError)):
        continue_route(r,event('must-not-drain'),ready,resume=True)
    assert writes == before and not any(e[0] == 'must-not-drain' for e in events)


@pytest.mark.parametrize('marker',controller.LATER_MARKERS)
def test_resume_refused_after_any_seal_freeze_or_execution_marker(monkeypatch,marker):
    r, events, writes, event = harness(monkeypatch)
    resume_records(r,writes)
    writes[marker] = {'present':True}
    before = dict(writes)
    with pytest.raises(RuntimeError,match='already attempted'):
        continue_route(r,event('must-not-drain'),ready,resume=True)
    assert writes == before


def test_resume_failure_uses_its_own_create_only_receipt(monkeypatch):
    r, events, writes, event = harness(monkeypatch)
    resume_records(r,writes)
    old_failure = dict(writes['CONTINUOUS-RUN-FAILURE.json'])
    with pytest.raises(AssertionError):
        continue_route(r,forbidden_runner_call,ready,resume=True)
    assert writes['CONTINUOUS-RUN-FAILURE.json'] == old_failure
    assert writes['CONTINUOUS-PLAN-RESUME-FAILURE.json']['stage'] == 'CONSTRUCTION'
    assert controller.RESUME_START in writes


@pytest.mark.parametrize('before_freeze',[False,True])
def test_missing_or_changed_research_gate_is_pending_without_candidates(monkeypatch,before_freeze):
    r,events,writes,event=harness(monkeypatch)
    checks = []
    def research(r):
        checks.append('checked')
        if not before_freeze or len(checks) == 2:
            raise RuntimeError('private research evidence issue')
        return {'status':'PASS'}
    monkeypatch.setattr(controller,'require_research_runtime',research)
    result=continue_route(r,event('drain'),ready)
    assert result['overall_state']=='RESEARCH_RUNTIME_PENDING_OR_HELD'
    assert result['candidate_executed'] is False and result['research_runtime_ready'] is False
    assert not any(e[0] in ('freeze','run') for e in events)
    assert ('seal',) in events if before_freeze else ('seal',) not in events
    assert 'private research' not in str(result)


def test_pid_probe_is_non_signalling_and_permission_denied_is_running(monkeypatch):
    calls=[]
    def probe(pid, signal):
        calls.append((pid,signal))
        raise PermissionError
    monkeypatch.setattr(controller.os,'kill',probe)
    assert controller._pid_running(97088)
    assert calls == [(97088,0)]
    def dead(pid, signal):
        raise ProcessLookupError
    monkeypatch.setattr(controller.os,'kill',dead)
    assert not controller._pid_running(97088)
    for pid in (True,0,-1,None,'97088'):
        with pytest.raises(RuntimeError):
            controller._pid_running(pid)


def test_flock_is_nonblocking_released_and_never_unlinks(monkeypatch):
    supervisor = controller.creation
    events=[]
    monkeypatch.setattr(supervisor.os,'open',lambda path,flags,mode:events.append(('open',path,flags,mode)) or 91)
    monkeypatch.setattr(supervisor.os,'close',lambda fd:events.append(('close',fd)))
    monkeypatch.setattr(supervisor.fcntl,'flock',lambda fd,op:events.append(('flock',fd,op)))
    monkeypatch.setattr(supervisor.os,'unlink',forbidden_runner_call)
    r=SimpleNamespace(PUBLIC=Path('/synthetic/public'),safe_path=lambda p:None)
    with pytest.raises(ValueError):
        with supervisor.coordinator_lock(r):
            raise ValueError('synthetic loop failure')
    assert events[0][1].name=='CONTINUOUS-COORDINATOR.lock'
    assert events[0][2] & supervisor.os.O_NOFOLLOW
    assert events[1]==('flock',91,supervisor.fcntl.LOCK_EX | supervisor.fcntl.LOCK_NB)
    assert events[-2:]==[('flock',91,supervisor.fcntl.LOCK_UN),('close',91)]


def test_flock_busy_never_enters_dispatch_and_closes_descriptor(monkeypatch):
    supervisor=controller.creation
    closed=[]
    monkeypatch.setattr(supervisor.os,'open',lambda *args:91)
    monkeypatch.setattr(supervisor.os,'close',closed.append)
    def busy(*args):
        raise BlockingIOError
    monkeypatch.setattr(supervisor.fcntl,'flock',busy)
    r=SimpleNamespace(PUBLIC=Path('/synthetic/public'),safe_path=lambda p:None)
    with pytest.raises(RuntimeError,match='already running'):
        with supervisor.coordinator_lock(r):
            pytest.fail('busy lock entered dispatch')
    assert closed==[91]


def test_supervisor_order_shared_budget_and_old_failures_do_not_block_new_jobs(monkeypatch):
    from backend.tests.test_ge_unseen_creation_outcome import Runner
    supervisor=controller.creation
    r=Runner()
    events, submissions, queued = [], [], []
    for name in ('require_scope_amendment','prepare_oracles','prepare_fixtures'):
        setattr(r,name,lambda name=name:events.append(name))
    r.collect=lambda *args:[]
    r.status=lambda:{}
    r.AUTHOR_PROMPT='author'
    r.BANK_REVIEW_PROMPT='review'
    r.ORACLE_PROMPT='oracle'
    r.invoke=forbidden_runner_call
    monkeypatch.setattr(supervisor,'run',r)
    monkeypatch.setattr(supervisor.authorparts,'prepare_parts',lambda r:events.append('author-prepare'))
    monkeypatch.setattr(supervisor.authorparts,'assemble_parts',lambda r:events.append('author-assemble'))
    monkeypatch.setattr(supervisor,'prepare_parts',lambda r:events.append('oracle-prepare'))
    monkeypatch.setattr(supervisor,'assemble_parts',lambda r:events.append('oracle-assemble'))
    monkeypatch.setattr(supervisor.preseal_repair,'prepare_repairs',lambda r:events.append('repair-prepare'))
    monkeypatch.setattr(supervisor.preseal_repair,'prepare_rereviews',lambda r:events.append('rereview-prepare'))
    monkeypatch.setattr(supervisor,'advance_fixture_repairs',lambda:events.append('fixture-repair'))
    monkeypatch.setattr(supervisor,'inspect_outcome',lambda r:{'terminal':True,'overall_state':'CONSTRUCTION_TERMINAL_HOLD'})
    external=[]
    for i in range(3):
        work=r.PRIVATE/'oracle-parts'/f'shard-90-part-{i+1:02d}'
        r.write(work/'INVOCATION.json',{})
        external.append(work)
    old=r.PRIVATE/'oracle-parts/shard-91-part-01'
    r.write(old/'INVOCATION.json',{})
    r.write(old/'COMPLETION.json',{'returncode':1})
    r.alter(old/'stderr.log',data=b'usage limit')
    for stage in ('author-parts','oracle-repair','bank-review-repair','oracle-parts','fixture-inventory','fixture-format'):
        for i in range(3):
            work=r.PRIVATE/stage/f'shard-01-part-{i+1:02d}'
            r.write(work/'input.json',{})
            r.write(work/'schema.json',{})
    class Future:
        complete=False
        def done(self):
            return self.complete
        def result(self):
            return {'returncode':0,'validation_error':None}
    class Pool:
        def __init__(self, *, max_workers):
            assert max_workers==8
        def __enter__(self):
            return self
        def __exit__(self,*args):
            return False
        def submit(self, fn, work, prompt, *, browse):
            assert fn is forbidden_runner_call  # Executor double never invokes it.
            live={w for w,f in queued if not f.done()}
            assert len(supervisor.active_work() | live | {work})<=8
            future=Future()
            queued.append((work,future))
            submissions.append((work.parent.name,browse))
            return future
    def tick(seconds):
        assert seconds==10
        assert len(submissions)>0
        for work,future in queued:
            if not future.done():
                r.write(work/'INVOCATION.json',{})
                r.write(work/'COMPLETION.json',{'returncode':0,'validation_error':None})
                future.complete=True
        for work in external:
            if not (work/'COMPLETION.json').exists():
                r.write(work/'COMPLETION.json',{})
    monkeypatch.setattr(supervisor,'ThreadPoolExecutor',Pool)
    monkeypatch.setattr(supervisor.time,'sleep',tick)
    fixture=SimpleNamespace(REQUIREMENT_PROMPT='inventory',FORMATTER_PROMPT='formatter')
    with patch.dict(sys.modules, {'scripts.ge_unseen_fixture_repair':fixture}):
        supervisor.main(lock_held=True)
    assert len(submissions)==18
    assert all(browse is (stage not in ('author-parts','fixture-inventory','fixture-format'))
               for stage,browse in submissions)
    assert not any(path.name=='stderr.log' for path in r.reads)
    for i,event in enumerate(events):
        if event=='prepare_oracles':
            assert events[i-2:i]==['author-prepare','author-assemble']
        if event=='rereview-prepare':
            assert events[i-2:i]==['repair-prepare','fixture-repair']


def test_formatter_render_uses_bundled_subprocess_once_and_preserves_failure(monkeypatch):
    from backend.tests.test_ge_unseen_creation_outcome import Runner
    supervisor=controller.creation
    r=Runner()
    r.BUNDLED_PYTHON='/synthetic/bundled/python3'
    calls=[]
    def render(argv, **kwargs):
        calls.append((argv,kwargs))
        raise RuntimeError('synthetic renderer failure')
    r.subprocess=SimpleNamespace(run=render)
    r.validate_job=lambda work:{'case_id':'synthetic'}
    work=r.PRIVATE/'fixture-format/shard-01-case-01'
    r.write(work/'COMPLETION.json',{'returncode':0})
    r.write(work/'output.json',{'case_id':'synthetic'})
    monkeypatch.setattr(supervisor,'run',r)
    monkeypatch.setattr(supervisor.preseal_repair,'prepare_fixture_repairs',lambda r:None)
    supervisor.advance_fixture_repairs()
    assert calls[0][0][:3]==['/synthetic/bundled/python3','-B','-c']
    assert calls[0][0][4:7]==[str(work),str(r.ROOT),str(r.PRIVATE)]
    assert calls[0][0][-2:]==[r.sha(work/'output.json'),r.sha(work/'COMPLETION.json')]
    assert 'run_ge_codex_unseen' not in calls[0][0][3]
    assert calls[0][1]['cwd']==r.ROOT and calls[0][1]['check'] is True
    saved=dict(r.files)
    supervisor.advance_fixture_repairs()
    assert len(calls)==1 and r.files==saved
    assert any(p.name.endswith('-render-failure.json') for p in r.files)


@pytest.mark.parametrize('value',[None,{}, {'status':'HOLD'}, {'status':'PENDING'}])
def test_research_gate_must_return_a_validated_pass(monkeypatch,value):
    r,events,writes,event=harness(monkeypatch)
    monkeypatch.setattr(controller,'require_research_runtime',lambda r:value)
    result=continue_route(r,event('drain'),ready)
    assert result['research_runtime_ready'] is False
    assert not any(e[0] in ('seal','freeze','run') for e in events)
