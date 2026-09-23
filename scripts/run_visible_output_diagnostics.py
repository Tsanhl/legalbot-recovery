#!/usr/bin/env python3
"""Exposed, non-live Codex output diagnostics, separate from release admission.

Uses the actual isolated signed-in transport, SQLite research retrieval, active
assessment guide and host OSCOLA formatter. Never creates eligible EvidenceSpans
or release proofs. Captured sources remain research-only.
"""
import asyncio
import hashlib
import io
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
from pypdf import PdfReader

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'backend'))
from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE, budget_assessment_guidance
from app.citations.oscola import bibliography_requested, render_bibliography, render_oscola
from app.config import Settings
from app.model_routes import CodexBridgeGateway

ROOT = PROJECT / 'data/evaluations/visible-final-check-20260923'
CAP = ROOT / 'research-captures'
OUT = ROOT / 'output-diagnostics-r1'
GROUPS = {
 'GE01':['cra-9','cra-19','cra-20','cra-22','cra-31'],
 'GE02':['tenancy','grounds'],
 'GE03':['ccr-28','ccr-29','ccr-30','ccr-32','ccr-34','ccr-35'],
 'GE04':['era-13','era-14','era-17','era-23','wages','time-limits'],
 'GE05':['sar'],
 'ES01':['rock','tinkler-supplement'],
 'ES02':['cra-62','cra-64','cra-68','cra-69','ucta-3','ucta-11','ucta-13','ma-3','wood'],
 'PB01':['ma-2','ma-3','ucta-3','ucta-6','ucta-11','ucta-13','sga-13','sga-14','sga-53','sgsa-13','times-travel','rock','wood'],
}
SUPPLEMENTS = [
 ('tinkler-supplement','https://supremecourt.uk/uploads/uksc_2019_0183_judgment_3850d6b799.pdf','Tinkler v Commissioners for Her Majesty’s Revenue and Customs','[2021] UKSC 39'),
 ('wood','https://supremecourt.uk/uploads/uksc_2015_0212_judgment_bd11dce464.pdf','Wood v Capita Insurance Services Ltd','[2017] UKSC 24'),
]
SYSTEM = '''You are answering an exposed LegalBot research diagnostic, not certifying legal advice.
Apply the active assessment guide. Use only supplied source excerpts for legal propositions.
Facts supplied in the question are assumed facts, never legal authority. Do not infer an absent
fact, quote or case. Source captures have NOT received currentness/later-treatment approval;
state this limitation accurately and never claim full law verification as at the requested date.
Answer GE directly when facts suffice; ask only material missing facts (UK nation, occupation,
tenancy regime) when they do not. Continue the same matter on follow-up. Essay requires a thesis,
critical evaluation and counterargument, not client advice. PB requires separate issues, rule,
fact-specific application, alternative outcomes, clauses and remedies. Aim for the word target.
If an authority is discussed inside another judgment, cite the supplied judgment and explain
that mediated verification; do not pretend to have read the original. Do not conflate estoppel
by convention with promissory estoppel. Treat cited dicta as dicta when appropriate.
Return JSON: {"disposition":"answer|clarify|limited_answer", "paragraphs":[{"heading":"...",
"text":"prose without citation strings", "source_ids":["exact supplied chunk id"]}],
"questions":["only necessary clarification"], "limitations":["specific evidence gap"]}.
No invented citations or bibliography: the host supplies these from source metadata. Every
legal proposition must cite the exact chunk(s) supporting it. A conclusion applying law to
assumed user facts also needs the governing source. Distinguish evaluation from established law.
'''
REVIEW = '''Review the exact diagnostic answer against its question, supplied excerpts and active
assessment guide. You are a separate pass of the SAME model, not an independent expert. Do not
use outside knowledge or assume source currentness. Check every paragraph's legal support,
misleading omissions, false citations, task fit, fact application, counterargument where relevant,
material qualifications, useful next steps, repetitions and word target. A cited source ID is
not proof of entailment. Do not give 70 merely for fluent prose. Return JSON:
{"advisory_mark":0,"seventy_plus":false,"source_currentness_verified":false,
"paragraph_checks":[{"index":0,"verdict":"supported|partial|unsupported|uncertain",
"reason":"specific reason","source_ids":[]}],"material_omissions":[],
"strengths":[],"improvements":[],"task_fit":"pass|fail","hallucinations":[]}.
Marks are experimental advisory judgements, never university grades or legal assurance.
'''

def dump(path,value):
    with path.open('x') as handle: json.dump(value,handle,ensure_ascii=False,indent=2)

async def supplements():
    path=CAP/'SUPPLEMENT-MANIFEST.json'
    if path.exists(): return json.loads(path.read_text())
    rows=[]
    async with httpx.AsyncClient(timeout=45,follow_redirects=True,trust_env=False) as client:
        for ident,url,name,neutral in SUPPLEMENTS:
            r=await client.get(url);r.raise_for_status()
            (CAP/f'{ident}.pdf').write_bytes(r.content)
            text='\n\n'.join(p.extract_text() or '' for p in PdfReader(io.BytesIO(r.content)).pages)
            (CAP/f'{ident}.txt').write_text(text)
            rows.append({'id':ident,'url':url,'locator':'','format':'pdf',
                         'citation_data':{'source_type':'case','case_name':name,'neutral_citation':neutral},
                         'raw_sha256':hashlib.sha256(r.content).hexdigest(),
                         'text_sha256':hashlib.sha256(text.encode()).hexdigest(),
                         'currentness_reviewed':False,'production_admitted':False})
    dump(path,rows)
    db=sqlite3.connect(CAP/'research-fts.sqlite3')
    for row in rows:
        text=(CAP/f"{row['id']}.txt").read_text()
        for start in range(0,len(text),3900):
            db.execute('INSERT INTO chunks VALUES (?,?,?)',(f"{row['id']}:{start}",row['id'],text[start:start+4500]))
    db.commit();db.close()
    return rows

def retrieve(row,metadata):
    # Balanced per-source retrieval avoids a long statute crowding out a case.
    db=sqlite3.connect(f'file:{CAP}/research-fts.sqlite3?mode=ro',uri=True)
    words=set(re.findall(r'[a-zA-Z]{4,}', row['question']))
    extra={'ES01':'consideration Foakes Williams Combe promissory estoppel shield',
           'PB01':'duress illegitimate pressure breach contract consideration',
           'ES02':'interpretation text context commercial'}.get(row['id'],'')
    query=' OR '.join('"'+x+'"' for x in sorted(words | set(extra.split())))
    chosen=[]
    for source in GROUPS[row['id']]:
        rows=db.execute('SELECT id,text FROM chunks WHERE chunks MATCH ? AND source_id=? ORDER BY bm25(chunks) LIMIT 3',(query,source)).fetchall()
        if not rows: rows=db.execute('SELECT id,text FROM chunks WHERE source_id=? LIMIT 2',(source,)).fetchall()
        limit=2 if len(GROUPS[row['id']])>8 else 3
        for ident,text in rows[:limit]:
            chosen.append({'id':ident.replace(':','-'), 'source_id':source,'text':text,
                           'locator':metadata[source]['locator'],'citation_data':metadata[source]['citation_data'],
                           'capture_sha256':metadata[source]['raw_sha256'],
                           'currentness_reviewed':False})
    db.close()
    # Do not silently truncate an excerpt; exclude whole excess windows.
    budget=65000;result=[];used=0
    for item in chosen:
        cost=len(json.dumps(item,ensure_ascii=False))
        if used+cost<=budget:result.append(item);used+=cost
    return result

def render(answer, evidence, question):
    by_id={s['id']:s for s in evidence};used=[];lines=[];words=0;errors=[]
    for i,p in enumerate(answer.get('paragraphs',[])):
        text=p['text'];words+=len(text.split())
        if p.get('heading'):lines+=['## '+p['heading'],'']
        cites=[]
        for ident in p.get('source_ids',[]):
            if ident not in by_id:errors.append(f'paragraph {i}: unknown evidence {ident}');continue
            source=by_id[ident]
            cites.append(render_oscola(source['citation_data'],source['locator']))
            used.append(SimpleNamespace(citation_data=source['citation_data']))
        lines += [text+(' ('+'; '.join(dict.fromkeys(cites))+')' if cites else ''),'']
    if answer.get('questions'):lines+=['## Clarification','']+['- '+q for q in answer['questions']]+['']
    if answer.get('limitations'):lines+=['## Research limitations','']+['- '+q for q in answer['limitations']]+['']
    if bibliography_requested(question):lines += [render_bibliography(used),'']
    return '\n'.join(lines),words,errors

async def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'START.json').exists():raise RuntimeError('This run is spent; preserve it')
    sources=json.loads((CAP/'MANIFEST.json').read_text())['sources']+await supplements()
    metadata={s['id']:s for s in sources if s.get('status')!='CAPTURE_FAILED'}
    bank=json.loads((ROOT/'PRACTICE-QUESTIONS-50.json').read_text())
    rows=[r for r in bank['questions'] if r['selected_for_visible_run']]
    gateway=CodexBridgeGateway(Settings(project_root=PROJECT),{'model_id':'gpt-5.5','auth_mode':'chatgpt_signin'})
    dump(OUT/'START.json',{'at':datetime.now(timezone.utc).isoformat(),'model':'codex-requested:gpt-5.5',
        'cases':[r['id'] for r in rows],'method':'actual adapter, case-local FTS research, same-model separate review',
        'api_release_test':False,'training':False,'production_admitted':False,
        'guide_sha256':OWNER_ASSESSMENT_BUNDLE.sha256,
        'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    results=[]
    for row in rows:
        case=OUT/row['id'];case.mkdir()
        evidence=retrieve(row,metadata)
        guide=budget_assessment_guidance(OWNER_ASSESSMENT_BUNDLE,task_type=row['task_type'],subject='contract' if row['task_type']!='general' else None,max_characters=8000)
        payload={'question':row['question'],'task_type':row['task_type'],'word_target':row['word_target'],
                 'guidelines':list(guide.instructions),'omitted_rule_ids':list(guide.omitted_rule_ids),'evidence':evidence}
        dump(case/'INPUT.json',payload)
        try:
            invocation,answer=await gateway.invoke_json(system_prompt=SYSTEM,user_payload=payload,mode='visible_research_diagnostic')
            dump(case/'ANSWER.json',answer)
            initial=answer
            if row.get('follow_up') and answer.get('disposition')=='clarify':
                payload={**payload,'question':row['question']+'\n\nFollow-up:\n'+row['follow_up'],'prior_clarification':answer.get('questions',[])}
                dump(case/'FOLLOWUP-INPUT.json',payload)
                invocation,answer=await gateway.invoke_json(system_prompt=SYSTEM,user_payload=payload,mode='visible_research_followup')
                dump(case/'FOLLOWUP-ANSWER.json',answer)
            markdown,words,errors=render(answer,evidence,payload['question'])
            (case/'ANSWER.md').write_text(markdown)
            _,review=await gateway.invoke_json(system_prompt=REVIEW,user_payload={**payload,'answer':answer,'body_word_count':words},mode='visible_research_review')
            dump(case/'REVIEW.json',review)
            result={'id':row['id'],'status':'completed','word_count':words,'unknown_citation_errors':errors,
                    'initial_disposition':initial.get('disposition'),'disposition':answer.get('disposition'),
                    'advisory_mark':review.get('advisory_mark'),'seventy_plus':review.get('seventy_plus'),
                    'evidence_chunks':len(evidence),'omitted_guidelines':list(guide.omitted_rule_ids),
                    'currentness_verified':False,'released':False,'invocation_id':invocation}
        except Exception as exc:
            result={'id':row['id'],'status':'failed','error':str(exc),'released':False}
        dump(case/'RESULT.json',result);results.append(result)
        print(json.dumps(result),flush=True)
    dump(OUT/'RESULTS.json',results)

if __name__=='__main__':asyncio.run(main())
