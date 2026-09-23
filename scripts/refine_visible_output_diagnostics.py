#!/usr/bin/env python3
"""One changed-prompt revision per exposed case; review the actual rendered output."""
import asyncio
import hashlib
import json
import re
import sys
from pathlib import Path

import run_visible_output_diagnostics as base
from app.orchestration.behavior import BehaviorSignals, route_behavior

OUT=base.ROOT/'output-diagnostics-r2'
PROMPT=base.SYSTEM+'''
Revision rules: The complete body must fall within 90–110% of word_target; plan
the paragraph lengths before drafting and remove repeated rules/conclusions.
Do not sacrifice an issue to preserve a repeated introduction. GE needs a short
answer, relevant qualifications and practical actions. For an essay distinguish
your normative evaluation of a doctrine from facts claimed about its history or
established purposes. Do not treat estoppel by convention as promissory estoppel.
For PB separately address formation/terms, representations, variation consideration,
duress, the clauses and remedies. Where evidence cannot support a material issue,
identify the exact gap and give a limited conclusion; do not fill it from memory.
Every citation must support the proposition, not merely concern the same topic.
'''
REVIEW=base.REVIEW+'''
The rendered_markdown is the actual output being assessed. The host intentionally
omits citation strings from draft JSON and adds OSCOLA citations and a requested
bibliography in rendered_markdown. Assess their actual presence there. Do not
mistake absence from JSON prose for missing citations. A paragraph can use legal
reasoning to apply a rule to assumed facts without the statute naming that person.
Practical suggestions such as keeping relevant records are suggestions, not
statutory requirements; assess whether the wording falsely makes them mandatory.
Check whether the user has supplied the facts already; do not praise a repeated
question. A material unsupported rule, application or omission prevents seventy_plus.
'''

def pinpoint_cases(payload):
    """Use exact paragraph boundaries from captured judgments, never guessed pages."""
    original=payload['evidence']; result=[x for x in original if x['citation_data']['source_type']!='case']
    source_ids=list(dict.fromkeys(x['source_id'] for x in original if x['citation_data']['source_type']=='case'))
    terms=set(re.findall(r'[a-z]{4,}',payload['question'].lower()))
    terms |= {'consideration','estoppel','duress','pressure','interpretation','foakes','combe'}
    for source in source_ids:
        sample=next(x for x in original if x['source_id']==source)
        text=(base.CAP/(source+'.txt')).read_text()
        matches=list(re.finditer(r'(?m)^\s*(\d{1,3})\.\s+(?=[A-Z“‘])',text))
        paragraphs=[]
        for i,m in enumerate(matches):
            end=matches[i+1].start() if i+1<len(matches) else len(text)
            excerpt=text[m.start():end].strip()
            if len(excerpt)>16000:continue
            score=sum(excerpt.lower().count(term) for term in terms)
            paragraphs.append((score,int(m.group(1)),excerpt))
        if not paragraphs:
            result.extend(x for x in original if x['source_id']==source);continue
        ranked=sorted(paragraphs,reverse=True)[:5]
        for _,number,excerpt in sorted(ranked,key=lambda x:x[1]):
            result.append({**sample,'id':source+'-p'+str(number),'locator':'para '+str(number),'text':excerpt})
    # A changed, explicit evidence selection. Preserve the original input in r1.
    payload={**payload,'evidence':result}
    return payload

async def main():
    if OUT.exists():raise RuntimeError('This revision is spent')
    OUT.mkdir()
    base.dump(OUT/'START.json',{'parent':'output-diagnostics-r1','revision_limit':1,
        'changes':['exact paragraph pinpoints','bounded word target','host clarification routing','review rendered OSCOLA output'],
        'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'release_authority':False,'professional_review':False})
    bank=json.loads((base.ROOT/'PRACTICE-QUESTIONS-50.json').read_text())['questions']
    rows=[x for x in bank if x['selected_for_visible_run']]
    gateway=base.CodexBridgeGateway(base.Settings(project_root=base.PROJECT),{'model_id':'gpt-5.5','auth_mode':'chatgpt_signin'})
    semaphore=asyncio.Semaphore(2)
    async def run(row):
        async with semaphore:
            case=OUT/row['id'];case.mkdir()
            parent=base.ROOT/'output-diagnostics-r1'/row['id']
            payload=pinpoint_cases(json.loads((parent/'INPUT.json').read_text()))
            prior=json.loads((parent/'ANSWER.json').read_text())
            critique=json.loads((parent/'REVIEW.json').read_text())
            payload['prior_answer']=prior
            payload['repair_targets']=[x for x in critique['improvements'] if 'citation' not in x.lower() and 'bibliography' not in x.lower()]
            if row.get('follow_up'):
                decision=route_behavior(BehaviorSignals(question=row['question'],jurisdiction=row['jurisdiction'],expanded_development_jurisdiction=True))
                base.dump(case/'INITIAL-HOST-RESPONSE.json',{'reason':str(decision.reason_code),'message':decision.user_message,'model_invoked':False})
                payload['question']=row['question']+'\n\nFollow-up:\n'+row['follow_up']
                payload['prior_clarification']=decision.user_message
                payload['prior_answer']=None
            base.dump(case/'INPUT.json',payload)
            try:
                invocation,answer=await gateway.invoke_json(system_prompt=PROMPT,user_payload=payload,mode='visible_changed_prompt_revision')
                base.dump(case/'ANSWER.json',answer)
                markdown,words,errors=base.render(answer,payload['evidence'],payload['question'])
                (case/'ANSWER.md').write_text(markdown)
                review_payload={k:v for k,v in payload.items() if k not in ('prior_answer','repair_targets')}
                _,review=await gateway.invoke_json(system_prompt=REVIEW,user_payload={**review_payload,'answer':answer,'rendered_markdown':markdown,'body_word_count':words},mode='visible_rendered_review')
                base.dump(case/'REVIEW.json',review)
                within=.9*row['word_target']<=words<=1.1*row['word_target']
                unsupported=any(x['verdict'] in ('partial','unsupported','uncertain') for x in review.get('paragraph_checks',[]))
                result={'id':row['id'],'status':'completed','word_count':words,'within_target':within,
                        'unknown_citation_errors':errors,'advisory_mark':review.get('advisory_mark'),
                        'model_seventy_plus':review.get('seventy_plus'),'has_support_concerns':unsupported,
                        'local_quality_gate_passed':bool(within and not errors and not unsupported and not review.get('hallucinations') and review.get('seventy_plus')),
                        'currentness_verified':False,'released':False,'invocation_id':invocation}
            except Exception as exc:result={'id':row['id'],'status':'failed','error':str(exc),'released':False}
            base.dump(case/'RESULT.json',result);print(json.dumps(result),flush=True)
            return result
    results=await asyncio.gather(*(run(row) for row in rows))
    base.dump(OUT/'RESULTS.json',results)

if __name__=='__main__':asyncio.run(main())
