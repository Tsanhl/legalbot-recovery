#!/usr/bin/env python3
"""Complete the PB revision rejected before inference for excessive input size."""
import asyncio
import json
import re
from pathlib import Path
import run_visible_output_diagnostics as base
import refine_visible_output_diagnostics as revision

async def main():
    root=base.ROOT/'output-diagnostics-r3-PB01'
    if root.exists():raise RuntimeError('Preserve this bounded repair')
    root.mkdir()
    payload=json.loads((base.ROOT/'output-diagnostics-r2/PB01/INPUT.json').read_text())
    old=payload['evidence'];new=[x for x in old if x['citation_data']['source_type']!='case']
    targets={'times-travel':{1,14,77,78,79,80},'rock':{18},'wood':{10,11}}
    for source,numbers in targets.items():
        sample=next(x for x in old if x['source_id']==source)
        text=(base.CAP/(source+'.txt')).read_text()
        matches=[];expected=1
        for m in re.finditer(r'(?m)^\s*(\d{1,3})\.\s+(?=[A-Z“‘])',text):
            if int(m.group(1))==expected:matches.append(m);expected+=1
        for i,m in enumerate(matches):
            number=int(m.group(1))
            if number not in numbers:continue
            end=matches[i+1].start() if i+1<len(matches) else len(text)
            new.append({**sample,'id':source+'-p'+str(number),'locator':'para '+str(number),'text':text[m.start():end].strip()})
    payload['evidence']=new
    payload.pop('prior_answer',None)
    payload['word_target']=700
    payload['repair_targets'].append('Use about 650 words of substantive prose so the complete body stays near 700; no repeated overview. State the precise limits of missing remedies authority.')
    base.dump(root/'INPUT.json',payload)
    gateway=base.CodexBridgeGateway(base.Settings(project_root=base.PROJECT),{'model_id':'gpt-5.5','auth_mode':'chatgpt_signin'})
    result={'parent':'output-diagnostics-r2/PB01','parent_failure':'input_budget_pre_inference','released':False,'currentness_verified':False}
    try:
        invocation,answer=await gateway.invoke_json(system_prompt=revision.PROMPT,user_payload=payload,mode='visible_budget_corrected_revision')
        base.dump(root/'ANSWER.json',answer)
        markdown,words,errors=base.render(answer,new,payload['question']);(root/'ANSWER.md').write_text(markdown)
        review_payload={k:v for k,v in payload.items() if k!='repair_targets'}
        _,review=await gateway.invoke_json(system_prompt=revision.REVIEW,user_payload={**review_payload,'answer':answer,'rendered_markdown':markdown,'body_word_count':words},mode='visible_rendered_review')
        base.dump(root/'REVIEW.json',review)
        result.update(status='completed',word_count=words,unknown_citation_errors=errors,advisory_mark=review['advisory_mark'],model_seventy_plus=review['seventy_plus'],invocation_id=invocation)
    except Exception as exc:result.update(status='failed',error=str(exc))
    base.dump(root/'RESULT.json',result);print(json.dumps(result),flush=True)

if __name__=='__main__':asyncio.run(main())
