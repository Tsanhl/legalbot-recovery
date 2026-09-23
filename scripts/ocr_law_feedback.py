#!/usr/bin/env python3
"""Complete local OCR extraction without putting student work into a guide."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'backend'))
from app.crypto import LocalCipher

def main():
    output=ROOT/'data/evaluations/visible-final-check-20260923/law-feedback-ocr-r2'
    output.mkdir(mode=0o700,exist_ok=True)
    if (output/'START.json').exists():raise RuntimeError('Preserve prior OCR attempt')
    audit=json.loads((ROOT/'data/development-runtime/ge-dev-chat-20260923-r2/LAW-FEEDBACK-EXTRACTION-AUDIT.json').read_text())
    (output/'START.json').write_text(json.dumps({'engine':'Apple Vision accurate en-GB through Objective-C runtime; no SDK compilation','runtime_guide_admission':False,'predecessor':'law-feedback-ocr compiler failure'}))
    cipher=LocalCipher.from_local_key(create=False);results=[]
    for row in audit['records']:
        if row['format']!='pdf':continue
        source=Path(audit['law_root'])/row['path']
        if hashlib.sha256(source.read_bytes()).hexdigest()!=row['sha256']:raise RuntimeError('Feedback source changed')
        if any(r['source_sha256']==row['sha256'] for r in results):continue
        process=subprocess.run(['osascript','-l','JavaScript',str(ROOT/'scripts/ocr_law_feedback.js'),str(source)],capture_output=True,timeout=600)
        identity=row['sha256'][:20]
        if process.returncode:
            results.append({'source_sha256':row['sha256'],'status':'failed','exit_code':process.returncode});continue
        pages=json.loads(process.stdout)
        (output/(identity+'.enc')).write_bytes(cipher.encrypt_bytes(process.stdout))
        (output/(identity+'.enc')).chmod(0o600)
        result={'source_sha256':row['sha256'],'status':'ocr_extracted_not_guide_admitted',
                'page_count':len(pages),'character_count':sum(len(p['text']) for p in pages),
                'low_confidence_pages':[p['page'] for p in pages if (p['mean_confidence'] or 0)<.8],
                'annotation_character_count':sum(len(p['annotation_text']) for p in pages),
                'encrypted_text_file':identity+'.enc','student_work_in_shared_guide':False}
        results.append(result);print(json.dumps({k:result[k] for k in ('status','page_count','character_count')}),flush=True)
    (output/'RESULTS.json').write_text(json.dumps({'sources':results,'runtime_guide_admission':False,
        'limit':'OCR is extraction, not reliable separation of marker feedback from student answers; only reviewed general rules may be admitted.'},indent=2))

if __name__=='__main__':main()
