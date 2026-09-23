#!/usr/bin/env python3
"""Capture a public, case-local research corpus for exposed quality diagnostics.

Fetch does not approve currentness, later treatment, runtime admission or gold.
"""
import asyncio
import hashlib
import io
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import httpx
from bs4 import BeautifulSoup
from lxml import etree
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]/'data/evaluations/visible-final-check-20260923'

SPECS=[]
for group,identity,title,kind,sections in [
 ('cra','ukpga/2015/15','Consumer Rights Act 2015','section',[9,10,11,19,20,22,23,24,31,62,64,68,69]),
 ('ccr','uksi/2013/3134','Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013','regulation',[28,29,30,32,34,35]),
 ('era','ukpga/1996/18','Employment Rights Act 1996','section',[13,14,17,23]),
 ('ma','ukpga/1967/7','Misrepresentation Act 1967','section',[2,3]),
 ('ucta','ukpga/1977/50','Unfair Contract Terms Act 1977','section',[2,3,6,11,13]),
 ('sga','ukpga/1979/54','Sale of Goods Act 1979','section',[13,14,53]),
 ('sgsa','ukpga/1982/29','Supply of Goods and Services Act 1982','section',[13]),
]:
 for section in sections:
  citation={'source_type':'legislation','title':title}
  if kind=='regulation':citation.update(source_type='statutory_instrument',instrument_number='SI 2013/3134')
  SPECS.append({'id':f'{group}-{section}','group':group,'url':f'https://www.legislation.gov.uk/{identity}/{kind}/{section}/data.xml','citation_data':citation,'locator':f'{kind} {section}','format':'xml'})

for ident,url,title,body,updated in [
 ('tenancy','https://www.gov.uk/guidance/repossessing-your-privately-rented-property-after-1-may-2026','Repossessing your privately rented property after 1 May 2026','Ministry of Housing, Communities and Local Government','2026-07-13'),
 ('grounds','https://www.gov.uk/government/publications/grounds-for-possession-tenant-guidance/grounds-for-possession-guidance-for-tenants','Grounds for possession: guidance for tenants','Ministry of Housing, Communities and Local Government','2026-05-01'),
 ('wages','https://www.acas.org.uk/deductions-from-pay-and-wages','Deductions from pay and wages','Acas','2026-04-24'),
 ('time-limits','https://www.acas.org.uk/employment-tribunal-time-limits','Employment tribunal time limits','Acas','2026-09-23'),
 ('sar','https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/right-of-access/what-should-we-consider-when-responding-to-a-request/','What should we consider when responding to a request?','Information Commissioner’s Office','2025-12-08'),
]:
 # Web citations record access date; do not invent a publication date where the
 # page does not expose one reliably in the captured content.
 SPECS.append({'id':ident,'group':ident,'url':url,'format':'html','locator':'',
   'citation_data':{'source_type':'web','author':body,'bibliography_author':body,'title':title,'website':body,'url':url,'accessed':'2026-09-23'}})

for ident,url,name,neutral in [
 ('rock','https://supremecourt.uk/uploads/uksc_2016_0152_judgment_847e3e02dc.pdf','Rock Advertising Ltd v MWB Business Exchange Centres Ltd','[2018] UKSC 24'),
 ('times-travel','https://supremecourt.uk/uploads/uksc_2019_0142_judgment_906bbad04b.pdf','Pakistan International Airline Corporation v Times Travel (UK) Ltd','[2021] UKSC 40'),
 ('tinkler','https://www.supremecourt.uk/cases/docs/uksc-2019-0183-judgment.pdf','Tinkler v HMRC','[2021] UKSC 39'),
 ('mur','https://www.supremecourt.uk/cases/judgments/uksc-2022-0172','RTI Ltd v MUR Shipping BV','[2024] UKSC 18'),
]:
 SPECS.append({'id':ident,'group':ident,'url':url,'format':'html' if ident=='mur' else 'pdf','locator':'',
   'citation_data':{'source_type':'case','case_name':name,'neutral_citation':neutral}})

async def main():
 root=ROOT/'research-captures';root.mkdir(parents=True,exist_ok=True)
 if (root/'MANIFEST.json').exists():raise RuntimeError('Capture is create-only; preserve prior results')
 semaphore=asyncio.Semaphore(5)
 async with httpx.AsyncClient(timeout=45,follow_redirects=True,trust_env=False,headers={'User-Agent':'LegalBot-visible-research/1.0'}) as client:
  async def fetch(spec):
   async with semaphore:
    try:
     response=await client.get(spec['url']);response.raise_for_status()
     raw=response.content
     ext=spec['format'];(root/f"{spec['id']}.{ext}").write_bytes(raw)
     if ext=='xml':
      tree=etree.fromstring(raw,parser=etree.XMLParser(resolve_entities=False,no_network=True))
      bodies=tree.xpath('//*[local-name()="Primary" or local-name()="Secondary"]')
      text=' '.join(' '.join((bodies[0] if bodies else tree).itertext()).split())
      metadata={etree.QName(x).localname:(x.text or '').strip() for x in tree.iter() if etree.QName(x).localname in ('valid','modified')}
     elif ext=='pdf':
      pages=PdfReader(io.BytesIO(raw)).pages
      text='\n\n'.join(p.extract_text() or '' for p in pages);metadata={'pages':len(pages)}
     else:
      soup=BeautifulSoup(raw,'html.parser')
      for node in soup(['script','style','nav','header','footer']):node.decompose()
      node=soup.select_one('.gem-c-govspeak') or soup.select_one('article') or soup.select_one('main') or soup
      text=node.get_text('\n',strip=True);metadata={}
     if len(text)<100:raise ValueError('insufficient_extracted_text')
     (root/f"{spec['id']}.txt").write_text(text)
     return {**spec,'status':'CAPTURED_RESEARCH_ONLY','final_url':str(response.url),'raw_sha256':hashlib.sha256(raw).hexdigest(),'text_sha256':hashlib.sha256(text.encode()).hexdigest(),'text_characters':len(text),'metadata':metadata,'currentness_reviewed':False,'production_admitted':False}
    except Exception as exc:return {**spec,'status':'CAPTURE_FAILED','error_type':type(exc).__name__}
  rows=await asyncio.gather(*(fetch(s) for s in SPECS))
 manifest={'schema':'legalbot.visible-public-source-capture.v1','captured_at':datetime.now(timezone.utc).isoformat(),'scope':'case_local_non_live_research','sources':rows}
 (root/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n')
 db=sqlite3.connect(root/'research-fts.sqlite3');db.execute('CREATE VIRTUAL TABLE chunks USING fts5(id UNINDEXED, source_id UNINDEXED, text)')
 for row in rows:
  if row['status']!='CAPTURED_RESEARCH_ONLY':continue
  text=(root/f"{row['id']}.txt").read_text()
  # Whole statutory provisions stay intact. Long judgments are overlapping
  # bounded windows for diagnostic retrieval, with their exact character span.
  size=8000 if row['format']=='xml' else 4500
  for start in range(0,len(text),size-600):
   chunk=text[start:start+size]
   db.execute('INSERT INTO chunks VALUES (?,?,?)',(f"{row['id']}:{start}",row['id'],chunk))
 db.commit();db.close()
 print(json.dumps({'captured':sum(r['status']=='CAPTURED_RESEARCH_ONLY' for r in rows),'failed':[r['id'] for r in rows if r['status']=='CAPTURE_FAILED'],'scope':'research only, not runtime admitted'}))

if __name__=='__main__':asyncio.run(main())
