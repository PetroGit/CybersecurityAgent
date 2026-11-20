"""Offline, review-only merge of CybersecurityAgent threat-model packages."""
import argparse
import copy
import hashlib
import json
import re
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

STRIDE = ('Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege')
FIELDS = ('id','title','domain','stride','threat_actor','asset','trust_boundary','preconditions','attack_tree_path','kill_chain_phases','attack_hypothesis','likelihood','impact','mitigations','acceptance_tests','reference_ids','evidence_gaps')
LISTS = ('preconditions','attack_tree_path','kill_chain_phases','mitigations','acceptance_tests','reference_ids','evidence_gaps')
SUFFIXES = ('.json','.md','-requirements.csv','-requirements.json','-test-catalog.csv','-test-catalog.json','-coverage-gaps.json','-review.md')

def safe_path(root, value):
    rel = Path(value)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise ValueError('Inputs must be repository-relative and cannot contain ..')
    path = root / rel
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise ValueError(f'Unsafe or missing input: {value}')
    if path.suffix.lower() != '.json' or path.stat().st_size > 2_000_000:
        raise ValueError(f'Input must be JSON and <= 2 MB: {value}')
    return path

def validate(package, label):
    if not isinstance(package, dict) or package.get('artifact_type') != 'design_time_threat_model':
        raise ValueError(f'{label}: expected design_time_threat_model package')
    model = package.get('threat_model')
    refs = package.get('references')
    domains = package.get('requested_domains')
    if not isinstance(model,dict) or not isinstance(refs,dict) or not refs or not isinstance(domains,list) or not domains:
        raise ValueError(f'{label}: malformed model, references, or domains')
    if any(not isinstance(k,str) or not isinstance(v,str) for k,v in refs.items()):
        raise ValueError(f'{label}: malformed reference catalog')
    if any(not isinstance(d,str) for d in domains):
        raise ValueError(f'{label}: malformed requested domains')
    if any(not isinstance(model.get(k),str) for k in ('scope','architecture_summary')):
        raise ValueError(f'{label}: missing scope/architecture_summary')
    for k in ('assets','trust_boundaries','assumptions','open_questions'):
        if not isinstance(model.get(k),list) or not all(isinstance(v,str) for v in model[k]):
            raise ValueError(f'{label}: malformed {k}')
    scenarios = model.get('scenarios')
    if not isinstance(scenarios,list) or not scenarios:
        raise ValueError(f'{label}: missing scenarios')
    for i,s in enumerate(scenarios,1):
        if not isinstance(s,dict) or any(k not in s for k in FIELDS):
            raise ValueError(f'{label}: scenario {i} missing fields')
        if s['id'] != f'TM-{i:03d}':
            raise ValueError(f'{label}: nonsequential scenario IDs')
        if any(not isinstance(s[k],list) or not all(isinstance(x,str) for x in s[k]) for k in LISTS):
            raise ValueError(f'{label}: scenario {i} malformed lists')
        if any(not isinstance(s[k],str) for k in FIELDS if k not in LISTS):
            raise ValueError(f'{label}: scenario {i} malformed strings')
        if s['domain'] not in domains or s['stride'] not in STRIDE or s['likelihood'] not in ('Low','Medium','High','Unknown') or s['impact'] not in ('Low','Medium','High','Unknown'):
            raise ValueError(f'{label}: scenario {i} invalid enum')
        if not s['reference_ids'] or any(r not in refs for r in s['reference_ids']):
            raise ValueError(f'{label}: scenario {i} invalid references')
    return model, refs, domains

def normalized(text):
    return ' '.join(text.casefold().split())

def markdown(package, provenance, duplicates):
    m=package['threat_model']
    lines=['# Consolidated design-time threat model (review required)','',
           '> Offline merge of AI-generated hypotheses. Not verified vulnerabilities, test results, or compliance evidence.','',
           '## Source models','']
    for source in package['merge_sources']:
        lines.append(f'- `{source["file"]}` (SHA-256 `{source["sha256"]}`, {source["scenario_count"]} scenarios)')
    lines += ['','## Scope',m['scope'],'','## Architecture summary',m['architecture_summary'],'']
    for key,title in [('assets','Assets'),('trust_boundaries','Trust boundaries'),('assumptions','Assumptions'),('open_questions','Open questions')]:
        lines += ['## '+title,''] + ['- '+x.replace('\n',' ') for x in m[key]] + ['']
    lines += ['## Potential duplicates (retained for review)','']
    if duplicates:
        for item in duplicates:
            lines.append(f'- {item["scenario_id"]} resembles {item["possible_duplicate_of"]}: {item["reason"]}')
    else:
        lines.append('- No exact normalized title/hypothesis matches found; semantic duplicates may still exist.')
    lines.append('')
    for s in m['scenarios']:
        prov=provenance[s['id']]
        lines += [f'## {s["id"]}: {s["title"]}','',
                  f'**Source:** `{prov["source_file"]}` / `{prov["original_id"]}`','',
                  f'**Domain:** {s["domain"]} | **STRIDE:** {s["stride"]} | **Likelihood:** {s["likelihood"]} | **Impact:** {s["impact"]}','',
                  f'**Threat actor:** {s["threat_actor"]} | **Asset:** {s["asset"]} | **Trust boundary:** {s["trust_boundary"]}','',
                  '**Attack hypothesis:** '+s['attack_hypothesis'],'']
        for key,title in [('preconditions','Preconditions'),('attack_tree_path','Attack tree'),('kill_chain_phases','Kill chain (if applicable)'),('mitigations','Proposed controls'),('acceptance_tests','Proposed acceptance tests'),('evidence_gaps','Evidence gaps')]:
            lines += ['### '+title,''] + (['- '+x.replace('\n',' ') for x in s[key]] or ['- None supplied']) + ['']
        lines += ['### Framework references',''] + [f'- [{r}]({package["references"][r]})' for r in s['reference_ids']] + ['']
    lines += ['## Review requirements','','- Verify provenance, possible duplicates, architecture assumptions, threat relevance and exact standards mappings.','- No tests executed and no patches applied.','']
    return '\n'.join(lines)

def merge_main(argv):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo',default='.')
    p.add_argument('--input',action='append',required=True,help='Repository-relative threat-model JSON; repeat for each model')
    p.add_argument('--output-name',required=True)
    p.add_argument('--allow-design-mismatch',action='store_true',help='Allow differing design hashes; requires review')
    args=p.parse_args(argv)
    if len(args.input)<2 or len(set(args.input))!=len(args.input):
        p.error('Supply at least two distinct --input values')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',args.output_name):
        p.error('Invalid output name')
    root=Path(args.repo).resolve(strict=True)
    if not root.is_dir(): p.error('--repo must be a directory')
    out_dir=root/'remediation'/'threat-models'
    if (root/'remediation').is_symlink() or out_dir.is_symlink() or (out_dir.exists() and not out_dir.resolve().is_relative_to(root)):
        raise ValueError('Unsafe output directory')
    out_dir.mkdir(parents=True,exist_ok=True)
    targets=[out_dir/(args.output_name+s) for s in SUFFIXES]
    if any(t.exists() or t.is_symlink() for t in targets):
        raise FileExistsError('Output exists; choose a new --output-name')
    models=[]; refs={}; domains=[]; hashes=set(); sources=[]
    for value in args.input:
        path=safe_path(root,value)
        data=json.loads(path.read_text(encoding='utf-8'))
        model, catalog, selected=validate(data,value)
        for k,v in catalog.items():
            if k in refs and refs[k]!=v:
                raise ValueError(f'Conflicting framework URL for {k}')
            refs[k]=v
        for d in selected:
            if d not in domains: domains.append(d)
        if data.get('design_sha256'): hashes.add(data['design_sha256'])
        sources.append({'file':path.relative_to(root).as_posix(), 'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'scenario_count':len(model['scenarios']), 'design_sha256':data.get('design_sha256')})
        models.append(model)
    if len(hashes)>1 and not args.allow_design_mismatch:
        raise ValueError('Input design hashes differ; use --allow-design-mismatch only after review')
    merged={key:[] for key in ('assets','trust_boundaries','assumptions','open_questions')}
    for key in merged:
        seen=set()
        for m in models:
            for v in m[key]:
                if normalized(v) not in seen:
                    merged[key].append(v); seen.add(normalized(v))
    scenarios=[]; provenance={}; duplicates=[]; signatures=defaultdict(list)
    for model,src in zip(models,sources):
        for old in model['scenarios']:
            s=copy.deepcopy(old)
            new_id=f'TM-{len(scenarios)+1:03d}'
            sigs=[('title', (s['domain'],s['stride'],normalized(s['title']))),
                  ('hypothesis',(s['domain'],s['stride'],normalized(s['attack_hypothesis'])))]
            for reason, sig in sigs:
                if signatures[(reason,sig)]:
                    duplicates.append({'scenario_id':new_id,'possible_duplicate_of':signatures[(reason,sig)][0],'reason':'Exact normalized '+reason+' within domain and STRIDE'})
            for reason,sig in sigs: signatures[(reason,sig)].append(new_id)
            provenance[new_id]={'source_file':src['file'],'original_id':old['id'],'source_sha256':src['sha256']}
            s['id']=new_id
            scenarios.append(s)
    model={'scope':'Consolidation of: '+'; '.join(m['scope'] for m in models),
           'architecture_summary':'\n\n'.join(m['architecture_summary'] for m in models),
           **merged,'scenarios':scenarios}
    package={'schema_version':1,'artifact_type':'design_time_threat_model','generated_at_utc':datetime.now(timezone.utc).isoformat(),
             'model':'offline-merge','design_source':'multiple (see merge_sources)','design_sha256':next(iter(hashes)) if len(hashes)==1 else None,
             'requested_domains':domains,'review_required':True,'references':refs,'threat_model':model,
             'merge_sources':sources,'scenario_provenance':provenance,'possible_duplicates':duplicates,
             'limitations':['Offline merge; no model call or independent verification','Potential semantic duplicates may remain','No patches applied or tests executed']}
    from threat_artifacts import generate
    with tempfile.TemporaryDirectory(prefix='threat-merge-',dir=out_dir) as tmp:
        stage=Path(tmp)
        js=stage/(args.output_name+'.json')
        js.write_text(json.dumps(package,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (stage/(args.output_name+'.md')).write_text(markdown(package,provenance,duplicates),encoding='utf-8')
        _,summary=generate(js,stage,args.output_name,domains)
        for suffix in SUFFIXES:
            src=stage/(args.output_name+suffix)
            if not src.is_file(): raise RuntimeError('Missing staged artifact: '+str(src))
        for suffix in SUFFIXES:
            (stage/(args.output_name+suffix)).replace(out_dir/(args.output_name+suffix))
    print(f'Merged {len(sources)} models: {len(scenarios)} scenarios; {len(duplicates)} potential duplicate matches.')
    print(f'Security requirements: {summary["requirements_count"]}; proposed tests: {summary["proposed_tests_count"]}')
    print(f'Coverage review: {out_dir/(args.output_name+"-review.md")}')
    print('Human review required; no API call, tests, or patch execution.')

if __name__=='__main__':
    merge_main(__import__('sys').argv[1:])
