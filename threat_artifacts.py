"""Offline, review-only security requirements, verification catalog, and STRIDE gap analysis.

Consumes a generated threat-model JSON. No model/API/network calls, no tests run.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

STRIDE = ('Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege')
DOMAINS = ('iam','pki','network','data','web-api','mobile','mcp','agentic-ai')
REF_URLS = {
 'OSA':'https://www.opensecurityarchitecture.org/frameworks/',
 'OWASP_TM':'https://owasp.org/www-community/Threat_Modeling_Process',
 'MITRE_ATTACK':'https://attack.mitre.org/',
 'OWASP_MCP':'https://owasp.org/projects/mcp-top-10',
 'OWASP_AGENTIC':'https://owasp.github.io/www-project-agentic-skills-top-10/',
 'OWASP_WEB':'https://owasp.org/Top10/2025/',
 'OWASP_MASVS':'https://mas.owasp.org/',
 'NIST_CSF':'https://www.nist.gov/cyberframework',
 'NIST_800_53':'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
 'NIST_800_63':'https://pages.nist.gov/800-63-4/',
 'NIST_AI_RMF':'https://www.nist.gov/itl/ai-risk-management-framework',
 'ISO_27001':'https://www.iso.org/standard/27001',
}
DOMAIN_REFERENCES = {
 'iam':['NIST_800_63','NIST_800_53'], 'pki':['NIST_800_53'],
 'network':['NIST_800_53','NIST_CSF'], 'data':['NIST_800_53','ISO_27001'],
 'web-api':['OWASP_WEB','NIST_800_53'], 'mobile':['OWASP_MASVS'],
 'mcp':['OWASP_MCP','OWASP_AGENTIC'], 'agentic-ai':['OWASP_AGENTIC','NIST_AI_RMF'],
}

def load_model(path: Path) -> dict:
    raw = path.read_text(encoding='utf-8-sig')
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Accept the pasted PowerShell output containing a single top-level
        # "threat_model" property and trailing shell prompt; no eval.
        start = raw.find('"threat_model"')
        if start < 0:
            raise ValueError('Not a valid JSON threat-model document') from None
        raw = '{' + raw[start:]
        data, _ = json.JSONDecoder().raw_decode(raw)
    if not isinstance(data, dict):
        raise ValueError('Expected JSON object')
    model = data.get('threat_model', data)
    if not isinstance(model, dict) or not isinstance(model.get('scenarios'), list):
        raise ValueError('Missing threat_model.scenarios list')
    return model

def clean(value):
    return re.sub(r'\s+', ' ', str(value or '')).strip()

def build(model: dict, requested_domains: list[str]):
    scenarios = model['scenarios']
    ids = set()
    requirements, tests, gaps = [], [], []
    counts = Counter()
    for index, s in enumerate(scenarios, 1):
        if not isinstance(s, dict):
            raise ValueError(f'Scenario {index} must be an object')
        sid = clean(s.get('id'))
        if not re.fullmatch(r'TM-\d{3,5}', sid) or sid in ids:
            raise ValueError(f'Invalid or duplicate scenario id: {sid}')
        ids.add(sid)
        domain, stride = s.get('domain'), s.get('stride')
        if domain not in DOMAINS or stride not in STRIDE:
            raise ValueError(f'Invalid domain/STRIDE for {sid}')
        counts[(domain,stride)] += 1
        refs = [r for r in s.get('reference_ids',[]) if r in REF_URLS]
        status = 'CONDITIONAL' if any(x in ' '.join(map(str,s.get('preconditions',[]))).lower() for x in ['is introduced','if present','may be introduced']) else 'UNVERIFIED'
        for i, mitigation in enumerate(s.get('mitigations', []),1):
            rid = f'{sid}-REQ-{i:02d}'
            requirements.append({
                'requirement_id':rid,'scenario_id':sid,'domain':domain,'stride':stride,
                'scenario_title':clean(s.get('title')),'security_requirement':clean(mitigation),
                'asset':clean(s.get('asset')),'trust_boundary':clean(s.get('trust_boundary')),
                'likelihood_hypothesis':clean(s.get('likelihood')),
                'impact_hypothesis':clean(s.get('impact')),
                'framework_reference_ids':'; '.join(refs),
                'framework_entry_urls':'; '.join(REF_URLS[r] for r in refs),
                'exact_control_mapping':'NOT_VERIFIED',
                'verification_method':'Review related scenario test catalog; map specific control after source verification',
                'evidence':'NOT_COLLECTED','implementation_status':status,
                'owner':'UNASSIGNED','approval':'PENDING',
            })
        for i, criterion in enumerate(s.get('acceptance_tests',[]),1):
            tests.append({
                'test_id':f'{sid}-TEST-{i:02d}', 'scenario_id':sid,
                'domain':domain,'stride':stride,'test_objective':clean(criterion),
                'test_type':'PROPOSED_SECURITY_VERIFICATION',
                'preconditions':'; '.join(map(clean,s.get('preconditions',[]))),
                'execution_environment':'ISOLATED_TEST_ENVIRONMENT_REQUIRED',
                'test_steps':'NOT_IMPLEMENTED — design test procedure and safety constraints',
                'expected_result':clean(criterion), 'evidence_to_collect':'Execution log; policy decision; observed outcome',
                'execution_status':'NOT_EXECUTED','result':'NOT_ASSESSED',
                'owner':'UNASSIGNED','human_approval_required':True,
            })
        if not s.get('mitigations'):
            gaps.append({'type':'MISSING_CONTROLS','scenario_id':sid,'detail':'No mitigations proposed'})
        if not s.get('acceptance_tests'):
            gaps.append({'type':'MISSING_TESTS','scenario_id':sid,'detail':'No acceptance tests proposed'})
        if not refs:
            gaps.append({'type':'UNVERIFIED_REFERENCES','scenario_id':sid,'detail':'No recognized framework entry references'})
    for d in requested_domains:
        if not any(s.get('domain')==d for s in scenarios):
            gaps.append({'type':'DOMAIN_NOT_COVERED','scenario_id':None,'detail':d})
    for st in STRIDE:
        if not any(s.get('stride')==st for s in scenarios):
            gaps.append({'type':'STRIDE_NOT_COVERED','scenario_id':None,'detail':st})
    for d in requested_domains:
        for st in STRIDE:
            if not counts[(d,st)]:
                gaps.append({'type':'DOMAIN_STRIDE_UNCOVERED','scenario_id':None,'detail':f'{d} / {st}'})
    for s in scenarios:
        if s.get('evidence_gaps'):
            gaps.append({'type':'IMPLEMENTATION_EVIDENCE_MISSING','scenario_id':s['id'],
                         'detail':'; '.join(map(clean,s['evidence_gaps']))})
    return requirements, tests, gaps, counts

def write_csv(path, rows, fields):
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); w.writerows(rows)

def generate(input_path: Path, output_dir: Path, name: str, domains: list[str]):
    model=load_model(input_path)
    req, tests, gaps, counts=build(model,domains)
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',name):
        raise ValueError('Invalid output name')
    output_dir.mkdir(parents=True,exist_ok=True)
    if output_dir.is_symlink():
        raise ValueError('Output directory is a symlink')
    base=output_dir/name
    paths={k:Path(str(base)+suffix) for k,suffix in {
        'requirements_csv':'-requirements.csv', 'requirements_json':'-requirements.json',
        'tests_csv':'-test-catalog.csv','tests_json':'-test-catalog.json',
        'gaps_json':'-coverage-gaps.json','review_md':'-review.md'}.items()}
    if any(p.exists() or p.is_symlink() for p in paths.values()):
        raise FileExistsError('One or more outputs exist; use a new --output-name')
    digest=hashlib.sha256(input_path.read_bytes()).hexdigest()
    common={'schema_version':1,'generated_at_utc':datetime.now(timezone.utc).isoformat(),
            'source_sha256':digest,'review_required':True,'tests_executed':False,
            'exact_framework_mappings_verified':False}
    paths['requirements_json'].write_text(json.dumps({**common,'requirements':req},indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    paths['tests_json'].write_text(json.dumps({**common,'tests':tests},indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    write_csv(paths['requirements_csv'],req,list(req[0]) if req else ['requirement_id','scenario_id'])
    write_csv(paths['tests_csv'],tests,list(tests[0]) if tests else ['test_id','scenario_id'])
    summary={'scenario_count':len(model['scenarios']),'requirements_count':len(req),
             'proposed_tests_count':len(tests),'requested_domains':domains,
             'stride_counts':{st:sum(v for (d,x),v in counts.items() if x==st) for st in STRIDE},
             'domain_counts':{d:sum(v for (x,st),v in counts.items() if x==d) for d in domains},
             'uncovered_domain_stride_pairs':sum(g['type']=='DOMAIN_STRIDE_UNCOVERED' for g in gaps),
             'gap_count':len(gaps)}
    paths['gaps_json'].write_text(json.dumps({**common,'summary':summary,'gaps':gaps,
        'interpretation':'Coverage gaps are prompts for analysis, not proof that all 48 domain/STRIDE combinations need scenarios.'},indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    lines=['# Threat-model security requirements and verification review','',
        '> Offline derivation from an AI-generated model. No standards clauses independently verified; no tests executed.','',
        f'**Source SHA-256:** `{digest}`','',
        f'**Scenarios:** {len(model["scenarios"])} | **Requirements:** {len(req)} | **Proposed tests:** {len(tests)}','',
        '## STRIDE coverage','', '| STRIDE | Scenarios |','|---|---:|']
    lines += [f'| {st} | {summary["stride_counts"][st]} |' for st in STRIDE]
    lines += ['','## Domain coverage','','| Domain | Scenarios |','|---|---:|']
    lines += [f'| {d} | {summary["domain_counts"][d]} |' for d in domains]
    lines += ['','## Gaps requiring review','']
    for g in gaps:
        if g['type'] != 'DOMAIN_STRIDE_UNCOVERED':
            lines.append(f'- **{g["type"]}** ({g["scenario_id"] or "global"}): {g["detail"]}')
    lines += ['','## Domain × STRIDE analysis','','A missing combination is a review prompt, not automatically a defect.','',
              '| Domain | '+' | '.join(STRIDE)+' |','|---|'+'---|'*len(STRIDE)]
    for d in domains:
        lines.append('| '+d+' | '+' | '.join(str(counts[(d,st)]) for st in STRIDE)+' |')
    lines += ['','## Suggested next threat-modeling pass','',
        '1. Confirm which components are implemented versus planned, and attach architecture evidence.',
        '2. Prioritize missing STRIDE categories, particularly repudiation of approvals and evidence provenance.',
        '3. Add scenario hypotheses only where assets, trust boundaries and plausible preconditions support them.',
        '4. Verify exact framework control/category IDs against official publications before assigning compliance mappings.',
        '5. Turn proposed acceptance criteria into independently reviewed, isolated tests; record results separately.',
        '6. Reassess likelihood and impact using observed controls and threat intelligence.','',
        '## Artifact descriptions','',
        '- Requirements CSV/JSON: proposed security requirements with unverified framework pointers.',
        '- Test catalog CSV/JSON: proposed tests, NOT runnable test code.',
        '- Coverage gaps JSON: systematic gaps and evidence requests.','']
    paths['review_md'].write_text('\n'.join(lines),encoding='utf-8')
    return paths,summary

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',required=True)
    p.add_argument('--output-dir',default='remediation/threat-models')
    p.add_argument('--output-name',default='cybersecurityagent-threat-model')
    p.add_argument('--domains',default=','.join(DOMAINS))
    a=p.parse_args()
    domains=[d.strip() for d in a.domains.split(',')]
    if not domains or len(domains)!=len(set(domains)) or any(d not in DOMAINS for d in domains):
        p.error('Invalid domains')
    paths,summary=generate(Path(a.input),Path(a.output_dir),a.output_name,domains)
    print(json.dumps({'files':{k:str(v) for k,v in paths.items()},'summary':summary},indent=2))

if __name__=='__main__':
    main()
