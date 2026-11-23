"""Normalize OWASP ZAP baseline JSON into CybersecurityAgent findings."""
import argparse
import json
from pathlib import Path


def normalize(data):
    findings = []
    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            instances = alert.get('instances') or []
            findings.append({
                'engine': 'owasp-zap',
                'rule_id': str(alert.get('pluginid', '')),
                'title': alert.get('name', ''),
                'risk': alert.get('riskdesc', ''),
                'confidence': alert.get('confidence', ''),
                'description': alert.get('desc', ''),
                'remediation': alert.get('solution', ''),
                'cwe_id': alert.get('cweid', ''),
                'evidence': [{'uri': i.get('uri', ''), 'method': i.get('method', '')} for i in instances],
            })
    return {'schema_version': '0.1', 'assessment_mode': 'local-dast-passive', 'findings': findings, 'finding_count': len(findings)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.input).read_text(encoding='utf-8'))
    result = normalize(data)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(f"Normalized {result['finding_count']} ZAP alerts to {output}")


if __name__ == '__main__':
    main()
