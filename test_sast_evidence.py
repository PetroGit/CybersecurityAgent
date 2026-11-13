import json
import tempfile
import unittest
from pathlib import Path

from sast_evidence import build_reports, resolve_source_path
from sast_mistral import format_evidence, load_evidence_report


SOURCE = """\
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import re

def fetch(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "cwe.mitre.org":
        raise ValueError("invalid URL")
    match = re.fullmatch(r"/data/definitions/\\\\d+\\\\.html", parsed.path)
    if match is None:
        raise ValueError("invalid path")
    request = Request(url)
    return urlopen(request)
"""


def finding(path, line):
    return {
        "check_id": "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected",
        "path": str(path),
        "start": {"line": line},
        "extra": {
            "severity": "WARNING",
            "message": "Do not expose this source message to the model.",
            "lines": "return urlopen(request)",
            "metadata": {
                "confidence": "LOW",
                "cwe": ["CWE-939: Improper Authorization in Handler for Custom URL Scheme"],
            },
        },
    }


class EvidenceTests(unittest.TestCase):
    def test_builds_local_context_and_strict_sanitized_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "src" / "sample.py"
            source_path.parent.mkdir()
            source_path.write_text(SOURCE, encoding="utf-8")
            line = next(
                number
                for number, text in enumerate(SOURCE.splitlines(), start=1)
                if "return urlopen(request)" in text
            )

            local, sanitized = build_reports([finding("src/sample.py", line)], root)

            self.assertEqual(local["findings"][0]["source"]["enclosing_symbol"]["name"], "fetch")
            self.assertEqual(local["findings"][0]["url_controls"]["scheme_check_in_sink_function"], "detected")
            self.assertEqual(local["findings"][0]["url_controls"]["host_allowlist_in_sink_function"], "detected")
            self.assertEqual(local["findings"][0]["url_controls"]["path_check_in_sink_function"], "detected")
            self.assertEqual(local["findings"][0]["dataflow"]["source_to_sink_confirmed"], "unknown")
            serialized = json.dumps(sanitized)
            self.assertNotIn("src/sample.py", serialized)
            self.assertNotIn("urlopen(request)", serialized)
            self.assertNotIn("Do not expose", serialized)
            self.assertEqual(
                set(sanitized["findings"][0]),
                {
                    "finding_id",
                    "rule_id",
                    "severity",
                    "confidence",
                    "cwe_ids",
                    "sink_type",
                    "input_origin",
                    "taint_path_confirmed",
                    "url_controls",
                    "local_validation",
                    "evidence_type",
                },
            )

    def test_guards_in_a_different_function_are_not_attributed_to_finding(self):
        source = SOURCE + """\

def vulnerable(url):
    request = Request(url)
    return urlopen(request)
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "sample.py"
            source_path.write_text(source, encoding="utf-8")
            line = next(
                number
                for number, text in enumerate(source.splitlines(), start=1)
                if text == "    return urlopen(request)" and number > len(SOURCE.splitlines())
            )

            local, _ = build_reports([finding("sample.py", line)], root)

            self.assertEqual(local["findings"][0]["url_controls"]["scheme_check_in_sink_function"], "not_detected")
            self.assertEqual(local["findings"][0]["url_controls"]["host_allowlist_in_sink_function"], "not_detected")
            self.assertEqual(local["findings"][0]["url_controls"]["path_check_in_sink_function"], "not_detected")

    def test_sarif_source_to_sink_trace_is_local_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "src" / "sample.py"
            source_path.parent.mkdir()
            source_path.write_text(SOURCE, encoding="utf-8")
            line = next(
                number
                for number, text in enumerate(SOURCE.splitlines(), start=1)
                if "return urlopen(request)" in text
            )
            sarif_path = root / "trace.sarif"
            sarif_path.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "results": [
                                    {
                                        "ruleId": finding("src/sample.py", line)["check_id"],
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "src/sample.py"},
                                                    "region": {"startLine": line},
                                                }
                                            }
                                        ],
                                        "codeFlows": [
                                            {
                                                "threadFlows": [
                                                    {
                                                        "locations": [
                                                            {
                                                                "location": {
                                                                    "kinds": ["source"],
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "src/sample.py"},
                                                                        "region": {
                                                                            "startLine": line - 1,
                                                                            "snippet": {"text": "PRIVATE_SOURCE_MARKER"},
                                                                        },
                                                                    },
                                                                }
                                                            },
                                                            {
                                                                "location": {
                                                                    "kinds": ["sink"],
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "src/sample.py"},
                                                                        "region": {"startLine": line},
                                                                    },
                                                                }
                                                            },
                                                        ]
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            local, sanitized = build_reports(
                [finding("src/sample.py", line)], root, sarif_path
            )

            self.assertTrue(local["findings"][0]["dataflow"]["source_to_sink_confirmed"])
            self.assertIn("PRIVATE_SOURCE_MARKER", json.dumps(local))
            self.assertNotIn("PRIVATE_SOURCE_MARKER", json.dumps(sanitized))

    def test_source_resolution_rejects_paths_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            outside = Path(directory) / "outside.py"
            outside.write_text("pass\n", encoding="utf-8")

            self.assertIsNone(resolve_source_path(str(outside), root.resolve()))

    def test_mistral_loader_rejects_unallowlisted_fields(self):
        evidence = {
            "schema_version": 1,
            "report_type": "mistral_allowlisted_evidence",
            "policy": {
                "source_code_included": False,
                "repository_paths_included": False,
                "secrets_included": False,
                "allowlist_enforced": True,
            },
            "findings": [
                {
                    "finding_id": "SAST-0001",
                    "rule_id": "python.rule",
                    "severity": "WARNING",
                    "confidence": "LOW",
                    "cwe_ids": ["CWE-939"],
                    "sink_type": "urllib.request.urlopen",
                    "input_origin": "unknown",
                    "taint_path_confirmed": "unknown",
                    "url_controls": {
                        "scheme_check_in_sink_function": "unknown",
                        "host_allowlist_in_sink_function": "unknown",
                        "path_check_in_sink_function": "unknown",
                        "redirect_restriction": "unknown",
                    },
                    "local_validation": "requires_further_investigation",
                    "evidence_type": "local_static_analysis",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "evidence.json"
            report_path.write_text(json.dumps(evidence), encoding="utf-8")
            loaded = load_evidence_report(report_path)
            _, outbound = format_evidence(loaded[0])
            self.assertNotIn("source_code", outbound)

            evidence["findings"][0]["repository_path"] = "private/module.py"
            report_path.write_text(json.dumps(evidence), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "outside the allowlist"):
                load_evidence_report(report_path)


if __name__ == "__main__":
    unittest.main()
