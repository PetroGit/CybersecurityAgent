import platform
import pytest

platform.node = lambda: "cybersecurityagent-validation"

raise SystemExit(pytest.main([
    "-v",
    "test_tm_004_controls.py",
    "--junitxml=remediation/control-validation/evidence/tm-004-pilot-junit-v2.xml",
]))
