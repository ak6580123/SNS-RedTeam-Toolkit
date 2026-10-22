import datetime as dt

from scripter.intel.matcher import match_findings
from scripter.intel.vuln_db import Signature
from scripter.models import Exploitability, MatchStatus, Severity, ServiceFinding


def _finding(service, version, banner="", host="10.10.1.5", port=21):
    return ServiceFinding(
        host=host, port=port, protocol="tcp", service=service, version=version,
        banner=banner, discovered_at=dt.datetime.now(dt.timezone.utc),
    )


def _sig(id_, service_pattern, version_pattern=None, confidence=0.5):
    return Signature(
        id=id_, cve="CVE-TEST", service_pattern=service_pattern, version_pattern=version_pattern,
        description="test", severity=Severity.HIGH, exploitability=Exploitability.TRIVIAL,
        time_to_validate_minutes=5, confidence_base=confidence, check=None,
    )


def test_match_by_service_and_version():
    findings = [_finding("ftp", "2.3.4", banner="220 vsFTPd 2.3.4")]
    sigs = [_sig("vsftpd-234", "^ftp$", r"2\.3\.4")]
    matches = match_findings(findings, sigs)
    assert len(matches) == 1
    assert matches[0].status == MatchStatus.HYPOTHESIS
    assert matches[0].signature_id == "vsftpd-234"


def test_no_match_when_version_differs():
    findings = [_finding("ftp", "3.0.3")]
    sigs = [_sig("vsftpd-234", "^ftp$", r"2\.3\.4")]
    assert match_findings(findings, sigs) == []


def test_match_without_version_requirement():
    findings = [_finding("redis", None)]
    sigs = [_sig("redis-unauth", "^redis$", None)]
    matches = match_findings(findings, sigs)
    assert len(matches) == 1


def test_finding_with_no_service_is_skipped():
    findings = [_finding(None, None)]
    sigs = [_sig("anything", ".*")]
    assert match_findings(findings, sigs) == []
