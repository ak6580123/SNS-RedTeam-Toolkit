import json
import urllib.error

import pytest

from scripter.intel.cve_lookup import CveLookupError, lookup_cves


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _nvd_payload(*, cve_id="CVE-9999-0001", severity="HIGH", score=8.1, summary="A test vulnerability."):
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": summary}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseSeverity": severity, "baseScore": score}}
                        ]
                    },
                }
            }
        ]
    }


def test_lookup_cves_empty_keyword_returns_empty_list_without_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("urlopen should not be called for an empty keyword")

    monkeypatch.setattr("scripter.intel.cve_lookup.urllib.request.urlopen", boom)
    assert lookup_cves("", None) == []


def test_lookup_cves_parses_successful_response(monkeypatch):
    monkeypatch.setattr(
        "scripter.intel.cve_lookup.urllib.request.urlopen",
        lambda request, timeout: _FakeResponse(_nvd_payload()),
    )
    results = lookup_cves("openssh", "7.2", max_results=5)
    assert len(results) == 1
    r = results[0]
    assert r.cve_id == "CVE-9999-0001"
    assert r.severity == "HIGH"
    assert r.cvss_score == 8.1
    assert r.summary == "A test vulnerability."
    assert r.url == "https://nvd.nist.gov/vuln/detail/CVE-9999-0001"


def test_lookup_cves_no_matches_returns_empty_list(monkeypatch):
    monkeypatch.setattr(
        "scripter.intel.cve_lookup.urllib.request.urlopen",
        lambda request, timeout: _FakeResponse({"vulnerabilities": []}),
    )
    assert lookup_cves("some-obscure-service", "1.0") == []


def test_lookup_cves_raises_on_http_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr("scripter.intel.cve_lookup.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(CveLookupError):
        lookup_cves("openssh", "7.2")


def test_lookup_cves_raises_on_url_error(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr("scripter.intel.cve_lookup.urllib.request.urlopen", fake_urlopen)
    with pytest.raises(CveLookupError):
        lookup_cves("openssh", "7.2")


def test_lookup_cves_raises_on_malformed_json(monkeypatch):
    class _BadResponse(_FakeResponse):
        def read(self) -> bytes:
            return b"not json"

    monkeypatch.setattr(
        "scripter.intel.cve_lookup.urllib.request.urlopen",
        lambda request, timeout: _BadResponse({}),
    )
    with pytest.raises(CveLookupError):
        lookup_cves("openssh", "7.2")
