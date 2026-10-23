"""Online CVE lookup against the public NVD CVE API.

This is the one place in Scripter that calls out to a third party instead
of a scoped target or the bundled offline signature dataset - see
``intel/vuln_db.py`` for the offline side of vulnerability intelligence.
It builds a keyword query from an enumerated service/version string (as
recorded on a ``ServiceFinding``/``VulnMatch``) and asks
https://services.nvd.nist.gov for matching CVE records.

Gated by ``[intel] cve_lookup_enabled`` in config (default ``false``),
the same opt-in-network pattern as ``[validate] enabled`` and
``[redteam] network_audits_enabled`` - callers (cli.py's ``cve-lookup``
command, tui/app.py's Findings-tab button) are responsible for checking
that flag before calling ``lookup_cves``; this module itself has no
config dependency so it stays trivially unit-testable.
"""
from __future__ import annotations

import dataclasses
import json
import urllib.error
import urllib.parse
import urllib.request

_NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "scripter-redteam-toolkit-cve-lookup"


class CveLookupError(Exception):
    """The NVD API could not be reached, or returned something this module
    could not parse. Callers should catch this per service/version pair
    so one bad/rate-limited query does not abort an entire bulk lookup."""


@dataclasses.dataclass(frozen=True)
class CveResult:
    cve_id: str
    summary: str
    severity: str | None
    cvss_score: float | None
    published: str | None
    url: str


def _best_metric(metrics: dict) -> tuple[str | None, float | None]:
    """NVD reports CVSS under whichever metric version(s) were scored for
    that CVE - prefer the newest available rather than requiring v3.1."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            score = data.get("baseScore")
            return severity, (float(score) if score is not None else None)
    return None, None


def _english_description(descriptions: list[dict]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def lookup_cves(
    service: str,
    version: str | None,
    *,
    timeout_seconds: float = 10.0,
    max_results: int = 5,
    api_key: str | None = None,
) -> list[CveResult]:
    """Keyword-search NVD for CVEs matching ``service`` (+ ``version`` if
    known). Returns an empty list for a clean "no matches" - raises
    ``CveLookupError`` on any network/HTTP/parse failure so a caller can
    surface a clear error instead of a silently empty result.
    """
    keyword = f"{service} {version}".strip() if version else (service or "").strip()
    if not keyword:
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(max(1, min(max_results, 20))),
    }
    url = f"{_NVD_CVE_API_URL}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise CveLookupError(f"NVD API returned HTTP {exc.code} for {keyword!r}") from exc
    except urllib.error.URLError as exc:
        raise CveLookupError(f"could not reach the NVD API for {keyword!r}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise CveLookupError(f"NVD API request timed out for {keyword!r}") from exc
    except json.JSONDecodeError as exc:
        raise CveLookupError(f"NVD API returned unparseable JSON for {keyword!r}: {exc}") from exc

    results: list[CveResult] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "unknown")
        severity, score = _best_metric(cve.get("metrics", {}))
        results.append(
            CveResult(
                cve_id=cve_id,
                summary=_english_description(cve.get("descriptions", [])),
                severity=severity,
                cvss_score=score,
                published=cve.get("published"),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )
    return results
