"""
Tests for engine_vantage/cve_lookup.py retry hardening
and engine_vantage/cve_matcher.py applicability (unchanged).

Covers requirements A–T from the test specification.
"""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock

import requests

from engine_vantage.cve_lookup import (
    search_cves,
    normalize_cve,
    _fetch_page,
    _parse_retry_after,
    _compute_wait,
    _MAX_ATTEMPTS,
    _RETRYABLE_STATUS_CODES,
    _BACKOFF_BASE,
    _BACKOFF_MAX,
    _PAGE_DELAY,
)
from engine_vantage.cve_matcher import (
    normalize_product,
    parse_cpe,
    compare_versions,
    cve_matches_product,
    _check_version_applicability,
)


# ────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────

def _make_nvd_page(vulns, total):
    """Build an NVD-shaped response dict."""
    return {
        "vulnerabilities": vulns,
        "totalResults": total,
    }


def _ok_response(json_data, status_code=200):
    """Build a mock requests.Response that succeeds."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    resp.headers = {}
    return resp


def _error_response(status_code, retry_after=None):
    """Build a mock requests.Response that raises HTTPError on raise_for_status."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    resp.headers = headers
    http_err = requests.exceptions.HTTPError(response=resp)
    resp.raise_for_status.side_effect = http_err
    return resp


# ────────────────────────────────────────────────────────
# A. Successful NVD request
# ────────────────────────────────────────────────────────

class TestSuccessfulRequest:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_single_page_success(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0001"}}]
        mock_get.return_value = _ok_response(_make_nvd_page(vulns, 1))

        result = search_cves("MySQL")

        assert len(result) == 1
        assert result[0]["cve"]["id"] == "CVE-2024-0001"
        assert mock_get.call_count == 1

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_returns_list_type(self, mock_get, mock_sleep):
        mock_get.return_value = _ok_response(_make_nvd_page([], 0))
        result = search_cves("MySQL")
        assert isinstance(result, list)


# ────────────────────────────────────────────────────────
# B. HTTP 429 → retry → success
# ────────────────────────────────────────────────────────

class TestRetry429Success:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_429_then_success(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0001"}}]

        mock_get.side_effect = [
            _error_response(429),
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("MySQL")

        assert len(result) == 1
        assert mock_get.call_count == 2
        mock_sleep.assert_called()

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_429_twice_then_success(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0001"}}]

        mock_get.side_effect = [
            _error_response(429),
            _error_response(429),
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("MySQL")

        assert len(result) == 1
        assert mock_get.call_count == 3


# ────────────────────────────────────────────────────────
# C. HTTP 429 → exhausted retries → RuntimeError
# ────────────────────────────────────────────────────────

class TestRetry429Exhausted:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_persistent_429_raises_runtime_error(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            _error_response(429) for _ in range(_MAX_ATTEMPTS)
        ]

        with pytest.raises(RuntimeError) as exc_info:
            search_cves("MySQL")

        assert "429" in str(exc_info.value)
        assert str(_MAX_ATTEMPTS) in str(exc_info.value)
        assert mock_get.call_count == _MAX_ATTEMPTS

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_exhausted_429_does_not_return_empty(self, mock_get, mock_sleep):
        """Failure must raise, never return []."""
        mock_get.side_effect = [
            _error_response(429) for _ in range(_MAX_ATTEMPTS)
        ]

        with pytest.raises(RuntimeError):
            search_cves("MySQL")


# ────────────────────────────────────────────────────────
# D. Retry-After numeric header is respected
# ────────────────────────────────────────────────────────

class TestRetryAfterRespected:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_retry_after_5_seconds(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0001"}}]

        mock_get.side_effect = [
            _error_response(429, retry_after=5),
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("MySQL")

        assert len(result) == 1
        # First sleep call should be the Retry-After value of 5
        mock_sleep.assert_any_call(5)

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_retry_after_10_seconds(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0001"}}]

        mock_get.side_effect = [
            _error_response(429, retry_after=10),
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("MySQL")

        assert len(result) == 1
        mock_sleep.assert_any_call(10)

    def test_parse_retry_after_valid(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "5"}
        assert _parse_retry_after(resp) == 5

    def test_parse_retry_after_large_valid(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "25"}
        assert _parse_retry_after(resp) == 25


# ────────────────────────────────────────────────────────
# E. Missing Retry-After uses fallback backoff
# ────────────────────────────────────────────────────────

class TestMissingRetryAfterFallback:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_no_retry_after_uses_exponential_backoff(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0001"}}]

        mock_get.side_effect = [
            _error_response(429),  # No Retry-After header
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        search_cves("MySQL")

        # With no Retry-After, attempt 0 should use _BACKOFF_BASE * 2^0 = 2
        mock_sleep.assert_any_call(_BACKOFF_BASE)

    def test_compute_wait_no_response(self):
        """No response means fallback to exponential backoff."""
        assert _compute_wait(0, None) == _BACKOFF_BASE
        assert _compute_wait(1, None) == _BACKOFF_BASE * 2
        assert _compute_wait(2, None) == _BACKOFF_BASE * 4

    def test_compute_wait_missing_header(self):
        resp = MagicMock()
        resp.headers = {}
        assert _compute_wait(0, resp) == _BACKOFF_BASE


# ────────────────────────────────────────────────────────
# F. Malformed Retry-After does not crash
# ────────────────────────────────────────────────────────

class TestMalformedRetryAfter:

    def test_non_numeric_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "not-a-number"}
        assert _parse_retry_after(resp) is None

    def test_empty_string_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": ""}
        assert _parse_retry_after(resp) is None

    def test_float_string_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "3.5"}
        assert _parse_retry_after(resp) is None

    def test_none_response(self):
        assert _parse_retry_after(None) is None

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_malformed_header_does_not_crash(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0001"}}]

        resp_429 = _error_response(429)
        resp_429.headers = {"Retry-After": "garbage"}

        mock_get.side_effect = [
            resp_429,
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("MySQL")
        assert len(result) == 1


# ────────────────────────────────────────────────────────
# G. Negative/invalid Retry-After does not cause
#    unbounded waiting
# ────────────────────────────────────────────────────────

class TestInvalidRetryAfterBounded:

    def test_negative_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "-5"}
        assert _parse_retry_after(resp) is None

    def test_zero_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "0"}
        assert _parse_retry_after(resp) is None

    def test_absurdly_large_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": "99999"}
        assert _parse_retry_after(resp) is None

    def test_just_above_max_retry_after(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": str(_BACKOFF_MAX + 1)}
        assert _parse_retry_after(resp) is None

    def test_at_max_is_valid(self):
        resp = MagicMock()
        resp.headers = {"Retry-After": str(_BACKOFF_MAX)}
        assert _parse_retry_after(resp) == _BACKOFF_MAX

    def test_exponential_backoff_is_capped(self):
        """Even at high attempt numbers, wait never exceeds _BACKOFF_MAX."""
        assert _compute_wait(10, None) == _BACKOFF_MAX
        assert _compute_wait(100, None) == _BACKOFF_MAX


# ────────────────────────────────────────────────────────
# H. HTTP 503 → retry
# ────────────────────────────────────────────────────────

class TestRetry503:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_503_then_success(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0002"}}]

        mock_get.side_effect = [
            _error_response(503),
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("Apache")

        assert len(result) == 1
        assert mock_get.call_count == 2


# ────────────────────────────────────────────────────────
# I. Timeout → retry
# ────────────────────────────────────────────────────────

class TestRetryTimeout:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_timeout_then_success(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0003"}}]

        mock_get.side_effect = [
            requests.exceptions.Timeout("timed out"),
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("OpenSSH")

        assert len(result) == 1
        assert mock_get.call_count == 2

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_persistent_timeout_raises(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            requests.exceptions.Timeout(f"t{i}") for i in range(_MAX_ATTEMPTS)
        ]

        with pytest.raises(RuntimeError) as exc_info:
            search_cves("MySQL")

        assert "timed out" in str(exc_info.value)
        assert mock_get.call_count == _MAX_ATTEMPTS


# ────────────────────────────────────────────────────────
# J. Connection error → retry
# ────────────────────────────────────────────────────────

class TestRetryConnectionError:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_connection_error_then_success(self, mock_get, mock_sleep):
        vulns = [{"cve": {"id": "CVE-2024-0004"}}]

        mock_get.side_effect = [
            requests.exceptions.ConnectionError("connection refused"),
            _ok_response(_make_nvd_page(vulns, 1)),
        ]

        result = search_cves("Samba")

        assert len(result) == 1
        assert mock_get.call_count == 2

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_persistent_connection_error_raises(self, mock_get, mock_sleep):
        mock_get.side_effect = [
            requests.exceptions.ConnectionError(f"c{i}")
            for i in range(_MAX_ATTEMPTS)
        ]

        with pytest.raises(RuntimeError) as exc_info:
            search_cves("MySQL")

        assert "connection failed" in str(exc_info.value)
        assert mock_get.call_count == _MAX_ATTEMPTS


# ────────────────────────────────────────────────────────
# K–N. Permanent HTTP errors — no retry
# ────────────────────────────────────────────────────────

class TestNonRetryable:

    @patch("engine_vantage.cve_lookup.requests.get")
    def test_400_fails_immediately(self, mock_get):
        mock_get.return_value = _error_response(400)

        with pytest.raises(RuntimeError) as exc_info:
            search_cves("MySQL")

        assert "400" in str(exc_info.value)
        assert mock_get.call_count == 1

    @patch("engine_vantage.cve_lookup.requests.get")
    def test_401_fails_immediately(self, mock_get):
        mock_get.return_value = _error_response(401)

        with pytest.raises(RuntimeError) as exc_info:
            search_cves("MySQL")

        assert "401" in str(exc_info.value)
        assert mock_get.call_count == 1

    @patch("engine_vantage.cve_lookup.requests.get")
    def test_403_fails_immediately(self, mock_get):
        mock_get.return_value = _error_response(403)

        with pytest.raises(RuntimeError) as exc_info:
            search_cves("MySQL")

        assert "403" in str(exc_info.value)
        assert mock_get.call_count == 1

    @patch("engine_vantage.cve_lookup.requests.get")
    def test_404_fails_immediately(self, mock_get):
        mock_get.return_value = _error_response(404)

        with pytest.raises(RuntimeError) as exc_info:
            search_cves("MySQL")

        assert "404" in str(exc_info.value)
        assert mock_get.call_count == 1


# ────────────────────────────────────────────────────────
# O. Pagination still works
# ────────────────────────────────────────────────────────

class TestPagination:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_two_page_pagination(self, mock_get, mock_sleep):
        page1_vulns = [{"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(100)]
        page2_vulns = [{"cve": {"id": f"CVE-2024-{i:04d}"}} for i in range(100, 150)]

        mock_get.side_effect = [
            _ok_response(_make_nvd_page(page1_vulns, 150)),
            _ok_response(_make_nvd_page(page2_vulns, 150)),
        ]

        result = search_cves("MySQL")

        assert len(result) == 150
        assert mock_get.call_count == 2

        # Verify startIndex was set correctly for page 2
        call_args = mock_get.call_args_list[1]
        assert call_args[1]["params"]["startIndex"] == 100

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_page_delay_between_pages(self, mock_get, mock_sleep):
        """Inter-page delay is applied between successful pages."""
        page1 = [{"cve": {"id": f"CVE-{i}"}} for i in range(100)]
        page2 = [{"cve": {"id": f"CVE-{i}"}} for i in range(100, 120)]

        mock_get.side_effect = [
            _ok_response(_make_nvd_page(page1, 120)),
            _ok_response(_make_nvd_page(page2, 120)),
        ]

        search_cves("MySQL")

        # Exactly one inter-page sleep with _PAGE_DELAY
        mock_sleep.assert_called_once_with(_PAGE_DELAY)


# ────────────────────────────────────────────────────────
# P. Multi-page lookup retrieves all results
# ────────────────────────────────────────────────────────

class TestMultiPageComplete:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_three_page_pagination(self, mock_get, mock_sleep):
        page1 = [{"cve": {"id": f"CVE-{i}"}} for i in range(100)]
        page2 = [{"cve": {"id": f"CVE-{i}"}} for i in range(100, 200)]
        page3 = [{"cve": {"id": f"CVE-{i}"}} for i in range(200, 250)]

        mock_get.side_effect = [
            _ok_response(_make_nvd_page(page1, 250)),
            _ok_response(_make_nvd_page(page2, 250)),
            _ok_response(_make_nvd_page(page3, 250)),
        ]

        result = search_cves("OpenSSH")

        assert len(result) == 250
        assert mock_get.call_count == 3

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_retry_on_second_page_still_completes(self, mock_get, mock_sleep):
        """Retry during pagination still retrieves all results."""
        page1_vulns = [{"cve": {"id": f"CVE-{i}"}} for i in range(100)]
        page2_vulns = [{"cve": {"id": f"CVE-{i}"}} for i in range(100, 130)]

        mock_get.side_effect = [
            _ok_response(_make_nvd_page(page1_vulns, 130)),
            _error_response(503),
            _ok_response(_make_nvd_page(page2_vulns, 130)),
        ]

        result = search_cves("Apache")

        assert len(result) == 130
        assert mock_get.call_count == 3


# ────────────────────────────────────────────────────────
# Q. Empty successful NVD response returns []
# ────────────────────────────────────────────────────────

class TestEmptySuccess:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_empty_results_returns_empty_list(self, mock_get, mock_sleep):
        mock_get.return_value = _ok_response(_make_nvd_page([], 0))

        result = search_cves("NonExistentProduct")

        assert result == []
        assert mock_get.call_count == 1


# ────────────────────────────────────────────────────────
# R. Exhausted lookup raises RuntimeError
# ────────────────────────────────────────────────────────

class TestExhaustedRaises:

    @patch("engine_vantage.cve_lookup.time.sleep")
    @patch("engine_vantage.cve_lookup.requests.get")
    def test_exhausted_raises_not_empty(self, mock_get, mock_sleep):
        """A lookup failure must NOT be converted to zero findings."""
        mock_get.side_effect = [
            _error_response(429) for _ in range(_MAX_ATTEMPTS)
        ]

        with pytest.raises(RuntimeError):
            search_cves("MySQL")

    @patch("engine_vantage.cve_lookup.requests.get")
    def test_permanent_error_raises(self, mock_get):
        mock_get.return_value = _error_response(400)

        with pytest.raises(RuntimeError):
            search_cves("MySQL")


# ────────────────────────────────────────────────────────
# S. CVSS v2 severity remains correct
# ────────────────────────────────────────────────────────

class TestCVSSv2:

    def test_cvss_v2_severity(self):
        cve_data = {
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [
                    {"lang": "en", "value": "Test v2 vulnerability"}
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "baseSeverity": "HIGH",
                            "cvssData": {
                                "baseScore": 7.5
                            }
                        }
                    ]
                },
                "weaknesses": []
            }
        }
        result = normalize_cve(cve_data)

        assert result["cve_id"] == "CVE-2024-9999"
        assert result["cvss"] == 7.5
        assert result["severity"] == "HIGH"
        assert result["description"] == "Test v2 vulnerability"


# ────────────────────────────────────────────────────────
# CVSS v3 severity tests (additional)
# ────────────────────────────────────────────────────────

class TestCVSSv3:

    def test_cvss_v31_severity(self):
        cve_data = {
            "cve": {
                "id": "CVE-2024-1111",
                "descriptions": [
                    {"lang": "en", "value": "v3.1 vuln"}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ]
                },
                "weaknesses": []
            }
        }
        result = normalize_cve(cve_data)

        assert result["cvss"] == 9.8
        assert result["severity"] == "CRITICAL"

    def test_cvss_v30_severity(self):
        cve_data = {
            "cve": {
                "id": "CVE-2024-2222",
                "descriptions": [
                    {"lang": "en", "value": "v3.0 vuln"}
                ],
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "cvssData": {
                                "baseScore": 5.3,
                                "baseSeverity": "MEDIUM"
                            }
                        }
                    ]
                },
                "weaknesses": []
            }
        }
        result = normalize_cve(cve_data)

        assert result["cvss"] == 5.3
        assert result["severity"] == "MEDIUM"

    def test_v31_takes_precedence_over_v2(self):
        cve_data = {
            "cve": {
                "id": "CVE-2024-3333",
                "descriptions": [{"lang": "en", "value": "dual metrics"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.1,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "baseSeverity": "HIGH",
                            "cvssData": {
                                "baseScore": 7.5
                            }
                        }
                    ]
                },
                "weaknesses": []
            }
        }
        result = normalize_cve(cve_data)

        assert result["cvss"] == 9.1
        assert result["severity"] == "CRITICAL"

    def test_no_metrics_returns_unknown(self):
        cve_data = {
            "cve": {
                "id": "CVE-2024-4444",
                "descriptions": [{"lang": "en", "value": "no metrics"}],
                "metrics": {},
                "weaknesses": []
            }
        }
        result = normalize_cve(cve_data)

        assert result["cvss"] is None
        assert result["severity"] == "UNKNOWN"


# ────────────────────────────────────────────────────────
# T. Existing cve_matcher applicability tests (59 tests)
# ────────────────────────────────────────────────────────

class TestProductNormalization:
    """Tests 1-8: Product identity normalization."""

    def test_apache_httpd(self):
        r = normalize_product("Apache HTTPD")
        assert r == {"vendor": "apache", "product": "http_server"}

    def test_apache_alone(self):
        r = normalize_product("Apache")
        assert r == {"vendor": "apache", "product": "http_server"}

    def test_vsftpd(self):
        r = normalize_product("vsftpd")
        assert r == {"vendor": "vsftpd_project", "product": "vsftpd"}

    def test_openssh(self):
        r = normalize_product("OpenSSH")
        assert r == {"vendor": "openbsd", "product": "openssh"}

    def test_mysql(self):
        r = normalize_product("MySQL")
        assert r == {"vendor": "oracle", "product": "mysql"}

    def test_samba_smbd(self):
        r = normalize_product("Samba smbd")
        assert r == {"vendor": "samba", "product": "samba"}

    def test_unknown_product(self):
        r = normalize_product("SomeUnknownProduct")
        assert r == {"vendor": "unknown", "product": "someunknownproduct"}

    def test_empty_product(self):
        r = normalize_product("")
        assert r == {"vendor": "unknown", "product": "unknown"}


class TestCPEParsing:
    """Tests 9-16: CPE 2.3 parsing."""

    def test_standard_cpe(self):
        r = parse_cpe("cpe:2.3:a:oracle:mysql:5.7.0:*:*:*:*:*:*:*")
        assert r["part"] == "a"
        assert r["vendor"] == "oracle"
        assert r["product"] == "mysql"
        assert r["version"] == "5.7.0"

    def test_escaped_colon(self):
        r = parse_cpe("cpe:2.3:a:vendor\\:name:product:1.0:*:*:*:*:*:*:*")
        assert r["vendor"] == "vendor:name"

    def test_wildcard_version(self):
        r = parse_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        assert r["version"] == "*"

    def test_missing_prefix(self):
        r = parse_cpe("some:random:string")
        assert r is None

    def test_empty_string(self):
        r = parse_cpe("")
        assert r is None

    def test_none_input(self):
        r = parse_cpe(None)
        assert r is None

    def test_too_few_fields(self):
        r = parse_cpe("cpe:2.3:a:vendor")
        assert r is None

    def test_openssh_cpe(self):
        r = parse_cpe("cpe:2.3:a:openbsd:openssh:7.4p1:*:*:*:*:*:*:*")
        assert r["vendor"] == "openbsd"
        assert r["product"] == "openssh"
        assert r["version"] == "7.4p1"


class TestVersionComparison:
    """Tests 17-28: Version comparison logic."""

    def test_equal_simple(self):
        assert compare_versions("1.0", "1.0") == 0

    def test_less_than(self):
        assert compare_versions("1.0", "2.0") == -1

    def test_greater_than(self):
        assert compare_versions("2.0", "1.0") == 1

    def test_multi_segment(self):
        assert compare_versions("1.2.3", "1.2.4") == -1

    def test_suffix_p1(self):
        assert compare_versions("7.4p1", "7.4p2") == -1

    def test_suffix_equal(self):
        assert compare_versions("7.4p1", "7.4p1") == 0

    def test_longer_version(self):
        assert compare_versions("1.0.0", "1.0") == 0

    def test_shorter_vs_longer(self):
        assert compare_versions("1.0", "1.0.1") == -1

    def test_alpha_suffix(self):
        assert compare_versions("1.1.1w", "1.1.1x") == -1

    def test_none_version(self):
        assert compare_versions("", "1.0") is None

    def test_none_both(self):
        assert compare_versions("", "") is None

    def test_complex_versions(self):
        assert compare_versions("2023.83", "2023.84") == -1


class TestVersionApplicability:
    """Tests 29-38: Version applicability checks."""

    def test_exact_match(self):
        match, reason = _check_version_applicability(
            "5.7.0", {}, "5.7.0"
        )
        assert match is True

    def test_exact_mismatch(self):
        match, reason = _check_version_applicability(
            "5.7.0", {}, "5.7.1"
        )
        assert match is False

    def test_wildcard_no_constraints(self):
        match, reason = _check_version_applicability(
            "*", {}, "any.version"
        )
        assert match is True

    def test_start_including(self):
        match, _ = _check_version_applicability(
            "*",
            {"versionStartIncluding": "1.0"},
            "2.0"
        )
        assert match is True

    def test_start_including_at_boundary(self):
        match, _ = _check_version_applicability(
            "*",
            {"versionStartIncluding": "1.0"},
            "1.0"
        )
        assert match is True

    def test_start_including_below(self):
        match, _ = _check_version_applicability(
            "*",
            {"versionStartIncluding": "2.0"},
            "1.0"
        )
        assert match is False

    def test_end_excluding(self):
        match, _ = _check_version_applicability(
            "*",
            {"versionEndExcluding": "3.0"},
            "2.9"
        )
        assert match is True

    def test_end_excluding_at_boundary(self):
        match, _ = _check_version_applicability(
            "*",
            {"versionEndExcluding": "3.0"},
            "3.0"
        )
        assert match is False

    def test_range_inside(self):
        match, _ = _check_version_applicability(
            "*",
            {
                "versionStartIncluding": "1.0",
                "versionEndExcluding": "3.0"
            },
            "2.0"
        )
        assert match is True

    def test_range_outside(self):
        match, _ = _check_version_applicability(
            "*",
            {
                "versionStartIncluding": "1.0",
                "versionEndExcluding": "3.0"
            },
            "4.0"
        )
        assert match is False


class TestCVEMatchesProduct:
    """Tests 39-59: Full CVE applicability evaluation (cve_matches_product)."""

    def _make_cve(self, cpe_criteria, vulnerable=True, **range_kwargs):
        """Helper to build a CVE record with a single CPE match."""
        cpe_match = {
            "vulnerable": vulnerable,
            "criteria": cpe_criteria,
        }
        cpe_match.update(range_kwargs)
        return {
            "cve": {
                "id": "CVE-TEST",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [cpe_match]
                            }
                        ]
                    }
                ]
            }
        }

    def test_match_mysql(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "MATCH"

    def test_no_match_version(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "5.7.1")
        assert r["state"] == "NO_MATCH"

    def test_match_openssh_range(self):
        cve = self._make_cve(
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            versionStartIncluding="7.0",
            versionEndExcluding="7.5"
        )
        r = cve_matches_product(cve, "OpenSSH", "7.4p1")
        assert r["state"] == "MATCH"

    def test_no_match_openssh_below_range(self):
        cve = self._make_cve(
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            versionStartIncluding="8.0",
            versionEndExcluding="8.5"
        )
        r = cve_matches_product(cve, "OpenSSH", "7.4p1")
        assert r["state"] == "NO_MATCH"

    def test_match_apache(self):
        cve = self._make_cve("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "Apache HTTPD", "2.4.49")
        assert r["state"] == "MATCH"

    def test_unknown_product(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "SomeRandom", "1.0")
        assert r["state"] == "NO_MATCH"

    def test_empty_version(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "")
        assert r["state"] == "NO_MATCH"

    def test_unknown_version(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "unknown")
        assert r["state"] == "NO_MATCH"

    def test_vendor_mismatch(self):
        cve = self._make_cve("cpe:2.3:a:mariadb:mysql:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "NO_MATCH"

    def test_product_mismatch(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mariadb:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "NO_MATCH"

    def test_wildcard_all_versions(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "99.99")
        assert r["state"] == "MATCH"

    def test_os_cpe_no_match(self):
        cve = self._make_cve("cpe:2.3:o:oracle:mysql:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "NO_MATCH"

    def test_no_configurations(self):
        cve = {"cve": {"id": "CVE-EMPTY", "configurations": []}}
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "NO_MATCH"

    def test_missing_configurations(self):
        cve = {"cve": {"id": "CVE-MISSING"}}
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "NO_MATCH"

    def test_end_including_boundary(self):
        cve = self._make_cve(
            "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
            versionEndIncluding="5.7.10"
        )
        r = cve_matches_product(cve, "MySQL", "5.7.10")
        assert r["state"] == "MATCH"

    def test_end_including_beyond(self):
        cve = self._make_cve(
            "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
            versionEndIncluding="5.7.10"
        )
        r = cve_matches_product(cve, "MySQL", "5.7.11")
        assert r["state"] == "NO_MATCH"

    def test_start_excluding_boundary(self):
        cve = self._make_cve(
            "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
            versionStartExcluding="5.7.0"
        )
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "NO_MATCH"

    def test_start_excluding_above(self):
        cve = self._make_cve(
            "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
            versionStartExcluding="5.7.0"
        )
        r = cve_matches_product(cve, "MySQL", "5.7.1")
        assert r["state"] == "MATCH"

    def test_non_vulnerable_cpe_is_indeterminate(self):
        cve = self._make_cve(
            "cpe:2.3:a:oracle:mysql:5.7.0:*:*:*:*:*:*:*",
            vulnerable=False
        )
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "INDETERMINATE"

    def test_match_evidence_has_vendor(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["state"] == "MATCH"
        assert r["evidence"]["detected_vendor"] == "oracle"

    def test_match_evidence_has_product(self):
        cve = self._make_cve("cpe:2.3:a:oracle:mysql:5.7.0:*:*:*:*:*:*:*")
        r = cve_matches_product(cve, "MySQL", "5.7.0")
        assert r["evidence"]["detected_product"] == "mysql"


# ────────────────────────────────────────────────────────
# Constants verification
# ────────────────────────────────────────────────────────

class TestConstants:

    def test_max_attempts(self):
        assert _MAX_ATTEMPTS >= 3

    def test_retryable_codes(self):
        assert 429 in _RETRYABLE_STATUS_CODES
        assert 500 in _RETRYABLE_STATUS_CODES
        assert 502 in _RETRYABLE_STATUS_CODES
        assert 503 in _RETRYABLE_STATUS_CODES
        assert 504 in _RETRYABLE_STATUS_CODES

    def test_non_retryable_codes_excluded(self):
        assert 400 not in _RETRYABLE_STATUS_CODES
        assert 401 not in _RETRYABLE_STATUS_CODES
        assert 403 not in _RETRYABLE_STATUS_CODES
        assert 404 not in _RETRYABLE_STATUS_CODES

    def test_backoff_max_is_reasonable(self):
        assert _BACKOFF_MAX <= 60

    def test_page_delay_is_small(self):
        assert _PAGE_DELAY <= 5
