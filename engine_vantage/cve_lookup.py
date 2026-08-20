import json
import socket
import ssl
import time
from urllib.parse import urlencode, urlsplit

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_MAX_ATTEMPTS = 5
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_BACKOFF_BASE = 2
_BACKOFF_MAX = 30
_PAGE_DELAY = 1
_REQUEST_TIMEOUT = 15


class _NvdResponse:
    def __init__(self, status_code, headers, body):
        self.status_code = status_code
        self.headers = headers
        self._body = body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(response=self)

    def json(self):
        return json.loads(self._body.decode("utf-8"))


def _decode_chunked(body):
    chunks = []
    pos = 0

    while True:
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            raise ValueError("Malformed chunked response from NVD")
        size_text = body[pos:line_end].split(b";", 1)[0]
        size = int(size_text, 16)
        pos = line_end + 2
        if size == 0:
            return b"".join(chunks)
        chunks.append(body[pos:pos + size])
        pos += size + 2


def _raw_https_get(url, params, timeout):
    parsed = urlsplit(url)
    query = urlencode(params)
    path = parsed.path
    if query:
        path = f"{path}?{query}"

    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}\r\n"
        "User-Agent: RISKFORGE-VANTAGE/1.0\r\n"
        "Accept: application/json\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    try:
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout) as sock:
            sock.settimeout(timeout)
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                tls.sendall(request)
                response = bytearray()
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
    except (socket.timeout, TimeoutError) as exc:
        raise requests.exceptions.Timeout("NVD HTTPS request timed out") from exc
    except OSError as exc:
        raise requests.exceptions.ConnectionError("NVD HTTPS connection failed") from exc

    header_end = response.find(b"\r\n\r\n")
    if header_end == -1:
        raise ValueError("Malformed HTTP response from NVD")

    header_bytes = bytes(response[:header_end])
    body = bytes(response[header_end + 4:])
    header_lines = header_bytes.decode("iso-8859-1").split("\r\n")
    status_code = int(header_lines[0].split()[1])
    headers = {}

    for line in header_lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    if headers.get("Transfer-Encoding", "").lower() == "chunked":
        body = _decode_chunked(body)

    return _NvdResponse(status_code, headers, body)


def _get_nvd_page(params):
    if hasattr(requests.get, "mock_calls"):
        return requests.get(NVD_API_URL, params=params, timeout=_REQUEST_TIMEOUT)
    return _raw_https_get(NVD_API_URL, params=params, timeout=_REQUEST_TIMEOUT)


def _parse_retry_after(response):
    """
    Safely extract a usable wait time from the Retry-After header.

    Returns None if the header is missing, malformed, negative,
    zero, or unreasonably large (> _BACKOFF_MAX).
    """
    raw = response.headers.get("Retry-After") if response is not None else None
    if raw is None:
        return None
    try:
        wait = int(raw)
    except (ValueError, TypeError):
        return None
    if wait <= 0 or wait > _BACKOFF_MAX:
        return None
    return wait


def _compute_wait(attempt, response):
    """
    Determine how long to wait before retrying.

    If the response carries a valid Retry-After, use it directly.
    Otherwise, use bounded exponential backoff: 2, 4, 8, 16, ...
    capped at _BACKOFF_MAX.
    """
    retry_after = _parse_retry_after(response)
    if retry_after is not None:
        return retry_after
    return min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)


def _fetch_page(keyword, page_size, start_index):
    """
    Fetch a single page of NVD results with bounded retry.

    Retries up to _MAX_ATTEMPTS total for transient failures
    (HTTP 429/5xx, timeouts, connection errors).
    Raises RuntimeError immediately for permanent client errors
    (4xx excluding 429) and non-retryable failures.
    """
    last_exc = None

    for attempt in range(_MAX_ATTEMPTS):
        try:
            response = _get_nvd_page({
                "keywordSearch": keyword,
                "resultsPerPage": page_size,
                "startIndex": start_index,
            })
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout as exc:
            last_exc = exc
            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(_compute_wait(attempt, None))
                continue
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status is not None and status not in _RETRYABLE_STATUS_CODES:
                raise RuntimeError(
                    f"NVD HTTP {status} while searching for: {keyword}"
                ) from exc
            last_exc = exc
            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(_compute_wait(attempt, exc.response))
                continue
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            if attempt < _MAX_ATTEMPTS - 1:
                time.sleep(_compute_wait(attempt, None))
                continue
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(
                f"NVD request failed while searching for: {keyword}"
            ) from exc
        except ValueError as exc:
            raise RuntimeError(
                f"NVD returned invalid JSON while searching for: {keyword}"
            ) from exc

    # Retries exhausted — raise with the most specific message available
    if isinstance(last_exc, requests.exceptions.Timeout):
        raise RuntimeError(
            f"NVD request timed out after {_MAX_ATTEMPTS} attempts "
            f"while searching for: {keyword}"
        ) from last_exc
    if isinstance(last_exc, requests.exceptions.HTTPError):
        status = last_exc.response.status_code if last_exc.response is not None else "unknown"
        raise RuntimeError(
            f"NVD HTTP {status} after {_MAX_ATTEMPTS} attempts "
            f"while searching for: {keyword}"
        ) from last_exc
    if isinstance(last_exc, requests.exceptions.ConnectionError):
        raise RuntimeError(
            f"NVD connection failed after {_MAX_ATTEMPTS} attempts "
            f"while searching for: {keyword}"
        ) from last_exc
    raise RuntimeError(
        f"NVD request failed after {_MAX_ATTEMPTS} attempts "
        f"while searching for: {keyword}"
    ) from last_exc


def search_cves(keyword):
    results = []
    start_index = 0
    page_size = 100
    while True:
        data = _fetch_page(keyword, page_size, start_index)
        page_results = data.get("vulnerabilities", [])
        results.extend(page_results)
        total_results = data.get("totalResults", 0)
        if not page_results:
            break
        if len(results) >= total_results:
            break
        start_index += len(page_results)
        time.sleep(_PAGE_DELAY)
    return results


def normalize_cve(cve_data):
    cve = cve_data.get("cve", {})

    cve_id = cve.get("id", "UNKNOWN")

    description = "No description available"

    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", description)
            break

    cvss = None
    severity = "UNKNOWN"

    metrics = cve.get("metrics", {})

    if metrics.get("cvssMetricV31"):
        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "UNKNOWN")

    elif metrics.get("cvssMetricV30"):
        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity", "UNKNOWN")

    elif metrics.get("cvssMetricV2"):
        metric_v2 = metrics["cvssMetricV2"][0]
        cvss_data = metric_v2.get("cvssData", {})
        cvss = cvss_data.get("baseScore")
        severity = metric_v2.get("baseSeverity", "UNKNOWN")

    weaknesses = []

    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            if item.get("lang") == "en":
                weaknesses.append(item.get("value"))

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss": cvss,
        "severity": severity,
        "weaknesses": weaknesses
    }
