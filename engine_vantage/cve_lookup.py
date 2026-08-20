import time

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_MAX_ATTEMPTS = 5
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
_BACKOFF_BASE = 2
_BACKOFF_MAX = 30
_PAGE_DELAY = 1


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
            response = requests.get(
                NVD_API_URL,
                params={
                    "keywordSearch": keyword,
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                },
                timeout=15,
            )
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
