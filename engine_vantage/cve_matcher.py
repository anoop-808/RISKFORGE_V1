# ============================================================
# Product identity normalization
# ============================================================

PRODUCT_ALIASES = {
    "apache httpd": {
        "vendor": "apache",
        "product": "http_server"
    },
    "apache": {
        "vendor": "apache",
        "product": "http_server"
    },
    "vsftpd": {
        "vendor": "vsftpd_project",
        "product": "vsftpd"
    },
    "openssh": {
        "vendor": "openbsd",
        "product": "openssh"
    },
    "mysql": {
        "vendor": "oracle",
        "product": "mysql"
    },
    "samba smbd": {
        "vendor": "samba",
        "product": "samba"
    }
}


def normalize_product(product):
    """
    Convert a scanner product name into a normalized
    vendor/product identity suitable for CPE matching.
    """

    if not product:
        return {
            "vendor": "unknown",
            "product": "unknown"
        }

    normalized = product.strip().lower()

    return PRODUCT_ALIASES.get(
        normalized,
        {
            "vendor": "unknown",
            "product": normalized
        }
    )


# ============================================================
# CPE 2.3 parser
# ============================================================

def parse_cpe(cpe_string):
    """
    Parse a CPE 2.3 formatted string, handling escaped characters.

    Walks the string character-by-character to correctly split on
    unescaped colons, preserving escaped values such as \\: \\* \\?

    Returns a dict with part, vendor, product, version fields,
    or None if the string is not a valid CPE 2.3 string.
    """

    if not cpe_string or not cpe_string.startswith("cpe:2.3:"):
        return None

    # Strip the "cpe:2.3:" prefix and split on unescaped colons
    remainder = cpe_string[8:]
    fields = []
    current = []
    i = 0

    while i < len(remainder):
        if remainder[i] == '\\' and i + 1 < len(remainder):
            # Escaped character — include the literal next character
            current.append(remainder[i + 1])
            i += 2
        elif remainder[i] == ':':
            fields.append(''.join(current))
            current = []
            i += 1
        else:
            current.append(remainder[i])
            i += 1

    fields.append(''.join(current))

    # CPE 2.3 requires at least: part, vendor, product, version
    if len(fields) < 4:
        return None

    return {
        "part": fields[0],
        "vendor": fields[1],
        "product": fields[2],
        "version": fields[3],
    }


# ============================================================
# Version parsing and comparison
# ============================================================

def _parse_version_segment(segment):
    """
    Parse a single version segment into alternating
    numeric and alphabetic tokens.

    Examples:
        "7"    -> [7]
        "7p1"  -> [7, "p", 1]
        "1w"   -> [1, "w"]
        "rc2"  -> ["rc", 2]
    """

    tokens = []
    i = 0

    while i < len(segment):
        if segment[i].isdigit():
            j = i
            while j < len(segment) and segment[j].isdigit():
                j += 1
            tokens.append(int(segment[i:j]))
            i = j
        elif segment[i].isalpha():
            j = i
            while j < len(segment) and segment[j].isalpha():
                j += 1
            tokens.append(segment[i:j].lower())
            i = j
        else:
            # Skip non-alphanumeric separators (-, _, +, etc.)
            i += 1

    return tokens if tokens else [0]


def _parse_version(version_str):
    """
    Parse a full version string into a list of segment token lists.

    Splits on '.' and parses each segment individually.
    Returns None if the version string is empty.
    """

    if not version_str:
        return None

    segments = version_str.split(".")
    return [_parse_version_segment(seg) for seg in segments]


def _compare_segments(seg_a, seg_b):
    """
    Compare two parsed version segments token by token.

    Returns:
        -1   if seg_a < seg_b
         0   if seg_a == seg_b
         1   if seg_a > seg_b
        None if comparison is indeterminate (mixed types)
    """

    max_len = max(len(seg_a), len(seg_b))

    for i in range(max_len):
        if i >= len(seg_a):
            return -1  # seg_a is shorter -> less
        if i >= len(seg_b):
            return 1   # seg_b is shorter -> seg_a is greater

        tok_a = seg_a[i]
        tok_b = seg_b[i]

        if isinstance(tok_a, int) and isinstance(tok_b, int):
            if tok_a < tok_b:
                return -1
            if tok_a > tok_b:
                return 1
        elif isinstance(tok_a, str) and isinstance(tok_b, str):
            if tok_a < tok_b:
                return -1
            if tok_a > tok_b:
                return 1
        else:
            # Mixed types (int vs str) — cannot reliably compare
            return None

    return 0


def compare_versions(version_a, version_b):
    """
    Compare two software version strings.

    Correctly handles version suffixes such as:
        4.7p1, 1.1.1w, 10.0p2, 2023.83

    Returns:
        -1   if version_a < version_b
         0   if version_a == version_b
         1   if version_a > version_b
        None if comparison is indeterminate
    """

    parsed_a = _parse_version(version_a)
    parsed_b = _parse_version(version_b)

    if parsed_a is None or parsed_b is None:
        return None

    max_len = max(len(parsed_a), len(parsed_b))

    for i in range(max_len):
        seg_a = parsed_a[i] if i < len(parsed_a) else [0]
        seg_b = parsed_b[i] if i < len(parsed_b) else [0]

        result = _compare_segments(seg_a, seg_b)

        if result is None:
            return None
        if result != 0:
            return result

    return 0


# ============================================================
# Version applicability check
# ============================================================

def _check_version_applicability(cpe_version, cpe_match, detected_version):
    """
    Determine whether a detected version satisfies the CPE
    version constraints.

    Returns:
        (True, None)  — version matches (vulnerable)
        (False, reason) — version does not match
        (None, reason)  — comparison is indeterminate
    """

    # Exact CPE version (not wildcard)
    if cpe_version not in ("*", "-"):
        if cpe_version == detected_version:
            return True, None
        return False, "version_mismatch"

    # Wildcard/any — check version range boundaries
    start_incl = cpe_match.get("versionStartIncluding")
    start_excl = cpe_match.get("versionStartExcluding")
    end_incl = cpe_match.get("versionEndIncluding")
    end_excl = cpe_match.get("versionEndExcluding")

    has_constraints = any(
        v is not None
        for v in (start_incl, start_excl, end_incl, end_excl)
    )

    if not has_constraints:
        # Wildcard with no boundaries -> all versions affected
        return True, None

    # Lower bound checks
    if start_incl is not None:
        cmp = compare_versions(detected_version, start_incl)
        if cmp is None:
            return None, "version_comparison_indeterminate"
        if cmp < 0:
            return False, "version_out_of_bounds"

    if start_excl is not None:
        cmp = compare_versions(detected_version, start_excl)
        if cmp is None:
            return None, "version_comparison_indeterminate"
        if cmp <= 0:
            return False, "version_out_of_bounds"

    # Upper bound checks
    if end_incl is not None:
        cmp = compare_versions(detected_version, end_incl)
        if cmp is None:
            return None, "version_comparison_indeterminate"
        if cmp > 0:
            return False, "version_out_of_bounds"

    if end_excl is not None:
        cmp = compare_versions(detected_version, end_excl)
        if cmp is None:
            return None, "version_comparison_indeterminate"
        if cmp >= 0:
            return False, "version_out_of_bounds"

    return True, None


# ============================================================
# Single CPE match evaluation
# ============================================================

def _evaluate_vulnerable_cpe(cpe_match, detected):
    """
    Evaluate a single vulnerable CPE match entry against
    detected software identity and version.

    Checks:
        1. CPE part must be "a" (application)
        2. CPE vendor must match detected canonical vendor
        3. CPE product must match detected canonical product
        4. Version must satisfy CPE version constraints

    Returns:
        ("MATCH", evidence_dict)
        ("NO_MATCH", None)
        ("INDETERMINATE", evidence_dict)
    """

    criteria = cpe_match.get("criteria", "")
    parsed = parse_cpe(criteria)

    if not parsed:
        return "NO_MATCH", {"reason": "applicability_constraints_not_satisfied"}

    # CPE part must be application for application detection
    if parsed["part"] not in ("a", "*"):
        return "NO_MATCH", {"reason": "cpe_part_mismatch", "expected": "a", "actual": parsed["part"]}

    # Vendor identity must match
    cpe_vendor = parsed["vendor"]
    if cpe_vendor not in ("*", detected["vendor"]):
        return "NO_MATCH", {"reason": "vendor_mismatch", "expected": cpe_vendor, "actual": detected["vendor"]}

    # Product identity must match
    cpe_product = parsed["product"]
    if cpe_product not in ("*", detected["product"]):
        return "NO_MATCH", {"reason": "product_mismatch", "expected": cpe_product, "actual": detected["product"]}

    # Version applicability
    version_match, version_reason = _check_version_applicability(
        parsed["version"], cpe_match, detected["version"]
    )

    evidence = {
        "detected_vendor": detected["vendor"],
        "detected_product": detected["product"],
        "detected_version": detected["version"],
        "matched_cpe_part": parsed["part"],
        "matched_cpe_vendor": cpe_vendor,
        "matched_cpe_product": cpe_product,
        "matched_cpe_version": parsed["version"],
    }

    for key in ("versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding"):
        val = cpe_match.get(key)
        if val is not None:
            evidence[key] = val

    if version_match is True:
        return "MATCH", evidence
    elif version_match is False:
        evidence["reason"] = version_reason
        return "NO_MATCH", evidence
    else:
        evidence["reason"] = version_reason
        return "INDETERMINATE", evidence


# ============================================================
# Result combination helpers
# ============================================================

def _combine_or(results):
    """
    Combine evaluation results with OR logic.

    Any MATCH -> MATCH.
    Any INDETERMINATE (with no MATCH) -> INDETERMINATE.
    Otherwise -> NO_MATCH.
    """

    best_state = "NO_MATCH"
    best_evidence = None
    no_match_evidence = None

    for state, evidence in results:
        if state == "MATCH":
            return "MATCH", evidence
        if state == "INDETERMINATE" and best_state == "NO_MATCH":
            best_state = "INDETERMINATE"
            best_evidence = evidence
        if state == "NO_MATCH" and no_match_evidence is None:
            no_match_evidence = evidence

    if best_state == "NO_MATCH":
        return "NO_MATCH", no_match_evidence
    return best_state, best_evidence


def _combine_and(results):
    """
    Combine evaluation results with AND logic.

    Any NO_MATCH -> NO_MATCH (AND fails).
    Any INDETERMINATE (with no NO_MATCH) -> INDETERMINATE.
    All MATCH -> MATCH.
    """

    has_no_match = False
    has_indeterminate = False
    match_evidence = None
    indet_evidence = None
    no_match_evidence = None

    for state, evidence in results:
        if state == "NO_MATCH":
            has_no_match = True
            if no_match_evidence is None:
                no_match_evidence = evidence
        elif state == "INDETERMINATE":
            has_indeterminate = True
            if indet_evidence is None:
                indet_evidence = evidence
        elif state == "MATCH":
            if match_evidence is None:
                match_evidence = evidence

    if has_no_match:
        return "NO_MATCH", no_match_evidence
    if has_indeterminate:
        return "INDETERMINATE", indet_evidence or match_evidence
    if match_evidence is not None:
        return "MATCH", match_evidence
    return "NO_MATCH", {"reason": "applicability_constraints_not_satisfied"}


def _apply_negate(state, evidence):
    """
    Apply negation to an evaluation result.

    Conservative security-oriented three-state logic inspired
    by Kleene semantics, with domain-specific handling of
    unknown negated prerequisites.

    MATCH -> NO_MATCH (negated match definitively fails).
    NO_MATCH or INDETERMINATE -> INDETERMINATE
    (cannot confirm the negated condition from available evidence).
    """

    if state == "MATCH":
        evidence_copy = dict(evidence) if evidence else {}
        evidence_copy["reason"] = "negated_match"
        return "NO_MATCH", evidence_copy
    return "INDETERMINATE", evidence


# ============================================================
# Node evaluation
# ============================================================

def _evaluate_node(node, detected):
    """
    Evaluate a single NVD configuration node.

    A node contains cpeMatch entries grouped by an operator
    (OR/AND) and an optional negate flag.

    Nodes with only vulnerable=false CPE entries represent
    platform/environment conditions that VANTAGE cannot
    currently evaluate -> INDETERMINATE.
    """

    operator = node.get("operator", "OR")
    negate = node.get("negate", False)
    cpe_matches = node.get("cpeMatch", [])

    if not cpe_matches:
        return "NO_MATCH", {"reason": "applicability_constraints_not_satisfied"}

    # Separate vulnerable and non-vulnerable CPE entries
    vuln_entries = [
        m for m in cpe_matches if m.get("vulnerable", False)
    ]
    non_vuln_entries = [
        m for m in cpe_matches if not m.get("vulnerable", False)
    ]

    if not vuln_entries and non_vuln_entries:
        # This node contains only platform/environment conditions.
        # VANTAGE does not currently perform OS/platform detection
        # and cannot confirm or deny these conditions.
        result_state = "INDETERMINATE"
        result_evidence = {
            "reason": "platform_condition_not_evaluable"
        }
    elif vuln_entries:
        # Evaluate vulnerable CPE entries
        results = []
        for entry in vuln_entries:
            state, evidence = _evaluate_vulnerable_cpe(entry, detected)
            results.append((state, evidence))

        if operator == "AND":
            result_state, result_evidence = _combine_and(results)
        else:
            result_state, result_evidence = _combine_or(results)
    else:
        return "NO_MATCH", {"reason": "applicability_constraints_not_satisfied"}

    if negate:
        return _apply_negate(result_state, result_evidence)

    return result_state, result_evidence


# ============================================================
# Configuration evaluation
# ============================================================

def _evaluate_configuration(config, detected):
    """
    Evaluate a single NVD configuration.

    A configuration has an optional operator (AND/OR) determining
    how its nodes relate, and a list of nodes.

    AND: all nodes must be satisfied.
    OR:  any node may satisfy the configuration.
    """

    config_operator = config.get("operator")
    negate = config.get("negate", False)
    nodes = config.get("nodes", [])

    if not nodes:
        return "NO_MATCH", {"reason": "applicability_constraints_not_satisfied"}

    # Evaluate each node
    node_results = []
    for node in nodes:
        state, evidence = _evaluate_node(node, detected)
        node_results.append((state, evidence))

    # Combine node results based on configuration operator
    if config_operator == "AND":
        combined_state, combined_evidence = _combine_and(node_results)
    else:
        # OR or absent (default for simple single-node configs)
        combined_state, combined_evidence = _combine_or(node_results)

    if negate:
        return _apply_negate(combined_state, combined_evidence)

    return combined_state, combined_evidence


# ============================================================
# Top-level CVE applicability evaluation
# ============================================================

def _evaluate_cve_applicability(cve_data, detected):
    """
    Evaluate all configurations in a CVE record.

    Multiple configurations are implicitly OR'd:
    any matching configuration makes the CVE applicable.
    """

    configurations = cve_data.get("cve", {}).get("configurations", [])

    if not configurations:
        return {"state": "NO_MATCH", "evidence": {"reason": "applicability_constraints_not_satisfied"}}

    best_state = "NO_MATCH"
    best_evidence = None
    no_match_evidence = None

    for config in configurations:
        state, evidence = _evaluate_configuration(config, detected)

        if state == "MATCH":
            return {"state": "MATCH", "evidence": evidence}

        if state == "INDETERMINATE" and best_state == "NO_MATCH":
            best_state = "INDETERMINATE"
            best_evidence = evidence
            
        if state == "NO_MATCH" and no_match_evidence is None:
            no_match_evidence = evidence

    if best_state == "NO_MATCH":
        return {"state": "NO_MATCH", "evidence": no_match_evidence}

    return {"state": best_state, "evidence": best_evidence}


# ============================================================
# Public API
# ============================================================

def cve_matches_product(cve_data, product, version):
    """
    Determine whether a CVE is applicable to a detected product
    and version based on NVD CPE configuration data.

    Returns a dict with:
        state: "MATCH" | "NO_MATCH" | "INDETERMINATE"
        evidence: dict with applicability details, or None

    MATCH:
        Sufficient evidence exists that the detected software
        matches the vulnerable CPE/configuration.

    NO_MATCH:
        The detected software identity/version definitely does
        not satisfy the CPE/configuration.

    INDETERMINATE:
        The product/version may match, but additional conditions
        (platform, runtime, environment) cannot be established
        from the evidence currently available to VANTAGE.
    """

    normalized = normalize_product(product)

    if normalized["vendor"] == "unknown":
        return {"state": "NO_MATCH", "evidence": {"reason": "vendor_mismatch", "detected_product": product}}

    if normalized["product"] == "unknown":
        return {"state": "NO_MATCH", "evidence": {"reason": "product_mismatch", "detected_product": product}}

    if not version or version.strip().lower() in ("unknown", ""):
        return {"state": "NO_MATCH", "evidence": {"reason": "version_mismatch", "detected_version": version}}

    detected = {
        "vendor": normalized["vendor"],
        "product": normalized["product"],
        "version": version.strip().lower(),
    }

    return _evaluate_cve_applicability(cve_data, detected)
