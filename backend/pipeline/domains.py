"""Shared domain-scope helpers (public-suffix aware, no external deps).

These power the subdomain enumeration scope guard used by both the passive
subdomain scanner (``pipeline.scanner.subdomains_httpx``) and the base skill
(``skills.recon.subdomain_enum``).

A naive "last two labels" registrable-domain heuristic is WRONG for second-level
public suffixes: ``portal.svkm.ac.in`` has registrable domain ``svkm.ac.in``
(``ac.in`` is itself a public suffix), not ``ac.in``. Treating ``ac.in`` as the
scope would enumerate — and deep-scan — every ``.ac.in`` website in existence.
"""

# Multi-label public suffixes (second-level domains). For any of these, the
# registrable domain is the label immediately above the suffix PLUS the suffix,
# regardless of how deeply the host is nested.
MULTI_LABEL_SUFFIXES = frozenset({
    # India (UGC-recognised second-level .in domains)
    "ac.in", "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "gov.in", "edu.in", "mil.in", "res.in",
    # United Kingdom
    "ac.uk", "co.uk", "org.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "edu.uk", "ltd.uk", "plc.uk", "nhs.uk",
    # Australia / New Zealand / Ireland
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "ac.nz", "co.nz",
    "org.nz", "net.nz", "gen.nz",
    # Other common multi-label suffixes
    "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn", "org.cn",
    "gov.cn", "edu.cn", "ac.cn", "com.mx", "com.ar", "com.co", "co.jp",
    "or.jp", "ne.jp", "ac.jp", "com.sg", "edu.sg", "co.kr", "or.kr",
    "com.tr", "com.my", "com.ph", "co.id", "ac.id", "co.za", "co.ke",
})


def registrable_domain(domain: str) -> str:
    """Return the registrable domain for scope enforcement.

    Public-suffix aware: when the final two labels match a known multi-label
    suffix (``ac.in``, ``co.uk``, ``com.au``, ...) the registrable domain is
    the label above the suffix plus the suffix itself (``svkm.ac.in`` even for
    deeply nested ``host.portal.svkm.ac.in``); otherwise it is the last two
    labels (``example.com``).
    """
    labels = [label for label in domain.split(".") if label]
    n = len(labels)
    if n <= 2:
        return ".".join(labels) or domain
    if ".".join(labels[n - 2:]).lower() in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[n - 3:])
    return ".".join(labels[n - 2:])


def is_under_domain(candidate: str, registrable: str) -> bool:
    """True when candidate is the registrable domain itself (``svkm.ac.in``) or
    is under it (``portal.svkm.ac.in``, ``cdn.api.svkm.ac.in``). Never true for
    a sibling like ``abie.ac.in`` when the registrable domain is ``svkm.ac.in``.
    """
    cand = candidate.lower().rstrip(".")
    reg = registrable.lower().rstrip(".")
    if cand == reg:
        return True
    return cand.endswith("." + reg)