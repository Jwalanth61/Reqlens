"""Turn optional-tool output into informational findings (source ``external``)."""

from __future__ import annotations

from reqlens.checks import Context
from reqlens.checks.tokens import family_key, hash_of_interest
from reqlens.external import ToolStatus, hashcat, jwt_tool
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Evidence, Finding, TokenRecord

_HEADER_FIELDS = ("alg", "typ", "kid", "cty", "jku", "x5u", "jwk", "x5c")


def describe_jwt_tool(status: ToolStatus, record: TokenRecord) -> tuple[str, str]:
    """``(observed, problem)`` for one token; exactly one of them is non-empty."""
    result = jwt_tool.decode(status, record)
    if result.problem:
        return "", result.problem
    fields = ", ".join(
        f"{key}={value}" for key, value in result.header.items() if key in _HEADER_FIELDS
    )
    ours = str(record.jwt_header.get("alg", ""))
    theirs = result.header.get("alg", "")
    verdict = (
        f"This agrees with reqlens (alg {ours})."
        if theirs == ours
        else f"reqlens read alg '{ours}' but jwt_tool reports '{theirs}': check by hand."
    )
    observed = f"jwt_tool {status.label} decoded the redacted token offline: {fields}. {verdict}"
    if result.notes:
        observed += " jwt_tool notes: " + " ".join(result.notes)
    return observed, ""


def describe_hashcat(status: ToolStatus, fmt: str) -> tuple[str, str]:
    """``(observed, problem)`` for one value format."""
    modes = hashcat.identify_format(status, fmt)
    if modes is None:
        return "", f"hashcat could not identify shape {fmt}"
    if not modes:
        return f"hashcat {status.label} found no hash mode matching shape {fmt}.", ""
    listed = "; ".join(f"{m.mode} {m.name}" for m in modes)
    return f"For a value shaped {fmt}, hashcat {status.label} --identify lists: {listed}.", ""


def external_findings(
    ctx: Context, tools: dict[str, ToolStatus]
) -> tuple[list[Finding], list[str]]:
    """Run available tools on redacted shapes. Returns findings and one-line problem notes."""
    findings: list[Finding] = []
    notes: list[str] = []
    jwt_status = tools.get("jwt_tool")
    hash_status = tools.get("hashcat")

    jwt_families: dict[tuple, tuple[TokenRecord, list[Evidence]]] = {}
    hash_formats: dict[str, list[Evidence]] = {}
    for tx in ctx.transactions:
        for token in tx.tokens:
            if token.kind == "jwt":
                _, evidence = jwt_families.setdefault(family_key(token), (token, []))
                evidence.append(
                    ctx.evidence(
                        tx, token.location, token.name or "jwt", f"<jwt:{token.fingerprint}>"
                    )
                )
            elif hash_of_interest(token) and hashcat.sample_for_format(token.format):
                hash_formats.setdefault(token.format, []).append(
                    ctx.evidence(tx, token.location, token.name, f"<redacted:{token.fingerprint}>")
                )

    if jwt_status and jwt_status.available:
        for record, evidence in jwt_families.values():
            observed, problem = describe_jwt_tool(jwt_status, record)
            if problem:
                notes.append(problem)
                continue
            alg = record.jwt_header.get("alg", "?")
            finding = make_finding("EXT-JWT-TOOL", evidence, source="external", observed=observed)
            finding.title = f"{finding.title} [{alg}]"
            findings.append(finding)

    if hash_status and hash_status.available:
        for fmt, evidence in hash_formats.items():
            observed, problem = describe_hashcat(hash_status, fmt)
            if problem:
                notes.append(problem)
                continue
            finding = make_finding(
                "EXT-HASHCAT-IDENTIFY", evidence, source="external", observed=observed
            )
            finding.title = f"{finding.title} ({fmt})"
            findings.append(finding)
    return findings, notes
