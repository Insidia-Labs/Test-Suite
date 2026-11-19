"""DVWA: one case per module, labelled by the security level the run uses.

DVWA documents low, medium and high as vulnerable and impossible as the secure
reference. The module list is read from ``vulnerabilities/`` in the checkout. Each
module's CWE set comes from the module's own title and is frozen here; a module
missing from this table fails the build, so a DVWA update can't silently add
unlabelled cases.
"""

from __future__ import annotations

from itsuite.keys.base import AnswerKey, Case, KeyBuildError, KeyContext, KeyPlugin, Location

# module directory -> (title in DVWA, CWEs)
MODULES: dict[str, tuple[str, tuple[int, ...]]] = {
    "api": ("API Security", (284, 285, 639, 862, 863, 915)),
    "authbypass": ("Authorisation Bypass", (284, 285, 639, 862, 863)),
    "bac": ("Broken Access Control", (284, 285, 639, 862, 863)),
    "brute": ("Brute Force", (307,)),
    "captcha": ("Insecure CAPTCHA", (804,)),
    "cryptography": ("Cryptography Problems", (326, 327)),
    "csp": ("Content Security Policy (CSP) Bypass", (693, 79)),
    "csrf": ("Cross Site Request Forgery (CSRF)", (352,)),
    "exec": ("Command Injection", (78,)),
    "fi": ("File Inclusion", (98, 22)),
    "javascript": ("JavaScript Attacks", (602,)),
    "open_redirect": ("Open HTTP Redirect", (601,)),
    "sqli": ("SQL Injection", (89,)),
    "sqli_blind": ("SQL Injection (Blind)", (89,)),
    "upload": ("File Upload", (434,)),
    "weak_id": ("Weak Session IDs", (330, 331)),
    "xss_d": ("DOM Based Cross Site Scripting (XSS)", (79,)),
    "xss_r": ("Reflected Cross Site Scripting (XSS)", (79,)),
    "xss_s": ("Stored Cross Site Scripting (XSS)", (79,)),
}
LEVELS = {"low": True, "medium": True, "high": True, "impossible": False}


def _modules(ctx: KeyContext) -> list[str]:
    folder = ctx.src / "vulnerabilities"
    if not folder.is_dir():
        raise KeyBuildError(f"{ctx.target_id}: vulnerabilities/ not found")
    found = sorted(p.name for p in folder.iterdir() if (p / "source").is_dir())
    unknown = [name for name in found if name not in MODULES]
    if unknown:
        raise KeyBuildError(f"{ctx.target_id}: modules without a frozen label: {unknown}")
    return found


def build(ctx: KeyContext) -> AnswerKey:
    level = ctx.variant.name
    if level not in LEVELS:
        raise KeyBuildError(f"{ctx.target_id}: variant must be one of {sorted(LEVELS)}")
    positive = LEVELS[level]
    cases = tuple(
        Case(
            case_id=module,
            positive=positive,
            cwes=MODULES[module][1],
            category=MODULES[module][0],
            locations=(Location(token=f"/vulnerabilities/{module}"),),
        )
        for module in _modules(ctx)
    )
    return AnswerKey(
        target=ctx.target_id,
        variant=level,
        key_type="dvwa-modules",
        match="token",
        source_commit=ctx.commit,
        cases=cases,
        task=ctx.task,
        provenance=f"vulnerabilities/ at {ctx.commit}; level {level}; CWEs from module titles",
    )


PLUGIN = KeyPlugin("dvwa-modules", "token", build)
