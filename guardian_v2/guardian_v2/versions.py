"""Deterministic version handling. The LLM never decides whether a version is
affected; this module does."""
from __future__ import annotations

from univers import versions as uv

_BY_ECOSYSTEM = {
    "pypi": uv.PypiVersion,
    "npm": uv.SemverVersion,
    "maven": uv.MavenVersion,
    "golang": uv.GolangVersion,
    "go": uv.GolangVersion,
    "nuget": uv.NugetVersion,
    "gem": uv.RubygemsVersion,
    "rubygems": uv.RubygemsVersion,
    "composer": uv.ComposerVersion,
    "packagist": uv.ComposerVersion,
    "cargo": uv.SemverVersion,
    "crates.io": uv.SemverVersion,
}


def ecosystem_of(purl: str) -> str:
    return purl.split(":", 1)[1].split("/", 1)[0].lower()


def name_of(purl: str) -> str:
    body = purl.split("/", 1)[1]
    return body.split("@", 1)[0].split("?", 1)[0]


def version_of(purl: str) -> str | None:
    tail = purl.rsplit("/", 1)[-1]
    if "@" not in tail:
        return None
    return tail.split("@", 1)[1].split("?", 1)[0].split("#", 1)[0]


def base_purl(purl: str) -> str:
    """purl without version, qualifiers or subpath."""
    head = purl.split("?", 1)[0].split("#", 1)[0]
    return head.rsplit("@", 1)[0] if "@" in head.rsplit("/", 1)[-1] else head


def parse(ecosystem: str, version: str):
    cls = _BY_ECOSYSTEM.get(ecosystem.lower())
    if cls is None:
        raise ValueError(f"no deterministic version ordering for ecosystem {ecosystem!r}")
    return cls(version)


def _native_contains(ecosystem: str, version: str, native: str) -> bool:
    from univers import version_range as vr
    cls = {"npm": vr.NpmVersionRange, "pypi": vr.PypiVersionRange,
           "maven": vr.MavenVersionRange}.get(ecosystem.lower())
    if cls is None:
        raise ValueError(f"no native range parser for {ecosystem!r}")
    return parse(ecosystem, version) in cls.from_native(native)


def is_affected(ecosystem: str, version: str, ranges: list[dict]) -> bool:
    """Evaluate OSV-style event ranges, or native ranges from ecosystem tools:
    [{"introduced": "0", "fixed": "2.2.3"}, {"introduced": "3.0.0", "last_affected": "3.0.1"}]
    [{"native": ">=3.7.0 <4.17.19"}]   (npm audit style)
    """
    v = parse(ecosystem, version)
    for r in ranges:
        if "native" in r:
            if _native_contains(ecosystem, version, r["native"]):
                return True
            continue
        intro = r.get("introduced", "0")
        if intro not in ("0", "", None) and v < parse(ecosystem, intro):
            continue
        if r.get("fixed") and v >= parse(ecosystem, r["fixed"]):
            continue
        if r.get("last_affected") and v > parse(ecosystem, r["last_affected"]):
            continue
        return True
    return False


def is_prerelease(ecosystem: str, version: str) -> bool:
    eco = ecosystem.lower()
    if eco == "pypi":
        from packaging.version import Version
        try:
            return Version(version).is_prerelease
        except Exception:
            return True
    return "-" in version or any(t in version.lower() for t in ("alpha", "beta", "rc", "snapshot"))
