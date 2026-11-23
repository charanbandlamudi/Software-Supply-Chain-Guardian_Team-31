"""Source workers. Each returns {"raw_advisories": [...], "evidence": {...}, "coverage": {...}}.
They must never write findings: findings are created once, after alias dedup."""
