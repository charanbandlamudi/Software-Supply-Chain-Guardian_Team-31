# Blast Radius Report

**Target:** juice-shop@20.4.0-SNAPSHOT
**Graph generated:** 2026-11-23  
**Scanners in graph:** Grype, OSV-Scanner
**Scale:** 1109 packages, 2147 dependency edges (98 direct, 1010 transitive)  
**Findings:** 54 across 20 vulnerable packages (7 CRITICAL, 20 HIGH, 25 MEDIUM, 2 LOW)

## 1. Summary

- 12 of 20 vulnerable packages score CRITICAL or HIGH on blast radius.
- Highest scoring: `lodash@2.4.2` (79.7), `jsonwebtoken@0.4.0` (68.5), `jsonwebtoken@0.1.0` (68.4).
- Widest reach: `@cyclonedx/cyclonedx-npm@4.2.1` (0 dependents above, 164 packages below).

## 2. How the score works

Blast radius is a 0-100 score combining five components: severity (35%), exploit (25%), proximity (15%), spread (15%), volume (10%). *Severity* is the higher of worst CVSS/10 and the severity band; *exploit* is worst EPSS scaled so 20% counts as 1.0; *proximity* decays with hops from the application; *spread* is the log-scaled count of dependents plus sub-dependencies; *volume* is findings/10 (capped). Tiers: CRITICAL >= 60, HIGH >= 45, MEDIUM >= 30.

## 3. Ranked packages

| # | Package | Tier | Score | Worst sev | Findings | Max CVSS | Max EPSS | Hops | Dependents | Subtree | Via direct dependency |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `lodash@2.4.2` | CRITICAL | 79.7 | CRITICAL | 4 | 9.1 | 20.2% | 2 | 1 | 0 | sanitize-html@1.4.2 |
| 2 | `jsonwebtoken@0.4.0` | CRITICAL | 68.5 | CRITICAL | 4 | 9.8 | 8.4% | 1 | 0 | 3 | jsonwebtoken@0.4.0 |
| 3 | `jsonwebtoken@0.1.0` | CRITICAL | 68.4 | CRITICAL | 4 | 9.8 | 8.4% | 2 | 1 | 4 | express-jwt@0.1.3 |
| 4 | `tar@6.2.1` | CRITICAL | 66.7 | CRITICAL | 12 | 9.2 | 0.6% | 2 | 4 | 7 | sqlite3@5.1.7 |
| 5 | `moment@2.0.0` | CRITICAL | 63.3 | HIGH | 3 | 7.8 | 13.8% | 3 | 2 | 0 | express-jwt@0.1.3 |
| 6 | `@cyclonedx/cyclonedx-npm@4.2.1` | CRITICAL | 62.0 | HIGH | 2 | 8.5 | 0.2% | 1 | 0 | 164 | @cyclonedx/cyclonedx-npm@4.2.1 |
| 7 | `sanitize-html@1.4.2` | CRITICAL | 61.0 | HIGH | 10 | 7.5 | 2.0% | 1 | 0 | 11 | sanitize-html@1.4.2 |
| 8 | `marsdb@0.6.11` | HIGH | 57.5 | CRITICAL | 1 | - | - | 1 | 0 | 8 | marsdb@0.6.11 |
| 9 | `express-jwt@0.1.3` | HIGH | 54.5 | HIGH | 1 | 9.1 | 1.1% | 1 | 0 | 5 | express-jwt@0.1.3 |
| 10 | `crypto-js@3.3.0` | HIGH | 53.5 | CRITICAL | 2 | 9.1 | 0.6% | 2 | 1 | 0 | pdfkit@0.11.0 |
| 11 | `jws@0.2.6` | HIGH | 51.6 | HIGH | 2 | 8.7 | 0.2% | 2 | 3 | 2 | express-jwt@0.1.3, jsonwebtoken@0.4.0 |
| 12 | `uuid@8.3.2` | HIGH | 48.2 | MEDIUM | 1 | 8.1 | 0.4% | 2 | 4 | 0 | @istanbuljs/nyc-config-typescript@1.0.2, nyc@15.1.0, sequelize@6.37.8 |
| 13 | `glob@10.5.0` | MEDIUM | 44.5 | MEDIUM | 1 | 6.3 | 0.5% | 6 | 6 | 34 | @cyclonedx/cyclonedx-npm@4.2.1 |
| 14 | `file-type@16.5.4` | MEDIUM | 43.2 | MEDIUM | 1 | 5.3 | 0.4% | 1 | 0 | 15 | file-type@16.5.4 |
| 15 | `notevil@1.3.3` | MEDIUM | 43.2 | MEDIUM | 1 | 6.5 | 1.0% | 1 | 0 | 2 | notevil@1.3.3 |
| 16 | `hbs@4.4.0` | MEDIUM | 42.2 | MEDIUM | 1 | 5.3 | 1.0% | 1 | 0 | 8 | hbs@4.4.0 |
| 17 | `minimatch@9.0.9` | MEDIUM | 41.8 | MEDIUM | 1 | 6.9 | 0.4% | 7 | 7 | 2 | @cyclonedx/cyclonedx-npm@4.2.1 |
| 18 | `base64url@0.0.6` | MEDIUM | 36.3 | MEDIUM | 1 | - | - | 3 | 5 | 0 | express-jwt@0.1.3, jsonwebtoken@0.4.0 |
| 19 | `messageformat@2.3.0` | LOW | 28.7 | LOW | 1 | - | - | 2 | 1 | 4 | i18n@0.11.1 |
| 20 | `@tootallnate/once@1.1.2` | LOW | 28.2 | LOW | 1 | 3.3 | 0.1% | 5 | 4 | 0 | sqlite3@5.1.7 |

## 4. Detail for the top 10 packages

### lodash@2.4.2 - CRITICAL (79.7)

- **Type:** transitive dependency, cdxgen scope `optional`, 2 hop(s) from the app
- **Exposure classes:** Code / command injection, Denial of service, Prototype pollution
- **Dependents (blast upward):** 1 - `sanitize-html@1.4.2`
- **Sub-dependencies (blast downward):** 0
- **Fix:** upgrade to at least `4.17.21`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2019-10744 | CRITICAL | 9.1 | 5.01% | Prototype pollution | 4.17.12 | Prototype Pollution in lodash |
| CVE-2021-23337 | HIGH | 7.2 | 20.16% | Code / command injection | 4.17.21 | Command Injection in lodash |
| CVE-2018-16487 | HIGH | 6.8 | 1.49% | Denial of service | 4.17.11 | Prototype Pollution in lodash |
| CVE-2018-3721 | MEDIUM | 6.5 | 2.33% | Prototype pollution | 4.17.5 | Prototype Pollution in lodash |

### jsonwebtoken@0.4.0 - CRITICAL (68.5)

- **Type:** direct dependency, cdxgen scope `required`, 1 hop(s) from the app
- **Exposure classes:** Authentication / authorization bypass, Weak cryptography
- **Dependents (blast upward):** 0
- **Sub-dependencies (blast downward):** 3 - `jwa@0.0.1`, `base64url@0.0.6`, `jws@0.2.6`
- **Fix:** upgrade to at least `9.0.0`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2015-9235 | CRITICAL | 9.8 | 8.37% | Weak cryptography | 4.2.2 | Verification Bypass in jsonwebtoken |
| CVE-2022-23539 | HIGH | 8.1 | 0.52% | Weak cryptography | 9.0.0 | jsonwebtoken unrestricted key type could lead to legacy keys usage |
| CVE-2022-23540 | MEDIUM | 7.6 | 0.57% | Authentication / authorization bypass | 9.0.0 | jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify() |
| CVE-2022-23541 | MEDIUM | 6.3 | 0.81% | Authentication / authorization bypass | 9.0.0 | jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA  |

### jsonwebtoken@0.1.0 - CRITICAL (68.4)

- **Type:** transitive dependency, cdxgen scope `required`, 2 hop(s) from the app
- **Exposure classes:** Authentication / authorization bypass, Weak cryptography
- **Dependents (blast upward):** 1 - `express-jwt@0.1.3`
- **Sub-dependencies (blast downward):** 4 - `jwa@0.0.1`, `base64url@0.0.6`, `moment@2.0.0`, `jws@0.2.6`
- **Fix:** upgrade to at least `9.0.0`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2015-9235 | CRITICAL | 9.8 | 8.37% | Weak cryptography | 4.2.2 | Verification Bypass in jsonwebtoken |
| CVE-2022-23539 | HIGH | 8.1 | 0.52% | Weak cryptography | 9.0.0 | jsonwebtoken unrestricted key type could lead to legacy keys usage |
| CVE-2022-23540 | MEDIUM | 7.6 | 0.57% | Authentication / authorization bypass | 9.0.0 | jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify() |
| CVE-2022-23541 | MEDIUM | 6.3 | 0.81% | Authentication / authorization bypass | 9.0.0 | jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA  |

### tar@6.2.1 - CRITICAL (66.7)

- **Type:** transitive dependency, cdxgen scope `optional`, 2 hop(s) from the app
- **Exposure classes:** Denial of service, Other / unclassified, Path traversal / arbitrary file write
- **Dependents (blast upward):** 4 - `sqlite3@5.1.7`, `node-gyp@8.4.1`, `make-fetch-happen@9.1.0`, `cacache@15.3.0`
- **Sub-dependencies (blast downward):** 7 - `minipass@3.3.6`, `chownr@2.0.0`, `fs-minipass@2.1.0`, `yallist@4.0.0`, `mkdirp@1.0.4`, `minipass@5.0.0`, `minizlib@2.1.2`
- **Fix:** upgrade to at least `7.5.21`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2026-59873 | CRITICAL | 9.2 | 0.58% | Denial of service | 7.5.19 | node-tar: Decompression/parse DoS via unlimited input |
| CVE-2026-23950 | HIGH | 8.8 | 0.26% | Other / unclassified | 7.5.4 | Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS |
| CVE-2026-59874 | HIGH | 8.7 | 0.43% | Denial of service | 7.5.18 | node-tar: Negative tar entry size causes infinite loop in archive replace |
| CVE-2026-29786 | HIGH | 8.6 | 0.51% | Path traversal / arbitrary file write | 7.5.10 | tar has Hardlink Path Traversal via Drive-Relative Linkpath |
| CVE-2026-24842 | HIGH | 8.2 | 0.61% | Path traversal / arbitrary file write | 7.5.7 | node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal |
| CVE-2026-23745 | HIGH | 8.2 | 0.59% | Path traversal / arbitrary file write | 7.5.3 | node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient Path Sanitization |
| CVE-2026-31802 | HIGH | 8.2 | 0.29% | Path traversal / arbitrary file write | 7.5.11 | node-tar Symlink Path Traversal via Drive-Relative Linkpath |
| CVE-2026-73566 | HIGH | 7.5 | 0.53% | Denial of service | 7.5.21 | node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow DoS via crafted long-path tar w |
| CVE-2026-26960 | HIGH | 7.1 | 0.32% | Path traversal / arbitrary file write | 7.5.8 | Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Extraction |
| CVE-2026-59871 | MEDIUM | 7.5 | 0.64% | Denial of service | 7.5.18 | node-tar: Process crash via PAX numeric path type confusion |
| CVE-2026-53655 | MEDIUM | 6.9 | 0.16% | Other / unclassified | 7.5.16 | node-tar applies PAX size override to intermediary GNU long-name/long-link headers, causing tar parser interpretation di |
| CVE-2026-59875 | MEDIUM | 5.3 | 0.35% | Denial of service | 7.5.17 | node-tar: Uncaught Exception DoS via NUL byte in PAX path/linkpath records |

### moment@2.0.0 - CRITICAL (63.3)

- **Type:** transitive dependency, cdxgen scope `optional`, 3 hop(s) from the app
- **Exposure classes:** Denial of service, Path traversal / arbitrary file write
- **Dependents (blast upward):** 2 - `jsonwebtoken@0.1.0`, `express-jwt@0.1.3`
- **Sub-dependencies (blast downward):** 0
- **Fix:** upgrade to at least `2.29.2`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2022-24785 | HIGH | 7.5 | 13.84% | Path traversal / arbitrary file write | 2.29.2 | Path Traversal: 'dir/../../filename' in moment.locale |
| CVE-2017-18214 | HIGH | 7.5 | 3.65% | Denial of service | 2.19.3 | Regular Expression Denial of Service in moment |
| CVE-2016-4055 | MEDIUM | 7.8 | 9.90% | Denial of service | 2.11.2 | Regular Expression Denial of Service in moment |

### @cyclonedx/cyclonedx-npm@4.2.1 - CRITICAL (62.0)

- **Type:** direct dependency, cdxgen scope `optional`, 1 hop(s) from the app
- **Exposure classes:** Code / command injection
- **Dependents (blast upward):** 0
- **Sub-dependencies (blast downward):** 164 - `http-proxy-agent@7.0.2`, `minimatch@9.0.9`, `semver@7.8.6`, `detect-libc@2.1.2`, `lru-cache@11.5.3`, `util-deprecate@1.0.2`, `minizlib@3.1.0`, `strip-json-comments@2.0.1` ...
- **Fix:** upgrade to at least `6.0.0`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2026-55849 | HIGH | 8.5 | 0.24% | Code / command injection | 5.0.0 | @cyclonedx/cyclonedx-npm: Shell Injection via Unsanitized --workspace Argument |
| CVE-2026-71538 | HIGH | 8.5 | 0.21% | Code / command injection | 6.0.0 | @cyclonedx/cyclonedx-npm: Shell Injection via Unsanitized --workspace Argument on Windows |

### sanitize-html@1.4.2 - CRITICAL (61.0)

- **Type:** direct dependency, cdxgen scope `required`, 1 hop(s) from the app
- **Exposure classes:** Cross-site scripting, Denial of service, Information exposure, Other / unclassified
- **Dependents (blast upward):** 0
- **Sub-dependencies (blast downward):** 11 - `htmlparser2@3.3.0`, `lodash@2.4.2`, `inherits@2.0.4`, `readable-stream@1.0.34`, `domelementtype@1.3.1`, `string_decoder@0.10.31`, `domhandler@2.1.0`, `core-util-is@1.0.2` ...
- **Fix:** upgrade to at least `2.18.0`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2022-25887 | HIGH | 7.5 | 1.60% | Denial of service | 2.7.1 | Sanitize-html Vulnerable To REDoS Attacks |
| CVE-2017-16016 | MEDIUM | 6.1 | 1.31% | Cross-site scripting | 1.11.4 | Cross-Site Scripting in sanitize-html |
| CVE-2016-1000237 | MEDIUM | 6.1 | 0.84% | Cross-site scripting | 1.4.3 | Cross-Site Scripting in sanitize-html |
| CVE-2026-63670 | MEDIUM | 6.1 | 0.33% | Cross-site scripting | 2.17.6 | ApostropheCMS: Mutation-XSS / allowedTags bypass via literal `</textarea/>` solidus close |
| CVE-2019-25225 | MEDIUM | 6.1 | 0.28% | Cross-site scripting | 2.0.0-beta | sanitize-html is vulnerable to XSS through incomprehensive sanitization |
| CVE-2026-113661 | MEDIUM | 5.4 | 0.26% | Cross-site scripting | 2.18.0 | ApostropheCMS: Incomplete CVE-2026-53606: `meta http-equiv=refresh` `content` still ships `javascript:` / `data:` URLs |
| CVE-2021-26539 | MEDIUM | 5.3 | 1.98% | Other / unclassified | 2.3.1 | Improper Input Validation in sanitize-html |
| CVE-2021-26540 | MEDIUM | 5.3 | 1.77% | Other / unclassified | 2.3.2 | Improper Input Validation in sanitize-html |
| CVE-2024-21501 | MEDIUM | 5.3 | 1.03% | Information exposure | 2.12.1 | sanitize-html Information Exposure vulnerability |
| CVE-2026-113654 | MEDIUM | 5.3 | 0.43% | Cross-site scripting | 2.18.0 | ApostropheCMS sanitize-html: nonTextTags discard region ends early on an implied close, letting <noscript> content rende |

### marsdb@0.6.11 - HIGH (57.5)

- **Type:** direct dependency, cdxgen scope `required`, 1 hop(s) from the app
- **Exposure classes:** Code / command injection
- **Dependents (blast upward):** 0
- **Sub-dependencies (blast downward):** 8 - `double-ended-queue@0.9.7`, `check-types@6.0.0`, `loose-envify@1.4.0`, `js-tokens@4.0.0`, `geojson-utils@1.1.0`, `fast.js@0.1.1`, `eventemitter3@1.1.1`, `invariant@2.2.4`
- **Fix:** no fixed version reported

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| GHSA-5mrr-rgp6-x4gr | CRITICAL | - | - | Code / command injection | - | Command Injection in marsdb |

### express-jwt@0.1.3 - HIGH (54.5)

- **Type:** direct dependency, cdxgen scope `required`, 1 hop(s) from the app
- **Exposure classes:** Authentication / authorization bypass
- **Dependents (blast upward):** 0
- **Sub-dependencies (blast downward):** 5 - `jsonwebtoken@0.1.0`, `jwa@0.0.1`, `moment@2.0.0`, `jws@0.2.6`, `base64url@0.0.6`
- **Fix:** upgrade to at least `6.0.0`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2020-15084 | HIGH | 9.1 | 1.08% | Authentication / authorization bypass | 6.0.0 | Authorization bypass in express-jwt |

### crypto-js@3.3.0 - HIGH (53.5)

- **Type:** transitive dependency, cdxgen scope `optional`, 2 hop(s) from the app
- **Exposure classes:** Weak cryptography
- **Dependents (blast upward):** 1 - `pdfkit@0.11.0`
- **Sub-dependencies (blast downward):** 0
- **Fix:** upgrade to at least `4.2.0`

| Finding | Severity | CVSS | EPSS | Class | Fixed in | Summary |
|---|---|---|---|---|---|---|
| CVE-2023-46233 | CRITICAL | 9.1 | 0.64% | Weak cryptography | 4.2.0 | crypto-js PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard |
| CVE-2026-71851 | CRITICAL | 9 | 0.55% | Weak cryptography | 4.0.0 | crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain |

## 5. Fix leverage by direct dependency

Upgrading one direct dependency can clear every finding beneath it. Check that the new release actually pins patched transitive versions, or use package-manager overrides.

| Direct dependency | Findings cleared | Worst | Vulnerable packages beneath it |
|---|---|---|---|
| `sanitize-html@1.4.2` | 14 | CRITICAL | `lodash@2.4.2`, `sanitize-html@1.4.2` |
| `sqlite3@5.1.7` | 13 | CRITICAL | `tar@6.2.1`, `@tootallnate/once@1.1.2` |
| `express-jwt@0.1.3` | 11 | CRITICAL | `jsonwebtoken@0.1.0`, `moment@2.0.0`, `express-jwt@0.1.3`, `jws@0.2.6`, `base64url@0.0.6` |
| `jsonwebtoken@0.4.0` | 7 | CRITICAL | `jsonwebtoken@0.4.0`, `jws@0.2.6`, `base64url@0.0.6` |
| `@cyclonedx/cyclonedx-npm@4.2.1` | 4 | HIGH | `@cyclonedx/cyclonedx-npm@4.2.1`, `glob@10.5.0`, `minimatch@9.0.9` |
| `pdfkit@0.11.0` | 2 | CRITICAL | `crypto-js@3.3.0` |
| `marsdb@0.6.11` | 1 | CRITICAL | `marsdb@0.6.11` |
| `@istanbuljs/nyc-config-typescript@1.0.2` | 1 | MEDIUM | `uuid@8.3.2` |
| `nyc@15.1.0` | 1 | MEDIUM | `uuid@8.3.2` |
| `sequelize@6.37.8` | 1 | MEDIUM | `uuid@8.3.2` |
| `file-type@16.5.4` | 1 | MEDIUM | `file-type@16.5.4` |
| `notevil@1.3.3` | 1 | MEDIUM | `notevil@1.3.3` |
| `hbs@4.4.0` | 1 | MEDIUM | `hbs@4.4.0` |
| `i18n@0.11.1` | 1 | LOW | `messageformat@2.3.0` |

## 6. Environment amplifiers (Trivy)

**Secrets in the repository**

| File | Type | Severity |
|---|---|---|
| frontend/src/app/app.guard.spec.ts | JWT token | MEDIUM |
| frontend/src/app/last-login-ip/last-login-ip.component.spec.ts | JWT token | MEDIUM |
| infrastructure/terraform/networking.tf | Asymmetric Private Key | HIGH |
| lib/insecurity.ts | Asymmetric Private Key | HIGH |
| terraform/networking.tf | Asymmetric Private Key | HIGH |

**Dockerfile misconfigurations**

| File | Issue | Severity |
|---|---|---|
| Dockerfile | DS-0001: ':latest' tag used | MEDIUM |
| Dockerfile | DS-0026: No HEALTHCHECK defined | LOW |
| infrastructure/Dockerfile | DS-0026: No HEALTHCHECK defined | LOW |
| test/smoke/Dockerfile | DS-0001: ':latest' tag used | MEDIUM |
| test/smoke/Dockerfile | DS-0002: Image user should not be 'root' | HIGH |
| test/smoke/Dockerfile | DS-0025: 'apk add' is missing '--no-cache' | HIGH |
| test/smoke/Dockerfile | DS-0026: No HEALTHCHECK defined | LOW |

**Infrastructure-as-code misconfigurations:** 20 HIGH, 20 CRITICAL, 37 LOW, 5 MEDIUM

## 7. Limitations

- Blast radius here is dependency-graph impact. It does not prove the vulnerable code is called.
- Missing CVSS/EPSS (for example advisories without a CVE) lowers the score, so check those manually.
- cdxgen `scope` is informational and not used in the score.
