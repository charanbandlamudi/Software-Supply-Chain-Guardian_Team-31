# Attack Path Report

**Target:** juice-shop@20.4.0-SNAPSHOT
**Graph generated:** 2026-11-23  
**Scanners in graph:** Grype, OSV-Scanner
**Scale:** 1109 packages, 2147 dependency edges (98 direct, 1010 transitive)  
**Findings:** 54 across 20 vulnerable packages (7 CRITICAL, 20 HIGH, 25 MEDIUM, 2 LOW)

## 1. Summary

- 30 distinct dependency paths lead from `juice-shop@20.4.0-SNAPSHOT` to 20 vulnerable packages (longest shortest-path: 7 hops).
- 8 vulnerable packages are direct dependencies, so there is no intermediary between them and the application.
- A path shows how a flaw is *reachable in the dependency tree*. Whether it is exploitable depends on how the code uses the package.

## 2. Entry points

Direct dependencies through which vulnerable code enters the application.

| Direct dependency | Vulnerable packages reached | Findings | Worst |
|---|---|---|---|
| `sanitize-html@1.4.2` | `lodash@2.4.2`, `sanitize-html@1.4.2` | 14 | CRITICAL |
| `sqlite3@5.1.7` | `tar@6.2.1`, `@tootallnate/once@1.1.2` | 13 | CRITICAL |
| `express-jwt@0.1.3` | `jsonwebtoken@0.1.0`, `moment@2.0.0`, `express-jwt@0.1.3`, `jws@0.2.6`, `base64url@0.0.6` | 11 | CRITICAL |
| `jsonwebtoken@0.4.0` | `jsonwebtoken@0.4.0`, `jws@0.2.6`, `base64url@0.0.6` | 7 | CRITICAL |
| `@cyclonedx/cyclonedx-npm@4.2.1` | `@cyclonedx/cyclonedx-npm@4.2.1`, `glob@10.5.0`, `minimatch@9.0.9` | 4 | HIGH |
| `pdfkit@0.11.0` | `crypto-js@3.3.0` | 2 | CRITICAL |
| `marsdb@0.6.11` | `marsdb@0.6.11` | 1 | CRITICAL |
| `@istanbuljs/nyc-config-typescript@1.0.2` | `uuid@8.3.2` | 1 | MEDIUM |
| `nyc@15.1.0` | `uuid@8.3.2` | 1 | MEDIUM |
| `sequelize@6.37.8` | `uuid@8.3.2` | 1 | MEDIUM |
| `file-type@16.5.4` | `file-type@16.5.4` | 1 | MEDIUM |
| `notevil@1.3.3` | `notevil@1.3.3` | 1 | MEDIUM |
| `hbs@4.4.0` | `hbs@4.4.0` | 1 | MEDIUM |
| `i18n@0.11.1` | `messageformat@2.3.0` | 1 | LOW |

## 3. Chokepoints

Intermediate packages that sit on the paths to several vulnerable packages. Fixing or replacing one breaks all of them.

| Package | Vulnerable targets behind it | Findings behind it |
|---|---|---|
| `sqlite3@5.1.7` | 2 | 13 |
| `node-gyp@8.4.1` | 2 | 13 |
| `make-fetch-happen@9.1.0` | 2 | 13 |
| `cacache@15.3.0` | 1 | 12 |
| `express-jwt@0.1.3` | 4 | 10 |
| `jsonwebtoken@0.1.0` | 3 | 6 |
| `sanitize-html@1.4.2` | 1 | 4 |
| `jsonwebtoken@0.4.0` | 2 | 3 |
| `@cyclonedx/cyclonedx-npm@4.2.1` | 2 | 2 |
| `libxmljs2@0.37.0` | 2 | 2 |

## 4. Attack paths by exposure class

Classes come from each finding's CWE. Chains read from the application to the vulnerable package (in bold).

### Code / command injection

**`lodash@2.4.2`** - 1 finding(s), worst CVE-2021-23337 (CVSS 7.2, EPSS 20.2%)

- `juice-shop@20.4.0-SNAPSHOT` → `sanitize-html@1.4.2` → **`lodash@2.4.2`**

**`@cyclonedx/cyclonedx-npm@4.2.1`** - 2 finding(s), worst CVE-2026-55849 (CVSS 8.5, EPSS 0.2%)

- `juice-shop@20.4.0-SNAPSHOT` → **`@cyclonedx/cyclonedx-npm@4.2.1`**

**`marsdb@0.6.11`** - 1 finding(s), worst GHSA-5mrr-rgp6-x4gr (CVSS n/a)

- `juice-shop@20.4.0-SNAPSHOT` → **`marsdb@0.6.11`**

### Denial of service

**`lodash@2.4.2`** - 1 finding(s), worst CVE-2018-16487 (CVSS 6.8, EPSS 1.5%)

- `juice-shop@20.4.0-SNAPSHOT` → `sanitize-html@1.4.2` → **`lodash@2.4.2`**

**`tar@6.2.1`** - 5 finding(s), worst CVE-2026-59873 (CVSS 9.2, EPSS 0.6%)

- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → **`tar@6.2.1`**
- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → `node-gyp@8.4.1` → **`tar@6.2.1`**
- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → `node-gyp@8.4.1` → `make-fetch-happen@9.1.0` → `cacache@15.3.0` → **`tar@6.2.1`**

**`moment@2.0.0`** - 2 finding(s), worst CVE-2016-4055 (CVSS 7.8, EPSS 9.9%)

- `juice-shop@20.4.0-SNAPSHOT` → `express-jwt@0.1.3` → `jsonwebtoken@0.1.0` → **`moment@2.0.0`**

**`sanitize-html@1.4.2`** - 1 finding(s), worst CVE-2022-25887 (CVSS 7.5, EPSS 1.6%)

- `juice-shop@20.4.0-SNAPSHOT` → **`sanitize-html@1.4.2`**

**`glob@10.5.0`** - 1 finding(s), worst CVE-2026-118773 (CVSS 6.3, EPSS 0.5%)

- `juice-shop@20.4.0-SNAPSHOT` → `@cyclonedx/cyclonedx-npm@4.2.1` → `libxmljs2@0.37.0` → `node-gyp@11.5.0` → `make-fetch-happen@14.0.3` → `cacache@19.0.1` → **`glob@10.5.0`**
- `juice-shop@20.4.0-SNAPSHOT` → `@cyclonedx/cyclonedx-npm@4.2.1` → `@cyclonedx/cyclonedx-library@10.5.1` → `libxmljs2@0.37.0` → `node-gyp@11.5.0` → `make-fetch-happen@14.0.3` → `cacache@19.0.1` → **`glob@10.5.0`**

**`file-type@16.5.4`** - 1 finding(s), worst CVE-2026-31808 (CVSS 5.3, EPSS 0.4%)

- `juice-shop@20.4.0-SNAPSHOT` → **`file-type@16.5.4`**

**`minimatch@9.0.9`** - 1 finding(s), worst CVE-2026-118764 (CVSS 6.9, EPSS 0.4%)

- `juice-shop@20.4.0-SNAPSHOT` → `@cyclonedx/cyclonedx-npm@4.2.1` → `libxmljs2@0.37.0` → `node-gyp@11.5.0` → `make-fetch-happen@14.0.3` → `cacache@19.0.1` → `glob@10.5.0` → **`minimatch@9.0.9`**
- `juice-shop@20.4.0-SNAPSHOT` → `@cyclonedx/cyclonedx-npm@4.2.1` → `@cyclonedx/cyclonedx-library@10.5.1` → `libxmljs2@0.37.0` → `node-gyp@11.5.0` → `make-fetch-happen@14.0.3` → `cacache@19.0.1` → `glob@10.5.0` → **`minimatch@9.0.9`**

### Prototype pollution

**`lodash@2.4.2`** - 2 finding(s), worst CVE-2019-10744 (CVSS 9.1, EPSS 5.0%)

- `juice-shop@20.4.0-SNAPSHOT` → `sanitize-html@1.4.2` → **`lodash@2.4.2`**

**`notevil@1.3.3`** - 1 finding(s), worst CVE-2021-23771 (CVSS 6.5, EPSS 1.0%)

- `juice-shop@20.4.0-SNAPSHOT` → **`notevil@1.3.3`**

**`messageformat@2.3.0`** - 1 finding(s), worst CVE-2025-57349 (CVSS n/a)

- `juice-shop@20.4.0-SNAPSHOT` → `i18n@0.11.1` → **`messageformat@2.3.0`**

### Authentication / authorization bypass

**`jsonwebtoken@0.4.0`** - 2 finding(s), worst CVE-2022-23540 (CVSS 7.6, EPSS 0.6%)

- `juice-shop@20.4.0-SNAPSHOT` → **`jsonwebtoken@0.4.0`**

**`jsonwebtoken@0.1.0`** - 2 finding(s), worst CVE-2022-23540 (CVSS 7.6, EPSS 0.6%)

- `juice-shop@20.4.0-SNAPSHOT` → `express-jwt@0.1.3` → **`jsonwebtoken@0.1.0`**

**`express-jwt@0.1.3`** - 1 finding(s), worst CVE-2020-15084 (CVSS 9.1, EPSS 1.1%)

- `juice-shop@20.4.0-SNAPSHOT` → **`express-jwt@0.1.3`**

**`jws@0.2.6`** - 1 finding(s), worst CVE-2025-65945 (CVSS 7.5, EPSS 0.2%)

- `juice-shop@20.4.0-SNAPSHOT` → `jsonwebtoken@0.4.0` → **`jws@0.2.6`**
- `juice-shop@20.4.0-SNAPSHOT` → `express-jwt@0.1.3` → `jsonwebtoken@0.1.0` → **`jws@0.2.6`**

### Weak cryptography

**`jsonwebtoken@0.4.0`** - 2 finding(s), worst CVE-2015-9235 (CVSS 9.8, EPSS 8.4%)

- `juice-shop@20.4.0-SNAPSHOT` → **`jsonwebtoken@0.4.0`**

**`jsonwebtoken@0.1.0`** - 2 finding(s), worst CVE-2015-9235 (CVSS 9.8, EPSS 8.4%)

- `juice-shop@20.4.0-SNAPSHOT` → `express-jwt@0.1.3` → **`jsonwebtoken@0.1.0`**

**`crypto-js@3.3.0`** - 2 finding(s), worst CVE-2023-46233 (CVSS 9.1, EPSS 0.6%)

- `juice-shop@20.4.0-SNAPSHOT` → `pdfkit@0.11.0` → **`crypto-js@3.3.0`**

### Other / unclassified

**`tar@6.2.1`** - 2 finding(s), worst CVE-2026-23950 (CVSS 8.8, EPSS 0.3%)

- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → **`tar@6.2.1`**
- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → `node-gyp@8.4.1` → **`tar@6.2.1`**
- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → `node-gyp@8.4.1` → `make-fetch-happen@9.1.0` → `cacache@15.3.0` → **`tar@6.2.1`**

**`sanitize-html@1.4.2`** - 2 finding(s), worst CVE-2021-26539 (CVSS 5.3, EPSS 2.0%)

- `juice-shop@20.4.0-SNAPSHOT` → **`sanitize-html@1.4.2`**

**`jws@0.2.6`** - 1 finding(s), worst CVE-2016-1000223 (CVSS 8.7)

- `juice-shop@20.4.0-SNAPSHOT` → `jsonwebtoken@0.4.0` → **`jws@0.2.6`**
- `juice-shop@20.4.0-SNAPSHOT` → `express-jwt@0.1.3` → `jsonwebtoken@0.1.0` → **`jws@0.2.6`**

**`@tootallnate/once@1.1.2`** - 1 finding(s), worst CVE-2026-3449 (CVSS 3.3, EPSS 0.1%)

- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → `node-gyp@8.4.1` → `make-fetch-happen@9.1.0` → `http-proxy-agent@4.0.1` → **`@tootallnate/once@1.1.2`**

### Path traversal / arbitrary file write

**`tar@6.2.1`** - 5 finding(s), worst CVE-2026-29786 (CVSS 8.6, EPSS 0.5%)

- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → **`tar@6.2.1`**
- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → `node-gyp@8.4.1` → **`tar@6.2.1`**
- `juice-shop@20.4.0-SNAPSHOT` → `sqlite3@5.1.7` → `node-gyp@8.4.1` → `make-fetch-happen@9.1.0` → `cacache@15.3.0` → **`tar@6.2.1`**

**`moment@2.0.0`** - 1 finding(s), worst CVE-2022-24785 (CVSS 7.5, EPSS 13.8%)

- `juice-shop@20.4.0-SNAPSHOT` → `express-jwt@0.1.3` → `jsonwebtoken@0.1.0` → **`moment@2.0.0`**

### Cross-site scripting

**`sanitize-html@1.4.2`** - 6 finding(s), worst CVE-2017-16016 (CVSS 6.1, EPSS 1.3%)

- `juice-shop@20.4.0-SNAPSHOT` → **`sanitize-html@1.4.2`**

### Information exposure

**`sanitize-html@1.4.2`** - 1 finding(s), worst CVE-2024-21501 (CVSS 5.3, EPSS 1.0%)

- `juice-shop@20.4.0-SNAPSHOT` → **`sanitize-html@1.4.2`**

**`hbs@4.4.0`** - 1 finding(s), worst CVE-2021-32822 (CVSS 5.3, EPSS 1.0%)

- `juice-shop@20.4.0-SNAPSHOT` → **`hbs@4.4.0`**

### Memory safety

**`uuid@8.3.2`** - 1 finding(s), worst CVE-2026-41907 (CVSS 8.1, EPSS 0.4%)

- `juice-shop@20.4.0-SNAPSHOT` → `sequelize@6.37.8` → **`uuid@8.3.2`**
- `juice-shop@20.4.0-SNAPSHOT` → `nyc@15.1.0` → `istanbul-lib-processinfo@2.0.3` → **`uuid@8.3.2`**
- `juice-shop@20.4.0-SNAPSHOT` → `@istanbuljs/nyc-config-typescript@1.0.2` → `nyc@15.1.0` → `istanbul-lib-processinfo@2.0.3` → **`uuid@8.3.2`**

**`base64url@0.0.6`** - 1 finding(s), worst GHSA-rvg8-pwq2-xj7q (CVSS n/a)

- `juice-shop@20.4.0-SNAPSHOT` → `jsonwebtoken@0.4.0` → `jws@0.2.6` → **`base64url@0.0.6`**
- `juice-shop@20.4.0-SNAPSHOT` → `express-jwt@0.1.3` → `jsonwebtoken@0.1.0` → `jws@0.2.6` → **`base64url@0.0.6`**
- `juice-shop@20.4.0-SNAPSHOT` → `jsonwebtoken@0.4.0` → `jws@0.2.6` → `jwa@0.0.1` → **`base64url@0.0.6`**
- ...1 more path(s)

## 5. Environment amplifiers

Secrets in the repository can widen the damage once a path is exploited:

| File | Type | Severity |
|---|---|---|
| frontend/src/app/app.guard.spec.ts | JWT token | MEDIUM |
| frontend/src/app/last-login-ip/last-login-ip.component.spec.ts | JWT token | MEDIUM |
| infrastructure/terraform/networking.tf | Asymmetric Private Key | HIGH |
| lib/insecurity.ts | Asymmetric Private Key | HIGH |
| terraform/networking.tf | Asymmetric Private Key | HIGH |

## 6. Limitations

- Paths are derived from the SBOM graph, not from runtime call analysis.
- Exposure classes depend on CWE data; findings without a CWE appear as unclassified.
- Path enumeration is capped per package; truncation is flagged where it applies.
