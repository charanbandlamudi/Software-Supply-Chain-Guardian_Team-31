# Remediation report

## Upgrade summary (one target per package)

| Package | Installed | Vulns | Upgrade to | No fix known |
|---|---|---|---|---|
| tar | 6.2.1 | 12 | 7.5.21 | 0 |
| sanitize-html | 1.4.2 | 10 | 2.18.0 | 0 |
| jsonwebtoken | 0.1.0 | 4 | 9.0.0 | 0 |
| jsonwebtoken | 0.4.0 | 4 | 9.0.0 | 0 |
| lodash | 2.4.2 | 4 | 4.17.21 | 0 |
| moment | 2.0.0 | 3 | 2.29.2 | 0 |
| @cyclonedx/cyclonedx-npm | 4.2.1 | 2 | 6.0.0 | 0 |
| crypto-js | 3.3.0 | 2 | 4.2.0 | 0 |
| jws | 0.2.6 | 2 | 3.2.3 | 0 |
| @tootallnate/once | 1.1.2 | 1 | 2.0.1 | 0 |
| base64url | 0.0.6 | 1 | 3.0.0 | 0 |
| express-jwt | 0.1.3 | 1 | 6.0.0 | 0 |
| file-type | 16.5.4 | 1 | 21.3.1 | 0 |
| glob | 10.5.0 | 1 | 14.0.2 | 0 |
| hbs | 4.4.0 | 1 | - | 1 |
| marsdb | 0.6.11 | 1 | - | 1 |
| messageformat | 2.3.0 | 1 | 3.0.0-beta.0 | 0 |
| minimatch | 9.0.9 | 1 | 11.0.1 | 0 |
| notevil | 1.3.3 | 1 | - | 1 |
| uuid | 8.3.2 | 1 | 11.1.1 | 0 |

---

## GHSA-q69g-4hcv-6jg4 - @cyclonedx/cyclonedx-npm 4.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: @cyclonedx/cyclonedx-npm: Shell Injection via Unsanitized --workspace Argument on Windows
- Severity: HIGH  |  CVSS: CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
- Fixed versions: 6.0.0 (for your version: 6.0.0)
- Affected ranges: >= 0, < 6.0.0
- Advisories: https://github.com/CycloneDX/cyclonedx-node-npm/security/advisories/GHSA-q69g-4hcv-6jg4, https://github.com/CycloneDX/cyclonedx-node-npm/pull/1489, https://github.com/CycloneDX/cyclonedx-node-npm/commit/15d3beb5bcd2b0b6eccfdf31192f5103b3f12c0f

**GitHub Advisory (GHSA)**  
- GHSA-q69g-4hcv-6jg4: https://github.com/advisories/GHSA-q69g-4hcv-6jg4
- Summary: @cyclonedx/cyclonedx-npm: Shell Injection via Unsanitized --workspace Argument on Windows
- Severity: high  |  CVSS: -  |  CWEs: CWE-78
- Vulnerable range -> first patched: < 6.0.0 -> patched 6.0.0

**Recommended target:** 6.0.0

**Remediation summary** _(template)_

Upgrade @cyclonedx/cyclonedx-npm from 4.2.1 to 6.0.0 or later to fix GHSA-q69g-4hcv-6jg4. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-v75r-vx73-82pj - @cyclonedx/cyclonedx-npm 4.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: @cyclonedx/cyclonedx-npm: Shell Injection via Unsanitized --workspace Argument
- Severity: HIGH  |  CVSS: CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
- Fixed versions: 5.0.0 (for your version: 5.0.0)
- Affected ranges: >= 2.1.0, < 5.0.0
- Advisories: https://github.com/CycloneDX/cyclonedx-node-npm/security/advisories/GHSA-v75r-vx73-82pj, https://github.com/CycloneDX/cyclonedx-node-npm/pull/1476, https://github.com/CycloneDX/cyclonedx-node-npm/releases/tag/v5.0.0

**GitHub Advisory (GHSA)**  
- GHSA-v75r-vx73-82pj: https://github.com/advisories/GHSA-v75r-vx73-82pj
- Summary: @cyclonedx/cyclonedx-npm: Shell Injection via Unsanitized --workspace Argument
- Severity: high  |  CVSS: -  |  CWEs: CWE-78
- Vulnerable range -> first patched: >= 2.1.0, < 5.0.0 -> patched 5.0.0

**Recommended target:** 5.0.0

**Remediation summary** _(template)_

Upgrade @cyclonedx/cyclonedx-npm from 4.2.1 to 5.0.0 or later to fix GHSA-v75r-vx73-82pj. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-vpq2-c234-7xj6 - @tootallnate/once 1.1.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: @tootallnate/once vulnerable to Incorrect Control Flow Scoping
- Severity: LOW  |  CVSS: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L, CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:P
- Fixed versions: 2.0.1, 3.0.1 (for your version: 2.0.1)
- Affected ranges: >= 3.0.0, < 3.0.1; >= 0, < 2.0.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-3449, https://github.com/TooTallNate/once/issues/8, https://github.com/TooTallNate/once/commit/b9f43cc5259bee2952d91ad3cdbd201a82df448a

**GitHub Advisory (GHSA)**  
- GHSA-vpq2-c234-7xj6: https://github.com/advisories/GHSA-vpq2-c234-7xj6
- Summary: @tootallnate/once vulnerable to Incorrect Control Flow Scoping
- Severity: low  |  CVSS: 3.3  |  CWEs: CWE-705
- Vulnerable range -> first patched: >= 3.0.0, < 3.0.1 -> patched 3.0.1; < 2.0.1 -> patched 2.0.1

**Recommended target:** 2.0.1

**Remediation summary** _(template)_

Upgrade @tootallnate/once from 1.1.2 to 2.0.1 or later to fix GHSA-vpq2-c234-7xj6. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-rvg8-pwq2-xj7q - base64url 0.0.6

**OSV.dev**  
- Source: OSV.dev API
- Summary: Out-of-bounds Read in base64url
- Severity: MODERATE  |  CVSS: -
- Fixed versions: 3.0.0 (for your version: 3.0.0)
- Affected ranges: >= 0, < 3.0.0
- Advisories: https://github.com/brianloveswords/base64url/pull/25, https://github.com/brianloveswords/base64url/commit/4fbd954a0a69e9d898de2146557cc6e893e79542, https://hackerone.com/reports/321687

**GitHub Advisory (GHSA)**  
- GHSA-rvg8-pwq2-xj7q: https://github.com/advisories/GHSA-rvg8-pwq2-xj7q
- Summary: Out-of-bounds Read in base64url
- Severity: medium  |  CVSS: -  |  CWEs: CWE-125
- Vulnerable range -> first patched: < 3.0.0 -> patched 3.0.0

**Recommended target:** 3.0.0

**Remediation summary** _(template)_

Upgrade base64url from 0.0.6 to 3.0.0 or later to fix GHSA-rvg8-pwq2-xj7q. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-rg76-677x-56q9 - crypto-js 3.3.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain
- Severity: CRITICAL  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H
- Fixed versions: 4.0.0 (for your version: 4.0.0)
- Affected ranges: >= 0, < 4.0.0
- Advisories: https://github.com/brix/crypto-js/security/advisories/GHSA-rg76-677x-56q9, https://github.com/brix/crypto-js/commit/b405ff597fb3ac76a7bdfbc72dca10ba1079b1d5, https://www.coinspect.com/blog/ill-bloom-investigation

**GitHub Advisory (GHSA)**  
- GHSA-rg76-677x-56q9: https://github.com/advisories/GHSA-rg76-677x-56q9
- Summary: crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerable CryptoJS Dependency Chain
- Severity: critical  |  CVSS: 9.0  |  CWEs: CWE-331, CWE-334, CWE-338
- Vulnerable range -> first patched: < 4.0.0 -> patched 4.0.0

**Recommended target:** 4.0.0

**Remediation summary** _(template)_

Upgrade crypto-js from 3.3.0 to 4.0.0 or later to fix GHSA-rg76-677x-56q9. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-xwcq-pm8m-c4vf - crypto-js 3.3.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: crypto-js PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard
- Severity: CRITICAL  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- Fixed versions: 4.2.0 (for your version: 4.2.0)
- Affected ranges: >= 0, < 4.2.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2023-46233, https://github.com/brix/crypto-js/security/advisories/GHSA-xwcq-pm8m-c4vf, https://github.com/brix/crypto-js/commit/421dd538b2d34e7c24a5b72cc64dc2b9167db40a

**GitHub Advisory (GHSA)**  
- GHSA-xwcq-pm8m-c4vf: https://github.com/advisories/GHSA-xwcq-pm8m-c4vf
- Summary: crypto-js PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard
- Severity: critical  |  CVSS: 9.1  |  CWEs: CWE-327, CWE-328, CWE-916
- Vulnerable range -> first patched: < 4.2.0 -> patched 4.2.0

**Recommended target:** 4.2.0

**Remediation summary** _(template)_

Upgrade crypto-js from 3.3.0 to 4.2.0 or later to fix GHSA-xwcq-pm8m-c4vf. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-6g6m-m6h5-w9gf - express-jwt 0.1.3

**OSV.dev**  
- Source: OSV.dev API
- Summary: Authorization bypass in express-jwt
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N
- Fixed versions: 6.0.0 (for your version: 6.0.0)
- Affected ranges: >= 0, < 6.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2020-15084, https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf, https://github.com/auth0/express-jwt/commit/7ecab5f8f0cab5297c2b863596566eb0c019cdef

**GitHub Advisory (GHSA)**  
- GHSA-6g6m-m6h5-w9gf: https://github.com/advisories/GHSA-6g6m-m6h5-w9gf
- Summary: Authorization bypass in express-jwt
- Severity: high  |  CVSS: 7.7  |  CWEs: CWE-285, CWE-863
- Vulnerable range -> first patched: <= 5.3.3 -> patched 6.0.0

**Recommended target:** 6.0.0

**Remediation summary** _(template)_

Upgrade express-jwt from 0.1.3 to 6.0.0 or later to fix GHSA-6g6m-m6h5-w9gf. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-5v7r-6r5c-r473 - file-type 16.5.4

**OSV.dev**  
- Source: OSV.dev API
- Summary: file-type affected by infinite loop in ASF parser on malformed input with zero-size sub-header
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Fixed versions: 21.3.1 (for your version: 21.3.1)
- Affected ranges: >= 13.0.0, < 21.3.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-31808, https://github.com/sindresorhus/file-type/security/advisories/GHSA-5v7r-6r5c-r473, https://github.com/sindresorhus/file-type/commit/319abf871b50ba2fa221b4a7050059f1ae096f4f

**GitHub Advisory (GHSA)**  
- GHSA-5v7r-6r5c-r473: https://github.com/advisories/GHSA-5v7r-6r5c-r473
- Summary: file-type affected by infinite loop in ASF parser on malformed input with zero-size sub-header
- Severity: medium  |  CVSS: 5.3  |  CWEs: CWE-835
- Vulnerable range -> first patched: >= 13.0.0, < 21.3.1 -> patched 21.3.1

**Recommended target:** 21.3.1

**Remediation summary** _(template)_

Upgrade file-type from 16.5.4 to 21.3.1 or later to fix GHSA-5v7r-6r5c-r473. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-3g3m-2fjr-6pw4 - glob 10.5.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: Glob: AbortSignal cancellation bypass allows post-timeout filesystem traversal
- Severity: MODERATE  |  CVSS: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N
- Fixed versions: 14.0.2 (for your version: 14.0.2)
- Affected ranges: >= 9.0.0, < 14.0.2
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-118773, https://github.com/isaacs/node-glob/security/advisories/GHSA-3g3m-2fjr-6pw4, https://github.com/isaacs/node-glob/commit/4682e8c9babee1b385202ede36389634e12076d7

**GitHub Advisory (GHSA)**  
- GHSA-3g3m-2fjr-6pw4: https://github.com/advisories/GHSA-3g3m-2fjr-6pw4
- Summary: Glob: AbortSignal cancellation bypass allows post-timeout filesystem traversal
- Severity: medium  |  CVSS: -  |  CWEs: CWE-400
- Vulnerable range -> first patched: >= 9.0.0, <= 14.0.1 -> patched 14.0.2

**Recommended target:** 14.0.2

**Remediation summary** _(template)_

Upgrade glob from 10.5.0 to 14.0.2 or later to fix GHSA-3g3m-2fjr-6pw4. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-7f5c-rpf4-86p8 - hbs 4.4.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: hbs: Insertion of Sensitive Information into Externally-Accessible File or Directory and Exposure of Sensitive Information to an Unauthorized Actor
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N
- Fixed versions: none listed (for your version: -)
- Affected ranges: >= 0, <= 4.4.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2021-32822, https://securitylab.github.com/advisories/GHSL-2021-020-pillarjs-hbs

**GitHub Advisory (GHSA)**  
- GHSA-7f5c-rpf4-86p8: https://github.com/advisories/GHSA-7f5c-rpf4-86p8
- Summary: hbs: Insertion of Sensitive Information into Externally-Accessible File or Directory and Exposure of Sensitive Information to an Unauthorized Actor
- Severity: medium  |  CVSS: 4.0  |  CWEs: CWE-94, CWE-200, CWE-538
- Vulnerable range -> first patched: <= 4.4.0 -> patched none

**Recommended target:** no fixed version known

**Remediation summary** _(template)_

No fixed version of hbs is known for GHSA-7f5c-rpf4-86p8. Consider replacing the package or applying a mitigation, and review the linked advisory.

---

## GHSA-8cf7-32gw-wr33 - jsonwebtoken 0.1.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: jsonwebtoken unrestricted key type could lead to legacy keys usage 
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- Fixed versions: 9.0.0 (for your version: 9.0.0)
- Affected ranges: >= 0, < 9.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-23539, https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-8cf7-32gw-wr33, https://github.com/auth0/node-jsonwebtoken/commit/e1fa9dcc12054a8681db4e6373da1b30cf7016e3

**GitHub Advisory (GHSA)**  
- GHSA-8cf7-32gw-wr33: https://github.com/advisories/GHSA-8cf7-32gw-wr33
- Summary: jsonwebtoken unrestricted key type could lead to legacy keys usage 
- Severity: high  |  CVSS: 8.1  |  CWEs: CWE-327
- Vulnerable range -> first patched: <= 8.5.1 -> patched 9.0.0

**Recommended target:** 9.0.0

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.1.0 to 9.0.0 or later to fix GHSA-8cf7-32gw-wr33. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-c7hr-j4mj-j2w6 - jsonwebtoken 0.1.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: Verification Bypass in jsonwebtoken
- Severity: CRITICAL  |  CVSS: -
- Fixed versions: 4.2.2 (for your version: 4.2.2)
- Affected ranges: >= 0, < 4.2.2
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2015-9235, https://github.com/advisories/GHSA-c7hr-j4mj-j2w6, https://github.com/auth0/node-jsonwebtoken/commit/1bb584bc382295eeb7ee8c4452a673a77a68b687

**GitHub Advisory (GHSA)**  
- GHSA-c7hr-j4mj-j2w6: https://github.com/advisories/GHSA-c7hr-j4mj-j2w6
- Summary: Verification Bypass in jsonwebtoken
- Severity: critical  |  CVSS: -  |  CWEs: CWE-20
- Vulnerable range -> first patched: < 4.2.2 -> patched 4.2.2

**Recommended target:** 4.2.2

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.1.0 to 4.2.2 or later to fix GHSA-c7hr-j4mj-j2w6. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-hjrf-2m68-5959 - jsonwebtoken 0.1.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L
- Fixed versions: 9.0.0 (for your version: 9.0.0)
- Affected ranges: >= 0, < 9.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-23541, https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959, https://github.com/auth0/node-jsonwebtoken/commit/e1fa9dcc12054a8681db4e6373da1b30cf7016e3

**GitHub Advisory (GHSA)**  
- GHSA-hjrf-2m68-5959: https://github.com/advisories/GHSA-hjrf-2m68-5959
- Summary: jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
- Severity: medium  |  CVSS: 5.0  |  CWEs: CWE-287, CWE-1259
- Vulnerable range -> first patched: <= 8.5.1 -> patched 9.0.0

**Recommended target:** 9.0.0

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.1.0 to 9.0.0 or later to fix GHSA-hjrf-2m68-5959. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-qwph-4952-7xr6 - jsonwebtoken 0.1.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify()
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L
- Fixed versions: 9.0.0 (for your version: 9.0.0)
- Affected ranges: >= 0, < 9.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-23540, https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-qwph-4952-7xr6, https://github.com/auth0/node-jsonwebtoken/commit/e1fa9dcc12054a8681db4e6373da1b30cf7016e3

**GitHub Advisory (GHSA)**  
- GHSA-qwph-4952-7xr6: https://github.com/advisories/GHSA-qwph-4952-7xr6
- Summary: jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify()
- Severity: medium  |  CVSS: 6.4  |  CWEs: CWE-287, CWE-327, CWE-347
- Vulnerable range -> first patched: < 9.0.0 -> patched 9.0.0

**Recommended target:** 9.0.0

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.1.0 to 9.0.0 or later to fix GHSA-qwph-4952-7xr6. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-8cf7-32gw-wr33 - jsonwebtoken 0.4.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: jsonwebtoken unrestricted key type could lead to legacy keys usage 
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- Fixed versions: 9.0.0 (for your version: 9.0.0)
- Affected ranges: >= 0, < 9.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-23539, https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-8cf7-32gw-wr33, https://github.com/auth0/node-jsonwebtoken/commit/e1fa9dcc12054a8681db4e6373da1b30cf7016e3

**GitHub Advisory (GHSA)**  
- GHSA-8cf7-32gw-wr33: https://github.com/advisories/GHSA-8cf7-32gw-wr33
- Summary: jsonwebtoken unrestricted key type could lead to legacy keys usage 
- Severity: high  |  CVSS: 8.1  |  CWEs: CWE-327
- Vulnerable range -> first patched: <= 8.5.1 -> patched 9.0.0

**Recommended target:** 9.0.0

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.4.0 to 9.0.0 or later to fix GHSA-8cf7-32gw-wr33. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-c7hr-j4mj-j2w6 - jsonwebtoken 0.4.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: Verification Bypass in jsonwebtoken
- Severity: CRITICAL  |  CVSS: -
- Fixed versions: 4.2.2 (for your version: 4.2.2)
- Affected ranges: >= 0, < 4.2.2
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2015-9235, https://github.com/advisories/GHSA-c7hr-j4mj-j2w6, https://github.com/auth0/node-jsonwebtoken/commit/1bb584bc382295eeb7ee8c4452a673a77a68b687

**GitHub Advisory (GHSA)**  
- GHSA-c7hr-j4mj-j2w6: https://github.com/advisories/GHSA-c7hr-j4mj-j2w6
- Summary: Verification Bypass in jsonwebtoken
- Severity: critical  |  CVSS: -  |  CWEs: CWE-20
- Vulnerable range -> first patched: < 4.2.2 -> patched 4.2.2

**Recommended target:** 4.2.2

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.4.0 to 4.2.2 or later to fix GHSA-c7hr-j4mj-j2w6. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-hjrf-2m68-5959 - jsonwebtoken 0.4.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L
- Fixed versions: 9.0.0 (for your version: 9.0.0)
- Affected ranges: >= 0, < 9.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-23541, https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959, https://github.com/auth0/node-jsonwebtoken/commit/e1fa9dcc12054a8681db4e6373da1b30cf7016e3

**GitHub Advisory (GHSA)**  
- GHSA-hjrf-2m68-5959: https://github.com/advisories/GHSA-hjrf-2m68-5959
- Summary: jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC
- Severity: medium  |  CVSS: 5.0  |  CWEs: CWE-287, CWE-1259
- Vulnerable range -> first patched: <= 8.5.1 -> patched 9.0.0

**Recommended target:** 9.0.0

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.4.0 to 9.0.0 or later to fix GHSA-hjrf-2m68-5959. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-qwph-4952-7xr6 - jsonwebtoken 0.4.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify()
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L
- Fixed versions: 9.0.0 (for your version: 9.0.0)
- Affected ranges: >= 0, < 9.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-23540, https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-qwph-4952-7xr6, https://github.com/auth0/node-jsonwebtoken/commit/e1fa9dcc12054a8681db4e6373da1b30cf7016e3

**GitHub Advisory (GHSA)**  
- GHSA-qwph-4952-7xr6: https://github.com/advisories/GHSA-qwph-4952-7xr6
- Summary: jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify()
- Severity: medium  |  CVSS: 6.4  |  CWEs: CWE-287, CWE-327, CWE-347
- Vulnerable range -> first patched: < 9.0.0 -> patched 9.0.0

**Recommended target:** 9.0.0

**Remediation summary** _(template)_

Upgrade jsonwebtoken from 0.4.0 to 9.0.0 or later to fix GHSA-qwph-4952-7xr6. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-869p-cjfg-cm3x - jws 0.2.6

**OSV.dev**  
- Source: OSV.dev API
- Summary: auth0/node-jws Improperly Verifies HMAC Signature
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
- Fixed versions: 3.2.3, 4.0.1 (for your version: 3.2.3)
- Affected ranges: >= 0, < 3.2.3; >= 4.0.0, < 4.0.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2025-65945, https://github.com/auth0/node-jws/security/advisories/GHSA-869p-cjfg-cm3x, https://github.com/auth0/node-jws/commit/34c45b2c04434f925b638de6a061de9339c0ea2e

**GitHub Advisory (GHSA)**  
- GHSA-869p-cjfg-cm3x: https://github.com/advisories/GHSA-869p-cjfg-cm3x
- Summary: auth0/node-jws Improperly Verifies HMAC Signature
- Severity: high  |  CVSS: 7.5  |  CWEs: CWE-347
- Vulnerable range -> first patched: < 3.2.3 -> patched 3.2.3; = 4.0.0 -> patched 4.0.1

**Recommended target:** 3.2.3

**Remediation summary** _(template)_

Upgrade jws from 0.2.6 to 3.2.3 or later to fix GHSA-869p-cjfg-cm3x. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-gjcw-v447-2w7q - jws 0.2.6

**OSV.dev**  
- Source: OSV.dev API
- Summary: Forgeable Public/Private Tokens in jws
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N
- Fixed versions: 3.0.0 (for your version: 3.0.0)
- Affected ranges: >= 0, < 3.0.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2016-1000223, https://github.com/brianloveswords/node-jws/commit/585d0e1e97b6747c10cf5b7689ccc5618a89b299#diff-4ac32a78649ca5bdd8e0ba38b7006a1e, https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries

**GitHub Advisory (GHSA)**  
- GHSA-gjcw-v447-2w7q: https://github.com/advisories/GHSA-gjcw-v447-2w7q
- Summary: Forgeable Public/Private Tokens in jws
- Severity: high  |  CVSS: 8.7  |  CWEs: -
- Vulnerable range -> first patched: < 3.0.0 -> patched 3.0.0

**Recommended target:** 3.0.0

**Remediation summary** _(template)_

Upgrade jws from 0.2.6 to 3.0.0 or later to fix GHSA-gjcw-v447-2w7q. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-35jh-r3h4-6jhm - lodash 2.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Command Injection in lodash
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
- Fixed versions: 4.17.21 (for your version: 4.17.21)
- Affected ranges: >= 0, < 4.17.21
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2021-23337, https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c, https://www.oracle.com/security-alerts/cpuoct2021.html

**GitHub Advisory (GHSA)**  
- GHSA-35jh-r3h4-6jhm: https://github.com/advisories/GHSA-35jh-r3h4-6jhm
- Summary: Command Injection in lodash
- Severity: high  |  CVSS: 7.2  |  CWEs: CWE-77, CWE-94
- Vulnerable range -> first patched: < 4.17.21 -> patched 4.17.21

**Recommended target:** 4.17.21

**Remediation summary** _(template)_

Upgrade lodash from 2.4.2 to 4.17.21 or later to fix GHSA-35jh-r3h4-6jhm. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-4xc9-xhrj-v574 - lodash 2.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Prototype Pollution in lodash
- Severity: HIGH  |  CVSS: -
- Fixed versions: 4.17.11 (for your version: 4.17.11)
- Affected ranges: >= 0, < 4.17.11
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2018-16487, https://github.com/lodash/lodash/commit/90e6199a161b6445b01454517b40ef65ebecd2ad, https://hackerone.com/reports/380873

**GitHub Advisory (GHSA)**  
- GHSA-4xc9-xhrj-v574: https://github.com/advisories/GHSA-4xc9-xhrj-v574
- Summary: Prototype Pollution in lodash
- Severity: high  |  CVSS: -  |  CWEs: CWE-400
- Vulnerable range -> first patched: < 4.17.11 -> patched 4.17.11

**Recommended target:** 4.17.11

**Remediation summary** _(template)_

Upgrade lodash from 2.4.2 to 4.17.11 or later to fix GHSA-4xc9-xhrj-v574. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-fvqr-27wr-82fm - lodash 2.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Prototype Pollution in lodash
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N
- Fixed versions: 4.17.5 (for your version: 4.17.5)
- Affected ranges: >= 0, < 4.17.5
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2018-3721, https://github.com/lodash/lodash/commit/d8e069cc3410082e44eb18fcf8e7f3d08ebe1d4a, https://hackerone.com/reports/310443

**GitHub Advisory (GHSA)**  
- GHSA-fvqr-27wr-82fm: https://github.com/advisories/GHSA-fvqr-27wr-82fm
- Summary: Prototype Pollution in lodash
- Severity: medium  |  CVSS: 6.5  |  CWEs: CWE-471, CWE-1321
- Vulnerable range -> first patched: < 4.17.5 -> patched 4.17.5

**Recommended target:** 4.17.5

**Remediation summary** _(template)_

Upgrade lodash from 2.4.2 to 4.17.5 or later to fix GHSA-fvqr-27wr-82fm. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-jf85-cpcp-j695 - lodash 2.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Prototype Pollution in lodash
- Severity: CRITICAL  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H
- Fixed versions: 4.17.12 (for your version: 4.17.12)
- Affected ranges: >= 0, < 4.17.12
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2019-10744, https://github.com/lodash/lodash/pull/4336, https://access.redhat.com/errata/RHSA-2019:3024

**GitHub Advisory (GHSA)**  
- GHSA-jf85-cpcp-j695: https://github.com/advisories/GHSA-jf85-cpcp-j695
- Summary: Prototype Pollution in lodash
- Severity: critical  |  CVSS: 9.1  |  CWEs: CWE-20, CWE-1321
- Vulnerable range -> first patched: < 4.17.12 -> patched 4.17.12

**Recommended target:** 4.17.12

**Remediation summary** _(template)_

Upgrade lodash from 2.4.2 to 4.17.12 or later to fix GHSA-jf85-cpcp-j695. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-5mrr-rgp6-x4gr - marsdb 0.6.11

**OSV.dev**  
- Source: OSV.dev API
- Summary: Command Injection in marsdb
- Severity: CRITICAL  |  CVSS: -
- Fixed versions: none listed (for your version: -)
- Affected ranges: -
- Advisories: https://github.com/bkimminich/juice-shop/issues/1173, https://www.npmjs.com/advisories/1122

**GitHub Advisory (GHSA)**  
- GHSA-5mrr-rgp6-x4gr: https://github.com/advisories/GHSA-5mrr-rgp6-x4gr
- Summary: Command Injection in marsdb
- Severity: critical  |  CVSS: -  |  CWEs: CWE-77
- Vulnerable range -> first patched: >= 0.0.0 -> patched none

**Recommended target:** no fixed version known

**Remediation summary** _(template)_

No fixed version of marsdb is known for GHSA-5mrr-rgp6-x4gr. Consider replacing the package or applying a mitigation, and review the linked advisory.

---

## GHSA-xfqm-j7pc-xrfc - messageformat 2.3.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: messageformat has a prototype pollution vulnerability
- Severity: LOW  |  CVSS: CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:U
- Fixed versions: 3.0.0-beta.0 (for your version: 3.0.0-beta.0)
- Affected ranges: >= 0, < 3.0.0-beta.0
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2025-57349, https://github.com/messageformat/messageformat/issues/452

**GitHub Advisory (GHSA)**  
- GHSA-xfqm-j7pc-xrfc: https://github.com/advisories/GHSA-xfqm-j7pc-xrfc
- Summary: messageformat has a prototype pollution vulnerability
- Severity: low  |  CVSS: -  |  CWEs: CWE-1321
- Vulnerable range -> first patched: < 2.3.0 -> patched 3.0.0-beta.0

**Recommended target:** 3.0.0-beta.0

**Remediation summary** _(template)_

Upgrade messageformat from 2.3.0 to 3.0.0-beta.0 or later to fix GHSA-xfqm-j7pc-xrfc. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-g3hv-75wg-m249 - minimatch 9.0.9

**OSV.dev**  
- Source: OSV.dev API
- Summary: minimatch has potential denial of service via globparts amplification
- Severity: MODERATE  |  CVSS: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N
- Fixed versions: 11.0.1 (for your version: 11.0.1)
- Affected ranges: >= 7.0.0, < 11.0.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-118764, https://github.com/isaacs/minimatch/security/advisories/GHSA-g3hv-75wg-m249, https://github.com/isaacs/minimatch/commit/297b6c1a01f2410b3ba1ebed14ba222d0c3c1033

**GitHub Advisory (GHSA)**  
- GHSA-g3hv-75wg-m249: https://github.com/advisories/GHSA-g3hv-75wg-m249
- Summary: minimatch has potential denial of service via globparts amplification
- Severity: medium  |  CVSS: -  |  CWEs: CWE-405
- Vulnerable range -> first patched: >= 7.0.0, < 11.0.1 -> patched 11.0.1

**Recommended target:** 11.0.1

**Remediation summary** _(template)_

Upgrade minimatch from 9.0.9 to 11.0.1 or later to fix GHSA-g3hv-75wg-m249. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-446m-mv8f-q348 - moment 2.0.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: Regular Expression Denial of Service in moment
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Fixed versions: 2.19.3 (for your version: 2.19.3)
- Affected ranges: >= 0, < 2.19.3
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2017-18214, https://github.com/advisories/GHSA-446m-mv8f-q348, https://github.com/moment/moment/issues/4163

**GitHub Advisory (GHSA)**  
- GHSA-446m-mv8f-q348: https://github.com/advisories/GHSA-446m-mv8f-q348
- Summary: Regular Expression Denial of Service in moment
- Severity: high  |  CVSS: 7.5  |  CWEs: CWE-400
- Vulnerable range -> first patched: < 2.19.3 -> patched 2.19.3

**Recommended target:** 2.19.3

**Remediation summary** _(template)_

Upgrade moment from 2.0.0 to 2.19.3 or later to fix GHSA-446m-mv8f-q348.

---

## GHSA-87vv-r9j6-g5qv - moment 2.0.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: Regular Expression Denial of Service in moment
- Severity: MODERATE  |  CVSS: CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
- Fixed versions: 2.11.2 (for your version: 2.11.2)
- Affected ranges: >= 0, < 2.11.2
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2016-4055, https://github.com/advisories/GHSA-87vv-r9j6-g5qv, https://lists.apache.org/thread.html/10f0f3aefd51444d1198c65f44ffdf2d78ca3359423dbc1c168c9731@%3Cdev.flink.apache.org%3E

**GitHub Advisory (GHSA)**  
- GHSA-87vv-r9j6-g5qv: https://github.com/advisories/GHSA-87vv-r9j6-g5qv
- Summary: Regular Expression Denial of Service in moment
- Severity: medium  |  CVSS: 6.5  |  CWEs: CWE-400
- Vulnerable range -> first patched: < 2.11.2 -> patched 2.11.2

**Recommended target:** 2.11.2

**Remediation summary** _(template)_

Upgrade moment from 2.0.0 to 2.11.2 or later to fix GHSA-87vv-r9j6-g5qv.

---

## GHSA-8hfj-j24r-96c4 - moment 2.0.0

**OSV.dev**  
- Source: OSV.dev API
- Summary: Path Traversal: 'dir/../../filename' in moment.locale
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N
- Fixed versions: 2.29.2 (for your version: 2.29.2)
- Affected ranges: >= 0, < 2.29.2
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-24785, https://github.com/moment/moment/security/advisories/GHSA-8hfj-j24r-96c4, https://github.com/moment/moment/commit/4211bfc8f15746be4019bba557e29a7ba83d54c5

**GitHub Advisory (GHSA)**  
- GHSA-8hfj-j24r-96c4: https://github.com/advisories/GHSA-8hfj-j24r-96c4
- Summary: Path Traversal: 'dir/../../filename' in moment.locale
- Severity: high  |  CVSS: 7.5  |  CWEs: CWE-22, CWE-27
- Vulnerable range -> first patched: < 2.29.2 -> patched 2.29.2

**Recommended target:** 2.29.2

**Remediation summary** _(template)_

Upgrade moment from 2.0.0 to 2.29.2 or later to fix GHSA-8hfj-j24r-96c4.

---

## GHSA-8g4m-cjm2-96wq - notevil 1.3.3

**OSV.dev**  
- Source: OSV.dev API
- Summary: Sandbox escape in notevil and argencoders-notevil
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
- Fixed versions: none listed (for your version: -)
- Affected ranges: >= 0, <= 1.3.3
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2021-23771, https://snyk.io/vuln/SNYK-JS-ARGENCODERSNOTEVIL-2388587, https://snyk.io/vuln/SNYK-JS-NOTEVIL-2385946

**GitHub Advisory (GHSA)**  
- GHSA-8g4m-cjm2-96wq: https://github.com/advisories/GHSA-8g4m-cjm2-96wq
- Summary: Sandbox escape in notevil and argencoders-notevil
- Severity: medium  |  CVSS: 6.5  |  CWEs: CWE-1321
- Vulnerable range -> first patched: <= 1.3.3 -> patched none

**Recommended target:** no fixed version known

**Remediation summary** _(template)_

No fixed version of notevil is known for GHSA-8g4m-cjm2-96wq. Consider replacing the package or applying a mitigation, and review the linked advisory.

---

## GHSA-3j7m-hmh3-9jmp - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Cross-Site Scripting in sanitize-html
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
- Fixed versions: 1.4.3 (for your version: 1.4.3)
- Affected ranges: >= 0, < 1.4.3
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2016-1000237, https://github.com/apostrophecms/sanitize-html/issues/29, https://github.com/punkave/sanitize-html/issues/29

**GitHub Advisory (GHSA)**  
- GHSA-3j7m-hmh3-9jmp: https://github.com/advisories/GHSA-3j7m-hmh3-9jmp
- Summary: Cross-Site Scripting in sanitize-html
- Severity: medium  |  CVSS: 6.1  |  CWEs: CWE-79
- Vulnerable range -> first patched: < 1.4.3 -> patched 1.4.3

**Recommended target:** 1.4.3

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 1.4.3 or later to fix GHSA-3j7m-hmh3-9jmp.

---

## GHSA-cgfm-xwp7-2cvr - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Sanitize-html Vulnerable To REDoS Attacks
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Fixed versions: 2.7.1 (for your version: 2.7.1)
- Affected ranges: >= 0, < 2.7.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2022-25887, https://github.com/apostrophecms/sanitize-html/pull/557, https://github.com/apostrophecms/sanitize-html/commit/b4682c12fd30e12e82fa2d9b766de91d7d2cd23c

**GitHub Advisory (GHSA)**  
- GHSA-cgfm-xwp7-2cvr: https://github.com/advisories/GHSA-cgfm-xwp7-2cvr
- Summary: Sanitize-html Vulnerable To REDoS Attacks
- Severity: high  |  CVSS: 7.5  |  CWEs: CWE-1333
- Vulnerable range -> first patched: < 2.7.1 -> patched 2.7.1

**Recommended target:** 2.7.1

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.7.1 or later to fix GHSA-cgfm-xwp7-2cvr. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-cv27-6wvh-8x7j - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: ApostropheCMS: Incomplete CVE-2026-53606: `meta http-equiv=refresh` `content` still ships `javascript:` / `data:` URLs
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
- Fixed versions: 2.18.0 (for your version: 2.18.0)
- Affected ranges: >= 0, < 2.18.0
- Advisories: https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-cv27-6wvh-8x7j, https://github.com/apostrophecms/apostrophe/commit/9500b8b0e1d630d5e07fbb5fd2c25ed0943845ce, https://github.com/apostrophecms/apostrophe/commit/f84fd41cbf6c22eb8d0008fc9c25df1f7130b350

**GitHub Advisory (GHSA)**  
- GHSA-cv27-6wvh-8x7j: https://github.com/advisories/GHSA-cv27-6wvh-8x7j
- Summary: ApostropheCMS: Incomplete CVE-2026-53606: `meta http-equiv=refresh` `content` still ships `javascript:` / `data:` URLs
- Severity: medium  |  CVSS: 5.4  |  CWEs: CWE-79
- Vulnerable range -> first patched: < 2.18.0 -> patched 2.18.0

**Recommended target:** 2.18.0

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.18.0 or later to fix GHSA-cv27-6wvh-8x7j. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-jxwj-j7wr-gfrw - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: ApostropheCMS: Mutation-XSS / allowedTags bypass via literal `</textarea/>` solidus close
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
- Fixed versions: 2.17.6 (for your version: 2.17.6)
- Affected ranges: >= 0, < 2.17.6
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-63670, https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-jxwj-j7wr-gfrw, https://github.com/apostrophecms/apostrophe/pull/5501

**GitHub Advisory (GHSA)**  
- GHSA-jxwj-j7wr-gfrw: https://github.com/advisories/GHSA-jxwj-j7wr-gfrw
- Summary: ApostropheCMS: Mutation-XSS / allowedTags bypass via literal `</textarea/>` solidus close
- Severity: medium  |  CVSS: 6.1  |  CWEs: CWE-79
- Vulnerable range -> first patched: <= 2.17.5 -> patched 2.17.6

**Recommended target:** 2.17.6

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.17.6 or later to fix GHSA-jxwj-j7wr-gfrw. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-mjxr-4v3x-q3m4 - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Improper Input Validation in sanitize-html
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
- Fixed versions: 2.3.2 (for your version: 2.3.2)
- Affected ranges: >= 0, < 2.3.2
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2021-26540, https://github.com/apostrophecms/sanitize-html/pull/460, https://advisory.checkmarx.net/advisory/CX-2021-4309

**GitHub Advisory (GHSA)**  
- GHSA-mjxr-4v3x-q3m4: https://github.com/advisories/GHSA-mjxr-4v3x-q3m4
- Summary: Improper Input Validation in sanitize-html
- Severity: medium  |  CVSS: 5.3  |  CWEs: CWE-20
- Vulnerable range -> first patched: < 2.3.2 -> patched 2.3.2

**Recommended target:** 2.3.2

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.3.2 or later to fix GHSA-mjxr-4v3x-q3m4. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-qhxp-v273-g94h - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: sanitize-html is vulnerable to XSS through incomprehensive sanitization
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
- Fixed versions: 2.0.0-beta (for your version: 2.0.0-beta)
- Affected ranges: >= 0, < 2.0.0-beta
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2019-25225, https://github.com/apostrophecms/sanitize-html/issues/293, https://github.com/apostrophecms/sanitize-html/pull/156

**GitHub Advisory (GHSA)**  
- GHSA-qhxp-v273-g94h: https://github.com/advisories/GHSA-qhxp-v273-g94h
- Summary: sanitize-html is vulnerable to XSS through incomprehensive sanitization
- Severity: medium  |  CVSS: 6.1  |  CWEs: CWE-79
- Vulnerable range -> first patched: < 2.0.0-beta -> patched 2.0.0-beta

**Recommended target:** 2.0.0-beta

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.0.0-beta or later to fix GHSA-qhxp-v273-g94h. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-rjqq-98f6-6j3r - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Improper Input Validation in sanitize-html
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
- Fixed versions: 2.3.1 (for your version: 2.3.1)
- Affected ranges: >= 0, < 2.3.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2021-26539, https://github.com/apostrophecms/sanitize-html/pull/458, https://github.com/apostrophecms/sanitize-html/commit/bdf7836ef8f0e5b21f9a1aab0623ae8fcd09c1da

**GitHub Advisory (GHSA)**  
- GHSA-rjqq-98f6-6j3r: https://github.com/advisories/GHSA-rjqq-98f6-6j3r
- Summary: Improper Input Validation in sanitize-html
- Severity: medium  |  CVSS: 5.3  |  CWEs: CWE-20
- Vulnerable range -> first patched: < 2.3.1 -> patched 2.3.1

**Recommended target:** 2.3.1

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.3.1 or later to fix GHSA-rjqq-98f6-6j3r. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-rm97-x556-q36h - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: sanitize-html Information Exposure vulnerability
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
- Fixed versions: 2.12.1 (for your version: 2.12.1)
- Affected ranges: >= 0, < 2.12.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2024-21501, https://github.com/apostrophecms/sanitize-html/pull/650, https://github.com/apostrophecms/sanitize-html/commit/c5dbdf77fe8b836d3bf4554ea39edb45281ec0b4

**GitHub Advisory (GHSA)**  
- GHSA-rm97-x556-q36h: https://github.com/advisories/GHSA-rm97-x556-q36h
- Summary: sanitize-html Information Exposure vulnerability
- Severity: medium  |  CVSS: 5.3  |  CWEs: CWE-200, CWE-538
- Vulnerable range -> first patched: < 2.12.1 -> patched 2.12.1

**Recommended target:** 2.12.1

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.12.1 or later to fix GHSA-rm97-x556-q36h. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-x3q4-9hxx-gx8m - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: ApostropheCMS sanitize-html: nonTextTags discard region ends early on an implied close, letting <noscript> content render
- Severity: MODERATE  |  CVSS: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N
- Fixed versions: 2.18.0 (for your version: 2.18.0)
- Affected ranges: >= 0, < 2.18.0
- Advisories: https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-x3q4-9hxx-gx8m, https://github.com/apostrophecms/apostrophe/commit/9500b8b0e1d630d5e07fbb5fd2c25ed0943845ce, https://github.com/apostrophecms/apostrophe/commit/f84fd41cbf6c22eb8d0008fc9c25df1f7130b350

**GitHub Advisory (GHSA)**  
- GHSA-x3q4-9hxx-gx8m: https://github.com/advisories/GHSA-x3q4-9hxx-gx8m
- Summary: ApostropheCMS sanitize-html: nonTextTags discard region ends early on an implied close, letting <noscript> content render
- Severity: medium  |  CVSS: -  |  CWEs: CWE-79
- Vulnerable range -> first patched: < 2.18.0 -> patched 2.18.0

**Recommended target:** 2.18.0

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 2.18.0 or later to fix GHSA-x3q4-9hxx-gx8m. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-xc6g-ggrc-qq4r - sanitize-html 1.4.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: Cross-Site Scripting in sanitize-html
- Severity: MODERATE  |  CVSS: -
- Fixed versions: 1.11.4 (for your version: 1.11.4)
- Affected ranges: >= 0, < 1.11.4
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2017-16016, https://github.com/advisories/GHSA-xc6g-ggrc-qq4r, https://github.com/punkave/sanitize-html/issues/100

**GitHub Advisory (GHSA)**  
- GHSA-xc6g-ggrc-qq4r: https://github.com/advisories/GHSA-xc6g-ggrc-qq4r
- Summary: Cross-Site Scripting in sanitize-html
- Severity: medium  |  CVSS: -  |  CWEs: CWE-79
- Vulnerable range -> first patched: <= 1.11.1 -> patched 1.11.4

**Recommended target:** 1.11.4

**Remediation summary** _(template)_

Upgrade sanitize-html from 1.4.2 to 1.11.4 or later to fix GHSA-xc6g-ggrc-qq4r.

---

## GHSA-23hp-3jrh-7fpw - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar: Decompression/parse DoS via unlimited input
- Severity: CRITICAL  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
- Fixed versions: 7.5.19 (for your version: 7.5.19)
- Affected ranges: >= 0, < 7.5.19
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-59873, https://github.com/isaacs/node-tar/security/advisories/GHSA-23hp-3jrh-7fpw, https://github.com/isaacs/node-tar/commit/2812e9338665659b183aa7226518c307044957d3

**GitHub Advisory (GHSA)**  
- GHSA-23hp-3jrh-7fpw: https://github.com/advisories/GHSA-23hp-3jrh-7fpw
- Summary: node-tar: Decompression/parse DoS via unlimited input
- Severity: critical  |  CVSS: 7.5  |  CWEs: CWE-770
- Vulnerable range -> first patched: <= 7.5.18 -> patched 7.5.19

**Recommended target:** 7.5.19

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.19 or later to fix GHSA-23hp-3jrh-7fpw. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-34x7-hfp2-rc4v - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
- Fixed versions: 7.5.7 (for your version: 7.5.7)
- Affected ranges: >= 0, < 7.5.7
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-24842, https://github.com/isaacs/node-tar/security/advisories/GHSA-34x7-hfp2-rc4v, https://github.com/isaacs/node-tar/commit/f4a7aa9bc3d717c987fdf1480ff7a64e87ffdb46

**GitHub Advisory (GHSA)**  
- GHSA-34x7-hfp2-rc4v: https://github.com/advisories/GHSA-34x7-hfp2-rc4v
- Summary: node-tar Vulnerable to Arbitrary File Creation/Overwrite via Hardlink Path Traversal
- Severity: high  |  CVSS: 8.2  |  CWEs: CWE-22, CWE-59
- Vulnerable range -> first patched: < 7.5.7 -> patched 7.5.7

**Recommended target:** 7.5.7

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.7 or later to fix GHSA-34x7-hfp2-rc4v. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-83g3-92jg-28cx - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Extraction
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
- Fixed versions: 7.5.8 (for your version: 7.5.8)
- Affected ranges: >= 0, < 7.5.8
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-26960, https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx, https://github.com/isaacs/node-tar/commit/2cb1120bcefe28d7ecc719b41441ade59c52e384

**GitHub Advisory (GHSA)**  
- GHSA-83g3-92jg-28cx: https://github.com/advisories/GHSA-83g3-92jg-28cx
- Summary: Arbitrary File Read/Write via Hardlink Target Escape Through Symlink Chain in node-tar Extraction
- Severity: high  |  CVSS: 7.1  |  CWEs: CWE-22
- Vulnerable range -> first patched: < 7.5.8 -> patched 7.5.8

**Recommended target:** 7.5.8

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.8 or later to fix GHSA-83g3-92jg-28cx. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-8qq5-rm4j-mr97 - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient Path Sanitization
- Severity: HIGH  |  CVSS: CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N
- Fixed versions: 7.5.3 (for your version: 7.5.3)
- Affected ranges: >= 0, < 7.5.3
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-23745, https://github.com/isaacs/node-tar/security/advisories/GHSA-8qq5-rm4j-mr97, https://github.com/isaacs/node-tar/commit/340eb285b6d986e91969a1170d7fe9b0face405e

**GitHub Advisory (GHSA)**  
- GHSA-8qq5-rm4j-mr97: https://github.com/advisories/GHSA-8qq5-rm4j-mr97
- Summary: node-tar is Vulnerable to Arbitrary File Overwrite and Symlink Poisoning via Insufficient Path Sanitization
- Severity: high  |  CVSS: -  |  CWEs: CWE-22
- Vulnerable range -> first patched: <= 7.5.2 -> patched 7.5.3

**Recommended target:** 7.5.3

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.3 or later to fix GHSA-8qq5-rm4j-mr97. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-8x88-c5mf-7j5w - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar: Negative tar entry size causes infinite loop in archive replace
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
- Fixed versions: 7.5.18 (for your version: 7.5.18)
- Affected ranges: >= 0, < 7.5.18
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-59874, https://github.com/isaacs/node-tar/security/advisories/GHSA-8x88-c5mf-7j5w, https://github.com/isaacs/node-tar/commit/9e78bf058b2c22dd4d52e00d8922d5c06fc2f7b5

**GitHub Advisory (GHSA)**  
- GHSA-8x88-c5mf-7j5w: https://github.com/advisories/GHSA-8x88-c5mf-7j5w
- Summary: node-tar: Negative tar entry size causes infinite loop in archive replace
- Severity: high  |  CVSS: 7.5  |  CWEs: CWE-835
- Vulnerable range -> first patched: <= 7.5.17 -> patched 7.5.18

**Recommended target:** 7.5.18

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.18 or later to fix GHSA-8x88-c5mf-7j5w. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-9ppj-qmqm-q256 - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar Symlink Path Traversal via Drive-Relative Linkpath
- Severity: HIGH  |  CVSS: CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N
- Fixed versions: 7.5.11 (for your version: 7.5.11)
- Affected ranges: >= 0, < 7.5.11
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-31802, https://github.com/isaacs/node-tar/security/advisories/GHSA-9ppj-qmqm-q256, https://github.com/isaacs/node-tar/commit/f48b5fa3b7985ddab96dc0f2125a4ffc9911b6ad

**GitHub Advisory (GHSA)**  
- GHSA-9ppj-qmqm-q256: https://github.com/advisories/GHSA-9ppj-qmqm-q256
- Summary: node-tar Symlink Path Traversal via Drive-Relative Linkpath
- Severity: high  |  CVSS: -  |  CWEs: CWE-22
- Vulnerable range -> first patched: <= 7.5.10 -> patched 7.5.11

**Recommended target:** 7.5.11

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.11 or later to fix GHSA-9ppj-qmqm-q256. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-gvwx-54wh-qm9j - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar: Uncaught Exception DoS via NUL byte in PAX path/linkpath records
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Fixed versions: 7.5.17 (for your version: 7.5.17)
- Affected ranges: >= 0, < 7.5.17
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-59875, https://github.com/isaacs/node-tar/security/advisories/GHSA-gvwx-54wh-qm9j, https://github.com/isaacs/node-tar/commit/7a635c29f5edbf083557374d43984273ecfed5b3

**GitHub Advisory (GHSA)**  
- GHSA-gvwx-54wh-qm9j: https://github.com/advisories/GHSA-gvwx-54wh-qm9j
- Summary: node-tar: Uncaught Exception DoS via NUL byte in PAX path/linkpath records
- Severity: medium  |  CVSS: 5.3  |  CWEs: CWE-248
- Vulnerable range -> first patched: <= 7.5.16 -> patched 7.5.17

**Recommended target:** 7.5.17

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.17 or later to fix GHSA-gvwx-54wh-qm9j. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-qffp-2rhf-9h96 - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: tar has Hardlink Path Traversal via Drive-Relative Linkpath
- Severity: HIGH  |  CVSS: CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:H/SA:L
- Fixed versions: 7.5.10 (for your version: 7.5.10)
- Affected ranges: >= 0, < 7.5.10
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-29786, https://github.com/isaacs/node-tar/security/advisories/GHSA-qffp-2rhf-9h96, https://github.com/isaacs/node-tar/commit/7bc755dd85e623c0279e08eb3784909e6d7e4b9f

**GitHub Advisory (GHSA)**  
- GHSA-qffp-2rhf-9h96: https://github.com/advisories/GHSA-qffp-2rhf-9h96
- Summary: tar has Hardlink Path Traversal via Drive-Relative Linkpath
- Severity: high  |  CVSS: -  |  CWEs: CWE-22, CWE-59
- Vulnerable range -> first patched: <= 7.5.9 -> patched 7.5.10

**Recommended target:** 7.5.10

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.10 or later to fix GHSA-qffp-2rhf-9h96. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-r292-9mhp-454m - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow DoS via crafted long-path tar with member selection
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- Fixed versions: 7.5.21 (for your version: 7.5.21)
- Affected ranges: >= 0, < 7.5.21
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-73566, https://github.com/isaacs/node-tar/security/advisories/GHSA-r292-9mhp-454m, https://github.com/isaacs/node-tar/commit/631ae59121bf8fc8a22bbae35f074cb9b789cd4a

**GitHub Advisory (GHSA)**  
- GHSA-r292-9mhp-454m: https://github.com/advisories/GHSA-r292-9mhp-454m
- Summary: node-tar: Uncontrolled recursion in mapHas/filesFilter allows uncatchable stack-overflow DoS via crafted long-path tar with member selection
- Severity: high  |  CVSS: 7.5  |  CWEs: CWE-400, CWE-674
- Vulnerable range -> first patched: <= 7.5.20 -> patched 7.5.21

**Recommended target:** 7.5.21

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.21 or later to fix GHSA-r292-9mhp-454m. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-r6q2-hw4h-h46w - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS
- Severity: HIGH  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:L
- Fixed versions: 7.5.4 (for your version: 7.5.4)
- Affected ranges: >= 0, < 7.5.4
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-23950, https://github.com/isaacs/node-tar/security/advisories/GHSA-r6q2-hw4h-h46w, https://github.com/isaacs/node-tar/commit/3b1abfae650056edfabcbe0a0df5954d390521e6

**GitHub Advisory (GHSA)**  
- GHSA-r6q2-hw4h-h46w: https://github.com/advisories/GHSA-r6q2-hw4h-h46w
- Summary: Race Condition in node-tar Path Reservations via Unicode Ligature Collisions on macOS APFS
- Severity: high  |  CVSS: 8.8  |  CWEs: CWE-176, CWE-367
- Vulnerable range -> first patched: <= 7.5.3 -> patched 7.5.4

**Recommended target:** 7.5.4

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.4 or later to fix GHSA-r6q2-hw4h-h46w. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-vmf3-w455-68vh - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar applies PAX size override to intermediary GNU long-name/long-link headers, causing tar parser interpretation differential (file smuggling)
- Severity: MODERATE  |  CVSS: CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N
- Fixed versions: 7.5.16 (for your version: 7.5.16)
- Affected ranges: >= 0, < 7.5.16
- Advisories: https://github.com/isaacs/node-tar/security/advisories/GHSA-vmf3-w455-68vh

**GitHub Advisory (GHSA)**  
- GHSA-vmf3-w455-68vh: https://github.com/advisories/GHSA-vmf3-w455-68vh
- Summary: node-tar applies PAX size override to intermediary GNU long-name/long-link headers, causing tar parser interpretation differential (file smuggling)
- Severity: medium  |  CVSS: -  |  CWEs: CWE-436
- Vulnerable range -> first patched: <= 7.5.15 -> patched 7.5.16

**Recommended target:** 7.5.16

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.16 or later to fix GHSA-vmf3-w455-68vh. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-w8wr-v893-vjvp - tar 6.2.1

**OSV.dev**  
- Source: OSV.dev API
- Summary: node-tar: Process crash via PAX numeric path type confusion
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- Fixed versions: 7.5.18 (for your version: 7.5.18)
- Affected ranges: >= 0, < 7.5.18
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-59871, https://github.com/isaacs/node-tar/security/advisories/GHSA-w8wr-v893-vjvp, https://github.com/isaacs/node-tar/commit/e02a4e9e013c4be95302e2eb2047a942b883c27b

**GitHub Advisory (GHSA)**  
- GHSA-w8wr-v893-vjvp: https://github.com/advisories/GHSA-w8wr-v893-vjvp
- Summary: node-tar: Process crash via PAX numeric path type confusion
- Severity: medium  |  CVSS: 5.3  |  CWEs: CWE-704
- Vulnerable range -> first patched: <= 7.5.17 -> patched 7.5.18

**Recommended target:** 7.5.18

**Remediation summary** _(template)_

Upgrade tar from 6.2.1 to 7.5.18 or later to fix GHSA-w8wr-v893-vjvp. This is a major-version jump, so expect possible breaking changes and run your tests.

---

## GHSA-w5hq-g745-h8pq - uuid 8.3.2

**OSV.dev**  
- Source: OSV.dev API
- Summary: uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided
- Severity: MODERATE  |  CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N, CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N
- Fixed versions: 11.1.1, 12.0.1, 13.0.1 (for your version: 11.1.1)
- Affected ranges: >= 0, < 11.1.1; >= 12.0.0, < 12.0.1; >= 13.0.0, < 13.0.1
- Advisories: https://nvd.nist.gov/vuln/detail/CVE-2026-41907, https://github.com/uuidjs/uuid/security/advisories/GHSA-w5hq-g745-h8pq, https://github.com/uuidjs/uuid/commit/32389c887c9e75f90442ee4cc95bbab0c4e8346e

**GitHub Advisory (GHSA)**  
- GHSA-w5hq-g745-h8pq: https://github.com/advisories/GHSA-w5hq-g745-h8pq
- Summary: uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided
- Severity: medium  |  CVSS: 7.5  |  CWEs: CWE-787, CWE-1285
- Vulnerable range -> first patched: >= 12.0.0, < 12.0.1 -> patched 12.0.1; >= 13.0.0, < 13.0.1 -> patched 13.0.1; < 11.1.1 -> patched 11.1.1

**Recommended target:** 11.1.1

**Remediation summary** _(template)_

Upgrade uuid from 8.3.2 to 11.1.1 or later to fix GHSA-w5hq-g745-h8pq. This is a major-version jump, so expect possible breaking changes and run your tests.

---
