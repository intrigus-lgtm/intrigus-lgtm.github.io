---
layout: isl-entry
cveNumbers: ["CVE-2021-32631"]
islNumber: "ISL-2021-003"
ghAdvisories: ["https://github.com/nimble-platform/common/security/advisories/GHSA-fjq8-896w-pv28"]
excerpt: "nimble-platform/common before commit 3b96cb0 did not properly verify the signature of JSON Web Tokens.
This allows forging a valid JWT and can lead to authentication bypasses."
title: "ISL-2021-003: Missing Validation of JWT Signature in nimble-platform/common"
---

{% capture summary %}
nimble-platform/common before commit 3b96cb0 did not properly verify the signature of JSON Web Tokens.
This allows forging a valid JWT and can lead to authentication bypasses.
{% endcapture %}

{% capture product %}
[nimble-platform/common](https://github.com/nimble-platform/common)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "36324062a2c7eb35b8b82463f5907f656fef23cf" | truncate: 8, "" }}](https://github.com/nimble-platform/common/commit/36324062a2c7eb35b8b82463f5907f656fef23cf)
{% endcapture %}

{% capture details %}
A JWT consists of three parts:
- header
- claims/payload
- signature
The three parts are base64 encoded and concatenated to form a string like this:
`base64EncodedHeader.base64EncodedClaims.base64EncodedSignature`.
In a client-server context the signature is created by the server and so a (malicious) client could **not** change a JWT without making signature validation fail!

nimble-platform/common uses the [parse](https://github.com/nimble-platform/common/blob/36324062a2c7eb35b8b82463f5907f656fef23cf/utility/src/main/java/eu/nimble/utility/validation/ValidationUtil.java#L39) method to verify the signature of a JWT.
The `parse` method properly verifies the signature if it consists of the three parts.

**But** it will also verify a JWT that contains no signature at all!
So it will happily accept a token like this that could have been created by a malicious attacker:
`base64EncodedHeader.base64EncodedClaims`

The solution is to **always** use the `parseClaimsJws` method when parsing signed JWTs!

**(This vulnerability has been found using [this]({% link research/_posts/2021-08-05-finding-insecure-jwt-signature-validation-with-codeql.md%}) CodeQL query)**
{% endcapture %}

{% capture impact %}
Arbitrary JWT forging which may lead to authentication bypasses.
{% endcapture %}

{% capture disclosureTimeline %}
- 2021-04-15: Asked to open a Github security advisory.
- 2021-05-19: Invited to Github security advisory.
- 2021-05-20: CVE is assigned.
- 2021-07-26: Issue is patched.
- 2021-07-26: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
