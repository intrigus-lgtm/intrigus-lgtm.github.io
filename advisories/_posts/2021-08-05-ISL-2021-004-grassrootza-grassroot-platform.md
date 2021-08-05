---
layout: isl-entry
cveNumbers: ["CVE-2021-29455"]
islNumber: "ISL-2021-004"
ghAdvisories: ["https://github.com/grassrootza/grassroot-platform/security/advisories/GHSA-f65w-6xw8-6734"]
excerpt: "grassrootza/grassroot-platform before version 1.3.1 did not properly verify the signature of JSON Web Tokens when refreshing an existing JWT.
This allows forging a valid JWT and can lead to authentication bypasses."
title: "ISL-2021-004: Missing Validation of JWT Signature in grassrootza/grassroot-platform"
---

{% capture summary %}
grassrootza/grassroot-platform before version 1.3.1 did not properly verify the signature of JSON Web Tokens when refreshing an existing JWT.
This allows forging a valid JWT and can lead to authentication bypasses.
{% endcapture %}

{% capture product %}
[grassrootza/grassroot-platform](https://github.com/grassrootza/grassroot-platform)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "6308bed57e69d810136c3b4038ecf5d76fa3ada9" | truncate: 8, "" }}](https://github.com/grassrootza/grassroot-platform/commit/6308bed57e69d810136c3b4038ecf5d76fa3ada9)
{% endcapture %}

{% capture details %}
A JWT consists of three parts:
- header
- claims/payload
- signature
The three parts are base64 encoded and concatenated to form a string like this:
`base64EncodedHeader.base64EncodedClaims.base64EncodedSignature`.
In a client-server context the signature is created by the server and so a (malicious) client could **not** change a JWT without making signature validation fail!

grassrootza/grassroot-platform uses the [parse](https://github.com/grassrootza/grassroot-platform/blob/6308bed57e69d810136c3b4038ecf5d76fa3ada9/grassroot-integration/src/main/java/za/org/grassroot/integration/authentication/JwtServiceImpl.java#L181) method to verify the signature of a JWT when refreshing a JWT token.
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
- 2021-04-15: Invited to Github security advisory.
- 2021-04-16: Issue is patched.
- 2021-04-16: CVE is assigned.
- 2021-04-17: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
