---
layout: isl-entry
cveNumbers: ["CVE-2021-29451"]
islNumber: "ISL-2021-002"
ghAdvisories: ["https://github.com/ManyDesigns/Portofino/security/advisories/GHSA-6g3c-2mh5-7q6x"]
excerpt: "ManyDesigns/Portofino before version 5.2.1 did not properly verify the signature of JSON Web Tokens.
This allows forging a valid JWT and can lead to authentication bypasses."
title: "ISL-2021-002: Missing Validation of JWT Signature in ManyDesigns/Portofino"
---

{% capture summary %}
ManyDesigns/Portofino before version 5.2.1 did not properly verify the signature of JSON Web Tokens.
This allows forging a valid JWT and can lead to authentication bypasses.
{% endcapture %}

{% capture product %}
[ManyDesigns/Portofino](https://github.com/ManyDesigns/Portofino)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "8df94136b6807741c8db793e466236fe58b6878d" | truncate: 8, "" }}](https://github.com/ManyDesigns/Portofino/commit/8df94136b6807741c8db793e466236fe58b6878d)
{% endcapture %}

{% capture details %}
A JWT consists of three parts:
- header
- claims/payload
- signature
The three parts are base64 encoded and concatenated to form a string like this:
`base64EncodedHeader.base64EncodedClaims.base64EncodedSignature`.
In a client-server context the signature is created by the server and so a (malicious) client could **not** change a JWT without making signature validation fail!

ManyDesigns/Portofino uses the [parse](https://github.com/ManyDesigns/Portofino/blob/8df94136b6807741c8db793e466236fe58b6878d/dispatcher/src/main/java/com/manydesigns/portofino/dispatcher/security/jwt/JWTRealm.java#L58) method to verify the signature of a JWT.
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
- 2021-03-29: Asked to open a Github security advisory.
- 2021-04-01: Invited to Github security advisory.
- 2021-04-09: Issue is patched.
- 2021-04-15: CVE is assigned.
- 2021-04-16: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
