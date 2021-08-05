---
layout: isl-entry
cveNumbers: ["CVE-2021-29500"]
islNumber: "ISL-2021-005"
ghAdvisories: ["https://github.com/fxbin/bubble-fireworks/security/advisories/GHSA-hj36-84cp-29pr"]
excerpt: "fxbin/bubble-fireworks before commit 67b2ef4 did not properly verify the signature of JSON Web Tokens.
This allows forging a valid JWT."
title: "ISL-2021-005: Missing Validation of JWT Signature in fxbin/bubble-fireworks"
---

{% capture summary %}
fxbin/bubble-fireworks before commit 67b2ef4 did not properly verify the signature of JSON Web Tokens.
This allows forging a valid JWT.
{% endcapture %}

{% capture product %}
[fxbin/bubble-fireworks](https://github.com/fxbin/bubble-fireworks)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "9bf53d962a09640eea5f6e681afeca83c221c860" | truncate: 8, "" }}](https://github.com/fxbin/bubble-fireworks/commit/9bf53d962a09640eea5f6e681afeca83c221c860)
{% endcapture %}

{% capture details %}
A JWT consists of three parts:
- header
- claims/payload
- signature
The three parts are base64 encoded and concatenated to form a string like this:
`base64EncodedHeader.base64EncodedClaims.base64EncodedSignature`.
In a client-server context the signature is created by the server and so a (malicious) client could **not** change a JWT without making signature validation fail!

fxbin/bubble-fireworks uses the [parse](https://github.com/fxbin/bubble-fireworks/blob/9bf53d962a09640eea5f6e681afeca83c221c860/bubble-fireworks-project/bubble-fireworks-plugins/bubble-fireworks-plugin-token/src/main/java/cn/fxbin/bubble/plugin/token/SingleJwt.java#L172) method on two [occasions](https://github.com/fxbin/bubble-fireworks/blob/9bf53d962a09640eea5f6e681afeca83c221c860/bubble-fireworks-project/bubble-fireworks-plugins/bubble-fireworks-plugin-token/src/main/java/cn/fxbin/bubble/plugin/token/DoubleJwt.java#L144) to verify the signature of a JWT.
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
- 2021-04-17: Asked to open a Github security advisory.
- 2021-04-23: Invited to Github security advisory.
- 2021-05-06: Issue is patched.
- 2021-05-10: CVE is assigned.
- 2021-05-21: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
