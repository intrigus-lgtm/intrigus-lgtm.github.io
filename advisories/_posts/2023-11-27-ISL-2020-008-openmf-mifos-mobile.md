---
layout: isl-entry
cveNumbers: ["CVE-2021-21385"]
islNumber: "ISL-2020-008"
ghAdvisories: [https://github.com/openMF/mifos-mobile/security/advisories/GHSA-9657-33wf-rmvx]
excerpt: "openMF/mifos-mobile before commit e505f62 disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable to a machine-in-the-middle attack (MiTM)."
title: "ISL-2020-008: Missing Hostname Verification and Insecure TrustManager in openMF/mifos-mobile"
---

{% capture summary %}
openMF/mifos-mobile disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable a to machine-in-the-middle attack (MiTM).
{% endcapture %}

{% capture product %}
[openMF/mifos-mobile](https://github.com/openMF/mifos-mobile)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "7ed4f22f2541d38f32c9e26ba075ca1b41424369" | truncate: 8, "" }}](https://github.com/openMF/mifos-mobile/commit/7ed4f22f2541d38f32c9e26ba075ca1b41424369)
{% endcapture %}

{% capture details %}
The [SelfServiceOkHttpClient](https://github.com/openMF/mifos-mobile/blob/7ed4f22f2541d38f32c9e26ba075ca1b41424369/app/src/main/java/org/mifos/mobile/api/SelfServiceOkHttpClient.kt#L64) class disables hostname verification by using a hostname verifier that accepts all hostnames by always returning `true`. The method also uses an insecure `TrustManager` that [trusts all certificates](https://github.com/openMF/mifos-mobile/blob/7ed4f22f2541d38f32c9e26ba075ca1b41424369/app/src/main/java/org/mifos/mobile/api/SelfServiceOkHttpClient.kt#L25-L45) even self-signed certificates.

Disabled hostname verification allows an attacker to use any valid certificate when intercepting a connection. Even when the hostname of the certificate does **NOT** match the hostname of the connection.
An insecure `TrustManager` allows an attacker to create a self-signed certificate that matches the hostname of the intercepted connection.
{% endcapture %}

{% capture impact %}
Machine-in-the-middle attack.
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-10-18: Asked to open a security advisory.
- 2021-03-19: CVE id is shared with me.
- 2021-03-14: Issue is patched.
- 2021-03-22: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
