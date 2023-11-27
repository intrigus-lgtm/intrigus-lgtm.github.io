---
layout: isl-entry
cveNumbers: ["CVE-2020-26234"]
islNumber: "ISL-2020-007"
ghAdvisories: [https://github.com/advisories/GHSA-44cw-p2hm-gpf6]
excerpt: "opencast/opencast before commit 4225bf9 disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable to a machine-in-the-middle attack (MiTM)."
title: "ISL-2020-007: Missing Hostname Verification and Insecure TrustManager in opencast/opencast"
---

{% capture summary %}
opencast/opencast disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable a to machine-in-the-middle attack (MiTM).
{% endcapture %}

{% capture product %}
[opencast/opencast](https://github.com/opencast/opencast)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "4b905437e90bd19700a6a6688f227f9efb20e153" | truncate: 8, "" }}](https://github.com/opencast/opencast/commit/4b905437e90bd19700a6a6688f227f9efb20e153)
{% endcapture %}

{% capture details %}
The [HttpClientImpl](https://github.com/opencast/opencast/blob/4b905437e90bd19700a6a6688f227f9efb20e153/modules/kernel/src/main/java/org/opencastproject/kernel/http/impl/HttpClientImpl.java#L196-L199) class disables hostname verification by using a hostname verifier that accepts all hostnames by always returning `true`. The method also uses an insecure `TrustManager` that [trusts all certificates](https://github.com/opencast/opencast/blob/4b905437e90bd19700a6a6688f227f9efb20e153/modules/kernel/src/main/java/org/opencastproject/kernel/http/impl/HttpClientImpl.java#L119-L150) even self-signed certificates.

Disabled hostname verification allows an attacker to use any valid certificate when intercepting a connection. Even when the hostname of the certificate does **NOT** match the hostname of the connection.
An insecure `TrustManager` allows an attacker to create a self-signed certificate that matches the hostname of the intercepted connection.
{% endcapture %}

{% capture impact %}
Machine-in-the-middle attack.
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-10-16: Sent a mail to security@opencast.org.
- 2020-11-17: CVE id is shared with me.
- 2020-12-08: Issue is patched.
- 2020-12-08: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
