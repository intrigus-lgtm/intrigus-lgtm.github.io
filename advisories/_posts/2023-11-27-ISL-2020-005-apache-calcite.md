---
layout: isl-entry
cveNumbers: ["CVE-2020-13955"]
islNumber: "ISL-2020-005"
ghAdvisories: ["https://github.com/advisories/GHSA-hxp5-8pgq-mgv9"]
excerpt: "The `HttpUtils#getURLConnection` function of apache/calcite before commit 43eeafc disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable to a machine-in-the-middle attack (MiTM)."
title: "ISL-2020-005: Missing Hostname Verification and Insecure TrustManager in apache/calcite"
---

{% capture summary %}
The `HttpUtils#getURLConnection` function of apache/calcite disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable to a machine-in-the-middle attack (MiTM).
{% endcapture %}

{% capture product %}
[apache/calcite](https://github.com/apache/calcite)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "ab19f98172848fe303a18173946c2def0b0d0312" | truncate: 8, "" }}](https://github.com/apache/calcite/commit/ab19f98172848fe303a18173946c2def0b0d0312)
{% endcapture %}

{% capture details %}
The [HttpUtils#getURLConnection](https://github.com/apache/calcite/blob/ab19f98172848fe303a18173946c2def0b0d0312/core/src/main/java/org/apache/calcite/runtime/HttpUtils.java#L50) disables hostname verification by using a hostname verifier that accepts all hostnames by always returning `true`. The method also uses an insecure `TrustManager` that [trusts all certificates](https://github.com/apache/calcite/blob/ab19f98172848fe303a18173946c2def0b0d0312/core/src/main/java/org/apache/calcite/runtime/HttpUtils.java#L50) even self-signed certificates.

Disabled hostname verification allows an attacker to use any valid certificate when intercepting a connection. Even when the hostname of the certificate does **NOT** match the hostname of the connection.
An insecure `TrustManager` allows an attacker to create a self-signed certificate that matches the hostname of the intercepted connection.
{% endcapture %}

{% capture impact %}
Machine-in-the-middle attack.
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-08-13: Sent a mail to security@apache.org.
- 2020-09-27: CVE id is shared with me.
- 2020-10-01: Issue is patched.
- 2020-10-09: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
