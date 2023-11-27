---
layout: isl-entry
cveNumbers: ["CVE-2020-17514"]
islNumber: "ISL-2020-006"
ghAdvisories: []
excerpt: "apache/fineract before commit e054a6f disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable to a machine-in-the-middle attack (MiTM)."
title: "ISL-2020-006: Missing Hostname Verification and Insecure TrustManager in apache/fineract"
---

{% capture summary %}
apache/fineract disabled hostname verification and used an insecure `TrustManager` for HTTPS connections making clients vulnerable to a machine-in-the-middle attack (MiTM).
{% endcapture %}

{% capture product %}
[apache/fineract](https://github.com/apache/fineract)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "d83bdc41661ce3163231cf94d7a424da044c8b84" | truncate: 8, "" }}](https://github.com/apache/fineract/commit/d83bdc41661ce3163231cf94d7a424da044c8b84)
{% endcapture %}

{% capture details %}
The [ProcessorHelper#configureClient](https://github.com/apache/fineract/blob/d83bdc41661ce3163231cf94d7a424da044c8b84/fineract-provider/src/main/java/org/apache/fineract/infrastructure/hooks/processor/ProcessorHelper.java#L76-L83) method disables hostname verification by using a hostname verifier that accepts all hostnames by always returning `true`. The method also uses an insecure `TrustManager` that [trusts all certificates](https://github.com/apache/fineract/blob/d83bdc41661ce3163231cf94d7a424da044c8b84/fineract-provider/src/main/java/org/apache/fineract/infrastructure/hooks/processor/ProcessorHelper.java#L51-L63) even self-signed certificates.

Disabled hostname verification allows an attacker to use any valid certificate when intercepting a connection. Even when the hostname of the certificate does **NOT** match the hostname of the connection.
An insecure `TrustManager` allows an attacker to create a self-signed certificate that matches the hostname of the intercepted connection.
{% endcapture %}

{% capture impact %}
Machine-in-the-middle attack.
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-10-15: Sent a mail to security@apache.org.
- 2020-10-18: Issue is patched.
- 2021-01-05: CVE id is shared with me.
- 2021-05-26: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
