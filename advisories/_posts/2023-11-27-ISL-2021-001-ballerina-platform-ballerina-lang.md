---
layout: isl-entry
cveNumbers: ["CVE-2021-32700"]
islNumber: "ISL-2021-001"
ghAdvisories: [https://github.com/ballerina-platform/ballerina-lang/security/advisories/GHSA-9657-33wf-rmvx]
excerpt: "ballerina-platform/ballerina-lang before commit d7e08e0 used an insecure `TrustManager` for HTTPS connections making clients vulnerable to a machine-in-the-middle attack (MiTM) and Remote code execution (RCE)."
title: "ISL-2021-001: Insecure TrustManager in ballerina-platform/ballerina-lang"
---

{% capture summary %}
ballerina-platform/ballerina-lang used an insecure `TrustManager` for HTTPS connections making clients vulnerable a to machine-in-the-middle attack (MiTM) and remote code execution (RCE).
{% endcapture %}

{% capture product %}
[ballerina-platform/ballerina-lang](https://github.com/ballerina-platform/ballerina-lang)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "9a4d1967a72378636433c834ad9208e9fd32f1dd" | truncate: 8, "" }}](https://github.com/ballerina-platform/ballerina-lang/commit/9a4d1967a72378636433c834ad9208e9fd32f1dd)
{% endcapture %}

{% capture details %}
The Ballerina programming language provides the [bal](https://ballerina.io/learn/cli-documentation/cli-commands/) tool for managing everything related to Ballerina.
Dependency management is done using the `bal pull`/`push`/`search` commands that allow to download/upload packages from the central repository or search for a package.

I'm focusing on the `bal pull` command, the other sub-commands have the same problem and similar execution flow.
The `bal pull` command is internally represented by the [PullCommand](https://github.com/ballerina-platform/ballerina-lang/blob/9a4d1967a72378636433c834ad9208e9fd32f1dd/cli/ballerina-cli/src/main/java/io/ballerina/cli/cmd/PullCommand.java) class which will delegate the actual work to the [CentralAPIClient#pullPackage](https://github.com/ballerina-platform/ballerina-lang/blob/9a4d1967a72378636433c834ad9208e9fd32f1dd/cli/ballerina-cli/src/main/java/io/ballerina/cli/cmd/PullCommand.java#L168) method.
The [pullPackage](https://github.com/ballerina-platform/ballerina-lang/blob/9a4d1967a72378636433c834ad9208e9fd32f1dd/cli/central-client/src/main/java/org/ballerinalang/central/client/CentralAPIClient.java#L292) method then calls the [Utils#initializeSsl](https://github.com/ballerina-platform/ballerina-lang/blob/9a4d1967a72378636433c834ad9208e9fd32f1dd/cli/central-client/src/main/java/org/ballerinalang/central/client/Utils.java#L299) method which claims to "initializes SSL" but actually enables an insecure `TrustManager` (defined [here](https://github.com/ballerina-platform/ballerina-lang/blob/9a4d1967a72378636433c834ad9208e9fd32f1dd/cli/central-client/src/main/java/org/ballerinalang/central/client/Utils.java#L78-L90)).

An insecure `TrustManager` allows an attacker to create a self-signed certificate that matches the hostname of the intercepted connection.

After an attacker has forged such a certificate they can intercept and manipulate the requested package and include arbitrary code!
Because the issue affects both downloading and uploading of packages this could also be used for a **supply-chain attack**.
{% endcapture %}

{% capture impact %}
Machine-in-the-middle attack.
Remote code execution.
Supply chain attack.
{% endcapture %}

{% capture disclosureTimeline %}
- 2021-03-08: Sent a mail to security@ballerina.io.
- 2021-06-04: Issue is patched.
- 2021-06-22: CVE id is shared with me.
- 2021-06-22: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
