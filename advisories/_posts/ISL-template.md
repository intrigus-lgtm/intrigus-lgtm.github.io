---
layout: isl-entry
cveNumbers: ["CVE-202X-XXXX"]
islNumber: "ISL-202X-XXX"
ghAdvisories: ["https://github.com/ADVISORYLINK"]
excerpt: ""
title: "ISL-202X-XXX: [PROBLEM] in [PROJECT]"
---

{% capture summary %}
SUMMARY.
{% endcapture %}

{% capture product %}
[ORGANIZATION/REPOSITORY](https://github.com/ORGANIZATION/REPOSITORY)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "FULL_COMMIT_HASH" | truncate: 8, "" }}](https://github.com/ORGANIZATION/REPOSITORY/commit/FULL_COMMIT_HASH)
{% endcapture %}

{% capture details %}
DETAILS.
{% endcapture %}

{% capture impact %}
IMPACT.
{% endcapture %}

{% capture disclosureTimeline %}
- 202X-XX-XX: Asked to open a Github security advisory.
- 202X-XX-XX: Invited to Github security advisory.
- 202X-XX-XX: Issue is patched.
- 202X-XX-XX: CVE is assigned.
- 202X-XX-XX: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
