---
layout: isl-entry
cveNumbers: ["CVE-2020-15097"]
islNumber: "ISL-2020-002"
ghAdvisories: ["https://github.com/loklak/loklak_server/security/advisories/GHSA-7557-4v29-rqw6"]
excerpt: ""
title: "ISL-2020-002: Arbitrary File Read/Write in loklak/loklak_server"
---

{% capture summary %}
Insufficient input validation allowed a directory traversal vulnerability.
Any admin config and file readable by the app can be retrieved by the attacker.
Furthermore, user-controlled content could be written to any admin config and files readable by the application.
{% endcapture %}

{% capture product %}
[loklak/loklak_server](https://github.com/loklak/loklak_server)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "5f48476d6f06dc00d87d25def5f789db703dfe3e" | truncate: 8, "" }}](https://github.com/loklak/loklak_server/commit/5f48476d6f06dc00d87d25def5f789db703dfe3e)
{% endcapture %}

{% capture details %}
The [AssetServlet](https://github.com/loklak/loklak_server/blob/7ffdb6608753d3d988bd1102ed49d5573d380bbf/src/org/loklak/api/cms/AssetServlet.java#L56-L66) endpoint accepts three user-controlled parameters: [screenName](https://github.com/loklak/loklak_server/blob/7ffdb6608753d3d988bd1102ed49d5573d380bbf/src/org/loklak/api/cms/AssetServlet.java#L56), [idStr](https://github.com/loklak/loklak_server/blob/7ffdb6608753d3d988bd1102ed49d5573d380bbf/src/org/loklak/api/cms/AssetServlet.java#L61), and [file](https://github.com/loklak/loklak_server/blob/7ffdb6608753d3d988bd1102ed49d5573d380bbf/src/org/loklak/api/cms/AssetServlet.java#L66). The three parameters are used to build the path to a stored asset whose content is then returned to the user, but the path is not sanitized which allows directory traversal and arbitrary file reads.
```java
String screenName = post.get("screen_name", ""); // <- user-controlled
String idStr = post.get("id_str", ""); // <- user-controlled
String file = post.get("file", ""); // <- user-controlled
File assetFile = DAO.getAssetFile(screenName, idStr, file);
ByteArrayOutputStream data = new ByteArrayOutputStream();
InputStream is = new BufferedInputStream(new FileInputStream(assetFile));
// `is` is written to `data`
ServletOutputStream sos = response.getOutputStream();
sos.write(data.toByteArray()); // <- write content back to user
```

`AssetServlet` also allows arbitrary file write in its [doPost](https://github.com/loklak/loklak_server/blob/7ffdb6608753d3d988bd1102ed49d5573d380bbf/src/org/loklak/api/cms/AssetServlet.java#L105-L140) method.
{% endcapture %}

{% capture impact %}
It is likely that **Remote code execution** is possible by adding malicious `authorized_keys` entries to the SSH daemon or by adding malicious crontabs, but this has not been tested.
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-03-17: Asked to open a Github security advisory.
- 2020-06-04: Invited to Github security advisory.
- 2020-07-02: Issue is patched.
- 2020-07-06: CVE is assigned.
- 2021-02-02: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
