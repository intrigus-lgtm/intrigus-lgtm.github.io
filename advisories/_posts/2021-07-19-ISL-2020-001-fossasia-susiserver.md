---
layout: isl-entry
cveNumbers: ["CVE-2020-4039"]
islNumber: "ISL-2020-001"
ghAdvisories: ["https://github.com/fossasia/susi_server/security/advisories/GHSA-wcm4-2jp5-q269"]
excerpt: ""
title: "ISL-2020-001: Arbitrary File Read/Write in fossasia/susi_server Leading to RCE"
---

{% capture summary %}
Insufficient input validation allowed a directory traversal vulnerability.
Any admin config and file readable by the app can be retrieved by the attacker. Furthermore, some files can also be moved or deleted.
{% endcapture %}

{% capture product %}
[fossasia/susi_server](https://github.com/fossasia/susi_server)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "d27ed0f5dc6ec4a097f02e6db3794b3896205bc5" | truncate: 8, "" }}](https://github.com/fossasia/susi_server/commit/d27ed0f5dc6ec4a097f02e6db3794b3896205bc5)
{% endcapture %}

{% capture details %}
The [GetImageServlet](https://github.com/fossasia/susi_server/blob/95c1b7e8a373bc0b5727edda2b64f230b3bbe839/src/ai/susi/server/api/cms/GetImageServlet.java#L81) API endpoint accepts a user-controlled `image_path` that is used to build the path to a stored image.
The content that is stored at the path `image_path` is then returned to the user, but `image_path` is not sanitized which allows directory traversal and arbitrary file reads.
```java
String image_path = post.get("image",""); // <- user-controlled
imageFile = new File(DAO.data_dir  + File.separator + "image_uploads" + File.separator + image_path);
ByteArrayOutputStream data = new ByteArrayOutputStream();
InputStream is = new BufferedInputStream(new FileInputStream(imageFile));
// `is` is written to `data`
ServletOutputStream sos = response.getOutputStream();
sos.write(data.toByteArray()); // <- write content back to user
```
There are further similar vulnerabilities that all have been fixed by ensuring that directory traversal is not possible anymore.\
For further information please visit my [research article]({% link research/_posts/2021-07-18-from-arbitrary-file-write-to-rce-in-fossasia-susiserver.md%}) that shows how to escalate an **arbitrary file write** to **remote code execution** (RCE).
{% endcapture %}

{% capture impact %}
**Remote code execution** as shown in my [research article]({% link research/_posts/2021-07-18-from-arbitrary-file-write-to-rce-in-fossasia-susiserver.md%}).
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-03-06: Asked to open a Github security advisory.
- 2020-03-10: Invited to Github security advisory.
- 2020-05-13: Issue is patched.
- 2020-06-08: CVE is assigned.
- 2020-10-15: Advisory is published.
{% endcapture %}

{% include isl-entry.md %}
