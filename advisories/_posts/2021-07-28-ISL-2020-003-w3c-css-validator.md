---
layout: isl-entry
cveNumbers: ["CVE-2020-4070"]
islNumber: "ISL-2020-003"
ghAdvisories: ["https://github.com/w3c/css-validator/security/advisories/GHSA-wf36-7w73-rh8c"]
excerpt: "w3c/css-validator is vulnerable to cross-site scripting (XSS) due to insufficient input sanitization."
title: "ISL-2020-003: XSS in w3c/css-validator"
---

{% capture summary %}
w3c/css-validator is vulnerable to cross-site scripting (XSS) due to insufficient input sanitization.
{% endcapture %}

{% capture product %}
[w3c/css-validator](https://github.com/w3c/css-validator)
{% endcapture %}

{% capture productVersion %}
Commit [{{ "54d68a1abb6d91e1abb96e35128cdbe53180c0c0" | truncate: 8, "" }}](https://github.com/w3c/css-validator/commit/54d68a1abb6d91e1abb96e35128cdbe53180c0c0)
{% endcapture %}

{% capture details %}
The `css-validator` application takes a URI as input.\
For example, here the URI is `file:///<script>alert("xss")</script>.css` in `http://localhost:8080/css-validator/validator?uri=`**file%3A%2F%2F%2F%3Cscript%3Ealert(%22xss%22)%3C/script%3E.css**`&profile=css3svg&usermedium=all&warning=1&vextwarning=&lang=en`.\
In case of a CSS error, this URI is saved in the field [sourceFile](https://github.com/w3c/css-validator/blob/53bd453f678468ada3116f00026402249a781629/org/w3c/css/parser/CssError.java#L25) and it is also saved in the error message.
They are passed to the template engine [here](https://github.com/w3c/css-validator/blob/53bd453f678468ada3116f00026402249a781629/org/w3c/css/css/StyleSheetGenerator.java#L283) and [here](https://github.com/w3c/css-validator/blob/53bd453f678468ada3116f00026402249a781629/org/w3c/css/css/StyleSheetGenerator.java#L286-L287).
After that the values are read in the [template](https://github.com/w3c/css-validator/blob/53bd453f678468ada3116f00026402249a781629/org/w3c/css/css/xhtml.properties#L130-L131) and reflected back to the user unescaped [here](https://github.com/w3c/css-validator/blob/53bd453f678468ada3116f00026402249a781629/org/w3c/css/css/xhtml.properties#L157) and [here](https://github.com/w3c/css-validator/blob/53bd453f678468ada3116f00026402249a781629/org/w3c/css/css/xhtml.properties#L170), causing XSS.
{% endcapture %}

{% capture impact %}
XSS.
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-06-15: Asked to open a Github security advisory.
- 2020-06-18: Invited to Github security advisory.
- 2020-06-19: Issue is patched.
- 2020-06-19: Advisory is published.
- 2020-06-20: CVE is assigned.
{% endcapture %}

{% include isl-entry.md %}
