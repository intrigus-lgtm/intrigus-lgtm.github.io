# Summary
{{ summary }}

# Product
{{ product }}

# Tested Version
{{ productVersion }}

# Details
{{ details }}

# CVE
{% if page.cveNumbers.size > 0 %}
{% for cveNumber in page.cveNumbers %}
[{{ cveNumber}}](https://nvd.nist.gov/vuln/detail/{{ cveNumber}})
{% endfor %}
{% else %}
No CVE has been assigned.
{% endif %}

{% if page.ghAdvisories.size > 0 %}
# Github Advisories
{% for advisory in page.ghAdvisories %}
[{{ advisory | split: "/" | last }}]({{ advisory}})
{% endfor %}
{% endif %}

# Coordinated Disclosure Timeline
{{ disclosureTimeline }}

# Credit
{% if credit %}
{{ credit }}
{% else %}
This issue was discovered and reported by [@intrigus-lgtm](https://github.com/intrigus-lgtm).
{% endif %}

# Contact
{{ contact }}
{% if contact %}
{{ contact }}
{% else %}
You can contact the ISL at `isl@intrigus.org`. Please include a reference to `{{page.islNumber}}` in any communication regarding this issue.
{% endif %}
