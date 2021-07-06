---
layout: home
---
{% comment %}
// Calculate number of received CVEs.
{% endcomment %}

{% assign allCves = nil %}
{% for post in site.posts %}
{% if post.cveNumbers.size > 0 %}
{% assign allCves = allCves | concat: post.cveNumbers%}
{% endif %}
{% endfor %}

{% comment %}
// `uniq` so we don't count stuff twice
{% endcomment %}

{% assign numCves = allCves | uniq | size %}


Welcome to Intrigus' Security Lab.
This is my tiny contribution on securing the world's software by sharing my knowledge.

My research posts can be found [here]({% link research.md %}).

So far I have found **{{ numCves }}** CVEs, you can find the corresponding advisories [here]({% link advisories.md %}).
