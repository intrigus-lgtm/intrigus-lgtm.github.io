---
layout: isl-research-post
title: "GitHub Universe 2022 Highlighting my JWT Query"
excerpt: "My JWT query is highlighted at GitHub Universe 2022 by the GitHub Security Lab as an example for community-driven security contributions."
---
[Blog post about the mentioned JWT query.]({% link research/_posts/2021-08-05-finding-insecure-jwt-signature-validation-with-codeql.md%})

[Link to the Security Lab's CodeQL Bug Bounty program.](https://securitylab.github.com/bounties/)

<video preload="auto" controls="controls" style="width:100%">
{% for video in site.static_files %}
  {% if video.path contains 'assets/videos/gh_universe_22_jwt_query_highlight_full.mp4' %}
      <source type="video/mp4" src="{{ video.path }}">
  {% endif %}
  {% if video.path contains 'assets/videos/gh_universe_22_jwt_query_highlight_full.webm' %}
      <source type="video/webm" src="{{ video.path }}">
  {% endif %}
  {% if video.path contains 'assets/videos/gh_universe_22_jwt_query_highlight_full.vtt' %}
      <track label="English" kind="subtitles" srclang="en" src="{{ video.path }}" default>
  {% endif %}
{% endfor %}
  <p>Your browser does not support the video element.</p>
</video>
