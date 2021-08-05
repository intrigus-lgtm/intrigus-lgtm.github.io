---
layout: isl-research-post
title: "Finding Insecure JWT Signature Validation with CodeQL"
excerpt: "JSON Web Tokens (JWTs) are notorious for vulnerabilities. In this post I'm going to show how to find multiple CVEs in users of the jwtk/jjwt library."
---

# Finding Insecure JWT Signature Validation with CodeQL
In this post I want to show how I found four vulnerabilities in users of the [jwtk/jjwt](https://github.com/jwtk/jjwt) library using {{ site.linkToCodeQlGithub}}.

I start with a short section about what a JWT is, what CodeQL is, and finally I explain the query I used to find the vulnerabilities.

1. [CVE-2021-29451]({% link advisories/_posts/2021-08-05-ISL-2021-002-manydesigns-portofino.md%})
2. [CVE-2021-32631]({% link advisories/_posts/2021-08-05-ISL-2021-003-nimble-platform-common.md%})
3. [CVE-2021-29455]({% link advisories/_posts/2021-08-05-ISL-2021-004-grassrootza-grassroot-platform.md%})
4. [CVE-2021-29500]({% link advisories/_posts/2021-08-05-ISL-2021-005-fxbin-bubble-fireworks.md%})

## What Are JSON Web Tokens?
JWTs are based on the JSON format. They are used to exchange content ("payload") that can be signed, encrypted or both. They can also be neither which makes hackers and bounty-hunters happy :P

A JWT consists of three parts:
1. <span style="color:#648FFF">Header</span>:

   The header describes the algorithm that is used for signature validation.
   In this case we're using HMAC with SHA-256 (HS256).
   ```json
   {
     "alg": "HS256",
     "typ": "JWT"
   }
   ```
2. <span style="color:#DC267F">Payload</span>:

   The payload contains the actual content which is represented as a set of claims.
   There is a standard set of claims like `sub` - describes for which subject this token is -, `exp` - describes the expiration time of the token - and a few others. But it's also possible to use custom claims like `admin`.
   ```json
   {
     "sub": "1234567890",
     "admin": true
   }
   ```
3. <span style="color:#FFB000">Signature</span>:

   The signature is built from the base64 encoded header concatenated with a dot and the base64 encoded payload. We then apply the signature algorithm specified in the header and we have our signature.
   ```javascript
   HMAC_SHA256(
     secret,
     base64urlEncoding(header) + '.' +
     base64urlEncoding(payload)
   )
   ```

So if our JWT looks like this:\
<span style="color:#648FFF">{"alg": "HS256","typ": "JWT"}</span>.<span style="color:#DC267F">{"sub": "1234567890", "admin": true}</span>

After base64 encoding and signature generation it will look like this:\
<span style="color:#648FFF">eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIn0</span>.<span style="color:#DC267F">eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJhZG1pbiI6IHRydWV9</span>.<span style="color:#FFB000">fnsXsSs-1a0LUpQ6gEM6eFsadLQgYNNCaYMgWbG74Mo</span>

### The Problem with JWTs
With the structure explained, let's get to the problem with JWTs.
As I said, they can be used to exchange "content", but they are usually not used for ordinary "content" but for authentication information!

So if a user logs into a service using their credentials, the server will create a signed JWT (using their **secret** key) which is sent back to the user. A user will then have to **only** show their JWT as proof of authorization and if the signature is correct, the server will give access to the protected resources.

All proof that the user should have access to the service is only stored in the JWT which makes it critical that the user can not change the token and that the server **correctly** verifies the signature of the JWT.

**This is the problem! If we can forge a token, we don't need the password of the user, a 2FA token, or anything else from the user! If the server accepts our forged token as valid it's usually game-over for security.**

And sadly, JWTs are notorious for being used insecurely [^1][^2][^3][^4].
![A 4 panel meme: A: "I'm a big fan of cryptography engineering". B: "Okay, name 10 cryptography vulnerabilities". A: "JWT". B: "That's on me, I set the bar too low."]({{ "assets/images/isl-2021-jwt-meme.jpeg" | relative_url }})

[^1]: [How I Found An alg=none JWT Vulnerability in the NHS Contact Tracing App](https://www.zofrex.com/blog/2020/10/20/alg-none-jwt-nhs-contact-tracing-app/)

[^2]: [How Many Days Has It Been Since a JWT alg=none Vulnerability?](https://www.howmanydayssinceajwtalgnonevuln.com/)

[^3]: [Re-discovering a JWT Authentication Bypass in ServiceStack](https://www.shielder.it/blog/2020/11/re-discovering-a-jwt-authentication-bypass-in-servicestack/)

[^4]: [Zero-day in Sign in with Apple](https://bhavukjain.com/blog/2020/05/30/zeroday-signin-with-apple/)

## CodeQL
{{ site.linkToCodeQlGithub}} is a static analysis tool that has been developed by Semmle - now @ Github.

It can be used both for (targeted) [variant analysis](https://pwning.systems/posts/sequoia-variant-analysis/) and also (less targeted) analysis of entire bug classes like XSS, SSRF, and many more.

CodeQL has a simple but powerful, logical query language.
Let's look at a simple CodeQL query for Java:
```ql
import java

from IfStmt ifstmt, Block block
where ifstmt.getThen() = block and
  block.getNumStmt() = 0
select ifstmt, "This 'if' statement is redundant."
```
In our query we first have to import the Java specific CodeQL libraries. We then define what we want in the `from` part:\
All combinations of `if` statements and blocks.\
In the `where` part we specify that we are only interested in those `if` statements whose `then` block is the same as the block from the `from` clause and the `then` block has to have zero statements in it.\
The `select` clause will then create an alert with the message "This 'if' statement is redundant." at the location of the `if`statement.

## Finding Insecure JWT Validation in Users of The jwtk/jjwt Library.
[jwtk/jjwt](https://github.com/jwtk/jjwt) is a popular Java library for working with JWTs.

It offers not 1, not 2, but 6 different methods to parse a JWT!
The most problematic method is this parse method:
```java
Jwt parse(String jwt)
```
> Parses the specified compact serialized JWT string based on the builder’s current configuration state and returns the resulting JWT or JWS instance.
>
> [...]
>
> **Throws:**
>
> SignatureException - if a JWS signature was discovered, but could not be verified. JWTs that fail signature validation should not be trusted and should be discarded.

Looking at the Javadoc this is safe, right?
> SignatureException - if a JWS signature was discovered, but could not be verified.

So code like this should be perfectly safe, right?
```java
Jwts.parserBuilder()
     .setSigningKey("someBase64EncodedKey").build()
     .parse(token);
```

Sadly it isn't.
If we pass a JWT in the `header.payload.signature` format it will correctly verify the signature and throw an exception if the signature doesn't match. But if we pass `header.payload.` it **happily ignores the missing signature**, because a JWT seems to be valid with an empty signature. Even if in almost all cases what we want is a signed JWT (Known as a JWS)!

### The Query
When writing a query it's very helpful to verbalize the query:

We want to find all calls to the `parse` method of `JwtParser`. But only on parsers that have a signing key set (for example, if you - as a user/client - only want to know whether a token has expired it usually doesn't matter whether it is correctly signed) to reduce false-positives. Reducing false-positives is very important in static analysis because nobody likes alerts that are wrong.

We can directly translate this into a CodeQL `from` clause:\
`from JwtParserInsecureParseMethodAccess ma, JwtParserWithSigningKeyExpr parserExpr`\
`ma` are all calls to insecure `parse` methods of `JwtParser` and `parserExpr` are all parsers for which a signing key has been set!

Our `where` clause then only has to ensure that we are calling the insecure method on the signed parser:\
`where ma.getQualifier() = parserExpr`

The `select` clause then adds a message at the location of the `parse` method and also references where a signing key has been set:\
`select ma, "A signing key is set $@, but the signature is not verified.",
  parserExpr.getSigningMethodAccess(), "here"`

The rest of the query contains a little bit of boilerplate to make the query better structured and reusable.

(The full query can be found [here](https://github.com/github/codeql/blob/ad9ea40954e54a371fa5dc5d20ae30f3b5a68e82/java/ql/src/experimental/Security/CWE/CWE-347/MissingJWTSignatureCheck.ql))

### Boilerplate-y Section
(Some parts of the query are shown simplified)

For the `JwtParserInsecureParseMethodAccess` class that models all calls to insecure `parse` methods we first model all insecure `parse` methods:
```ql
private class JwtParserInsecureParseMethod extends Method { // #1
  JwtParserInsecureParseMethod() {
    this.hasName(["parse"]) and // #2
    this.getNumberOfParameters() = 1 and // #3
    this.getDeclaringType() instanceof TypeJwtParser // #4
  }
}
```
This models all methods (#1) that have the name `parse` (#2), have exactly one parameter (#3) and are declared in the type `JwtParser` (#4).
Finding all **calls** to these methods is then as simple as declaring a class that extends `Method`**`Access`** (#5) and requiring that the accessed method (#6) is an instance of the `JwtParserInsecureParseMethod` class we defined above:
```ql
private class JwtParserInsecureParseMethodAccess extends MethodAccess { // #5
  JwtParserInsecureParseMethodAccess() {
    this.getMethod() instanceof JwtParserInsecureParseMethod // #6
  }
}
```

For the `JwtParserWithSigningKeyExpr` class we have to determine whether a `JwtParser` expressions has a signing key set or not. For this we use our all-purpose tool, [data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/#about-data-flow-analysis)!

We first have to tell CodeQL what we are "interested in". In our case we want to track the flow *from* all method calls that set a signing key (#7) *to* all expressions that call the `parse` method (#8) on an expressions with a set signing key.\
We also have to tell CodeQL about additional ways data can flow (#9) because the `jwtk/jjwt`library uses a [fluent interface](https://en.wikipedia.org/wiki/Fluent_interface#Java) which is (currently) not modeled by default.
```ql
private class SigningToInsecureMethodAccessDataFlow extends DataFlow::Configuration {
  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof SigningKeyMethodAccess // #7
  }
  override predicate isSink(DataFlow::Node sink) {
    any(JwtParserInsecureParseMethodAccess ma).getQualifier() = sink.asExpr() // #8
  }
  override predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { // #9
    (
      pred.asExpr().getType() instanceof TypeDerivedJwtParser or
      pred.asExpr().getType().(RefType).getASourceSupertype*() instanceof TypeJwtParserBuilder
    ) and
    succ.asExpr().(MethodAccess).getQualifier() = pred.asExpr()
  }
}
```

In the `JwtParserWithSigningKeyExpr` class we then have to check whether the expression really is a `JwtParser` (#10) and whether there is any flow *from* a method call that sets a signing key (`signingMa`) *to* the `this` expression (#11) using the configuration `SigningToInsecureMethodAccessDataFlow` defined above.
```ql
private class JwtParserWithSigningKeyExpr extends Expr {
  SigningKeyMethodAccess signingMa;
  JwtParserWithSigningKeyExpr() {
    this.getType() instanceof TypeDerivedJwtParser and // #10
    any(SigningToInsecureMethodAccessDataFlow s)
      .hasFlow(DataFlow::exprNode(signingMa), DataFlow::exprNode(this)) // #11
  }
```

This is the core of the query. The whole query has 200 lines including additional metadata, docs, and some modeling of similar yet rarely used methods.

Let me know if you enjoyed this post!