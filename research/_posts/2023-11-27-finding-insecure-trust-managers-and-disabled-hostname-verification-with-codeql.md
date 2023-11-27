---
layout: isl-research-post
title: "Finding Insecure TrustManagers and Disabled Hostname Verification with CodeQL"
excerpt: "Certificates are a cornerstone of what makes Internet communication secure. In this post, I'm going to show how to find multiple CVEs in usage of the Java `TrustManager` and `HostnameVerifier` classes."
---

# Finding Insecure TrustManagers and Disabled Hostname Verification with CodeQL
In this post, I want to show how I found five vulnerabilities in usage of the Java [TrustManager](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/TrustManager.html) and [HostnameVerifier](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/HostnameVerifier.html) classes.

I start with a short section about what a certificate is, what CodeQL is, and finally I explain the query I used to find the vulnerabilities.

1. [CVE-2020-13955]({% link advisories/_posts/2023-11-27-ISL-2020-005-apache-calcite.md%})
1. [CVE-2020-17514]({% link advisories/_posts/2023-11-27-ISL-2020-006-apache-fineract.md%})
2. [CVE-2020-26234]({% link advisories/_posts/2023-11-27-ISL-2020-007-opencast-opencast.md%})
3. [CVE-2021-21385]({% link advisories/_posts/2023-11-27-ISL-2020-008-openmf-mifos-mobile.md%})
4. [CVE-2021-32700]({% link advisories/_posts/2023-11-27-ISL-2021-001-ballerina-platform-ballerina-lang.md%})

## What Are Certificates?
A certificate associates an identity (hostname, personal identity, ...) with a public key and can either be signed by a _Certificate Authority_ (CA) or be self-signed.
A CA is a trusted third party that verifies the identity of the owner of the certificate and signs the certificate with their own private key.
Both browsers and operating systems come with a set of CAs that they trust by default [^1].

[^1]: These CAs **can** and **will** be removed when there are problems with them, see e.g. [https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4/m/PKpJf5W6AQAJ), [https://wiki.mozilla.org/CA/Symantec_Issues](https://wiki.mozilla.org/CA/Symantec_Issues), or [https://www.techtarget.com/searchsecurity/news/252527914/Mozilla-Microsoft-drop-Trustcor-as-root-certificate-authority](https://www.techtarget.com/searchsecurity/news/252527914/Mozilla-Microsoft-drop-Trustcor-as-root-certificate-authority).

When a client connects to a server using TLS, the server sends its certificate to the client. The client then verifies the certificate by checking whether it is **signed by a trusted CA** and whether **the hostname of the server matches the hostname in the certificate**. If the certificate is valid, the client will establish a secure and encrypted connection with the server.

### So What's the Problem?
The problem is that the client can be configured to trust certificates that are **not signed by a trusted CA** or that **don't match the hostname of the server**. This is usually done for testing purposes, but it can also be done by mistake or just as an oversight.

Browsers usually get this right, but there have also been cases in the past where they incorrectly implemented hostname verification [^2][^3] or where they had other problems verifying a certificate [^4].

[^2]: [CVE-2004-0765](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0765)

[^3]: [CVE-2009-2408](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2408)

[^4]: [CVE-2016-4763](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4763)

In this post I'm going to focus on Java applications that use the `TrustManager` or `HostnameVerifier` classes unsafely.


## CodeQL
{{ site.linkToCodeQlGithub}} is a static analysis tool that has been developed by Semmle - now @ Github.

It can be used both for (targeted) [variant analysis](https://pwning.systems/posts/sequoia-variant-analysis/) and also (less targeted) analysis of entire bug classes like XSS, SSRF, and many more.

CodeQL has a simple but powerful, logical query language.
If you want to learn more about CodeQL I recommend reading the [CodeQL documentation](https://codeql.github.com/docs/).

## Finding Insecure TrustManagers
So what is an insecure `TrustManager`?
A `TrustManager` is insecure if it accepts all certificates, regardless of whether they are signed by a trusted CA or not.
This is usually done by implementing the `checkServerTrusted` method of the `X509TrustManager` interface and never throwing an exception -- therefore accepting all certificates.
In code this would look like this:
```java
class InsecureTrustManager implements X509TrustManager {
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // BAD: Does not verify the certificate chain, allowing any certificate.
    }
    
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }
}
```
If we then use this `TrustManager` like so in our application:
```java
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, new TrustManager[] { new InsecureTrustManager() }, null);

HttpsURLConnection connection = (HttpsURLConnection) new URL("https://untrusted-root.badssl.com/").openConnection();
connection.setSSLSocketFactory(sslContext.getSocketFactory());
connection.connect();
```
We will happily connect to the server even though the certificate is not signed by a trusted CA.

### The Query -- High-Level
When writing a query it's very helpful to verbalize the query:

We want to find all cases where an insecure `TrustManager` is used to initialize an `SSLContext`.
This means that we have a data flow query and we "just" have to define the source and the sink!

We can directly translate this into a CodeQL `from` clause:\
`from InsecureTrustManagerFlow::PathNode source, InsecureTrustManagerFlow::PathNode sink`\
`source`s are all `TrustManager` instances that are insecure and `sink`s are all `SSLContext` instances that are initialized with an insecure `TrustManager`!

Our `where` clause then only has to ensure that the source is actually used at the sink, that is, we need `flowPath` to hold:\
`where InsecureTrustManagerFlow::flowPath(source, sink)`

The `select` clause then adds a message at the location of the `SSLContext#init` method and also references where the trust manager has been defined:\
`select sink, source, sink, "This uses $@, which is defined in $@ and trusts any certificate.",
  source, "TrustManager",
  source.getNode().asExpr().(ClassInstanceExpr).getConstructedType() as type, type.nestedName()`

The rest of the query contains a little bit of boilerplate to make the query better structured and reusable.

(The main query can be found [here](https://github.com/github/codeql/blob/4f7fde7b879890009a5f955abed0a7e21dee8516/java/ql/src/Security/CWE/CWE-295/InsecureTrustManager.ql), support files are in [InsecureTrustManager.qll](https://github.com/github/codeql/blob/4f7fde7b879890009a5f955abed0a7e21dee8516/java/ql/lib/semmle/code/java/security/InsecureTrustManager.qll) and [InsecureTrustManagerQuery.qll](https://github.com/github/codeql/blob/4f7fde7b879890009a5f955abed0a7e21dee8516/java/ql/lib/semmle/code/java/security/InsecureTrustManagerQuery.qll)).

### The Query -- Low-Level
(Some parts of the query are shown simplified)

The `InsecureTrustManagerSource` class models all `TrustManager` instances that are insecure on the _data flow level_ [^5] by viewing the node as an _expression_ and then checking whether its constructed type [^6] is an `InsecureX509TrustManager`.
```ql
private class InsecureTrustManagerSource extends DataFlow::Node {
  InsecureTrustManagerSource() {
    this.asExpr().(ClassInstanceExpr).getConstructedType() instanceof InsecureX509TrustManager
  }
}
```

[^5]: There are multiple "levels" in CodeQL. The _data flow level_ is the highest level and is partially shared across **all** languages supported by CodeQL while the _abstract syntax tree level_ is specific to each language and is the lowest level.

[^6]: A [ClassInstanceExpr](https://codeql.github.com/codeql-standard-libraries/java/semmle/code/java/Expr.qll/type.Expr$ClassInstanceExpr.html) is for example `new FooBar()` and [getConstructedType](https://codeql.github.com/codeql-standard-libraries/java/semmle/code/java/Expr.qll/predicate.Expr$ConstructorCall$getConstructedType.0.html) gets the type of the constructed object, in this case `FooBar`.

`InsecureX509TrustManager` is a class that models all classes deriving from `X509TrustManager` (`#1`) that have overridden the "checkServerTrusted" method (`#2`) and that never throw a `CertificateException` (`#3`).
```ql
private class InsecureX509TrustManager extends RefType {
  InsecureX509TrustManager() {
    this.getAnAncestor() instanceof X509TrustManager and // #1
    exists(Method m |
      m.getDeclaringType() = this and
      m.hasName("checkServerTrusted") and // #2
      not mayThrowCertificateException(m) // #3
    )
  }
}
```

Under what conditions can a method throw a `CertificateException`?
When it contains a `throw` statement that throws a `CertificateException` (`#4`) or when it calls a method (`#5`) that may throw a `CertificateException` (`#6`) or if there is no source code available for the called method and the method has a `@throws` annotation that mentions `CertificateException` (`#7`).
```ql
private predicate mayThrowCertificateException(Method m) {
  exists(ThrowStmt throwStmt | // #4
    throwStmt.getThrownExceptionType().getAnAncestor() instanceof CertificateException // #4
  |
    throwStmt.getEnclosingCallable() = m // #4
  )
  or
  exists(Method otherMethod | m.polyCalls(otherMethod) | // #5
    mayThrowCertificateException(otherMethod) // #6
    or
    not otherMethod.fromSource() and // #7
    otherMethod.getAnException().getType().getAnAncestor() instanceof CertificateException // #7
  )
}
```

The `InsecureTrustManagerSink` class models all cases where any `TrustManager` (`#8`) is used to `init` (`#9`) an `SslContext` (`#10`).
```ql
private class InsecureTrustManagerSink extends DataFlow::Node {
  InsecureTrustManagerSink() {
    exists(MethodCall ma, Method m |
      m.hasName("init") and // #9
      m.getDeclaringType() instanceof SslContext and // #10
      ma.getMethod() = m
    |
      ma.getArgument(1) = this.asExpr() // #8
    )
  }
}
```

The `InsecureTrustManagerConfig` module then simply combines the source (`#11`) and the sink (`#12`) like this:
```ql
module InsecureTrustManagerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof InsecureTrustManagerSource } // #11

  predicate isSink(DataFlow::Node sink) { sink instanceof InsecureTrustManagerSink } // #12
}
```

However, we have a slight problem:
remember that we have a _data flow query_ and not a _taint tracking query_.
Recall the example from above:
```java
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, 
new TrustManager[] { // #14
  new InsecureTrustManager() // #13 #14
} // #14
, null);
```
We want to find flow from `#13` to the second (`1` in the definition of `InsecureTrustManagerSink`, because CodeQL is zero-based) argument of `init`.
However, `#13` is an array **element** and cannot flow to the **array** itself (`#14`) (CodeQL distinguishes between the array elements and the array itself). To fix this, we can allow implicit reads of array elements by overriding the `allowImplicitRead` predicate.
```ql
predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
  (isSink(node) or isAdditionalFlowStep(node, _)) and
  node.getType() instanceof Array and
  c instanceof DataFlow::ArrayContent
}
```
This predicate allows **implicit read**s of array elements when the array is used as a sink or when it is used as an additional flow step.
By enabling **implicit read**s, CodeQL will not distinguish between data stored inside something (in a field, in an array as an element, in a map as a key or value, ...) and the thing itself (the object the field belongs to, the array where the element is in, the map where the key/value is from, ...) [^7].

[^7]: For more information about implicit reads see [this discussion](https://github.com/github/codeql/discussions/14092#discussioncomment-6926222).

## Finding Disabled Hostname Verification
So what is disabled hostname verification?
Hostname verification is disabled if we have a `HostnameVerifier` that always returns `true` in its `verify` method.
Always returning `true` means that we will accept any hostname, regardless of whether it matches the hostname in the certificate or not!
In code this would look like this:
```java
HostnameVerifier verifier = new HostnameVerifier() {
	@Override
	public boolean verify(String hostname, SSLSession session) {
		return true; // BAD: accept even if the hostname doesn't match
	}
};
```
If we then use this `HostnameVerifier` like so in our application:
```java
HttpsURLConnection connection = (HttpsURLConnection) new URL("https://wrong.host.badssl.com/").openConnection();
connection.setHostnameVerifier(verifier);
connection.connect();
```
We will happily connect to the server even though the certificate is not valid for the `wrong.host.badssl.com` domain [^8].

[^8]: The certificate is only valid for `*.badssl.com` and `badssl.com`. Wildcard certificates -- like `*.badssl.com` -- only apply to one level of subdomains, so `wrong.host.badssl.com` is not covered by the certificate, but `host.badssl.com` or `foobar.badssl.com` would be.

### The Query -- High-Level
Again, when writing a query it's very helpful to verbalize the query:

We want to find all cases where an all-accepting `HostnameVerifier` is used in a `HttpsURLConnection#set(Default)HostnameVerifier` call.
This means that we again have a data flow query and we "just" have to define the source and the sink!

We can directly translate this into a CodeQL `from` clause:\
`from
  TrustAllHostnameVerifierFlow::PathNode source, TrustAllHostnameVerifierFlow::PathNode sink`\
`source`s are all `HostnameVerifier` instances that are all-accepting and `sink`s are all `HttpsURLConnection#set(Default)HostnameVerifier` calls!

Our `where` clause then only has to ensure that the source is actually used at the sink, that is, we need `flowPath` to hold:\
`where TrustAllHostnameVerifierFlow::flowPath(source, sink)`

The `select` clause then adds a message at the location of the `HttpsURLConnection#set(Default)HostnameVerifier` method and also references where the all-accepting hostname verifier has been defined:\
`select sink, source, sink,
  "The $@ defined by $@ always accepts any certificate, even if the hostname does not match.",
  source, "hostname verifier", source.getNode().asExpr().(ClassInstanceExpr).getConstructedType() as verifier, "this type"`

The rest of the query contains a little bit of boilerplate to make the query better structured and reusable.

(The main query can be found [here](https://github.com/github/codeql/blob/257fe1ad6b5e8e596ece2306213dcfc340420e2c/java/ql/src/Security/CWE/CWE-297/UnsafeHostnameVerification.ql), support files are in[UnsafeHostnameVerificationQuery.qll](https://github.com/github/codeql/blob/257fe1ad6b5e8e596ece2306213dcfc340420e2c/java/ql/lib/semmle/code/java/security/UnsafeHostnameVerificationQuery.qll)).

### The Query -- Low-Level
(Some parts of the query are shown simplified)

The `TrustAllHostnameVerifier` class models all `HostnameVerifier` instances that accept any hostname by checking whether the instance derives from `HostnameVerifier` (`#1`) and if it overrides the verify method (`#2`) to always return `true` (`#3`).
```ql
class TrustAllHostnameVerifier extends RefType {
  TrustAllHostnameVerifier() {
    this.getAnAncestor() instanceof HostnameVerifier and // #1
    exists(HostnameVerifierVerify m |
      m.getDeclaringType() = this and // #2
      alwaysReturnsTrue(m) // #3
    )
  }
}
```

When does a method always return `true`?
When **all** return statements return `true` (`#4`). Note that this is a simplification, there could be methods that always return `true` in practice/at runtime, but we cannot determine this statically.
```ql
private predicate alwaysReturnsTrue(HostnameVerifierVerify m) {
  forex(ReturnStmt rs | rs.getEnclosingCallable() = m |
    rs.getResult().(CompileTimeConstantExpr).getBooleanValue() = true // #4
  )
}
```

The `HostnameVerifierSink` class models all cases where any `HostnameVerifier` is used in e.g. a `HttpsURLConnection#setHostnameVerifier` call.
```ql
private class HostnameVerifierSink extends DataFlow::Node {
  HostnameVerifierSink() { sinkNode(this, "hostname-verification") }
}
```

It does this by using the special [sinkNode](https://github.com/github/codeql/blob/257fe1ad6b5e8e596ece2306213dcfc340420e2c/java/ql/lib/semmle/code/java/dataflow/ExternalFlow.qll#L489) predicate that gets all nodes that are annotated with `hostname-verification` in a "Models-as-Data" (MaD) file.

The MaD files can be found in `.yml` files in the [java/ql/lib/ext](https://github.com/github/codeql/tree/257fe1ad6b5e8e596ece2306213dcfc340420e2c/java/ql/lib/ext) folder.
In our case, there are three definitions:
```yaml
- ["javax.net.ssl", "HttpsURLConnection", True, "setDefaultHostnameVerifier", "", "", "Argument[0]", "hostname-verification", "manual"]
- ["javax.net.ssl", "HttpsURLConnection", True, "setHostnameVerifier", "", "", "Argument[0]", "hostname-verification", "manual"]
# from https://github.com/github/codeql/blob/257fe1ad6b5e8e596ece2306213dcfc340420e2c/java/ql/lib/ext/javax.net.ssl.model.yml#L6-L7
- ["org.apache.cxf.configuration.jsse", "TLSClientParameters", True, "setHostnameVerifier", "(HostnameVerifier)", "", "Argument[0]", "hostname-verification", "manual"
# from https://github.com/github/codeql/blob/257fe1ad6b5e8e596ece2306213dcfc340420e2c/java/ql/lib/ext/org.apache.cxf.configuration.jsse.model.yml#L7
```

The first element is the package name (`"javax.net.ssl"`), the second element is the class name (`"HttpsURLConnection"`).
The third element is a boolean that indicates whether to jump to an arbitrary subtype of that type (`True`), the fourth element is the method name (`"setDefaultHostnameVerifier"`) although generally this just selects a specific member (method, field, ...) of the type.
The fifth element allows restriction based on the member signature (`""` so no filtering is done), the sixth element is not relevant in our case.
The seventh element defines how data enters the sink (`"Argument[0]"` in our case), the eighth element is the annotation that is used to annotate the sink (`"hostname-verification"`).
The ninth element is the origin of the model (in this case `manual` because the model has been added manually and not generated by e.g. the model generator). For more information about MaD files have a look at this [internal documentation](https://github.com/github/codeql/blob/257fe1ad6b5e8e596ece2306213dcfc340420e2c/java/ql/lib/semmle/code/java/dataflow/ExternalFlow.qll#L1-L88).


The `TrustAllHostnameVerifierConfig` module then simply combines the source (`#5`) and the sink (`#6`) like this:
```ql
module TrustAllHostnameVerifierConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(ClassInstanceExpr).getConstructedType() instanceof TrustAllHostnameVerifier // #5
  }

  predicate isSink(DataFlow::Node sink) { sink instanceof HostnameVerifierSink } // #6
}
```

Because we want to reduce false-positives, we add an `isBarrier` predicate to the query.
This predicate ignores all nodes that are in functions that _suggest_ that they intentionally disable hostname verification.

```ql
predicate isBarrier(DataFlow::Node barrier) {
  // ignore nodes that are in functions that intentionally disable hostname verification
  barrier
      .getEnclosingCallable()
      .getName()
      /*
       * Regex: (_)* :
       * some methods have underscores.
       * Regex: (no|ignore|disable)(strictssl|ssl|verify|verification|hostname)
       * noStrictSSL ignoreSsl
       * Regex: (set)?(accept|trust|ignore|allow)(all|every|any)
       * acceptAll trustAll ignoreAll setTrustAnyHttps
       * Regex: (use|do|enable)insecure
       * useInsecureSSL
       * Regex: (set|do|use)?no.*(check|validation|verify|verification)
       * setNoCertificateCheck
       * Regex: disable
       * disableChecks
       */
       
      .regexpMatch("^(?i)(_)*((no|ignore|disable)(strictssl|ssl|verify|verification|hostname)" +
          "|(set)?(accept|trust|ignore|allow)(all|every|any)" +
          "|(use|do|enable)insecure|(set|do|use)?no.*(check|validation|verify|verification)|disable).*$")
}
```

#### General Guards
To further reduce false-positives, we also extend the `where` clause with `and not isNodeGuardedByFlag(sink.getNode())` to remove all sinks that are guarded by a flag indicating intentional disabling of hostname verification.

```ql
predicate isNodeGuardedByFlag(DataFlow::Node node) {
  exists(Guard g | g.controls(node.asExpr().getBasicBlock(), _) | // #7
    g = getASecurityFeatureFlagGuard() or g = getAnUnsafeHostnameVerifierFlagGuard() // #8
  )
}
```
A `node` is guarded when there is a `Guard` that controls (`#7`) [^9] the `node` and that is either a security feature flag guard or an unsafe hostname verifier flag guard (`#8`).\
A `Guard` controls another node when the execution of the controlled node is dependent on the condition specified by the guard.

[^9]: Technically, the `Guard` verifies that it controls the [basic block](https://en.wikipedia.org/wiki/Basic_block) that contains the `node`.

For example, consider the following code:
```java
if (isHostnameVerificationDisabled()) { // #9
  connection.setHostnameVerifier(new TrustAllHostnameVerifier()); // #10
}
```

Here, the `connection.setHostnameVerifier` (`#10`) call is guarded/controlled by the `isHostnameVerificationDisabled` (`#9`) method call.

#### Security Feature Flag Guards
The `getASecurityFeatureFlagGuard` predicate gets some pre-defined guards indicating intentional disabling of a security feature while the `getAnUnsafeHostnameVerifierFlagGuard` predicate gets guards specific to hostname verification. For that reason, we extend the existing `FlagKind` class.
All we have to do is to override the `getAFlagName` predicate to get all strings that should be considered a flag.  
```ql
private class UnsafeHostnameVerificationFlag extends FlagKind {
  UnsafeHostnameVerificationFlag() { this = "UnsafeHostnameVerificationFlag" }

  bindingset[result]
  override string getAFlagName() {
    result
        .regexpMatch("(?i).*(secure|disable|selfCert|selfSign|validat|verif|trust|ignore|nocertificatecheck).*") and
    result != "equalsIgnoreCase"
  }
}
```

By extending the `FlagKind` class, we get all the functionality of the `FlagKind` class for free! Namely, we get the `getAFlag` predicate that gets all flags that are used to guard a node.
```ql
private Guard getAnUnsafeHostnameVerifierFlagGuard() {
  result = any(UnsafeHostnameVerificationFlag flag).getAFlag().asExpr()
}
```

This completes the implementation of `isNodeGuardedByFlag` and allows us to heavily reduce false-positives!

## Conclusion
In this post I showed how to find multiple CVEs in the usage of the Java `TrustManager` and `HostnameVerifier` classes using CodeQL.

I did this by using a data flow query that finds all cases where an insecure `TrustManager` or an all-accepting `HostnameVerifier` is used.

Many -- if not most -- problems can be viewed as data flow/taint tracking problems and CodeQL is a great tool to solve these problems!