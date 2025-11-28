---
layout: isl-research-post
title: "What to Do When Creating Your CodeQL Database Fails – and How to Report the Perfect Reproducer Using cvise"
excerpt: "How to debug CodeQL database creation failures, identify the root cause from build-tracer logs, and create minimal reproducers using cvise."
---

# What to Do When Creating Your CodeQL Database Fails – and How to Report the Perfect Reproducer Using cvise

Recently, a colleague was trying to create a CodeQL database for a specific version of the [monad project](https://github.com/category-labs/monad/) to perform some security analysis. 

Everything seemed to work fine during the database creation process. The build succeeded, CodeQL didn't report any errors, and the database was created successfully.

However, when trying to query the database, something was clearly wrong.

## The Problem

My colleague wanted to find a specific class in the database. Even a simple query to select everything that has a location in a specific folder failed to return any results:

```ql
import cpp

from Element e
where e.getLocation().getFile().getAbsolutePath().matches("%transaction%")
select e
```

This should have returned a few results, but instead returned **nothing**. Something was clearly broken with the database.

## Looking at the Build Tracer Log

When CodeQL database creation fails silently like this, the first thing to check is the build tracer log. This log contains detailed information about what happened during the build process and can reveal issues that aren't immediately obvious.

The build tracer log is located at `$DB/log/build-tracer.log` inside your CodeQL database directory.

If we open this file and scroll through it, we notice something alarming: **many "catastrophic errors"**.

```
[T 00:45:26 93] CodeQL CLI version 2.23.2
[T 00:45:26 93] Initializing tracer.
...
64 errors and 1 catastrophic error detected in the compilation of "/app/monad/category/execution/ethereum/core/transaction.cpp".
```

The log shows many traced compilations, but also 129 catastrophic errors detected during compilation!
If a compilation unit fails catastrophically, the extractor cannot extract any information from it, which explains why our queries returned no results.

To find what caused the catastrophic error, we need to scroll up a bit from where we see the catastrophic failures and look for actual error messages.

## Finding the Root Cause

After scrolling through the build tracer log, we eventually find error messages that look like this:

```
error: assertion failed at: "decls.c", line 18401 in add_src_seq_end_of_variable_if_needed
```

This is the smoking gun! The CodeQL C/C++ extractor is hitting an internal assertion failure when processing certain source files[^codeql-extractor]. When this happens, the extractor fails to extract any information from that compilation unit, which explains why our queries returned no results.

[^codeql-extractor]: Why does this only happen when CodeQL "compiles" the code? The CodeQL C/C++ extractor intercepts the compilation process to extract additional information about the command line, macros, types, and so on. During this process, it runs its own compiler frontend that is based on [EDG](https://www.edg.com/c). This frontend is separate from the actual compiler used to build the code (e.g., Clang or GCC) and can have its own bugs and limitations. So even if the original code compiles fine with Clang or GCC, the CodeQL extractor might still hit bugs in its own frontend!

The error points to a specific file (`decls.c`) and line number (18401) in the CodeQL extractor's internal code where an assertion failed. While we can't fix the extractor directly, we can create a minimal reproducer to report the bug to the CodeQL team.

## Creating a Minimal Reproducer with cvise

When reporting bugs to the CodeQL team (or any compiler/static analysis tool team), providing a minimal reproducer is incredibly valuable. Instead of asking them to clone and build the entire monad project, we can use a tool called [cvise](https://github.com/marxin/cvise) (or its predecessor, C-Reduce) to automatically reduce our failing test case to a minimal example.

### What Is cvise?

[cvise](https://github.com/marxin/cvise/) is a tool for reducing C/C++ programs. It takes a large program that triggers a bug and automatically removes code while ensuring the bug still reproduces. The result is a minimal test case that's much easier to understand and debug.

I cannot recommend `cvise` enough for this purpose - it saved me hours of manual reduction work!
**Whether you're dealing with compiler crashes, static analysis tool bugs, or any other C/C++ code issues, `cvise` is an invaluable tool in your debugging arsenal.**
In many cases, it even works pretty well for non-C/C++ languages, such as JavaScript or Java, by treating them as plain text files and applying similar reduction strategies!

### Setting Up the Interestingness Test

To use `cvise`, we need to create an "interestingness test" - a script that returns 0 (success) if the bug reproduces and non-zero (failure) if it doesn't.

Here's the interestingness test script we'll use:

```bash
#!/bin/bash

set -e

cleanup() {
    rm -rf "$mytmpdir"
}
trap cleanup EXIT

mytmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t 'mytmpdir')
codeql database create "$mytmpdir" --language=cpp --command="/usr/lib/llvm-19/bin/clang -std=gnu++23 -c minimal.cpp" --overwrite
cat "$mytmpdir/log/build-tracer.log" | grep 'error: assertion failed at: "decls.c", line 18401 in add_src_seq_end_of_variable_if_needed'
status=$?
exit $status
```

This script:
1. Creates a temporary directory for the CodeQL database
2. Tries to create a CodeQL database by compiling `minimal.cpp` with the same compiler and flags used in the original build
3. Searches the build tracer log for our specific error message
4. Returns 0 (success) if the error is found, non-zero (failure) if it's not
5. Cleans up the temporary directory when done

### Finding the Failing Source File

Before we can run `cvise`, we need to identify which source file is causing the problem. We can grep through the build tracer log for the error message and look at the preceding compilation commands to find the problematic file.

Once we've identified the file, we copy it to `minimal.cpp` and verify that our interestingness test works:

```bash
cp /path/to/monad/consensus/problematic_file.cpp minimal.cpp
chmod +x test.sh
./test.sh
echo $?  # should print 0
```

In our case, the log shows that the problematic file is from the GNU C++ standard library header `alloc_traits.h`, so we copy that file into `minimal.cpp`.

```
CodeQL C++ extractor: Current location: /app/monad/category/vm/core/assert.cpp:62055,3
CodeQL C++ extractor: Current physical location: /usr/lib/gcc/x86_64-linux-gnu/15/../../../../include/c++/15/bits/alloc_traits.h:146,3
"/usr/lib/gcc/x86_64-linux-gnu/15/../../../../include/c++/15/bits/alloc_traits.h", line 146: internal error: assertion failed at: "decls.c", line 18401 in add_src_seq_end_of_variable_if_needed

  	};
  	 ^
```

### Running cvise

Now we can run `cvise` to reduce the file:

```bash
cvise --n 8 test.sh minimal.cpp
```

The `--n 8` flag tells cvise to use 8 parallel processes to speed up the reduction.

`cvise` will now automatically try removing various parts of the code - functions, statements, expressions, type qualifiers, and more - while continuously checking that the bug still reproduces. This process can take anywhere from a few minutes to several hours depending on the size of the original file.

### What cvise Does

During the reduction process, `cvise` will:
1. Try removing entire functions
2. Try removing statements and expressions
3. Try simplifying complex expressions
4. Try removing template parameters and type qualifiers
5. Try renaming identifiers to simpler names
6. Try many other transformations

At each step, it runs our interestingness test to verify the bug still reproduces. If a transformation causes the bug to disappear, it's reverted. If the bug still reproduces, the transformation is kept.

### The Final Result

After `cvise` finishes, we'll have a `minimal.cpp` file that might look something like this:

```cpp
struct __allocator_traits_base {
  template < typename >
  static constexpr int __can_construct_at{
# 1
  };
};
```

This is much simpler than the original thousands of lines of code, but it still triggers the same assertion failure in the CodeQL extractor!

## Reporting the Bug

Now that we have a minimal reproducer, we can create a bug report for the CodeQL team. The report should include:

1. **Description**: A clear description of the problem ("CodeQL C/C++ extractor crashes with assertion failure on this code")
2. **CodeQL version**: The version where the bug occurs (e.g., "CodeQL CLI version 2.23.2")
3. **Minimal reproducer**: The reduced `minimal.cpp` file
4. **Command to reproduce**: The exact command that triggers the bug
5. **Expected behavior**: What should happen ("The code should be extracted successfully")
6. **Actual behavior**: What actually happens ("Assertion failure: error: assertion failed at: 'decls.c', line 18401")

With this information, the CodeQL team can quickly reproduce the issue, debug it, and create a fix.

## Conclusion

When CodeQL database creation appears to succeed but queries return no results:

1. Check the **build tracer log** at `codeql-db/log/build-tracer.log`
2. Look for error messages and assertion failures
3. Identify the failing source file(s)
4. Use **cvise** to create a minimal reproducer
5. Report the bug with all relevant details

By following this process, you can turn a frustrating debugging experience into a valuable bug report that helps improve CodeQL for everyone.

The bug has been fixed after just 9 days and released in [CodeQL CLI version 2.23.5](https://github.com/github/codeql-cli-binaries/releases/tag/v2.23.5)!

### Appendix: Dockerfile for Reproducing the Issue

```Dockerfile
# syntax=docker/dockerfile:1-labs

FROM ubuntu:25.04 AS base

RUN apt update && apt upgrade -y

RUN apt update && apt install -y apt-utils

RUN apt update && apt install -y dialog

RUN apt update && apt install -y \
    ca-certificates \
    curl \
    gnupg \
    software-properties-common \
    wget \
    git

RUN apt update && apt install -y \
    clang-19 \
    gcc-15 \
    g++-15

RUN apt update && apt install -y \
    libarchive-dev \
    libbrotli-dev \
    libcap-dev \
    libcli11-dev \
    libgmp-dev \
    libtbb-dev \
    libzstd-dev

RUN git clone https://github.com/category-labs/monad/ /monad && \
cd monad && git checkout 3f1f0063468e04f48ff068d388167af1c4ab5635 && \
cp /monad/scripts/ubuntu-build/* /opt/ && rm -rf /monad


RUN /opt/install-boost.sh
RUN /opt/install-tools.sh
RUN /opt/install-deps.sh


FROM base AS codeql

WORKDIR /app

RUN apt install -y unzip libstdc++-15-dev
# Change to v2.23.5 (fixed) or v.23.3 (broken) to test different versions
RUN curl -LO "https://github.com/github/codeql-cli-binaries/releases/download/v2.23.3/codeql-linux64.zip"
RUN unzip codeql-linux64.zip && rm codeql-linux64.zip

ENV PATH="/app/codeql:$PATH"
ENV ASMFLAGS=-march=haswell
ENV CFLAGS=-march=haswell
ENV CXXFLAGS=-march=haswell


RUN git clone --recursive https://github.com/category-labs/monad/ && cd monad && git checkout 3f1f0063468e04f48ff068d388167af1c4ab5635 && mkdir build
WORKDIR /app/monad

RUN cmake -S . -B build/ -DCMAKE_C_COMPILER=/usr/bin/clang-19 -DCMAKE_CXX_COMPILER=/usr/bin/clang++-19
RUN codeql database create codeql-db/ --language=cpp --command="cmake --build build/ --target monad -- -j" --overwrite
```