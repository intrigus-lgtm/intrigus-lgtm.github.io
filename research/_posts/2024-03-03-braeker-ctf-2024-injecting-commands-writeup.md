---
layout: isl-research-post
title: "BraekerCTF 2024 – Injecting Commands – Writeup"
excerpt: "How to reverse engineer a Mach-O binary from BraekerCTF 2024 that breaks all tools."
---

# BraekerCTF 2024 – Injecting Commands – Writeup

_TLDR: Hidden code in Mach-O load commands and a bit of anti-debugging._ \
400 points and 2 solves. \
Flag: `brck{Y0U_M4cho_C0mm4ndr}`.

For this challenge, we are given a single extensionless file `command_injection`.
If we run `file` on it, we quickly realize that it is a Mach-O binary:

```shell
$ file command_injection
command_injection: Mach-O 64-bit x86_64 executable, flags:<NOUNDEFS>
```

## Analyzing the Binary in Ghidra

We are given a binary, so we can just open it in Ghidra and see what it does, right?

Right?

Well, not quite.

When we import the binary as a Mach-O binary in Ghidra, we are greeted with this message:

```java
Attempted to read string at 0xfffffffff050f826
java.io.EOFException: Attempted to read string at 0xfffffffff050f826
	at ghidra.app.util.bin.BinaryReader.readUntilNullTerm(BinaryReader.java:716)
	at ghidra.app.util.bin.BinaryReader.readString(BinaryReader.java:874)
	at ghidra.app.util.bin.BinaryReader.readAsciiString(BinaryReader.java:759)
	at ghidra.app.util.bin.format.macho.commands.LoadCommandString.<init>(LoadCommandString.java:37)
	at ghidra.app.util.bin.format.macho.commands.SubFrameworkCommand.<init>(SubFrameworkCommand.java:39)
	at ghidra.app.util.bin.format.macho.commands.LoadCommandFactory.getLoadCommand(LoadCommandFactory.java:90)
	at ghidra.app.util.bin.format.macho.MachHeader.parse(MachHeader.java:188)
	at ghidra.app.util.bin.format.macho.MachHeader.parse(MachHeader.java:150)
	at ghidra.app.util.opinion.MachoProgramBuilder.build(MachoProgramBuilder.java:118)
	at ghidra.app.util.opinion.MachoProgramBuilder.buildProgram(MachoProgramBuilder.java:110)
	at ghidra.app.util.opinion.MachoLoader.load(MachoLoader.java:90)
	at ghidra.app.util.opinion.AbstractLibrarySupportLoader.doLoad(AbstractLibrarySupportLoader.java:883)
	at ghidra.app.util.opinion.AbstractLibrarySupportLoader.loadProgram(AbstractLibrarySupportLoader.java:98)
	at ghidra.app.util.opinion.AbstractProgramLoader.load(AbstractProgramLoader.java:131)
	at ghidra.plugin.importer.ImporterUtilities.importSingleFile(ImporterUtilities.java:395)
	at ghidra.plugin.importer.ImporterDialog.lambda$okCallback$7(ImporterDialog.java:336)
	at ghidra.util.task.TaskBuilder$TaskBuilderTask.run(TaskBuilder.java:306)
	at ghidra.util.task.Task.monitoredRun(Task.java:134)
	at ghidra.util.task.TaskRunner.lambda$startTaskThread$0(TaskRunner.java:106)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1136)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:635)
	at java.base/java.lang.Thread.run(Thread.java:840)
```

:/

We can still import the binary as a raw binary, but we won't get any symbols or function names and if we try to auto-analyze it, Ghidra will crash with the same exception.

## Analyzing the Binary in ImHex

What do we do when Ghidra fails us? We turn to a lower-level tool: ImHex.
Luckily, ImHex already has a Mach-O pattern, so we can just open the binary and start analyzing it, right?

Right?

Well, not quite.

When we open the binary in ImHex, we are greeted with this message:
![Array expanded past end of data.](/assets/images/brakerctf-24_imhex_macho_error.png "ImHex error message")

:/

While ImHex has an inbuilt debugger, I just uncommented the problematic pattern definition and reanalyzed the binary.
If we then look at the very first load command of type `Command::UUID`, we can see that the `uuid` field is not a valid UUID:
![The value of commandSize is 0x32.](/assets/images/brakerctf-24_imhex_uuid.png "Invalid UUID")

Normally, the `Command::UUID` consists of a 4-byte `command` field, a 4-byte `commandSize` field, and a 16-byte `uuid` field, so the `commandSize` should be 4 + 4 + 16 = 0x18, but it is 0x32.

ImHex only expects 0x18 bytes for the `Command::UUID` and then tries to parse the next load command, but the next load command is not at the expected offset.

We can easily fix this by changing the pattern definition from

```cpp
if (command == Command::UUID)
  CommandUUID data;
```

to

```cpp
if (command == Command::UUID) {
  CommandUUID data;
  u8 ignored[commandSize - 8 - sizeof(CommandUUID)] [[sealed]];
}
```

If we now look at the load commands in the "Pattern Data" view, we can see that the next command --- `Command::Segment64` is now parsed correctly:
![The parsed __PAGEZERO segment that has unusual values.](/assets/images/brakerctf-24_imhex_pagezero.png "__PAGEZERO segment in ImHex")

It is a `__PAGEZERO` segment that maps 3956 bytes starting at file offset 0x0 to virtual address 0x1000 with `r-x` permissions.
This is unusual, as `__PAGEZERO` is normally used to map the zero page [^pagezero], which is not executable and not writable.
With this information, we can now adjust the base address of the binary in both Ghidra and ImHex to 0x1000.

[^pagezero]: See this [Stack Overflow answer](https://apple.stackexchange.com/questions/435462/why-is-pagezero-missing-from-vmmap-output-at-darwin-21-2-0/435478#435478) for more information.

All other segments map exactly zero bytes, so they are not interesting.

However, we still don't know where the entry point is, so we can't start analyzing the binary.
As I write this, I **now** understand, that the entry point is determined by the `LC_UNIXTHREAD` command [^lc_main].
The `LC_UNIXTHREAD` command contains the full register state of the thread that is started when the binary is executed, including the instruction pointer (RIP) register, which points to the entry point of the binary.

[^lc_main]: Newer binaries use the `LC_MAIN` load command, which is not present in this binary.

As I had no way to run macOS binaries, I decided to (ab)use the macOS GitHub Actions runners to run the binary and see what it does :D

## (Ab)using macOS GitHub Actions Runners for Analysis

We create a new repository and add a new workflow file that uses the [mxschmitt/action-tmate](https://github.com/mxschmitt/action-tmate) action.

This action starts a new tmate session and prints the SSH connection string to the log.
We can then connect to the runner and add the binary by for example base64 decoding it.

After connecting to the runner, we can run the binary and see what it does.

```shell
$ ./command_injection
😕
```

Okay, now that we have a macOS runner, we can also use the `otool` command to analyze the binary.

```shell
$ otool -l command_injection
[...]
Load command 5
        cmd LC_UNIXTHREAD
    cmdsize 184
     flavor x86_THREAD_STATE64
      count x86_THREAD_STATE64_COUNT
   rax  0x000000000200001a rbx 0x0000000000000000 rcx  0x0000000000000000
   rdx  0x0000000000000000 rdi 0x000000000000001f rsi  0x0000000000000000
   rbp  0x0000000000000000 rsp 0x0000000000000000 r8   0x0000000000000000
    r9  0x0000000000000000 r10 0x0000000000000000 r11  0x0000000000000000
   r12  0x0000000000000000 r13 0x0000000000000000 r14  0x0000000000000000
   r15  0x0000000000000000 rip 0x00000000000017bd
rflags  0x0000000000000000 cs  0x0000000000000000 fs   0x0000000000000000
    gs  0x0000000000000000
[...]
```

So `0x00000000000017bd` is the entry point of the binary. However, I didn't know at the time that the entry point is determined by `LC_UNIXTHREAD`.

So I tried to debug the binary with `lldb`:

```shell
$ lldb
(lldb) process launch --stop-at-entry -- command_injection
Process 5805 stopped
* thread #1, stop reason = signal SIGSTOP
    frame #0: 0x00000000000017bd command_injection
->  0x17bd: syscall
```

The binary stops at the entry point 🎉
However, it immediately exists when stepping over the `syscall` instruction.

```shell
Process 5805 exited with status = 45 (0x0000002d)
```

If we google for `exited with status = 45 (0x0000002d)` we find that this is an anti-debugging feature that is based on the [ptrace system call](https://cardaci.xyz/blog/2018/02/12/a-macos-anti-debug-technique-using-ptrace/) [^initial_registers].

[^initial_registers]: `ptrace` is called, because `rax` is set to `0x1a` in the initial register state.

We can easily bypass this by adjusting the entry point to the next instruction after the `syscall` instruction.

Now we can analyze the binary in `lldb` and all should be good, right?

Not really, tmate/tmux is painful-ish to use and I am not familiar with `lldb` and I didn't want to learn it right now.

Instead, I figured that just emulating the binary with Unicorn would be easier and give me more control and insight into the binary.

## Emulating the Binary with Unicorn

Unicorn is a lightweight multi-platform, multi-architecture CPU emulator framework.
It is very easy to use and has a Python binding, so we can easily write a script that emulates the binary and prints the instructions and register values.

However, we have to load the binary into memory and set up the initial register state ourselves, as we don't have a loader that does this for us.

We set the entry point to `0x17bd + 2` because we want to skip the anti-debugging feature and the other registers to the values from the `LC_UNIXTHREAD` command.
Additionally, we have to set up the stack and the `argv[0]` variable.

The flag input is stored in `argv[0]`, so we just let it point to an empty string.

Also, we add hooks for tracing all instructions and memory accesses, so we can see what the binary does as well as a hook for all `cmp` instructions.

The `cmp` instructions are used to check whether the flag is correct, by comparing the value in `rax` with the value in `rdi`.
The value of `rax` is `rax ^ rcx`, so if we want to know the correct flag, we just have to XOR the value in `rdi` with the value in `rcx`.

If we run the script once, we get the flag part `brck{Y0U`. If we add this to the flag input, and run the script again, we get the next part `_M4cho_C`. If we repeat this once more, we get the full flag:

```shell
brck{Y0U_M4cho_C0mm4ndr}
```

### Python Source Code

{% raw  %}

```python
from unicorn import *
from unicorn.x86_const import *

from capstone import *
from capstone.x86 import *

# Initialize capstone disassembler
md = Cs(CS_ARCH_X86, CS_MODE_64)

from pwn import *

context.arch = "amd64"

# Memory address where emulation starts
ADDRESS = 0x1000
START_ADDRESS = 0x00000000000017BD + 2
STACK_START_ADDRESS = 0x7FFF_FF00_0000
STACK_SIZE = 1024 * 1024
STACK_END_ADDRESS = STACK_START_ADDRESS + STACK_SIZE
STACK_ADDRESS = STACK_START_ADDRESS + STACK_SIZE // 2

# Load binary
with open("command_injection_orig", "rb") as f:
    binary = f.read()

# Initialize emulator in X86-64 mode
mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map 2MB memory for this emulation
mu.mem_map(ADDRESS, 2 * 1024 * 1024)

# Write binary to memory
mu.mem_write(ADDRESS, binary)

# Map 1MB stack memory
mu.mem_map(STACK_START_ADDRESS, STACK_SIZE)

# Initialize stack pointer
mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS)
# Initialize argv[0]
argv0 = [b""] # flag input
argv0.append(b"\x00")  # Null-terminate the argv[0] list

# Write argv[0] to memory
argv_address = STACK_END_ADDRESS - 128 * 8  # Allocate space for argv on the stack
mu.mem_write(argv_address, argv0[0])
mu.mem_write(argv_address + len(argv0[0]), b"\x00")

mu.mem_write(
    STACK_ADDRESS + 0x8, p64(argv_address)
)  # Write the address of argv[0] to the stack

# Initialize registers
mu.reg_write(UC_X86_REG_RAX, 0x000000000200001A)
mu.reg_write(UC_X86_REG_RBX, 0x0000000000000000)
mu.reg_write(UC_X86_REG_RCX, 0x0000000000000000)
mu.reg_write(UC_X86_REG_RDX, 0x0000000000000000)
mu.reg_write(UC_X86_REG_RDI, 0x000000000000001F)
mu.reg_write(UC_X86_REG_RSI, 0x0000000000000000)
mu.reg_write(UC_X86_REG_RBP, 0x0000000000000000)
# mu.reg_write(UC_X86_REG_RSP, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R8, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R9, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R10, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R11, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R12, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R13, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R14, 0x0000000000000000)
mu.reg_write(UC_X86_REG_R15, 0x0000000000000000)
mu.reg_write(UC_X86_REG_RIP, START_ADDRESS)


# Tracing all instructions with customized callback
def hook_code(uc, address, size, user_data):
    print(">>>")
    instruction = mu.mem_read(address, size)
    dis = disasm(instruction, vma=address)
    print(f"0x{address:#x}: {dis}")
    r10 = mu.reg_read(UC_X86_REG_R10)
    rsp = mu.reg_read(UC_X86_REG_RSP)
    rax = mu.reg_read(UC_X86_REG_RAX)
    rcx = mu.reg_read(UC_X86_REG_RCX)
    rdi = mu.reg_read(UC_X86_REG_RDI)
    print(f"r10: {r10:#x}, rsp: {rsp:#x}, rax: {rax:#x}, rcx: {rcx:#x}, rdi: {rdi:#x}")
    if address == 0x19BE:
        print(">>> Stopping emulation")
        mu.emu_stop()
    if "cmp" in dis and rax != rdi:
        print(">>> Stopping emulation")
        print(p64(rdi^rcx))
        mu.emu_stop()

mu.hook_add(UC_HOOK_CODE, hook_code)


# Tracing all memory READ & WRITE
def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(
            f">>> Memory is being WRITTEN at {address:#x}, data size = {size}, data value = {value:#x} ({p64(value)})"
        )
    else:  # READ
        print(
            f">>> Memory is being READ at {address:#x}, data size = {size}, data value = {value:#x} ({(mu.mem_read(address, size))})"
        )


mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

# Emulate code in infinite time & unlimited instructions
mu.emu_start(START_ADDRESS, ADDRESS + len(binary))

```

{% endraw  %}
