---
layout: isl-research-post
title: "Fixing Decompilation of Stack Clash Protected Binaries"
excerpt: "How to fix decompilation when everything looks ugly, because stack probing breaks stack pointer tracking."
---

# Fixing Decompilation of Stack Clash Protected Binaries

I was playing DEFCON CTF Quals 2025 with (KITCTF⊂Sauercloud) and I looked into the `callmerust` challenge.
The actual challenge is not relevant for this post, but when opening the binary in Ghidra (or binja) [^ida], I was greeted with some very ugly decompilation output.

[^ida]: Only IDA tracks the stack pointer correctly, but it has different issues with for example strings (see the binary in [dogbolt](https://dogbolt.org/?id=2968ec50-148d-4fc8-b51e-5888de471e7d#BinaryNinja=593&Hex-Rays=454&Ghidra=619)).

The decompilation output looks ugly, because Ghidra is unable to track the stack pointer correctly.
This is because the binary is compiled with `-fstack-check` (or similar), which adds stack probing code to the binary.

Luckily, there is a very simple fix for this issue.

## What is Stack Probing and Why is it Necessary?

On Linux, the stack grows automatically when more stack space is needed.
This is done by allocating a guard page at the start of the stack, which is a page of memory that is not accessible to the program.
When the program tries to access this page, it will cause a segmentation fault, which causes the kernel to grow the stack by allocating a new page of memory.

However, this automatic expansion can lead to a stack clash attack, where an attacker can exploit the fact that the stack grows downwards and the heap grows upwards.
This can lead to a situation where the stack and heap collide, leading to a stack overflow or heap corruption.

All an attacker needs to do is to "jump" over the guard page (usually `0x1000` bytes), that is, move the stack pointer to a location that is below the guard page without reading/writing it.

To prevent this, the compiler adds stack probing code to the binary, which probes the stack before moving the stack pointer by more than `0x1000` bytes. This ensures that the guard page cannot be jumped over.

For a deeper dive into stack clash vulnerabilities and mitigations, you can refer to the [Qualys blog post on Stack Clash](https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt).

## The Problem
The problem with stack probing is that it breaks the stack pointer tracking in Ghidra (and binja).

Let's consider a very simple example:

```cpp
#include <stdio.h>

struct bar
{
    int a;
    int b;
    long long c;
};

int main()
{
    char foao[0x5000];
    int foo = 22;
    struct bar bar = {1, 23, 4};
    int z3 = foo + bar.b;
    puts("Hello");
    printf("z3: %d", z3);
}
```
This code is very simple, but it has a stack probe in it. The stack probe is added because the stack frame is larger than `0x1000` bytes (the size of the guard page).

When compiled with `-fstack-check`, the compiler will add a stack probe to the binary.

When opening the binary in Ghidra, we can see that the stack pointer tracking is broken.
The stack pointer is not tracked correctly, and the decompilation output is very ugly (notice the `(puVar2 + -0x28) = ...` in the decompilation output):

```c
undefined8 main(void)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  ulong uVar3;
  undefined1 local_6008 [4064];
  undefined4 local_5028;
  undefined4 local_5024;
  undefined8 local_5020;
  uint local_10;
  undefined4 local_c;
  
  puVar1 = &stack0xfffffffffffffff8;
  do {
    puVar2 = puVar1;
    *(undefined8 *)(puVar2 + -0x1000) = *(undefined8 *)(puVar2 + -0x1000);
    puVar1 = puVar2 + -0x1000;
  } while (puVar2 + -0x1000 != local_6008);
  *(undefined8 *)(puVar2 + -0x1040) = *(undefined8 *)(puVar2 + -0x1040);
  local_c = 0x16;
  local_5028 = 1;
  local_5024 = 0x17;
  local_5020 = 4;
  local_10 = 0x2d;
  *(undefined8 *)(puVar2 + -0x28) = 0x1011b9;
  puts("Hello");
  uVar3 = (ulong)local_10;
  *(undefined8 *)(puVar2 + -0x28) = 0x1011d2;
  printf("z3: %d",uVar3);
  return 0;
}
```

The stack probing code looks like this:

```asm
0000000000001149 <main>:
    1149:	55                   	push   rbp
    114a:	48 89 e5             	mov    rbp,rsp
    114d:	4c 8d 9c 24 00 a0 ff 	lea    r11,[rsp-0x6000]
    1154:	ff 
    1155:	48 81 ec 00 10 00 00 	sub    rsp,0x1000 <-- change stack pointer
    115c:	48 83 0c 24 00       	or     QWORD PTR [rsp],0x0 <-- stack probe
    1161:	4c 39 dc             	cmp    rsp,r11
    1164:	75 ef                	jne    1155 <main+0xc> <--loop
```

**Ghidra is likely unable to track the stack pointer correctly, because the stack pointer is moved in a loop.**
(I have opened an issue on the Ghidra GitHub repository [^ghidra_issue] and Binary Ninja GitHub repository [^binja_issue])

[^ghidra_issue]: [https://github.com/NationalSecurityAgency/ghidra/issues/8017](https://github.com/NationalSecurityAgency/ghidra/issues/8017)
[^binja_issue]: [https://github.com/Vector35/binaryninja-api/issues/6659](https://github.com/Vector35/binaryninja-api/issues/6659)

## The Fix
The fix for this issue is very simple. We just have to apply some manual analysis and patch a few instructions in the binary.

Patching in Ghidra is very simple. We can just right-click on the instruction and select "Patch Instruction" and watch the Ghidra dragon munch some bytes while constructing the assembler 😂

<img src="/assets/images/stack_clash_post_2025_ghidra_munching.png" alt="The Ghidra dragon munching bits" width="400"/>

To improve the decompilation, we can replace the `sub    rsp,0x1000` (in the stack probing code) simply with a `sub    rsp,0x6000` instruction, because that is what the loop does in the end.

Then we only have to replace the loop instruction (`jne 1155 <main+0xc>`) with a `nop` instruction, because the loop is not necessary anymore.
This is a very simple fix, but it makes the decompilation output much better!

When opening the patched binary in Ghidra, we can see that the stack pointer tracking is now correct and the decompilation output is much better:

```c
undefined8 main(void)

{
  puts("Hello");
  printf("z3: %d",0x2d);
  return 0;
}
```

So by manually patching the binary to simplify stack pointer adjustments and removing unnecessary loops, we can significantly improve the clarity of the decompiled code until this issue is fixed in Ghidra.
