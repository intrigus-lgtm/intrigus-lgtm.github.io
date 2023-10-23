---
layout: isl-research-post
title: "Cyber Security Rumble Finals CTF 2023 – elkcip – Writeup"
excerpt: "In this post, I'm going to show how to solve elkcip from Cyber Security Rumble Finals CTF 2023 and why SMT/SAT solver choice matters."
---

# Cyber Security Rumble Finals CTF 2023 – elkcip – Writeup
> Please reverse this simple¹ flag checker implemented in 8 lines² of Python³ code.

*TLDR: Flag checker implemented in the Python pickle VM using NAND gates. The gates define 128 equations over 128 variables which can be solved using sage.* \
*Depending on the SMT/SAT solver used, this challenge can be solved in a few minutes or not at all!* \
500 base points + 438 dynamic scoring points and 2 solves. \
Flag: `CSR{you_solved!}`.

For this challenge, we are given a Python `chall.py` script and a `code.pickle` object.

## Analyzing the Python Script
The Python script takes 16 flag bytes, combines them with a header (`b"C\x10"`) and the pickle bytes and then uses the `pickle` module to load the pickle object. \
If the result is `truthy` (`True`, or `1`, or ...), the flag is correct.

```python
#!/usr/bin/env python3

import pickle

flag = input("Flag: ").encode().ljust(16)[:16]

with open("code.pickle", "rb") as f:
    code = f.read()

if pickle.loads(b"C\x10" + flag + code):
    print("Correct")
else:
    print("Wrong")
```

## What is a Pickle Object? What is the Pickle VM?
The `pickle` _module_ is part of the Python standard library and allows serializing and deserializing Python objects. To do this, it defines a **pickle protocol** that is used to serialize and deserialize Python objects [^1].

[^1]: There are multiple protocols that evolved over time. The latest protocol is version 5, which was introduced in Python 3.8. The pickle protocol is documented in the [pickle](https://docs.python.org/3/library/pickle.html#data-stream-format) module documentation.

A pickle _object_ is a sequence of bytes that is executed by a "pickle machine" (PM).
The PM is a very simple machine:
> there are no looping, testing, or conditional instructions, no arithmetic and no function calls. Opcodes are executed once each, from first to last, until a `STOP` opcode is reached [^2].

The result of the execution -- the unpickled value -- is the value that is left on the stack after the `STOP` opcode is executed.

[^2]: More information about the [PM](https://github.com/python/cpython/blob/481aa7a40fdc43c18e1be210dbe21c6f227ee339/Lib/pickletools.py#L38-L89) and more information about the [available instructions](https://github.com/python/cpython/blob/481aa7a40fdc43c18e1be210dbe21c6f227ee339/Lib/pickle.py#L101-L189).


## Analyzing the Pickle Object Using pickletools
To analyze the pickle object, we can use the `pickletools` module, which is part of the standard library.
```python
import pickletools
with open("code.pickle", "rb") as f:
    code = f.read()
flag = b'CSR{ABCD_EFGH_I}' # 16 bytes

final_code = b"C\x10" + flag + code
open("final_code.pickle", "wb").write(final_code) # save for later use

print(pickletools.dis(final_code))
```

Unfortunately, `pickletools` crashes:
```python
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.11/pickletools.py", line 2531, in dis
    raise ValueError(errormsg)
ValueError: memo key 4 already defined
```

**Instead of using `pickletools.dis` we could have used `pickletoos.genops` to get the opcodes, but I wasn't aware of that at the time.** Also, the output of `pickletoos.genops` is harder to read than the output of the next tool.

## Analyzing the Pickle Object Using fickling
Luckily, one of my teammates ([Liam Wachter](https://wachter-space.de)) remembered a tool from Trail of Bits called [fickling](https://github.com/trailofbits/fickling) that can be used to analyze pickle objects.
```bash
$ pip install fickling && fickling final_code.pickle
```
However, this **also** crashes:
```python
Traceback (most recent call last):
  [...]
  File "fickling/pickle.py", line 135, in __new__
    raise NotImplementedError(f"TODO: Add support for Opcode {info.name}")
NotImplementedError: TODO: Add support for Opcode SHORT_BINSTRING
```

To me, a `NotImplementedError` sounded easier to fix than a `ValueError`, so I decided to fix this issue.

### Bugfixing fickling -- SHORT_BINSTRING
By looking at the source code of fickling we can find a definition for `SHORT_BINBYTES` [^3].
```python
class ShortBinBytes(DynamicLength, ConstantOpcode):
    name = "SHORT_BINBYTES"
    priority = Unicode.priority + 1
    length_bytes = 1

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, bytes):
            raise ValueError(
                f"{cls.__name__} must be instantiated with an object of type bytes, not {obj!r}"
            )
        return super().validate(obj)
```
and `STRING` [^4]:
```python
class String(ConstantOpcode):
    name = "STRING"
    priority = Unicode.priority + 1

    def encode_body(self) -> bytes:
        return repr(self.arg).encode("utf-8")

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, str):
            raise ValueError(f"String must be instantiated from a str, not {obj!r}")
        return obj
```

[^3]: [Source](https://github.com/trailofbits/fickling/blob/b5debefd189310218f24904377207ef25003ce38/fickling/pickle.py#L1350-L1361)
[^4]: [Source](https://github.com/trailofbits/fickling/blob/b5debefd189310218f24904377207ef25003ce38/fickling/pickle.py#L1077-L1088)

By combining parts of the two, we arrive at this definition for `SHORT_BINSTRING`:
```python
class ShortBinString(DynamicLength, ConstantOpcode):
    name = "SHORT_BINSTRING"
    priority = Unicode.priority + 1
    length_bytes = 1

    def encode_body(self) -> bytes:
        return repr(self.arg).encode("utf-8")

    @classmethod
    def validate(cls, obj):
        if not isinstance(obj, str):
            raise ValueError(f"String must be instantiated from a str, not {obj!r}")
        return obj
```

If we now run the command again, we get output that looks like this:
```python
_var0 = getattr({}, '__class__')
_var1 = getattr(_var0, '__getitem__')
# ...
_var279 = _var1({_var8: 1, _var8: 1, 0: 0}, 0)
_var280 = _var1({0: 1, 0: 1, 0: 0}, 0)
# Lots of lines similar to the next one follow
# _varFOOBAR = _var1({_varFOO: 1, _varBAR: 1, 0: 0}, 0)
```

`_var1` is the `__getitem__` method of the `dict` class.
So the code is basically doing this:
```python
_var279 = {}.__class__.__getitem__({_var8: 1, _var8: 1, 0: 0}, 0)
```
which is the same as this:
```python
_var279 = {_var8: 1, _var8: 1, 0: 0}[0]
```

If you are familiar with Python, you might notice that this is equivalent to this:
```python
_var279 = 0
```
This is because the last value of a key in a dictionary is the one that is used [^6].

[^6]: > If a key occurs more than once, the last value for that key becomes the corresponding value in the new dictionary. [Source](https://docs.python.org/3/library/stdtypes.html#mapping-types-dict).

So are all `_varFOOBAR` variables set to `0`? No, because this is another bug in `fickling`, the order of `dict` entries is wrong.
```python
_varFOOBAR = _var1({_varFOO: 1, _varBAR: 1, 0: 0}, 0)
# ^should really be this:
_varFOOBAR = _var1({0: 0, _varBAR: 1, _varFOO: 1}, 0)
```

Here is the PR that adds support for `SHORT_BINSTRING`: [trailofbits/fickling#68](https://github.com/trailofbits/fickling/pull/68).

### Bugfixing fickling -- Wrong Order of dict() Entries
How do we find the bug in `fickling`? We can enable tracing (`fickling --trace`) to find the instruction that builds the dictionary:
```bash
DICT
	Popped 1
	Popped _var8
	Popped 1
	Popped _var8
	Popped 0
	Popped 0
	Popped MARK
	Pushed {_var8: 1, _var8: 1, 0: 0}
```
If we cross-reference this with the documentation for the `DICT` opcode [^7], we can see that the order of the entries is wrong:
> Stack before: ... markobject 1 2 3 'abc' \
> Stack after:  ... {1: 2, 3: 'abc'}

[^7]: [Source](https://github.com/python/cpython/blob/481aa7a40fdc43c18e1be210dbe21c6f227ee339/Lib/pickletools.py#L1651-L1657)
In our case the stack looks like this:
> Stack before: ... markobject 0 0 _var8 1 _var8 1

And **should** look like this afterwards:
> Stack after:  ... {0: 0, _var8: 1, _var8: 1}

The fix is pretty easy, we just have to reverse the keys and values in the `fickling` `Dict` class [^8]:
```python
interpreter.stack.append(ast.Dict(keys=reversed(keys), values=reversed(values)))
# vs the original
interpreter.stack.append(ast.Dict(keys=keys, values=values))
```

[^8]: [Source](https://github.com/trailofbits/fickling/blob/b5debefd189310218f24904377207ef25003ce38/fickling/pickle.py#L1433)

Here is the PR that fixes the bug: [trailofbits/fickling#67](https://github.com/trailofbits/fickling/pull/67).

### Cleaning Up the Output
After fixing all these bugs, we can finally look at the output which I've split into three parts:
- initialization of variables
- flag bit extraction
- flag check

**Make sure to save the whole output to a file (for example `decompiled_code.py`), because we will need it later or use [my version]({{ "assets/files/elkcip/decompiled_code.py" | relative_url }}) as a reference.**

#### Raw Output
```python
# initialization of variables
_var0 = getattr({}, '__class__')
_var1 = getattr(_var0, '__getitem__')
_var2 = getattr(b'', '__class__')
_var3 = getattr(_var2, '__getitem__')
_var4 = getattr(0, '__class__')
_var5 = getattr(_var4, '__and__')
_var6 = getattr(_var4, '__rshift__')

# flag bit extraction
_var7 = _var3(b'CSR{ABCD_EFGH_I}', 0)
_var8 = _var5(_var7, 1)
_var9 = _var6(_var7, 1)
# ...

# flag check
_var279 = _var1({0: 0, _var8: 1, _var8: 1}, 0)
_var280 = _var1({0: 0, 0: 1, 0: 1}, 0)
# ...
result0 = _var50515
```
#### Initialization of Variables
```python
_var0 = getattr({}, '__class__')
_var1 = getattr(_var0, '__getitem__')
_var2 = getattr(b'', '__class__')
_var3 = getattr(_var2, '__getitem__')
_var4 = getattr(0, '__class__')
_var5 = getattr(_var4, '__and__')
_var6 = getattr(_var4, '__rshift__')
```

`_var1` allows us to get items from a dictionary, `_var3` allows us to get items from a bytes object, `_var5` allows us to do bitwise AND while `_var6` allows us to do bitwise right shift.

#### Flag Bit Extraction
```python
_var7 = _var3(b'CSR{ABCD_EFGH_I}', 0) # _var7 = b'CSR{ABCD_EFGH_I}'[0]
_var8 = _var5(_var7, 1)               # _var8 = _var7 & 1
_var9 = _var6(_var7, 1)               # _var9 = _var7 >> 1
_var10 = _var5(_var9, 1)              # _var10 = _var9 & 1
_var11 = _var6(_var9, 1)              # _var11 = _var9 >> 1
_var12 = _var5(_var11, 1)             # _var12 = _var11 & 1
```

`_var7` is the first byte of the flag, `_var8` is the first bit of the flag. \
`_var9` is the first byte of the flag shifted to the right, `_var10` is therefore the second bit of the flag, and so on. This is done for all 8 bits of all 16 bytes of the flag.

#### Flag Check -- Using dict() as NAND Gates
```python
_var279 = _var1({0: 0, _var8: 1, _var8: 1}, 0)     # _var279 = {0: 0, _var8: 1, _var8: 1}[0]
_var280 = _var1({0: 0, 0: 1, 0: 1}, 0)             # _var280 = {0: 0, 0: 1, 0: 1}[0]
_var281 = _var1({0: 0, _var280: 1, _var279: 1}, 0) # _var281 = {0: 0, _var280: 1, _var279: 1}[0]
_var282 = _var1({0: 0, _var8: 1, 0: 1}, 0)         # _var282 = {0: 0, _var8: 1, 0: 1}[0]
# lots of lines similar to the above follow
```

If we take a closer look at the code, we can see that the `dict` is actually used as a NAND gate 🤯.

Let's take a look at `_var281 = {0: 0, _var280: 1, _var279: 1}[0]`; we can create a truth table for this as the inputs are integers that can only be `0` or `1`:


| `_var279` | `_var280` | `_var281`/`result` |
| --------- | --------- | ------------------ |
| 0         | 0         | 1                  |
| 0         | 1         | 1                  |
| 1         | 0         | 1                  |
| 1         | 1         | 0                  |

Only if both `_var279` and `_var280` are `1`, `_var281` is `0`. Because then the `dict` will look like this: `{0: 0, 1: 1, 1: 1}` and getting the value for key `0` will return `0`.

We can further confirm that this is a NAND gate by looking at the Wikipedia page for [NAND gates](https://en.wikipedia.org/wiki/NAND_gate) and comparing the truth table with the one above.

#### Variable Cleanup
We can now start to clean up the code, by parsing the extracted python code as an AST and performing different transformations.
```python
# Load the code from a file
with open("decompiled_code.py", "rt") as file:
    code = file.read()

# Parse the code into an AST
ast_tree = ast.parse(code)

# Cleanup the AST
ast_tree = ReplaceVar1Visitor().visit(ast_tree)
ast_tree = CleanupAssignmentsVisitor().visit(ast_tree)
ast_tree = ReplaceAssignVisitor().visit(ast_tree)
ast_tree = ReplaceNameVisitor().visit(ast_tree)
```

`ReplaceVar1Visitor` first replaces all calls of the form `_var1({0: 0, _var280: 1, _var279: 1}, 0)` with `Nand(_var280, _var279)`. `CleanupAssignmentsVisitor` removes assignments that have become dead code and `ReplaceAssignVisitor` and `ReplaceNameVisitor` are used to replace `_varXXX` with `flag_{char_index}_{bit_index}` where appropriate.

Our code now looks much cleaner and we can reverse the NAND gates.
```python
# OLD CODE                                         # NEW CODE
_var0 = getattr({}, '__class__')                   #
_var1 = getattr(_var0, '__getitem__')              #
_var2 = getattr(b'', '__class__')                  #
_var3 = getattr(_var2, '__getitem__')              #
_var4 = getattr(0, '__class__')                    #
_var5 = getattr(_var4, '__and__')                  #
_var6 = getattr(_var4, '__rshift__')               #
_var7 = _var3(b'CSR{ABCD_EFGH_I}', 0)              # 
_var8 = _var5(_var7, 1)                            # flag_0_0 = Bool('flag_0_0')
_var9 = _var6(_var7, 1)                            # 
_var10 = _var5(_var9, 1)                           # flag_0_1 = Bool('flag_0_1')
_var11 = _var6(_var9, 1)                           # 
_var12 = _var5(_var11, 1)                          # flag_0_2 = Bool('flag_0_2')
# ...
_var279 = _var1({0: 0, _var8: 1, _var8: 1}, 0)     # _var279 = Nand(flag_0_0, flag_0_0)
_var280 = _var1({0: 0, 0: 1, 0: 1}, 0)             # _var280 = Nand(0, 0)
_var281 = _var1({0: 0, _var280: 1, _var279: 1}, 0) # _var281 = Nand(_var280, _var279)
_var282 = _var1({0: 0, _var8: 1, 0: 1}, 0)         # _var282 = Nand(flag_0_0, 0)
```

#### NAND Gates Cleanup
If we look closely at the code, we can spot a certain repeating pattern:
```python
_var285 = Nand(flag_0_1, flag_0_1)
_var286 = Nand(_var284, _var284)
_var287 = Nand(_var286, _var285)
_var288 = Nand(flag_0_1, _var284)
_var289 = Nand(_var287, _var288)
_var290 = Nand(_var289, _var289)
```
If we visualize all six NAND gates, we can see that this is actually an XOR gate.
![A XOR gate based on an XNOR gate and a NOT gate. The XNOR gate is realized using 5 NAND gates and the NOT gate is realized using 1 NAND gate."]({{ "assets/images/nand-gates-visualization.svg" | relative_url }})

If we repeatedly replace all lines that match the given structure (using some very ugly python code), we get 71 XOR gates and some NAND gates that are still left.
We can identify them as a NOT gate and an AND gate such that we get this code:
```python
_var284 = Xor(flag_0_0, 0)
_var290 = Xor(flag_0_1, _var284)
# 67 XOR gates ignored
_var698 = Xor(flag_15_5, _var692)
_var704 = Xor(flag_15_6, _var698)
_var705 = Not(_var704)
_var707 = And(_var705, 1)
```
In the end we have 128 blocks that each roughly contain 65 XOR gates. Each block has two inputs (in our case `flag_0_0` and `0`) and XORs them. Then XORs the result with another flag bit and so on. 
This effectively adds a different amount of flag bits (over the field GF(2)[^9]), then optionally adds a `1` (a NOT is the same as adding/subtracting a `1` in GF(2)).

[^9]: GF(2): We have two numbers `0` and `1` such that `1+1=0`. Adding two 1-bit numbers is therefore equivalent to XORing them.

The result of each block is then ANDed with the result of the previous block such that the final result is the following:
```python
_var707 = And(_var705, 1)
_var1094 = And(_var1092, _var707)
_var1498 = And(_var1496, _var1094)
# ...
_var49747 = And(_var49745, _var49366)
_var50116 = And(_var50114, _var49747)
_var50515 = And(_var50513, _var50116)
result0 = _var50515
```
We want `result0` to be `1`/`True` so every individual block must be `1`/`True`.

#### A Linear Equation System Over GF(2)
In the end, all those ANDs define a linear equation system over GF(2).

If we extract the 128x128 matrix and 128 vector that is the right side of the equation, we can use sage to get a solution for it like this:
```python
from sage.all import *
F = GF(2)
vec = vector(F, right_side)
mat = matrix(F, rows)
sol = mat.solve_right(vec)

print(int("".join(map(str, reversed(sol))), 2).to_bytes(16, "little"))
```
We finally get the flag: `b'CSR{you_solved!}'`.

(Full source code for the [sage solve script]({{ "assets/files/elkcip/sage_solve.py" | relative_url }}).)

#### SMT and SAT Solvers -- Why They Didn't Work
Initially, I left all the NAND gates as is and didn't realize that I'm actually solving a linear equation system.
So using [Z3](https://github.com/Z3Prover/z3/) should be enough to give us an easy solve, right?
```python
from z3 import *
# ...
_var50512 = Not(_var50511)
_var50513 = Not(_var50512)
_var50514 = Not(And(_var50116, _var50513))
_var50515 = Not(_var50514)
result0 = _var50515
s = Solver()
s.add(result0 != 0)
```
After running this for 2+ hours, I decided to instead transform the constraints to CNF (using Z3 for the conversion) and use the SAT solver [CaDiCal](https://github.com/arminbiere/cadical).

Unfortunately, besides heating the room, they never solved the problem.
This is because the solvers don't see the problem as a linear equation system, but just as many "individual constraints" making it exponentially hard [^10].

[^10]: > The larger hurdle is that once the XORs are in the CNF using the translation, the CNF becomes exponentially hard to solve using standard CDCL as used in most SAT solvers. This is because Gauss-Jordan elimination is exponentially hard for the standard CDCL to perform — but we need Gauss-Jordan elimination because the XORs will interact with each other, as we expect there to be many of them. _Without being able to resolve the XORs with each other efficiently and derive information from them, it will be **practically impossible** to solve the CNF_ [emphasis mine]. [Source](https://www.msoos.org/2018/12/how-approximate-model-counting-works/)

While writing this post, I realized that there exist SAT solvers that can detect XOR gates and perform Gauss-Jordan elimination on them!
One such solver is [cryptominisat](https://github.com/msoos/cryptominisat/tree/master#gauss-jordan-elimination).

Unfortunately there is another thing we have to be aware of.
If we use Z3 with only a single constraint (`s.add(result0 != 0)`), transform to CNF and then use cryptominisat, we will NOT get a solution in a reasonable time.
Instead, we have to introduce variables for every intermediate computation like this:
```python
from z3 import *
# ...
_var50513 = Int('_var50513')
_var50514 = Int('_var50514')
_var50515 = Int('_var50515')
#
s = Solver()
s.add(_var50513 == Not(_var50512))
s.add(_var50514 == Not(And(_var50116, _var50513)))
s.add(_var50515 == Not(_var50514))
s.add(result0 == _var50515)
s.add(result0 != 0)
```

If we do this, we also get the flag `b'CSR{you_solved!}'` in about a minute.

(Full source code for the [cryptominisat solve script]({{ "assets/files/elkcip/cryptominisat_solve.py" | relative_url }}).)