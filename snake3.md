# Snake 3
![](https://img.shields.io/badge/category-reversing-blue)
![](https://img.shields.io/badge/points-300-orange)

## Description
Maybe packaging my application with a newer Python version will keep you out...

[snake3.exe](https://ctf.mcpt.ca/media/problem/s2p6YnRxY1oyGCpr8rBVGixz6q_iqft8wRXfD9TFoaw/snake3.exe)
[snake3_linux](https://ctf.mcpt.ca/media/problem/s2p6YnRxY1oyGCpr8rBVGixz6q_iqft8wRXfD9TFoaw/snake3_linux)

## Solution
The first step is to unpackage the executable. [PyInstXtractor](https://github.com/extremecoders-re/pyinstxtractor) can do the job, but because the Python version used to create the challenge is Python 3.10, our local Python must be Python 3.10 as well.

After this, in the generated `snake3.exe_extracted` folder, we can see a snake3.pyc file. Unfortunately, decompyle3 doesn't work for Python 3.10, and neither do most tools. However, [pycdc](https://github.com/zrax/pycdc) claims to support all version of Python. After building and running it against the `snake3.pyc` file and doing some cleanup (like `None.a85encode` (should be `base64.a85encode`) and `None('some string')` instead of `print('some string')`, we get this:

```py
# Source Generated with Decompyle++
# File: snake3.pyc (Python 3.10)

import hashlib
import base64
import string
from sys import exit

md5 = lambda s: hashlib.md5(s.encode()).hexdigest()

def build_flag(s = None):
    return string.printable[38] + string.printable[55] + string.printable[41] + string.printable[90] + string.printable[25] + string.printable[34] + string.printable[29] + string.printable[17] + string.printable[0] + string.printable[23] + string.printable[88] + string.printable[13] + string.printable[1] + string.printable[28] + string.printable[28] + string.printable[4] + string.printable[28] + string.printable[28] + string.printable[3] + string.printable[22] + string.printable[11] + string.printable[21] + string.printable[34] + string.printable[88] + string.printable[15] + string.printable[30] + string.printable[23] + string.printable[88] + md5(s) + string.printable[92]


def check_pw(pw = None):
    if len(pw) != 8:
        return False
    pw = base64.a85encode(pw.encode())
    pw = base64.b85encode(pw)
    pw = pw[::-1]
    pw = xor(pw)
    return pw == [
        92,
        133,
        58,
        46,
        175,
        150,
        255,
        131,
        33,
        165,
        227,
        203,
        82]


def xor(pw = None):
    key = [
        99,
        175,
        106,
        19,
        198,
        194,
        203,
        208,
        5,
        194,
        132,
        252,
        24]
    out = list()
    return out

password = input('Enter the password: ')
if check_pw(password):
    print(build_flag(password))
    exit(0)
print('Password incorrect! Maybe ask for the flag nicely next time :p')
exit(1)
```

Now, pycdc did make a few mistakes, but it's close enough that we can see what's going on. Working backwards, starting with the array in check_pw, we need to xor it with the key in xor, reverse it, b85decode, and then a85decode.

```py
import base64
xor = [
        99,
        175,
        106,
        19,
        198,
        194,
        203,
        208,
        5,
        194,
        132,
        252,
        24]

res = [
        92,
        133,
        58,
        46,
        175,
        150,
        255,
        131,
        33,
        165,
        227,
        203,
        82]

a = [xor[i] ^ res[i] for i in range(len(res))]
a = a[::-1]
a = bytes(a)
a = base64.b85decode(a)
a = base64.a85decode(a)
print(a) # b'SYU4wfiE'
```

Now we can use this password on the executable to get the flag.
```
jw@Windows:/tmp/snake3$ ./snake3.exe
Enter the password: SYU4wfiE
CTF{pyth0n_d1ss4ss3mbly_fun_490c407348dfd39b8574605382b035d3}
```

Flag: `CTF{pyth0n_d1ss4ss3mbly_fun_490c407348dfd39b8574605382b035d3}`
