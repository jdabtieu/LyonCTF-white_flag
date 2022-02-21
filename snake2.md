# Snake 2
![](https://img.shields.io/badge/category-reversing-blue)
![](https://img.shields.io/badge/points-150-orange)

## Description
To stop you from finding the password from my code this time, I compiled it! Good Luck!

[snake2.pyc](https://ctf.mcpt.ca/media/problem/Q75SWmsi7rYh9GKQ3VGq29XVGNTr0uyHgqlSqAekbEE/snake2.pyc)

## Solution
We can decompile the file using `decompyle3`

```py
# decompyle3 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.8.5 (tags/v3.8.5:580fbb0, Jul 20 2020, 15:57:54) [MSC v.1924 64 bit (AMD64)]
# Embedded file name: snake2.py
# Compiled at: 2022-01-30 18:50:38
# Size of source mod 2**32: 880 bytes
from base64 import b64encode
from sys import exit

def shuffle(text: str) -> str:
    indexes = [3, 0, 9, 5, 1, 6, 10, 8, 4, 11, 7, 2]
    out = ''
    for i in indexes:
        out += text[i]
    else:
        return out


def xor(text: str) -> bytes:
    key = [204, 21, 149, 129, 5, 82, 242, 163, 113, 75, 23, 168]
    out = ''
    for i in range(12):
        out += chr(ord(text[i]) ^ key[i])
    else:
        return out


def main():
    pw = input('Enter password to get flag: ')
    s = b64encode(pw.encode('utf-8')).decode()
    if len(s) != 12:
        print('Password incorrect!')
        exit(1)
    s = shuffle(s)
    s = xor(s)
    if s.encode('utf-8') != b'\xc2\x88Z\xc2\xa6\xc2\xb3Qc\xc2\xa7\xc3\xb1\x10vG\xc3\xa2':
        print('Password incorect!')
        exit(1)
    else:
        print('Wow you found the password! Here have a flag: CTF{pyth0n_15_c0mp1l3d_' + pw + '}')


main()
# okay decompiling E:/downloads\snake2.pyc
```

Now, we can just reverse all the steps (as xor and shuffle are easily reversable)
```py
import base64
s = b'\xc2\x88Z\xc2\xa6\xc2\xb3Qc\xc2\xa7\xc3\xb1\x10vG\xc3\xa2'.decode('utf-8')
key = [204, 21, 149, 129, 5, 82, 242, 163, 113, 75, 23, 168]
indexes = [3, 0, 9, 5, 1, 6, 10, 8, 4, 11, 7, 2]
map = dict()
for i in range(len(indexes)):
  map[indexes[i]] = i

a1 = ""
for i in range(len(s)):
  a1 += chr(ord(s[i]) ^ key[i])

a2 = ""
for i in range(len(a1)):
  a2 += a1[map[i]]

print('CTF{pyth0n_15_c0mp1l3d_' + base64.b64decode(a2).decode('utf-8') + '}')

Flag: `CTF{pyth0n_15_c0mp1l3d_92CkmOGu}`
