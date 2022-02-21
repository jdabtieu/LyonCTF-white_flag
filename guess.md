# guess
![](https://img.shields.io/badge/category-reversing-blue)
![](https://img.shields.io/badge/points-200-orange)

## Description
Guess the flag!

[guess.html](https://ctf.mcpt.ca/media/problem/odujdDyQip1lNqCVziYvxuwRFMawcGZJVCXlRTrOTzk/guess.html)

## Solution
The html file contains some obfuscated JS that we can [deobfuscate](https://lelinhtinh.github.io/de4js/).

After that, we can do some manual cleaning up: the first function simply returns an array of tokens, the second function takes some key, transforms it, and returns the corresponding entry in the array, and the last function attaches a submit listener to the form that checks if our flag is correct.

The middle nested if statements is what checks our flag, but it's obfuscated. Oh no!

To deal with this, since the program needs to call the transform key function to grab the correct functions, we can use it too to figure out what the original functions are. To do this, we can just pop the terms function and transform key function into `node`, or your browser's console to run the JS ourselves.

Once the function is loaded, to check what `0x89` corresponds to, you can simply call the function with `0x89` as a parameter.

Repeating this for all the keywords, I managed to replace the flag check function with this:
```js
    var transform_key3 = transform_key2;
    if (terms1.substr(0x0, 0x6) == 'CTF{cl') {//y
        if (terms1.substring(0x8, 0xf) == 'nt_s1d3') {//y
            if (terms1.substring(0x6, 0x8).split('').reverse().join('') == '31') {//y
                if (terms1.substr(0xf, 0xa) == '_passw0rds') {//y
                    if (terms1.substr(0x2d, 0x6).replace('_3', 'a3') == 'a33f19') {//y
                        if (terms1.substr(0x23, 0x4).replace(/9/, '3') == '349a') {//y
                            if (terms1.substring(0x1e, 0x23).substring(0x0) == 'b4d_3') {//y
                                if (terms1.substring(0x33, 0x3b) == '999}') {//y
                                    if (terms1.substr(0x27, 0x6).split('').reverse().join('@') == '1@d@9@2@_@4') {//y
                                        if (terms1.substr(0x19, 0x3).replace(/_/, '_').split('').reverse().join('') == 'ra_') {
                                            if (!![]/* || terms1.substring(0x33, 0x5) == '33'*/) {
                                                if (terms1.substring(0x1c, 0x1e) == '3_') return !![];
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
```
You will notice in the second last if statement, that one of the conditions was cancelled out. This is because `!![]` is true, so because of short-circuiting, the second part won't be run. It's also a red herring - the program checks for `0x33` earlier on, against a different string.

Now we can just use these rules to build the flag. For example, from the first if statement, bytes 0-6 should be `CTF{cl`, from the second one, we know that bytes 8-f should be `nt_s1d3`, 6-8 will be `13`, etc.

There are a few ambiguous rules, like the replaces. It's possible that our flag contains the string to be replaced, but also possible that it doesn't. I marked these characters with a `?` in my notes, but luckily they both did have to be replaced.

```
0               1               2               3                   <= string index (tens digit)
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef    <= string index (ones digit)
CTF{cl13nt_s1d3_passw0rds_ar3_b4d_3949a4_29d1_33f19999}             <= the flag
                                   ?         ?                      <= ambiguous characters
```



Flag: `CTF{cl13nt_s1d3_passw0rds_ar3_b4d_3949a4_29d1_33f19999}`
