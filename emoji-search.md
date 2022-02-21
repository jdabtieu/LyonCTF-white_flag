# Emoji Search
![](https://img.shields.io/badge/category-web-blue)
![](https://img.shields.io/badge/points-150-orange)

## Description
I made a website of my favourite Discord emoji! Wait, what do you mean one of them isn't a real emoticon?

## Solution

Navigating to each enoji, we see that POST is the odd one out. It just happens, that with the HTTP protocol, there is a POST method that can be used to access the page. When a link is clicked, a GET request is made. To make a POST request, we can simply use `curl` to create one for us.

```
jw@Windows:~$ curl -X POST http://ff822f8.0x16.ink/post
<html>
    <head>
        <title>flag?</title>
        <meta content="text/html; charset=UTF-8" http-equiv="content-type">
        <style type="text/css">useless</style>
    </head>
    <body class="c5">
        <p>
            <span style="font-size:0%;">SEJTe3</span>
            dtM3ozXzE1X2EwX
            <span style="font-size:0%;">3UzaV9wM2V1MXM5</span>
            XzF2XzUxOXV3fQ==
        </p>
        <p>Congratulations! You found the flag! This flag is absolutely not a red herring. Definitely. Surely. o% chance that it's not invisible or hidden in any way.</p>
        <span style="font-size:0%;">Key: find</span>
    </body>
</html>
```

We can see 4 segments of what appears to be base64 show up, and throwing that into a base64 decode gives us `HBS{wm3z3_15_a0_u3i_p3eu1s9_1v_519uw}`.

**Edit**: Along with the flag in base64, we also see key: find. This suggests a cipher of some sort, and trying a Vigenere cipher with find as the key gives the flag. I didn't notice this during the contest, and bruteforced the key instead, the details of which can be seen below.
<details>
    <summary>Old solution</summary>
Looks like some sort of basic cipher, but trying a caesar cipher doesn't work. Another option is to guess a Vigenere cipher key, since we know that the flag must start with `CTF`.

A cool trick with vigenere ciphers is that for each character `X`, if you want it to equal `Y`, you can use `Y` as the key, check what `X` changed into (suppose it changes into `A`), and then that means `A` is the key you want to use.

Repeating this technique for the first three characters, we find that they key starts with `FIN`. At this point, the 4th letter can be bruteforced (or you can try some common words, like [FIND](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Vigen%C3%A8re_Decode('FIND')&input=U0VKVGUzZHRNM296WHpFMVgyRXdYM1V6YVY5d00yVjFNWE01WHpGMlh6VXhPWFYzZlE9PQ), FINISH, etc.) to get the flag.
</details>
    
Flag: `CTF{th3r3_15_n0_r3d_h3rr1n9_1n_519ht}`
