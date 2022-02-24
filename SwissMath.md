# Mathematics in Switzerland
![](https://img.shields.io/badge/category-crypto-blue)
![](https://img.shields.io/badge/points-100-orange)

## Description
`placeholder - problem hidden`
```
placeholder - Switzerland.txt

MzQgNDUgMjAgMzYgMzQgMjAgMzIgMzYgMjAgMzYgMzAgMjAgMzIgMzEgMjAgMzMgMzAgMjAgMzcg
MzYgMjAgMzYgMzAgMjAgMzYgMzcgMjAgMzMgMzAgMjAgMzYgMzIgMjAgMzcgMzcgMjAgMzYgMzYg
MjAgMzMgMzAgMjAgMzQgMzUgMjAgMzYgMzMgMjAgMzMgMzAgMjAgMzMgNDMgMjAgMzUgNDYgMjAg
MzUgNDMgMjAgMzQgMzAgMjAgMzcgNDIgMjAgMzUgMzAgMjAgMzMgNDYgMjAgMzcgNDUgMjAgMzcg
MzggMjAgMzQgMzUgMjAgMzcgMzggMjAgMzMgMzUgMjAgMzcgMzMgMjAgMzYgMzMgMjAgMzQgNDMg
MjAgMzcgMzUgMjAgMzIgMzUgMjAgMzcgMzIgMjAgMzAgNDE=
```

## Solution
The title suggests that some adding will be in the solution, since the Swiss flag is just a huge addition sign.

That being said, the file is very obviously in base64 right now, as signified by the `=` at the end of the file. We can use [CyberChef](https://gchq.github.io/CyberChef/#input=TXpRZ05EVWdNakFnTXpZZ016UWdNakFnTXpJZ016WWdNakFnTXpZZ016QWdNakFnTXpJZ016RWdNakFnTXpNZ016QWdNakFnTXpjZwpNellnTWpBZ016WWdNekFnTWpBZ016WWdNemNnTWpBZ016TWdNekFnTWpBZ016WWdNeklnTWpBZ016Y2dNemNnTWpBZ016WWdNellnCk1qQWdNek1nTXpBZ01qQWdNelFnTXpVZ01qQWdNellnTXpNZ01qQWdNek1nTXpBZ01qQWdNek1nTkRNZ01qQWdNelVnTkRZZ01qQWcKTXpVZ05ETWdNakFnTXpRZ016QWdNakFnTXpjZ05ESWdNakFnTXpVZ016QWdNakFnTXpNZ05EWWdNakFnTXpjZ05EVWdNakFnTXpjZwpNemdnTWpBZ016UWdNelVnTWpBZ016Y2dNemdnTWpBZ016TWdNelVnTWpBZ016Y2dNek1nTWpBZ016WWdNek1nTWpBZ016UWdORE1nCk1qQWdNemNnTXpVZ01qQWdNeklnTXpVZ01qQWdNemNnTXpJZ01qQWdNekFnTkRFPQ) to help us decode it.

![](https://cdn.discordapp.com/attachments/359503958601105418/946225656331644948/unknown.png)

Now, there's a bunch of numbers. These are all in the ascii range (0x20 - 0x7e), so it's likely hex.

![](https://cdn.discordapp.com/attachments/359503958601105418/946225873525288980/unknown.png)

Once again, this looks like hex, and all the characters are still in the ascii range.

![](https://cdn.discordapp.com/attachments/359503958601105418/946226097178157148/unknown.png)

Huh, some weird characters. This is where the title comes into play. By 'adding,' do the problem setters mean shifting all the letters by a certain amount, like a caesar cipher? Well obviously it's not a caesar cipher, since we have very little alphabet characters. We can, however, try shifting by other amounts. You can try all the rotation ciphers, but one common(ish) cipher that's available is ROT47, which typically produces symbols and numbers from text, which looks about right here.

Applying the cipher, we now get `}5U1P_G18_3H7_t4_k0-oL!nOItIdD4{FTC`, which just looks like the reversed flag.

![](https://cdn.discordapp.com/attachments/359503958601105418/946227207980855376/unknown.png)

Full CyberChef recipe: [here](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)From_Hex('Auto')From_Hex('Auto')ROT47(47)Reverse('Character')&input=TXpRZ05EVWdNakFnTXpZZ016UWdNakFnTXpJZ016WWdNakFnTXpZZ016QWdNakFnTXpJZ016RWdNakFnTXpNZ016QWdNakFnTXpjZwpNellnTWpBZ016WWdNekFnTWpBZ016WWdNemNnTWpBZ016TWdNekFnTWpBZ016WWdNeklnTWpBZ016Y2dNemNnTWpBZ016WWdNellnCk1qQWdNek1nTXpBZ01qQWdNelFnTXpVZ01qQWdNellnTXpNZ01qQWdNek1nTXpBZ01qQWdNek1nTkRNZ01qQWdNelVnTkRZZ01qQWcKTXpVZ05ETWdNakFnTXpRZ016QWdNakFnTXpjZ05ESWdNakFnTXpVZ016QWdNakFnTXpNZ05EWWdNakFnTXpjZ05EVWdNakFnTXpjZwpNemdnTWpBZ016UWdNelVnTWpBZ016Y2dNemdnTWpBZ016TWdNelVnTWpBZ016Y2dNek1nTWpBZ016WWdNek1nTWpBZ016UWdORE1nCk1qQWdNemNnTXpVZ01qQWdNeklnTXpVZ01qQWdNemNnTXpJZ01qQWdNekFnTkRFPQ)

Flag: `CTF{4DdItIOn!Lo-0k_4t_7H3_81G_P1U5}`
