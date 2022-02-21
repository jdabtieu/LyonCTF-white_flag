# Custom RSA

![](https://img.shields.io/badge/category-cryptography-blue)
![](https://img.shields.io/badge/points-400-orange)

Author of writeup: todaybrian

Through an analysis of the given code, we know the following:
- N, which is is a product of two large unknown prime numbers: p and q
- An odd number e1, which is between 1 and N
- `c1 = (p+q)^e1 (mod N)`
- `c2 = (p-q)^e1 (mod N)`
- An exponent `e = 65537`
- `f^e (mod N)`, where `f` is our flag

We notice that the only vulnerable parts of this code are variables `c1` and `c2`, which are usually not given in standard RSA implementations.

Since `N = pq`, we can realize that all the `pq` terms in an expansion of `c1` and `c2` get cancelled out. Since `e1` is odd, we get:

- `c1 = p^e1 + q^e1 (mod N)`
- `c2 = p^e1 - q^e1 (mod N)`

We can find `p^e1 (mod N)` and `q^e1 (mod N)` through a system of equations.

Our second observation uses a step in the euclidean algorithm:
- `gcd(a, b) = gcd(a%b, b)`

Since we know that `gcd(p^t, n) = gcd(p^t, pq) = p`, using our observation, we can find that:
- `gcd(p^t (mod N), n) = gcd(p^t, n) = p`

And vice versa for `q`. 

The above proceses can be done in sage: https://pastebin.com/s2eczK6w

Now that we have `p` and `q`, we can place all our values in here: https://www.dcode.fr/rsa-cipher, and we get our flag: `CTF{Seriously_stop_using_RSA}`
