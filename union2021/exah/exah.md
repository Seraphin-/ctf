# exah

Solved with not\_really, got first blood. Maybe will make an extended writeup later and post on team site.

Short explanation is the challenge builds strings out of your flag input (seperated into 4-byte blocks), uses them as keys for an object with letters, and then checks if the object is equal to the value it set. Although 4 byte blocks are pretty small, the challenge runs slow enough that you can't brute force it.

If you look at the weird strings near the bottom of the challenge, you'll see they produce weird behaviour in the interpreter - a function `var w = {"cdjholca": _ -> "s"}; trace(w)` returns `s` instead of `{cdjholca: #fun}`. This is because of a hash collision in the object name resolver.

Haxe's interpreter, eval, is built on OCaml and uses its hashtable implementation which is only 4 bytes (amazing). We can copy its C++ source and use that to brute force input blocks in a second. (You do need to reverse the rest of the challenge, but it's not so complicated.)

```
union{h4shC0ll1zion_m4ke5_HAXE_sad}
```
