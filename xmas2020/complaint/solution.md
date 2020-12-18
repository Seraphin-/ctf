# Complaint (34 points, 314 solves)

The description says they're redirecting our complaints to /dev/null. Assuming it's something like "echo complaint > /dev/null", we can just use `;` to inject commands. `; ls ;` shows a file called flag.txt, and while `cat` results in a "command not found" we can `tac` it out.

```
> ; tac flag.txt ;
X-MAS{h3ll0_k4r3n-8819d787dd38a397}
```
