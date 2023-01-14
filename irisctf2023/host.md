# Host Issues (misc)
> The flag's right there, but I think it's kinda stuck. Please help me.

The challenge has 2 parts: a server with an allowlist of environment variables and a flag endpoint, and a client you can interact with that uses the server.

The client tries to reach the flag endpoint with an hostname `flag_domain` which fails to resolve after each command is run.
```py
def check(url):
    return json.loads(subprocess.check_output(["curl", "-s", url]))

print(BANNER)
while True:
    choice = input("> ")
    try:
        print(check("http://flag_domain:25566/flag"))
    except subprocess.CalledProcessError: pass
    # note the except hides this curl failing by default
    # ...
```

The client allows you to set any environment variable if the server says the name is OK. In particular, the server will not allow any variables containing these substrings to be set:
```
"LD", "LC", "PATH", "ORIGIN"
```
```py
        if choice == '1':
            env = input("Name? ")
            if check(REMOTE + "env?q=" + b64encode(env.encode()).decode())["ok"]:
                os.environ[env] = input("Value? ") # set env
            else:
                print("No!")
        elif choice == '2':
            env = input("Name? ")
            if check(REMOTE + "env?q=" + b64encode(env.encode()).decode())["ok"]:
                if env in os.environ:
                    print(os.environ[env]) # print env
                else:
                    print("(Does not exist)")
            else:
                print("No!")
```

The intended vulnerability is that there are some unsafe environment variables which are not filtered. One can find a more trustworthy list of environment variables [here](https://codebrowser.dev/glibc/glibc/sysdeps/generic/unsecvars.h.html) in glibc.

The `RESOLV_HOST_CONF` variable in particular will cause the resolver code to try to read the file specified as its argument and, if parsing fails, print the offending line of the file. We can use this to read `/flag` as cURL will attempt to resolve the flag domain and trigger the file read by glibc. The error will be printed to stderr as Python's `check_output` passes it through by default.

The solution used by most, or all, solvers is that I did not properly realize that one could use cURL's proxy variables to have cURL send the `flag_domain` request to the server. That would cause the flag to be printed directly. I had looked through cURL's environemnt variables before, but passed over using a proxy for some reason.

```
irisctf{very_helpful_error_message}
```
