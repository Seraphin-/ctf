import os
import sys

FLAG = b"give me the flag"

print("Welcome to my stable SPHINCS+ signing service.")
os.system("./chal_genkey")

for attempt in range(1280):
    choice = input("> ")

    if choice == "1":
        m = input("Hex-encoded message: ")
        m = bytes.fromhex(m)
        if m == FLAG:
            print("NO")
            exit(-1)
        with open("req", "wb") as f:
            f.write(m)
        os.system("./chal_sign")
    elif choice == "2":
        smlen = int(input("Hex length: "))
        print("Hex-encoded signature: ", end="")
        rlen = 0
        m = ""
        while rlen < smlen:
            # ignore line breaks while reading
            m += sys.stdin.read(min(4096, smlen - rlen)).replace("\n","")
            rlen = len(m)

        m = bytes.fromhex(m)
        sys.stdin.readline()

        with open("ver", "wb") as f:
            f.write(m)
        os.system("./chal_verify")
    else:
        print("bye")
        exit()
