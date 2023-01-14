from pwn import *
import numpy
r = remote("challs.htsp.ro", 14001)
for _ in range(15):
    problem = r.recvuntil(b"Ans = ").decode().split("15!\n")[-1].split("\n")
    n = int(problem[0])
    mat = [[int(x) for x in m.split(" ")] for m in problem[1:-1]]
    assert len(mat) == n
    # if diff 0-1 is 1 then w else h
    if abs(mat[0][0] - mat[0][1]) not in [1, n-1]:
        mat2 = [[mat[j][i] for j in range(n)] for i in range(n)]
        mat = mat2
    s = 0
    #print(mat)
    for row in mat:
        # steps to go
        if row[0] == min(row): continue
        for i in range(1, n):
            if numpy.roll(row, i)[0] == min(row) or numpy.roll(row, -i)[0] == min(row):
                s += i
                break
    print(s)
    r.sendline(str(s).encode())
r.interactive()

# X-MAS{Elv35_4r3_g00d_4t_puzz73s}
