; seccomp-tools asm ./insecure_seccomp.asm -o seccomp -f raw
; seccomp-tools disasm ./raw
; copy columns

; uiuctf{seccomp_plus_new_privs_equals_inseccomp_e84609bf}

A = sys_number
A == faccessat ? next : ok
return ERRNO(1)
ok:
return ALLOW
