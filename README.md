## Instructions 
Compile with : 
- nasm -f win64 winexec_cmd.asm -o shelly.o
- radare2 -b 32 -c 'pc' ./shelly.o
